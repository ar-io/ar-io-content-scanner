from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from src.backfill import BackfillScanner
from src.config import Settings, load_settings
from src.db import ScannerDB
from src.gateway_client import GatewayClient
from src.logging_config import configure_logging
from src.metrics import ScanMetrics
from src.ml.classifier import PhishingClassifier
from src.models import WebhookPayload
from src.rules.engine import RuleEngine
from src.safe_browsing import SafeBrowsingClient
from src.scanner import Scanner
from src.screenshot import ScreenshotService
from src.worker import WorkerPool

logger = logging.getLogger("scanner.server")


def build_app(settings: Settings | None = None) -> FastAPI:
    if settings is None:
        settings = load_settings()

    configure_logging(settings.log_level)

    db = ScannerDB(settings.db_path)
    metrics = ScanMetrics()
    gateway = GatewayClient(
        gateway_url=settings.gateway_url,
        admin_api_key=settings.admin_api_key,
        max_bytes=settings.max_scan_bytes,
        timeout_ms=settings.scan_timeout_ms,
    )

    classifier = None
    if settings.ml_model_enabled:
        try:
            classifier = PhishingClassifier(settings.ml_model_path)
        except Exception:
            logger.exception("Failed to load ML model, continuing without it")

    engine = RuleEngine(settings, classifier)

    screenshot = None
    if settings.screenshot_enabled:
        screenshot = ScreenshotService(
            screenshot_dir=settings.screenshot_dir,
            gateway_url=settings.gateway_url,
            timeout_ms=settings.screenshot_timeout_ms,
        )

    # Verdict feed components
    feed_client = None
    feed_poller = None
    if settings.verdict_api_key:
        from src.feed.client import FeedClient

        if settings.verdict_feed_urls:
            feed_client = FeedClient(
                api_key=settings.verdict_api_key,
                timeout_ms=settings.verdict_feed_request_timeout_ms,
            )

        if feed_client and settings.verdict_feed_urls:
            from src.feed.poller import FeedPoller

            feed_poller = FeedPoller(settings, db, feed_client, gateway, metrics)

    # Safe Browsing client — domain monitoring uses the Transparency Report
    # (no API key needed). The Lookup API for individual URL checks is optional
    # and requires SAFE_BROWSING_API_KEY.
    safe_browsing = SafeBrowsingClient(
        api_key=settings.safe_browsing_api_key,
    )

    scanner = Scanner(
        settings, db, gateway, engine, metrics,
        screenshot=screenshot, feed_client=feed_client,
        safe_browsing=safe_browsing,
    )

    backfill = None
    if settings.backfill_enabled:
        backfill = BackfillScanner(settings, db, engine, gateway, metrics, screenshot=screenshot)
        if (
            settings.scanner_mode == "enforce"
            and not settings.backfill_gateway_db_path
        ):
            logger.warning(
                "Backfill enabled in enforce mode without BACKFILL_GATEWAY_DB_PATH. "
                "Malicious content will be detected but cannot be blocked "
                "(no TX ID lookup available)."
            )

    pool = WorkerPool(
        scanner, db, concurrency=settings.scanner_workers,
        backfill=backfill, feed_poller=feed_poller,
        safe_browsing=safe_browsing, gateway=gateway,
        settings=settings, metrics=metrics,
    )

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        db.initialize()
        if screenshot:
            await screenshot.startup()
        await pool.start()
        logger.info(
            "Content scanner started",
            extra={
                "mode": settings.scanner_mode,
                "version": settings.scanner_version,
                "gateway": settings.gateway_url,
                "workers": settings.scanner_workers,
                "ml_model": "enabled" if classifier else "disabled",
                "ml_threshold": settings.ml_suspicious_threshold,
                "max_scan_bytes": settings.max_scan_bytes,
                "backfill": settings.backfill_enabled,
                "admin_ui": settings.admin_ui_enabled,
                "screenshots": screenshot.available if screenshot else False,
                "verdict_feed": bool(settings.verdict_api_key),
                "verdict_feed_peers": len(settings.verdict_feed_urls),
                "safe_browsing": True,
                "safe_browsing_api_key": bool(settings.safe_browsing_api_key),
            },
        )
        yield
        logger.info("Shutting down worker pool...")
        try:
            await asyncio.wait_for(pool.stop(), timeout=10)
        except asyncio.TimeoutError:
            logger.warning("Worker pool shutdown timed out after 10s")
        await safe_browsing.close()
        if feed_client:
            await feed_client.close()
        if screenshot:
            await screenshot.shutdown()
        await gateway.close()
        db.close()
        logger.info("Content scanner stopped")

    app = FastAPI(title="ar.io Content Scanner", version="0.1.0", lifespan=lifespan)

    # Store refs for endpoint access
    app.state.scanner = scanner
    app.state.metrics = metrics
    app.state.db = db
    app.state.settings = settings
    app.state.gateway = gateway
    app.state.screenshot = screenshot
    app.state.feed_poller = feed_poller
    app.state.safe_browsing = safe_browsing

    # Mount verdict feed API if configured
    if settings.verdict_api_key:
        from src.feed.routes import build_feed_router

        app.include_router(build_feed_router(app.state))

    # Mount admin UI if enabled
    if settings.admin_ui_enabled:
        from src.admin.routes import build_admin_router

        app.mount(
            "/static/admin",
            StaticFiles(directory="src/static/admin"),
            name="admin-static",
        )
        app.include_router(build_admin_router(app.state))

    @app.post("/scan", status_code=202)
    async def scan(payload: WebhookPayload):
        await scanner.process_webhook(payload)
        return {"status": "accepted"}

    @app.get("/health")
    async def health():
        checks: dict = {}
        healthy = True

        # Database connectivity
        try:
            db.queue_depth()
            checks["database"] = "ok"
        except Exception:
            checks["database"] = "error"
            healthy = False

        # ML model
        if settings.ml_model_enabled:
            checks["ml_model"] = "loaded" if classifier else "failed"
            if not classifier:
                healthy = False
        else:
            checks["ml_model"] = "disabled"

        # Worker pool
        checks["workers"] = "running" if pool._running else "stopped"
        if not pool._running:
            healthy = False

        # Last webhook indicator
        data = metrics.to_dict()
        checks["last_webhook_at"] = data["last_webhook_at"]

        status_code = 200 if healthy else 503
        return JSONResponse(
            status_code=status_code,
            content={
                "status": "ok" if healthy else "degraded",
                "mode": settings.scanner_mode,
                "version": settings.scanner_version,
                "checks": checks,
            },
        )

    @app.get("/metrics")
    async def get_metrics():
        data = metrics.to_dict()
        data["queue_depth"] = db.queue_depth()
        return data

    @app.get("/metrics/prometheus")
    async def get_metrics_prometheus():
        return PlainTextResponse(
            content=metrics.to_prometheus(queue_depth=db.queue_depth()),
            media_type="text/plain; version=0.0.4; charset=utf-8",
        )

    @app.exception_handler(Exception)
    async def unhandled_exception(request: Request, exc: Exception):
        logger.exception("Unhandled error", extra={"path": request.url.path})
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error"},
        )

    return app


def main() -> None:
    import uvicorn

    settings = load_settings()
    app = build_app(settings)
    uvicorn.run(app, host="0.0.0.0", port=settings.scanner_port)


if __name__ == "__main__":
    main()
