from __future__ import annotations

import csv
import io
import json
import logging
import re

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, StreamingResponse
from fastapi.templating import Jinja2Templates

from src.admin.auth import require_admin_key
from src.models import Verdict

logger = logging.getLogger("scanner.admin")

_BASE64URL_43 = re.compile(r"^[A-Za-z0-9_-]{43}$")
_HASH_PATTERN = re.compile(r"^[A-Za-z0-9_+/=-]{1,64}$")


def build_admin_router(app_state) -> APIRouter:
    """Build the admin API router with access to app state.

    Uses accessor functions to read db/metrics/gateway from app_state
    at request time, so tests can replace them after build_app().
    """
    settings = app_state.settings
    _state = app_state  # closure over mutable state object

    router = APIRouter()
    auth = require_admin_key(settings.scanner_admin_key)
    templates = Jinja2Templates(directory="src/templates")

    # --- HTML page (no auth — login is client-side) ---

    @router.get("/admin", response_class=HTMLResponse)
    async def admin_page(request: Request):
        return templates.TemplateResponse(
            "admin/base.html",
            {"request": request},
        )

    # --- API endpoints (all require auth) ---

    @router.get("/api/admin/stats")
    async def stats(_key: str = Depends(auth)):
        db = _state.db
        data = _state.metrics.to_dict()
        counts = db.get_dashboard_counts()
        data["queue_depth"] = db.queue_depth()
        return {
            "mode": settings.scanner_mode,
            "version": settings.scanner_version,
            "uptime_seconds": data["uptime_seconds"],
            "workers": settings.scanner_workers,
            "counts": counts,
            "metrics": {
                "scans_total": data["scans_total"],
                "scans_by_verdict": data["scans_by_verdict"],
                "scans_skipped_not_html": data["scans_skipped_not_html"],
                "cache_hits": data["cache_hits"],
                "cache_misses": data["cache_misses"],
                "blocks_sent": data["blocks_sent"],
                "blocks_failed": data["blocks_failed"],
                "avg_scan_ms": data["avg_scan_ms"],
                "queue_depth": data["queue_depth"],
            },
            "last_webhook_at": data["last_webhook_at"],
            "backfill": {
                "enabled": settings.backfill_enabled,
                "files_scanned": int(db.get_state("backfill_files_scanned", "0")),
                "malicious_found": int(db.get_state("backfill_malicious_found", "0")),
                "sweeps_completed": int(db.get_state("backfill_sweeps_completed", "0")),
                "last_sweep_at": int(db.get_state("backfill_last_sweep_at", "0")) or None,
            },
            "recent_detections": db.get_recent_detections(limit=10),
        }

    @router.get("/api/admin/review")
    async def review_list(
        q: str = Query(""),
        verdict: str = Query("all"),
        status: str = Query("pending"),
        sort: str = Query("newest"),
        page: int = Query(1, ge=1),
        per_page: int = Query(25, ge=1, le=100),
        _key: str = Depends(auth),
    ):
        db = _state.db
        items, total = db.list_review_items(
            query=q,
            verdict_filter=verdict,
            status_filter=status,
            sort=sort,
            page=page,
            per_page=per_page,
        )
        pages = max(1, (total + per_page - 1) // per_page)
        return {
            "items": items,
            "total": total,
            "page": page,
            "per_page": per_page,
            "pages": pages,
        }

    @router.get("/api/admin/review/{content_hash}")
    async def review_detail(
        content_hash: str,
        _key: str = Depends(auth),
    ):
        if not _HASH_PATTERN.match(content_hash):
            raise HTTPException(status_code=400, detail="Invalid content hash")

        db = _state.db
        verdict = db.get_verdict(content_hash)
        if verdict is None:
            raise HTTPException(status_code=404, detail="Not found")

        override = db.get_override(content_hash)
        return {
            "content_hash": verdict.content_hash,
            "tx_id": verdict.tx_id,
            "verdict": verdict.verdict.value,
            "matched_rules": verdict.matched_rules,
            "ml_score": verdict.ml_score,
            "scanned_at": verdict.scanned_at,
            "scanner_version": verdict.scanner_version,
            "admin_override": override.admin_verdict if override else None,
            "admin_notes": override.notes if override else None,
            "content_preview_url": f"/api/admin/preview/{verdict.tx_id}",
        }

    @router.post("/api/admin/review/{content_hash}/confirm")
    async def review_confirm(
        content_hash: str,
        request: Request,
        _key: str = Depends(auth),
    ):
        if not _HASH_PATTERN.match(content_hash):
            raise HTTPException(status_code=400, detail="Invalid content hash")

        db = _state.db
        verdict = db.get_verdict(content_hash)
        if verdict is None:
            raise HTTPException(status_code=404, detail="Not found")

        body = await request.json() if await request.body() else {}
        notes = str(body.get("notes", ""))[:500]

        db.save_override(
            content_hash=content_hash,
            tx_id=verdict.tx_id,
            admin_verdict="confirmed_malicious",
            original_verdict=verdict.verdict.value,
            original_rules=verdict.matched_rules or "[]",
            original_ml_score=verdict.ml_score,
            notes=notes,
        )

        blocked_tx_ids = []
        if settings.scanner_mode == "enforce":
            gateway = _state.gateway
            rules = json.loads(verdict.matched_rules or "[]")
            success = await gateway.block_data(
                verdict.tx_id, content_hash, rules
            )
            if success:
                blocked_tx_ids.append(verdict.tx_id)

        logger.info(
            "admin_confirm",
            extra={
                "content_hash": content_hash,
                "tx_id": verdict.tx_id,
                "blocked": len(blocked_tx_ids) > 0,
            },
        )

        return {
            "status": "confirmed",
            "blocked": len(blocked_tx_ids) > 0,
            "blocked_tx_ids": blocked_tx_ids,
        }

    @router.post("/api/admin/review/{content_hash}/dismiss")
    async def review_dismiss(
        content_hash: str,
        request: Request,
        _key: str = Depends(auth),
    ):
        if not _HASH_PATTERN.match(content_hash):
            raise HTTPException(status_code=400, detail="Invalid content hash")

        db = _state.db
        verdict = db.get_verdict(content_hash)
        if verdict is None:
            raise HTTPException(status_code=404, detail="Not found")

        body = await request.json() if await request.body() else {}
        notes = str(body.get("notes", ""))[:500]

        db.save_override(
            content_hash=content_hash,
            tx_id=verdict.tx_id,
            admin_verdict="confirmed_clean",
            original_verdict=verdict.verdict.value,
            original_rules=verdict.matched_rules or "[]",
            original_ml_score=verdict.ml_score,
            notes=notes,
        )

        db.update_verdict(content_hash, Verdict.CLEAN)

        logger.info(
            "admin_dismiss",
            extra={"content_hash": content_hash, "tx_id": verdict.tx_id},
        )

        return {"status": "dismissed"}

    @router.post("/api/admin/review/{content_hash}/revert")
    async def review_revert(
        content_hash: str,
        _key: str = Depends(auth),
    ):
        if not _HASH_PATTERN.match(content_hash):
            raise HTTPException(status_code=400, detail="Invalid content hash")

        db = _state.db
        override = db.get_override(content_hash)
        if override is None:
            raise HTTPException(
                status_code=404, detail="No override found for this content"
            )

        # Restore the original verdict
        original = override.original_verdict
        try:
            original_verdict = Verdict(original)
        except ValueError:
            original_verdict = Verdict.SUSPICIOUS

        db.update_verdict(content_hash, original_verdict)
        db.delete_override(content_hash)

        logger.info(
            "admin_revert",
            extra={
                "content_hash": content_hash,
                "tx_id": override.tx_id,
                "reverted_from": override.admin_verdict,
                "restored_verdict": original_verdict.value,
            },
        )

        return {
            "status": "reverted",
            "restored_verdict": original_verdict.value,
        }

    @router.get("/api/admin/history")
    async def history_list(
        q: str = Query(""),
        verdict: str = Query("all"),
        source: str = Query("all"),
        period: str = Query("all"),
        page: int = Query(1, ge=1),
        per_page: int = Query(25, ge=1, le=100),
        _key: str = Depends(auth),
    ):
        db = _state.db
        items, total = db.list_history(
            query=q,
            verdict_filter=verdict,
            source_filter=source,
            period=period,
            page=page,
            per_page=per_page,
        )
        pages = max(1, (total + per_page - 1) // per_page)
        return {
            "items": items,
            "total": total,
            "page": page,
            "per_page": per_page,
            "pages": pages,
        }

    @router.get("/api/admin/history/export")
    async def history_export(
        q: str = Query(""),
        verdict: str = Query("all"),
        source: str = Query("all"),
        period: str = Query("all"),
        _key: str = Depends(auth),
    ):
        db = _state.db
        items, _ = db.list_history(
            query=q,
            verdict_filter=verdict,
            source_filter=source,
            period=period,
            page=1,
            per_page=10000,
        )
        output = io.StringIO()
        writer = csv.DictWriter(
            output,
            fieldnames=[
                "content_hash", "tx_id", "verdict", "matched_rules",
                "ml_score", "scanned_at", "scanner_version", "admin_status",
            ],
        )
        writer.writeheader()
        writer.writerows(items)

        return StreamingResponse(
            iter([output.getvalue()]),
            media_type="text/csv",
            headers={
                "Content-Disposition": "attachment; filename=scan_history.csv"
            },
        )

    @router.get("/api/admin/preview/{tx_id}")
    async def content_preview(
        tx_id: str,
        _key: str = Depends(auth),
    ):
        if not _BASE64URL_43.match(tx_id):
            raise HTTPException(status_code=400, detail="Invalid TX ID")

        gateway = _state.gateway
        content = await gateway.fetch_content(tx_id)
        if content is None:
            raise HTTPException(status_code=404, detail="Content not found")

        return PlainTextResponse(
            content=content.decode("utf-8", errors="replace"),
            headers={
                "Content-Security-Policy": "sandbox",
                "X-Content-Type-Options": "nosniff",
            },
        )

    @router.get("/api/admin/settings")
    async def get_settings(_key: str = Depends(auth)):
        db = _state.db
        return {
            "mode": settings.scanner_mode,
            "version": settings.scanner_version,
            "gateway_url": settings.gateway_url,
            "workers": settings.scanner_workers,
            "ml_model_enabled": settings.ml_model_enabled,
            "max_scan_bytes": settings.max_scan_bytes,
            "scan_timeout_ms": settings.scan_timeout_ms,
            "rules": {
                "seed_phrase": settings.rule_seed_phrase,
                "external_credential_form": settings.rule_external_credential_form,
                "wallet_impersonation": settings.rule_wallet_impersonation,
                "obfuscated_loader": settings.rule_obfuscated_loader,
            },
            "backfill": {
                "enabled": settings.backfill_enabled,
                "data_path": settings.backfill_data_path or None,
                "rate": settings.backfill_rate,
                "interval_hours": settings.backfill_interval_hours,
            },
            "db_stats": db.get_db_stats(),
        }

    @router.get("/api/admin/training-export")
    async def training_export(_key: str = Depends(auth)):
        db = _state.db
        overrides = db.list_overrides()
        output = io.StringIO()
        writer = csv.DictWriter(
            output,
            fieldnames=[
                "content_hash", "tx_id", "admin_verdict", "original_verdict",
                "original_rules", "original_ml_score", "notes", "created_at",
            ],
        )
        writer.writeheader()
        writer.writerows(overrides)

        return StreamingResponse(
            iter([output.getvalue()]),
            media_type="text/csv",
            headers={
                "Content-Disposition": "attachment; filename=training_data.csv"
            },
        )

    return router
