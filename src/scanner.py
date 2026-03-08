from __future__ import annotations

import asyncio
import json
import logging

from bs4 import BeautifulSoup

from src.config import Settings
from src.db import ScannerDB
from src.gateway_client import GatewayClient
from src.metrics import ScanMetrics
from src.ml.features import parse_html
from src.models import Verdict, WebhookPayload
from src.rules.engine import RuleEngine
from src.db import QueueRow

logger = logging.getLogger("scanner.core")

HTML_SIGNATURES = [
    b"<!doctype html",
    b"<html",
    b"<head",
    b"<body",
    b"<script",
    b"<iframe",
    b"<div",
    b"<form",
    b"<meta",
]


def looks_like_html(content: bytes) -> bool:
    head = content[:512].lstrip()
    if head.startswith(b"\xef\xbb\xbf"):
        head = head[3:]
    head = head.lower()
    return any(head.startswith(sig) for sig in HTML_SIGNATURES)


def is_html_content_type(content_type: str | None) -> bool | None:
    """Returns True if HTML, False if definitely not, None if unknown."""
    if content_type is None:
        return None
    ct = content_type.lower().split(";")[0].strip()
    if not ct:
        return None
    if ct in ("text/html", "application/xhtml+xml"):
        return True
    if ct in ("application/octet-stream", "text/plain"):
        return None
    return False


class Scanner:
    def __init__(
        self,
        settings: Settings,
        db: ScannerDB,
        gateway: GatewayClient,
        engine: RuleEngine,
        metrics: ScanMetrics,
    ):
        self.settings = settings
        self.db = db
        self.gateway = gateway
        self.engine = engine
        self.metrics = metrics

    async def process_webhook(self, payload: WebhookPayload) -> None:
        data = payload.data
        self.metrics.record_webhook()

        if payload.event != "data-cached":
            return

        # Fast path: skip non-HTML content types
        html_check = is_html_content_type(data.contentType)
        if html_check is False:
            logger.debug(
                "scan_skipped",
                extra={
                    "tx_id": data.id,
                    "reason": "not_html",
                    "content_type": data.contentType,
                },
            )
            self.metrics.record_skip()
            return

        # Skip large files with unknown content type (unlikely HTML)
        if html_check is None and data.dataSize and data.dataSize > 524288:
            logger.debug(
                "scan_skipped",
                extra={
                    "tx_id": data.id,
                    "reason": "unknown_type_too_large",
                    "data_size": data.dataSize,
                },
            )
            self.metrics.record_skip()
            return

        # Check verdict cache by hash
        if data.hash:
            cached = self.db.get_verdict(data.hash)
            if cached is not None:
                self.metrics.record_cache_hit()
                logger.debug(
                    "cache_hit",
                    extra={
                        "tx_id": data.id,
                        "cached_verdict": cached.verdict.value,
                    },
                )
                # If cached as malicious and we're enforcing, block this new tx
                if (
                    cached.verdict == Verdict.MALICIOUS
                    and self.settings.scanner_mode == "enforce"
                ):
                    try:
                        rules = json.loads(cached.matched_rules or "[]")
                    except (json.JSONDecodeError, TypeError):
                        rules = []
                    await self.gateway.block_data(
                        data.id,
                        data.hash,
                        rules,
                    )
                return

        # Enqueue for async scanning
        enqueued = self.db.enqueue(
            tx_id=data.id,
            content_hash=data.hash,
            content_type=data.contentType,
            data_size=data.dataSize,
        )
        if enqueued:
            logger.debug("enqueued", extra={"tx_id": data.id})

    async def process_queue_item(self, item: QueueRow) -> None:
        tx_id = item.tx_id
        content_hash = item.content_hash

        # Check admin overrides before scanning
        if content_hash:
            override = self.db.get_override(content_hash)
            if override is not None:
                if override.admin_verdict == "confirmed_clean":
                    self.db.save_verdict(
                        content_hash=content_hash,
                        tx_id=tx_id,
                        verdict=Verdict.CLEAN,
                        matched_rules="[]",
                        ml_score=None,
                        scanner_version=self.settings.scanner_version,
                    )
                    logger.info(
                        "scan_skipped_admin_override",
                        extra={"tx_id": tx_id, "override": "confirmed_clean"},
                    )
                    return
                elif override.admin_verdict == "confirmed_malicious":
                    self.db.save_verdict(
                        content_hash=content_hash,
                        tx_id=tx_id,
                        verdict=Verdict.MALICIOUS,
                        matched_rules=override.original_rules or "[]",
                        ml_score=None,
                        scanner_version=self.settings.scanner_version,
                    )
                    if self.settings.scanner_mode == "enforce":
                        try:
                            rules = json.loads(override.original_rules or "[]")
                        except (json.JSONDecodeError, TypeError):
                            rules = []
                        success = await self.gateway.block_data(
                            tx_id,
                            content_hash,
                            rules,
                        )
                        self.metrics.record_block(success)
                    logger.warning(
                        "scan_admin_override_malicious",
                        extra={"tx_id": tx_id, "override": "confirmed_malicious"},
                    )
                    return

        # Fetch content from gateway
        content = await self.gateway.fetch_content(tx_id)
        if content is None:
            raise RuntimeError(f"Failed to fetch content for {tx_id}")

        # Content sniff if content type was unknown
        if item.content_type is None or is_html_content_type(item.content_type) is None:
            if not looks_like_html(content):
                logger.debug(
                    "scan_skipped",
                    extra={
                        "tx_id": tx_id,
                        "reason": "content_sniff_not_html",
                    },
                )
                self.metrics.record_skip()
                # Cache as skipped so we don't fetch again
                if content_hash:
                    self.db.save_verdict(
                        content_hash=content_hash,
                        tx_id=tx_id,
                        verdict=Verdict.SKIPPED,
                        matched_rules="[]",
                        ml_score=None,
                        scanner_version=self.settings.scanner_version,
                    )
                return

        self.metrics.record_cache_miss()

        # Parse and scan — run CPU-bound work off the event loop
        html = content.decode("utf-8", errors="replace")
        loop = asyncio.get_running_loop()
        soup: BeautifulSoup = await loop.run_in_executor(
            None, parse_html, html
        )
        result = await loop.run_in_executor(
            None, self.engine.evaluate, html, soup
        )

        # Cache verdict
        if content_hash:
            try:
                self.db.save_verdict(
                    content_hash=content_hash,
                    tx_id=tx_id,
                    verdict=result.verdict,
                    matched_rules=json.dumps(result.matched_rules),
                    ml_score=result.ml_score,
                    scanner_version=self.settings.scanner_version,
                )
            except Exception:
                logger.warning(
                    "verdict_cache_failed",
                    extra={"tx_id": tx_id, "content_hash": content_hash},
                )

        self.metrics.record_scan(result.verdict, result.scan_duration_ms)

        # Take action
        action = "passed"
        if result.verdict == Verdict.MALICIOUS:
            if self.settings.scanner_mode == "enforce" and content_hash:
                success = await self.gateway.block_data(
                    tx_id, content_hash, result.matched_rules
                )
                self.metrics.record_block(success)
                action = "blocked" if success else "block_failed"
            elif self.settings.scanner_mode == "enforce" and not content_hash:
                action = "no_hash"
            else:
                action = "dry_run"

        log_level = (
            logging.WARNING
            if result.verdict in (Verdict.MALICIOUS, Verdict.SUSPICIOUS)
            else logging.INFO
        )
        logger.log(
            log_level,
            "scan_complete",
            extra={
                "tx_id": tx_id,
                "verdict": result.verdict.value,
                "rules": result.matched_rules,
                "ml_score": result.ml_score,
                "scan_ms": result.scan_duration_ms,
                "action": action,
            },
        )
