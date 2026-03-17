"""Integration tests for content scanner routing in Scanner and BackfillScanner."""
from __future__ import annotations

import asyncio
import json
import tempfile
import os

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from src.config import Settings
from src.db import ScannerDB, QueueRow
from src.gateway_client import GatewayClient
from src.metrics import ScanMetrics
from src.models import ScanResult, Verdict, WebhookPayload
from src.rules.engine import RuleEngine
from src.scanner import Scanner
from src.scanners.base import ContentMetadata, ContentScanner, ContentScannerResult
from src.scanners.dispatcher import ScanDispatcher
from src.scanners.registry import ContentScannerRegistry

from tests.fixtures import CLEAN_HTML, BINARY_PNG_HEADER


def _settings(**overrides) -> Settings:
    defaults = dict(
        gateway_url="http://localhost:3000",
        admin_api_key="test-key",
        scanner_admin_key="admin-key",
        ml_model_enabled=False,
        scanner_mode="enforce",
    )
    defaults.update(overrides)
    return Settings(**defaults)


class MaliciousImageScanner(ContentScanner):
    """Test scanner that flags all images as malicious."""

    @property
    def name(self) -> str:
        return "test-image-malicious"

    @property
    def supported_content_types(self) -> set[str]:
        return {"image/*"}

    async def evaluate(self, content, content_type, metadata):
        return ContentScannerResult(
            scanner_name=self.name,
            triggered=True,
            verdict=Verdict.MALICIOUS,
            signals={"reason": "test"},
        )


class CleanImageScanner(ContentScanner):
    """Test scanner that always returns CLEAN."""

    @property
    def name(self) -> str:
        return "test-image-clean"

    @property
    def supported_content_types(self) -> set[str]:
        return {"image/*"}

    async def evaluate(self, content, content_type, metadata):
        return ContentScannerResult(
            scanner_name=self.name,
            triggered=False,
            verdict=Verdict.CLEAN,
        )


def _make_scanner(settings=None, registry=None):
    """Create a Scanner with mocked dependencies."""
    s = settings or _settings()
    fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    db = ScannerDB(db_path)
    db.initialize()
    gateway = AsyncMock(spec=GatewayClient)
    engine = MagicMock(spec=RuleEngine)
    engine.evaluate.return_value = ScanResult(verdict=Verdict.CLEAN)
    metrics = ScanMetrics()

    reg = registry or ContentScannerRegistry()
    dispatcher = ScanDispatcher(engine, reg)

    scanner = Scanner(
        s, db, gateway, engine, metrics,
        dispatcher=dispatcher,
    )
    return scanner, db, gateway, engine, metrics


# --- Webhook routing tests ---


class TestWebhookRouting:
    async def test_non_html_with_scanner_enqueued(self):
        """Non-HTML type with registered scanner should be enqueued."""
        reg = ContentScannerRegistry()
        reg.register(MaliciousImageScanner())
        scanner, db, _, _, _ = _make_scanner(registry=reg)

        payload = WebhookPayload(
            event="data-cached",
            data={
                "id": "A" * 43,
                "contentType": "image/png",
                "hash": "testhash123",
                "dataSize": 1024,
            },
        )
        await scanner.process_webhook(payload)
        assert db.queue_depth() == 1

    async def test_non_html_without_scanner_skipped(self):
        """Non-HTML type without a scanner should still be skipped (backward compat)."""
        scanner, db, _, _, metrics = _make_scanner()

        payload = WebhookPayload(
            event="data-cached",
            data={
                "id": "A" * 43,
                "contentType": "image/png",
                "hash": "testhash123",
                "dataSize": 1024,
            },
        )
        await scanner.process_webhook(payload)
        assert db.queue_depth() == 0
        assert metrics.scans_skipped_not_html == 1

    async def test_large_unknown_with_scanner_enqueued(self):
        """Large unknown-type file should be enqueued if scanners accept non-HTML."""
        reg = ContentScannerRegistry()
        reg.register(MaliciousImageScanner())
        scanner, db, _, _, _ = _make_scanner(registry=reg)

        payload = WebhookPayload(
            event="data-cached",
            data={
                "id": "A" * 43,
                "contentType": "application/octet-stream",
                "hash": "testhash123",
                "dataSize": 600000,
            },
        )
        await scanner.process_webhook(payload)
        assert db.queue_depth() == 1


# --- Queue processing routing tests ---


class TestQueueProcessingRouting:
    async def test_image_with_scanner_uses_content_scanner(self):
        """image/png item with registered scanner should invoke scanner, not rule engine."""
        reg = ContentScannerRegistry()
        reg.register(MaliciousImageScanner())
        scanner, db, gateway, engine, metrics = _make_scanner(registry=reg)
        gateway.fetch_content = AsyncMock(return_value=BINARY_PNG_HEADER)
        gateway.block_data = AsyncMock(return_value=True)

        item = QueueRow(
            id=1,
            tx_id="A" * 43,
            content_hash="hash123",
            content_type="image/png",
            data_size=1024,
            received_at=0,
        )
        await scanner.process_queue_item(item)

        # Rule engine should NOT have been called
        engine.evaluate.assert_not_called()
        # Content scanner metric recorded
        assert metrics.content_scans_total == 1
        # Verdict should be cached as MALICIOUS
        cached = db.get_verdict("hash123")
        assert cached is not None
        assert cached.verdict == Verdict.MALICIOUS
        # Block should have been called (enforce mode)
        gateway.block_data.assert_called_once()

    async def test_html_item_uses_rule_engine(self):
        """text/html item should still go through the rule engine."""
        reg = ContentScannerRegistry()
        reg.register(MaliciousImageScanner())
        scanner, db, gateway, engine, metrics = _make_scanner(registry=reg)
        gateway.fetch_content = AsyncMock(
            return_value=CLEAN_HTML.encode()
        )
        engine.evaluate.return_value = ScanResult(verdict=Verdict.CLEAN)

        item = QueueRow(
            id=1,
            tx_id="A" * 43,
            content_hash="hash123",
            content_type="text/html",
            data_size=1024,
            received_at=0,
        )
        await scanner.process_queue_item(item)
        engine.evaluate.assert_called_once()
        assert metrics.content_scans_total == 0

    async def test_unknown_type_sniffs_and_routes_to_scanner(self):
        """Unknown type that sniffs as image should route to content scanner."""
        reg = ContentScannerRegistry()
        reg.register(MaliciousImageScanner())
        scanner, db, gateway, engine, metrics = _make_scanner(registry=reg)
        gateway.fetch_content = AsyncMock(return_value=BINARY_PNG_HEADER)
        gateway.block_data = AsyncMock(return_value=True)

        item = QueueRow(
            id=1,
            tx_id="A" * 43,
            content_hash="hash123",
            content_type=None,
            data_size=1024,
            received_at=0,
        )
        await scanner.process_queue_item(item)
        engine.evaluate.assert_not_called()
        assert metrics.content_scans_total == 1

    async def test_unknown_type_no_scanner_skipped(self):
        """Unknown type, no scanner → SKIPPED (existing behavior)."""
        scanner, db, gateway, engine, metrics = _make_scanner()
        gateway.fetch_content = AsyncMock(return_value=BINARY_PNG_HEADER)

        item = QueueRow(
            id=1,
            tx_id="A" * 43,
            content_hash="hash123",
            content_type=None,
            data_size=1024,
            received_at=0,
        )
        await scanner.process_queue_item(item)
        engine.evaluate.assert_not_called()
        cached = db.get_verdict("hash123")
        assert cached is not None
        assert cached.verdict == Verdict.SKIPPED

    async def test_malicious_scanner_blocks_in_enforce(self):
        """Scanner returning MALICIOUS in enforce mode should call block_data."""
        reg = ContentScannerRegistry()
        reg.register(MaliciousImageScanner())
        scanner, db, gateway, engine, metrics = _make_scanner(registry=reg)
        gateway.fetch_content = AsyncMock(return_value=BINARY_PNG_HEADER)
        gateway.block_data = AsyncMock(return_value=True)

        item = QueueRow(
            id=1,
            tx_id="A" * 43,
            content_hash="hash123",
            content_type="image/png",
            data_size=1024,
            received_at=0,
        )
        await scanner.process_queue_item(item)
        gateway.block_data.assert_called_once_with(
            "A" * 43, "hash123", ["test-image-malicious"]
        )

    async def test_screenshot_skipped_for_non_html(self):
        """Screenshots should not be captured for non-HTML content."""
        reg = ContentScannerRegistry()
        reg.register(MaliciousImageScanner())
        mock_screenshot = MagicMock()
        mock_screenshot.capture = AsyncMock()

        s = _settings()
        fd, db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        db = ScannerDB(db_path)
        db.initialize()
        gateway = AsyncMock(spec=GatewayClient)
        gateway.fetch_content = AsyncMock(return_value=BINARY_PNG_HEADER)
        gateway.block_data = AsyncMock(return_value=True)
        engine = MagicMock(spec=RuleEngine)
        metrics = ScanMetrics()
        dispatcher = ScanDispatcher(engine, reg)

        scanner = Scanner(
            s, db, gateway, engine, metrics,
            screenshot=mock_screenshot, dispatcher=dispatcher,
        )

        item = QueueRow(
            id=1,
            tx_id="A" * 43,
            content_hash="hash123",
            content_type="image/png",
            data_size=1024,
            received_at=0,
        )
        await scanner.process_queue_item(item)
        mock_screenshot.capture.assert_not_called()


# --- Backfill routing tests ---


class TestBackfillRouting:
    async def test_non_html_file_with_scanner(self):
        """Backfill: non-HTML file with registered scanner should be scanned."""
        from src.backfill import BackfillScanner

        reg = ContentScannerRegistry()
        reg.register(CleanImageScanner())

        s = _settings(
            backfill_enabled=True,
            backfill_data_path="/tmp/test-backfill",
        )
        fd, db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        db = ScannerDB(db_path)
        db.initialize()
        engine = MagicMock(spec=RuleEngine)
        gateway = AsyncMock(spec=GatewayClient)
        metrics = ScanMetrics()
        dispatcher = ScanDispatcher(engine, reg)

        backfill = BackfillScanner(
            s, db, engine, gateway, metrics, dispatcher=dispatcher,
        )

        # Write a fake PNG file
        tmpdir = tempfile.mkdtemp()
        filepath = os.path.join(tmpdir, "testhash")
        with open(filepath, "wb") as f:
            f.write(BINARY_PNG_HEADER)

        stats = {
            "skipped_cached": 0,
            "skipped_not_html": 0,
            "scanned": 0,
            "malicious": 0,
            "suspicious": 0,
            "clean": 0,
            "blocked": 0,
            "errors": 0,
        }
        loop = asyncio.get_running_loop()
        await backfill._process_file(filepath, "testhash", None, stats, loop)

        assert stats["scanned"] == 1
        assert stats["clean"] == 1
        assert stats["skipped_not_html"] == 0

    async def test_non_html_file_without_scanner(self):
        """Backfill: non-HTML file without scanner should be skipped."""
        from src.backfill import BackfillScanner

        s = _settings(
            backfill_enabled=True,
            backfill_data_path="/tmp/test-backfill",
        )
        fd, db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        db = ScannerDB(db_path)
        db.initialize()
        engine = MagicMock(spec=RuleEngine)
        gateway = AsyncMock(spec=GatewayClient)
        metrics = ScanMetrics()

        backfill = BackfillScanner(s, db, engine, gateway, metrics)

        tmpdir = tempfile.mkdtemp()
        filepath = os.path.join(tmpdir, "testhash")
        with open(filepath, "wb") as f:
            f.write(BINARY_PNG_HEADER)

        stats = {
            "skipped_cached": 0,
            "skipped_not_html": 0,
            "scanned": 0,
            "malicious": 0,
            "suspicious": 0,
            "clean": 0,
            "blocked": 0,
            "errors": 0,
        }
        loop = asyncio.get_running_loop()
        await backfill._process_file(filepath, "testhash", None, stats, loop)

        assert stats["skipped_not_html"] == 1
        assert stats["scanned"] == 0
