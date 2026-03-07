"""Tests for the Scanner orchestrator."""

import os
import tempfile
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.config import Settings
from src.db import QueueRow, ScannerDB
from src.gateway_client import GatewayClient
from src.metrics import ScanMetrics
from src.models import Verdict, WebhookData, WebhookPayload
from src.rules.engine import RuleEngine
from src.scanner import Scanner, is_html_content_type, looks_like_html

# Valid 43-char base64url IDs for tests
TX1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
TX2 = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"

TEST_SETTINGS = Settings(
    gateway_url="http://localhost:3000",
    admin_api_key="test-key",
    scanner_mode="enforce",
)


@pytest.fixture
def db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    database = ScannerDB(path)
    database.initialize()
    yield database
    database.close()
    os.unlink(path)


@pytest.fixture
def scanner(db):
    gateway = AsyncMock(spec=GatewayClient)
    engine = RuleEngine(TEST_SETTINGS, classifier=None)
    metrics = ScanMetrics()
    return Scanner(TEST_SETTINGS, db, gateway, engine, metrics)


class TestContentTypeDetection:
    def test_html_content_type(self):
        assert is_html_content_type("text/html") is True
        assert is_html_content_type("text/html; charset=utf-8") is True
        assert is_html_content_type("application/xhtml+xml") is True

    def test_non_html_content_type(self):
        assert is_html_content_type("application/json") is False
        assert is_html_content_type("image/png") is False

    def test_none_content_type(self):
        assert is_html_content_type(None) is None

    def test_looks_like_html(self):
        assert looks_like_html(b"<!doctype html><html>") is True
        assert looks_like_html(b"<html><body>") is True
        assert looks_like_html(b"  <html>") is True

    def test_not_html_content(self):
        assert looks_like_html(b'{"json": true}') is False
        assert looks_like_html(b"plain text content") is False


class TestWebhookProcessing:
    @pytest.mark.asyncio
    async def test_skip_non_data_cached_event(self, scanner, db):
        payload = WebhookPayload(
            event="block-indexed",
            data=WebhookData(id=TX1),
        )
        await scanner.process_webhook(payload)
        assert db.queue_depth() == 0

    @pytest.mark.asyncio
    async def test_skip_non_html_content_type(self, scanner, db):
        payload = WebhookPayload(
            event="data-cached",
            data=WebhookData(id=TX1, contentType="image/png"),
        )
        await scanner.process_webhook(payload)
        assert db.queue_depth() == 0

    @pytest.mark.asyncio
    async def test_enqueue_html_content(self, scanner, db):
        payload = WebhookPayload(
            event="data-cached",
            data=WebhookData(id=TX1, contentType="text/html", hash="h1"),
        )
        await scanner.process_webhook(payload)
        assert db.queue_depth() == 1

    @pytest.mark.asyncio
    async def test_enqueue_unknown_content_type(self, scanner, db):
        payload = WebhookPayload(
            event="data-cached",
            data=WebhookData(id=TX1, contentType=None, dataSize=1024),
        )
        await scanner.process_webhook(payload)
        assert db.queue_depth() == 1

    @pytest.mark.asyncio
    async def test_skip_large_unknown_content(self, scanner, db):
        payload = WebhookPayload(
            event="data-cached",
            data=WebhookData(id=TX1, contentType=None, dataSize=600000),
        )
        await scanner.process_webhook(payload)
        assert db.queue_depth() == 0

    @pytest.mark.asyncio
    async def test_cache_hit_skips_enqueue(self, scanner, db):
        # Pre-populate cache
        db.save_verdict("h1", "old-tx", Verdict.CLEAN, "[]", None, "0.1.0")
        payload = WebhookPayload(
            event="data-cached",
            data=WebhookData(id=TX2, hash="h1", contentType="text/html"),
        )
        await scanner.process_webhook(payload)
        assert db.queue_depth() == 0

    @pytest.mark.asyncio
    async def test_cache_hit_malicious_blocks_in_enforce(self, scanner, db):
        db.save_verdict("h1", "old-tx", Verdict.MALICIOUS, '["rule1"]', 0.9, "0.1.0")
        payload = WebhookPayload(
            event="data-cached",
            data=WebhookData(id=TX2, hash="h1", contentType="text/html"),
        )
        await scanner.process_webhook(payload)
        scanner.gateway.block_data.assert_called_once()


class TestQueueProcessing:
    @pytest.mark.asyncio
    async def test_process_clean_html(self, scanner):
        scanner.gateway.fetch_content = AsyncMock(
            return_value=b"<html><body><p>Hello</p></body></html>"
        )
        item = QueueRow(
            id=1, tx_id="tx1", content_hash="h1",
            content_type="text/html", data_size=100, received_at=0,
        )
        await scanner.process_queue_item(item)
        scanner.gateway.block_data.assert_not_called()

    @pytest.mark.asyncio
    async def test_process_phishing_blocks(self, scanner):
        from tests.fixtures import SEED_PHRASE_PHISHING

        scanner.gateway.fetch_content = AsyncMock(
            return_value=SEED_PHRASE_PHISHING.encode()
        )
        scanner.gateway.block_data = AsyncMock(return_value=True)
        item = QueueRow(
            id=1, tx_id="tx1", content_hash="h1",
            content_type="text/html", data_size=1000, received_at=0,
        )
        await scanner.process_queue_item(item)
        scanner.gateway.block_data.assert_called_once()

    @pytest.mark.asyncio
    async def test_fetch_failure_raises(self, scanner):
        scanner.gateway.fetch_content = AsyncMock(return_value=None)
        item = QueueRow(
            id=1, tx_id="tx1", content_hash="h1",
            content_type="text/html", data_size=100, received_at=0,
        )
        with pytest.raises(RuntimeError, match="Failed to fetch content"):
            await scanner.process_queue_item(item)
        scanner.gateway.block_data.assert_not_called()

    @pytest.mark.asyncio
    async def test_non_html_content_sniff_skips(self, scanner, db):
        scanner.gateway.fetch_content = AsyncMock(
            return_value=b'{"not": "html"}'
        )
        item = QueueRow(
            id=1, tx_id="tx1", content_hash="h1",
            content_type=None, data_size=100, received_at=0,
        )
        await scanner.process_queue_item(item)
        scanner.gateway.block_data.assert_not_called()
        # Should cache as SKIPPED
        cached = db.get_verdict("h1")
        assert cached is not None
        assert cached.verdict == Verdict.SKIPPED
