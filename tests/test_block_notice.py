"""Tests for skipping the gateway's 'content blocked' notice page.

When an already-blocked TX is re-enqueued (email intake, webhooks, backfill),
gateway.fetch_content returns the gateway's tiny notice page instead of the
original content. Scanning it produces self-referential false positives, so the
scanner must detect and SKIP it.
"""
from __future__ import annotations

import os
import tempfile

import pytest
from unittest.mock import AsyncMock, MagicMock

from src.config import Settings
from src.db import QueueRow, ScannerDB
from src.gateway_client import GatewayClient
from src.metrics import ScanMetrics
from src.models import Verdict
from src.rules.engine import RuleEngine
from src.scanner import Scanner, is_gateway_block_notice

from tests.fixtures import (
    CLEAN_HTML,
    GATEWAY_BLOCK_NOTICE,
    LEGIT_PAGE_QUOTING_BLOCK_PHRASE,
)


def _settings(**overrides) -> Settings:
    defaults = dict(
        gateway_url="http://localhost:3000",
        admin_api_key="test-key",
        scanner_admin_key="admin-key",
        ml_model_enabled=False,
        scanner_mode="enforce",
        rendered_dom_scan_enabled=False,
    )
    defaults.update(overrides)
    return Settings(**defaults)


def _make_scanner(fetch_bytes: bytes):
    fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    db = ScannerDB(db_path)
    db.initialize()
    gateway = AsyncMock(spec=GatewayClient)
    gateway.fetch_content = AsyncMock(return_value=fetch_bytes)
    s = _settings()
    scanner = Scanner(s, db, gateway, RuleEngine(s), ScanMetrics())
    return scanner, db, gateway


def _item() -> QueueRow:
    return QueueRow(
        id=1,
        tx_id="A" * 43,
        content_hash="hash123",
        content_type="text/html",
        data_size=512,
        received_at=0,
    )


# --- unit: the predicate -----------------------------------------------------

class TestIsGatewayBlockNotice:
    def test_recognizes_notice(self):
        assert is_gateway_block_notice(GATEWAY_BLOCK_NOTICE) is True

    def test_case_insensitive(self):
        assert is_gateway_block_notice(GATEWAY_BLOCK_NOTICE.upper()) is True

    def test_normal_page_is_not_notice(self):
        assert is_gateway_block_notice(CLEAN_HTML) is False

    def test_large_page_quoting_phrase_is_not_notice(self):
        # Guard: a big legit page containing the phrase must not match.
        assert len(LEGIT_PAGE_QUOTING_BLOCK_PHRASE) > 2048
        assert is_gateway_block_notice(LEGIT_PAGE_QUOTING_BLOCK_PHRASE) is False


# --- end-to-end: through process_queue_item ----------------------------------

@pytest.mark.asyncio
class TestBlockNoticeSkipped:
    async def test_block_notice_skipped(self):
        scanner, db, gateway = _make_scanner(GATEWAY_BLOCK_NOTICE.encode())
        await scanner.process_queue_item(_item())

        # Verdict cached as SKIPPED, never scanned/blocked
        cached = db.get_verdict("hash123")
        assert cached is not None
        assert cached.verdict == Verdict.SKIPPED
        gateway.block_data.assert_not_called()
        assert scanner.metrics.scans_skipped_not_html == 1  # record_skip fired

    async def test_normal_html_still_scanned(self):
        # Regression: a normal clean page is scanned, not skipped.
        scanner, db, gateway = _make_scanner(CLEAN_HTML.encode())
        await scanner.process_queue_item(_item())
        cached = db.get_verdict("hash123")
        assert cached is not None
        assert cached.verdict == Verdict.CLEAN

    async def test_large_page_quoting_phrase_not_skipped(self):
        # A big legit page that quotes the phrase must be scanned (→ CLEAN),
        # not skipped by the marker.
        scanner, db, gateway = _make_scanner(
            LEGIT_PAGE_QUOTING_BLOCK_PHRASE.encode()
        )
        await scanner.process_queue_item(_item())
        cached = db.get_verdict("hash123")
        assert cached is not None
        assert cached.verdict == Verdict.CLEAN
