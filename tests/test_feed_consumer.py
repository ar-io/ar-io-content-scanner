"""Tests for verdict feed consumer (poller and on-demand lookup)."""

from __future__ import annotations

import os
import tempfile
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.config import Settings
from src.db import ScannerDB
from src.feed.client import FeedClient
from src.feed.poller import FeedPoller
from src.metrics import ScanMetrics
from src.models import Verdict


def _make_settings(**overrides):
    defaults = dict(
        gateway_url="http://localhost:4000",
        admin_api_key="gateway-key",
        scanner_admin_key="admin-key",
        verdict_api_key="feed-key",
        verdict_feed_urls=("http://peer1:3100",),
        verdict_feed_trust_mode="malicious_only",
        ml_model_enabled=False,
        scanner_mode="dry-run",
    )
    defaults.update(overrides)
    return Settings(**defaults)


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
def metrics():
    return ScanMetrics()


@pytest.fixture
def gateway():
    gw = AsyncMock()
    gw.block_data = AsyncMock(return_value=True)
    return gw


@pytest.fixture
def feed_client():
    return AsyncMock(spec=FeedClient)


class TestFeedPoller:
    async def test_poll_imports_malicious_verdict(self, db, metrics, gateway, feed_client):
        settings = _make_settings()
        poller = FeedPoller(settings, db, feed_client, gateway, metrics)

        feed_client.fetch_feed.return_value = {
            "verdicts": [
                {
                    "content_hash": "hash1",
                    "tx_id": "tx1",
                    "verdict": "malicious",
                    "matched_rules": '["seed-phrase-harvesting"]',
                    "ml_score": 0.99,
                    "scanned_at": 1000,
                    "scanner_version": "0.1.0",
                    "admin_override": None,
                }
            ],
            "cursor": {"scanned_at": 1000, "content_hash": "hash1"},
            "has_more": False,
        }

        stats = await poller.poll_peer("http://peer1:3100")
        assert stats["imported"] == 1

        cached = db.get_verdict("hash1")
        assert cached is not None
        assert cached.verdict == Verdict.MALICIOUS
        assert cached.source == "http://peer1:3100"

    async def test_poll_skips_clean_in_malicious_only_mode(self, db, metrics, gateway, feed_client):
        settings = _make_settings(verdict_feed_trust_mode="malicious_only")
        poller = FeedPoller(settings, db, feed_client, gateway, metrics)

        feed_client.fetch_feed.return_value = {
            "verdicts": [
                {
                    "content_hash": "hash1",
                    "tx_id": "tx1",
                    "verdict": "clean",
                    "matched_rules": "[]",
                    "ml_score": 0.1,
                    "scanned_at": 1000,
                    "scanner_version": "0.1.0",
                    "admin_override": None,
                }
            ],
            "cursor": {"scanned_at": 1000, "content_hash": "hash1"},
            "has_more": False,
        }

        stats = await poller.poll_peer("http://peer1:3100")
        assert stats["imported"] == 0
        assert stats["skipped"] == 1
        assert db.get_verdict("hash1") is None

    async def test_poll_imports_clean_in_all_mode(self, db, metrics, gateway, feed_client):
        settings = _make_settings(verdict_feed_trust_mode="all")
        poller = FeedPoller(settings, db, feed_client, gateway, metrics)

        feed_client.fetch_feed.return_value = {
            "verdicts": [
                {
                    "content_hash": "hash1",
                    "tx_id": "tx1",
                    "verdict": "clean",
                    "matched_rules": "[]",
                    "ml_score": 0.1,
                    "scanned_at": 1000,
                    "scanner_version": "0.1.0",
                    "admin_override": None,
                }
            ],
            "cursor": {"scanned_at": 1000, "content_hash": "hash1"},
            "has_more": False,
        }

        stats = await poller.poll_peer("http://peer1:3100")
        assert stats["imported"] == 1
        assert db.get_verdict("hash1") is not None

    async def test_poll_skips_duplicate_hash(self, db, metrics, gateway, feed_client):
        """Already-existing local verdict prevents import."""
        settings = _make_settings()
        poller = FeedPoller(settings, db, feed_client, gateway, metrics)

        # Pre-existing local verdict
        db.save_verdict("hash1", "tx_local", Verdict.CLEAN, "[]", 0.1, "0.1.0")

        feed_client.fetch_feed.return_value = {
            "verdicts": [
                {
                    "content_hash": "hash1",
                    "tx_id": "tx_peer",
                    "verdict": "malicious",
                    "matched_rules": '["r1"]',
                    "ml_score": 0.99,
                    "scanned_at": 1000,
                    "scanner_version": "0.1.0",
                    "admin_override": None,
                }
            ],
            "cursor": {"scanned_at": 1000, "content_hash": "hash1"},
            "has_more": False,
        }

        stats = await poller.poll_peer("http://peer1:3100")
        assert stats["imported"] == 0
        assert stats["skipped"] == 1

        # Original verdict preserved
        cached = db.get_verdict("hash1")
        assert cached.verdict == Verdict.CLEAN
        assert cached.tx_id == "tx_local"

    async def test_poll_skips_admin_dismissed(self, db, metrics, gateway, feed_client):
        """Admin-dismissed hashes should not be reimported from peers."""
        settings = _make_settings()
        poller = FeedPoller(settings, db, feed_client, gateway, metrics)

        db.save_override("hash1", "tx1", "confirmed_clean", "malicious", "[]", 0.99, "false positive")

        feed_client.fetch_feed.return_value = {
            "verdicts": [
                {
                    "content_hash": "hash1",
                    "tx_id": "tx1",
                    "verdict": "malicious",
                    "matched_rules": '["r1"]',
                    "ml_score": 0.99,
                    "scanned_at": 1000,
                    "scanner_version": "0.1.0",
                    "admin_override": None,
                }
            ],
            "cursor": {"scanned_at": 1000, "content_hash": "hash1"},
            "has_more": False,
        }

        stats = await poller.poll_peer("http://peer1:3100")
        assert stats["imported"] == 0

    async def test_poll_blocks_in_enforce_mode(self, db, metrics, gateway, feed_client):
        settings = _make_settings(scanner_mode="enforce")
        poller = FeedPoller(settings, db, feed_client, gateway, metrics)

        feed_client.fetch_feed.return_value = {
            "verdicts": [
                {
                    "content_hash": "hash1",
                    "tx_id": "tx1",
                    "verdict": "malicious",
                    "matched_rules": '["seed-phrase-harvesting"]',
                    "ml_score": 0.99,
                    "scanned_at": 1000,
                    "scanner_version": "0.1.0",
                    "admin_override": None,
                }
            ],
            "cursor": {"scanned_at": 1000, "content_hash": "hash1"},
            "has_more": False,
        }

        await poller.poll_peer("http://peer1:3100")
        gateway.block_data.assert_called_once()

    async def test_poll_peer_down(self, db, metrics, gateway, feed_client):
        settings = _make_settings()
        poller = FeedPoller(settings, db, feed_client, gateway, metrics)

        feed_client.fetch_feed.return_value = None

        stats = await poller.poll_peer("http://peer1:3100")
        assert stats["error"] is not None
        assert metrics.feed_poll_errors == 1

        # Sync state should record the error
        state = db.get_feed_sync_state("http://peer1:3100")
        assert state is not None
        assert state["consecutive_errors"] == 1

    async def test_poll_drains_multiple_pages(self, db, metrics, gateway, feed_client):
        """Poller should follow has_more and drain all pages."""
        settings = _make_settings()
        poller = FeedPoller(settings, db, feed_client, gateway, metrics)

        # Page 1: has_more=True
        page1 = {
            "verdicts": [
                {
                    "content_hash": "hash1",
                    "tx_id": "tx1",
                    "verdict": "malicious",
                    "matched_rules": "[]",
                    "ml_score": 0.99,
                    "scanned_at": 1000,
                    "scanner_version": "0.1.0",
                    "admin_override": None,
                }
            ],
            "cursor": {"scanned_at": 1000, "content_hash": "hash1"},
            "has_more": True,
        }
        # Page 2: has_more=False
        page2 = {
            "verdicts": [
                {
                    "content_hash": "hash2",
                    "tx_id": "tx2",
                    "verdict": "malicious",
                    "matched_rules": "[]",
                    "ml_score": 0.98,
                    "scanned_at": 2000,
                    "scanner_version": "0.1.0",
                    "admin_override": None,
                }
            ],
            "cursor": {"scanned_at": 2000, "content_hash": "hash2"},
            "has_more": False,
        }

        feed_client.fetch_feed.side_effect = [page1, page2]

        stats = await poller.poll_peer("http://peer1:3100")

        # Both pages should have been fetched
        assert feed_client.fetch_feed.call_count == 2
        # Both verdicts imported
        assert db.get_verdict("hash1") is not None
        assert db.get_verdict("hash2") is not None
        # Cursor should be at page 2
        state = db.get_feed_sync_state("http://peer1:3100")
        assert state["last_scanned_at"] == 2000
        assert state["last_content_hash"] == "hash2"

    async def test_poll_updates_sync_cursor(self, db, metrics, gateway, feed_client):
        settings = _make_settings()
        poller = FeedPoller(settings, db, feed_client, gateway, metrics)

        feed_client.fetch_feed.return_value = {
            "verdicts": [
                {
                    "content_hash": "hash1",
                    "tx_id": "tx1",
                    "verdict": "malicious",
                    "matched_rules": "[]",
                    "ml_score": 0.99,
                    "scanned_at": 2000,
                    "scanner_version": "0.1.0",
                    "admin_override": None,
                }
            ],
            "cursor": {"scanned_at": 2000, "content_hash": "hash1"},
            "has_more": False,
        }

        await poller.poll_peer("http://peer1:3100")

        state = db.get_feed_sync_state("http://peer1:3100")
        assert state is not None
        assert state["last_scanned_at"] == 2000
        assert state["last_content_hash"] == "hash1"
        assert state["imported_count"] == 1
        assert state["consecutive_errors"] == 0


class TestFeedDBMethods:
    def test_save_verdict_with_source(self, db):
        db.save_verdict(
            "hash1", "tx1", Verdict.MALICIOUS, '["r1"]', 0.99, "0.1.0",
            source="http://peer:3100",
        )
        cached = db.get_verdict("hash1")
        assert cached.source == "http://peer:3100"

    def test_save_verdict_default_source(self, db):
        db.save_verdict("hash1", "tx1", Verdict.CLEAN, "[]", 0.1, "0.1.0")
        cached = db.get_verdict("hash1")
        assert cached.source == "local"

    def test_feed_query_filters_by_source(self, db):
        db.save_verdict("local1", "tx1", Verdict.MALICIOUS, '["r1"]', 0.99, "0.1.0")
        db.save_verdict(
            "imported1", "tx2", Verdict.MALICIOUS, '["r1"]', 0.95, "0.1.0",
            source="http://peer:3100",
        )
        feed = db.get_verdicts_feed()
        hashes = [v["content_hash"] for v in feed]
        assert "local1" in hashes
        assert "imported1" not in hashes

    def test_feed_pagination_cursor(self, db):
        for i in range(10):
            db.save_verdict(f"hash{i:03d}", f"tx{i}", Verdict.CLEAN, "[]", 0.1, "0.1.0")

        page1 = db.get_verdicts_feed(limit=3)
        assert len(page1) == 3
        last = page1[-1]

        page2 = db.get_verdicts_feed(
            since=last["scanned_at"],
            after_hash=last["content_hash"],
            limit=3,
        )
        assert len(page2) == 3

        hashes1 = {v["content_hash"] for v in page1}
        hashes2 = {v["content_hash"] for v in page2}
        assert hashes1.isdisjoint(hashes2)

    def test_feed_sync_state_crud(self, db):
        # Initially none
        assert db.get_feed_sync_state("http://peer:3100") is None
        assert db.list_feed_sync_states() == []

        # Save success state
        db.save_feed_sync_state("http://peer:3100", 1000, "hash1", imported_count_delta=5)
        state = db.get_feed_sync_state("http://peer:3100")
        assert state["last_scanned_at"] == 1000
        assert state["last_content_hash"] == "hash1"
        assert state["imported_count"] == 5
        assert state["consecutive_errors"] == 0

        # Save error state
        db.save_feed_sync_state("http://peer:3100", 1000, "hash1", error="timeout")
        state = db.get_feed_sync_state("http://peer:3100")
        assert state["consecutive_errors"] == 1
        assert state["last_error"] == "timeout"

        # List all
        db.save_feed_sync_state("http://peer2:3100", 500, "hash0")
        states = db.list_feed_sync_states()
        assert len(states) == 2

    def test_feed_import_stats(self, db):
        db.save_verdict("local1", "tx1", Verdict.CLEAN, "[]", 0.1, "0.1.0")
        db.save_verdict("imp1", "tx2", Verdict.MALICIOUS, "[]", 0.9, "0.1.0", source="http://peer1:3100")
        db.save_verdict("imp2", "tx3", Verdict.MALICIOUS, "[]", 0.8, "0.1.0", source="http://peer2:3100")
        db.save_verdict("imp3", "tx4", Verdict.CLEAN, "[]", 0.1, "0.1.0", source="http://peer1:3100")

        stats = db.get_feed_import_stats()
        assert stats["total_imported"] == 3
        assert stats["by_source"]["http://peer1:3100"] == 2
        assert stats["by_source"]["http://peer2:3100"] == 1
