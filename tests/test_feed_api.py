"""Tests for verdict feed API endpoints (producer side)."""

from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from src.config import Settings
from src.db import ScannerDB
from src.models import Verdict
from src.server import build_app


@pytest.fixture
def settings(tmp_path):
    return Settings(
        gateway_url="http://localhost:4000",
        admin_api_key="gateway-key",
        scanner_admin_key="test-admin-key",
        verdict_api_key="test-feed-key",
        admin_ui_enabled=True,
        ml_model_enabled=False,
        db_path=str(tmp_path / "test.db"),
    )


@pytest.fixture
def db(settings):
    _db = ScannerDB(settings.db_path)
    _db.initialize()
    return _db


@pytest.fixture
def app(settings, db):
    a = build_app(settings)
    a.state.db = db
    return a


@pytest.fixture
def client(app):
    return TestClient(app)


FEED_AUTH = {"Authorization": "Bearer test-feed-key"}
ADMIN_AUTH = {"Authorization": "Bearer test-admin-key"}
BAD_AUTH = {"Authorization": "Bearer wrong-key"}


class TestFeedAuth:
    def test_no_auth_returns_401(self, client):
        resp = client.get("/api/verdicts")
        assert resp.status_code == 401

    def test_wrong_key_returns_401(self, client):
        resp = client.get("/api/verdicts", headers=BAD_AUTH)
        assert resp.status_code == 401

    def test_correct_key_returns_200(self, client):
        resp = client.get("/api/verdicts", headers=FEED_AUTH)
        assert resp.status_code == 200

    def test_admin_key_does_not_work_for_feed(self, client):
        resp = client.get("/api/verdicts", headers=ADMIN_AUTH)
        assert resp.status_code == 401


class TestSingleVerdictLookup:
    def test_found(self, client, db):
        db.save_verdict("hash1", "tx1", Verdict.MALICIOUS, '["seed-phrase-harvesting"]', 0.99, "0.1.0")
        resp = client.get("/api/verdicts/hash1", headers=FEED_AUTH)
        assert resp.status_code == 200
        data = resp.json()
        assert data["content_hash"] == "hash1"
        assert data["tx_id"] == "tx1"
        assert data["verdict"] == "malicious"
        assert data["matched_rules"] == '["seed-phrase-harvesting"]'
        assert data["ml_score"] == 0.99
        assert data["scanner_version"] == "0.1.0"
        assert data["admin_override"] is None

    def test_not_found(self, client):
        resp = client.get("/api/verdicts/nonexistent", headers=FEED_AUTH)
        assert resp.status_code == 404

    def test_invalid_hash(self, client):
        resp = client.get("/api/verdicts/!!!invalid!!!", headers=FEED_AUTH)
        assert resp.status_code == 400

    def test_imported_verdict_not_exposed(self, client, db):
        """Verdicts imported from peers should NOT be served in the feed."""
        db.save_verdict(
            "hash1", "tx1", Verdict.MALICIOUS, '["r1"]', 0.99, "0.1.0",
            source="http://peer:3100",
        )
        resp = client.get("/api/verdicts/hash1", headers=FEED_AUTH)
        assert resp.status_code == 404

    def test_includes_admin_override(self, client, db):
        db.save_verdict("hash1", "tx1", Verdict.MALICIOUS, '["r1"]', 0.99, "0.1.0")
        db.save_override("hash1", "tx1", "confirmed_malicious", "malicious", '["r1"]', 0.99, "verified")
        resp = client.get("/api/verdicts/hash1", headers=FEED_AUTH)
        data = resp.json()
        assert data["admin_override"] == "confirmed_malicious"


class TestFeedPagination:
    def _seed(self, db, count=5):
        for i in range(count):
            db.save_verdict(f"hash{i:03d}", f"tx{i}", Verdict.CLEAN, "[]", 0.1, "0.1.0")
            # Ensure distinct timestamps for ordering
            time.sleep(0.01)

    def test_empty_feed(self, client):
        resp = client.get("/api/verdicts", headers=FEED_AUTH)
        data = resp.json()
        assert data["verdicts"] == []
        assert data["cursor"] is None
        assert data["has_more"] is False

    def test_returns_verdicts(self, client, db):
        self._seed(db, count=3)
        resp = client.get("/api/verdicts", headers=FEED_AUTH)
        data = resp.json()
        assert len(data["verdicts"]) == 3
        assert data["has_more"] is False
        assert data["cursor"] is not None

    def test_pagination_with_limit(self, client, db):
        self._seed(db, count=5)
        resp = client.get("/api/verdicts?limit=2", headers=FEED_AUTH)
        data = resp.json()
        assert len(data["verdicts"]) == 2
        assert data["has_more"] is True

    def test_cursor_continuation(self, client, db):
        self._seed(db, count=5)

        # First page
        resp1 = client.get("/api/verdicts?limit=2", headers=FEED_AUTH)
        data1 = resp1.json()
        assert len(data1["verdicts"]) == 2
        cursor = data1["cursor"]

        # Second page using cursor
        resp2 = client.get(
            f"/api/verdicts?limit=2&since={cursor['scanned_at']}&after_hash={cursor['content_hash']}",
            headers=FEED_AUTH,
        )
        data2 = resp2.json()
        assert len(data2["verdicts"]) == 2

        # Verify no overlap
        hashes1 = {v["content_hash"] for v in data1["verdicts"]}
        hashes2 = {v["content_hash"] for v in data2["verdicts"]}
        assert hashes1.isdisjoint(hashes2)

    def test_feed_excludes_imported(self, client, db):
        """Feed should only return local verdicts, not imported ones."""
        db.save_verdict("local1", "tx1", Verdict.MALICIOUS, '["r1"]', 0.99, "0.1.0")
        db.save_verdict(
            "imported1", "tx2", Verdict.MALICIOUS, '["r1"]', 0.95, "0.1.0",
            source="http://peer:3100",
        )
        resp = client.get("/api/verdicts", headers=FEED_AUTH)
        data = resp.json()
        hashes = [v["content_hash"] for v in data["verdicts"]]
        assert "local1" in hashes
        assert "imported1" not in hashes

    def test_feed_excludes_skipped(self, client, db):
        """SKIPPED verdicts (internal cache markers) should never appear in feed."""
        db.save_verdict("html1", "tx1", Verdict.MALICIOUS, '["r1"]', 0.99, "0.1.0")
        db.save_verdict("nonhtml1", "tx2", Verdict.SKIPPED, "[]", None, "0.1.0")
        resp = client.get("/api/verdicts", headers=FEED_AUTH)
        data = resp.json()
        hashes = [v["content_hash"] for v in data["verdicts"]]
        assert "html1" in hashes
        assert "nonhtml1" not in hashes

    def test_single_lookup_excludes_skipped(self, client, db):
        """SKIPPED verdicts should return 404 on single lookup."""
        db.save_verdict("nonhtml1", "tx1", Verdict.SKIPPED, "[]", None, "0.1.0")
        resp = client.get("/api/verdicts/nonhtml1", headers=FEED_AUTH)
        assert resp.status_code == 404

    def test_since_filter(self, client, db):
        db.save_verdict("old", "tx1", Verdict.CLEAN, "[]", 0.1, "0.1.0")
        future_time = int(time.time()) + 1000
        resp = client.get(f"/api/verdicts?since={future_time}", headers=FEED_AUTH)
        data = resp.json()
        assert len(data["verdicts"]) == 0


class TestFeedInAdminSettings:
    def test_admin_settings_includes_feed(self, client):
        resp = client.get("/api/admin/settings", headers=ADMIN_AUTH)
        data = resp.json()
        assert "verdict_feed" in data
        assert data["verdict_feed"]["enabled"] is True
        assert data["verdict_feed"]["api_key_set"] is True
        assert data["verdict_feed"]["trust_mode"] == "malicious_only"

    def test_admin_stats_includes_feed(self, client):
        resp = client.get("/api/admin/stats", headers=ADMIN_AUTH)
        data = resp.json()
        assert "verdict_feed" in data
        assert "import_stats" in data["verdict_feed"]
