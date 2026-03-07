"""Tests for admin API endpoints and override enforcement."""

import json
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
        admin_ui_enabled=True,
        ml_model_enabled=False,
        db_path=str(tmp_path / "test.db"),
    )


@pytest.fixture
def db(settings):
    """Initialize DB directly so it's available before the app lifespan runs."""
    _db = ScannerDB(settings.db_path)
    _db.initialize()
    return _db


@pytest.fixture
def app(settings, db):
    a = build_app(settings)
    # Replace the uninitialized db with our pre-initialized one
    a.state.db = db
    return a


@pytest.fixture
def client(app):
    return TestClient(app)


AUTH = {"Authorization": "Bearer test-admin-key"}
BAD_AUTH = {"Authorization": "Bearer wrong-key"}


class TestAuth:
    def test_no_auth_returns_401(self, client):
        resp = client.get("/api/admin/stats")
        assert resp.status_code == 401

    def test_wrong_key_returns_401(self, client):
        resp = client.get("/api/admin/stats", headers=BAD_AUTH)
        assert resp.status_code == 401

    def test_correct_key_returns_200(self, client):
        resp = client.get("/api/admin/stats", headers=AUTH)
        assert resp.status_code == 200

    def test_admin_page_loads_without_auth(self, client):
        resp = client.get("/admin")
        assert resp.status_code == 200
        assert "ar.io Content Scanner" in resp.text


class TestStats:
    def test_stats_shape(self, client):
        resp = client.get("/api/admin/stats", headers=AUTH)
        data = resp.json()
        assert "mode" in data
        assert "metrics" in data
        assert "backfill" in data
        assert "recent_detections" in data
        assert data["mode"] == "dry-run"

    def test_stats_includes_recent_detections(self, client, db):
        db.save_verdict("hash1", "tx1", Verdict.MALICIOUS, '["rule1"]', 0.99, "0.1.0")
        resp = client.get("/api/admin/stats", headers=AUTH)
        data = resp.json()
        assert len(data["recent_detections"]) == 1
        assert data["recent_detections"][0]["tx_id"] == "tx1"


class TestReview:
    def _seed(self, db):
        db.save_verdict("h1", "tx1", Verdict.MALICIOUS, '["seed-phrase-harvesting"]', 0.99, "0.1.0")
        db.save_verdict("h2", "tx2", Verdict.SUSPICIOUS, '[]', 0.97, "0.1.0")
        db.save_verdict("h3", "tx3", Verdict.CLEAN, '[]', 0.1, "0.1.0")

    def test_review_list_default_pending(self, client, db):
        self._seed(db)
        resp = client.get("/api/admin/review", headers=AUTH)
        data = resp.json()
        assert data["total"] == 2  # malicious + suspicious, not clean
        assert all(i["verdict"] in ("malicious", "suspicious") for i in data["items"])

    def test_review_filter_by_verdict(self, client, db):
        self._seed(db)
        resp = client.get("/api/admin/review?verdict=malicious", headers=AUTH)
        data = resp.json()
        assert data["total"] == 1
        assert data["items"][0]["verdict"] == "malicious"

    def test_review_detail(self, client, db):
        self._seed(db)
        resp = client.get("/api/admin/review/h1", headers=AUTH)
        assert resp.status_code == 200
        data = resp.json()
        assert data["tx_id"] == "tx1"
        assert data["verdict"] == "malicious"

    def test_review_detail_not_found(self, client):
        resp = client.get("/api/admin/review/nonexistent", headers=AUTH)
        assert resp.status_code == 404

    def test_confirm_creates_override(self, client, db):
        db.save_verdict("h1", "tx1", Verdict.MALICIOUS, '["rule1"]', 0.99, "0.1.0")
        resp = client.post(
            "/api/admin/review/h1/confirm",
            headers={**AUTH, "Content-Type": "application/json"},
            json={"notes": "verified phishing"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "confirmed"

        override = db.get_override("h1")
        assert override is not None
        assert override.admin_verdict == "confirmed_malicious"
        assert override.notes == "verified phishing"

    def test_dismiss_creates_override_and_clears_verdict(self, client, db):
        db.save_verdict("h1", "tx1", Verdict.MALICIOUS, '["rule1"]', 0.99, "0.1.0")
        resp = client.post(
            "/api/admin/review/h1/dismiss",
            headers={**AUTH, "Content-Type": "application/json"},
            json={"notes": "false positive"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "dismissed"

        override = db.get_override("h1")
        assert override is not None
        assert override.admin_verdict == "confirmed_clean"

        # Verdict should be updated to clean
        v = db.get_verdict("h1")
        assert v.verdict == Verdict.CLEAN

    def test_confirmed_items_filtered_as_confirmed(self, client, db):
        db.save_verdict("h1", "tx1", Verdict.MALICIOUS, '[]', 0.99, "0.1.0")
        db.save_override("h1", "tx1", "confirmed_malicious", "malicious", "[]", 0.99, "")
        resp = client.get("/api/admin/review?status=confirmed", headers=AUTH)
        data = resp.json()
        assert data["total"] == 1

    def test_dismissed_items_not_in_pending(self, client, db):
        db.save_verdict("h1", "tx1", Verdict.MALICIOUS, '[]', 0.99, "0.1.0")
        db.save_override("h1", "tx1", "confirmed_clean", "malicious", "[]", 0.99, "")
        resp = client.get("/api/admin/review?status=pending", headers=AUTH)
        data = resp.json()
        assert data["total"] == 0


class TestHistory:
    def _seed(self, db):
        db.save_verdict("h1", "tx1", Verdict.CLEAN, '[]', 0.1, "0.1.0")
        db.save_verdict("h2", "backfill", Verdict.MALICIOUS, '["rule1"]', 0.99, "0.1.0")
        db.save_verdict("h3", "tx3", Verdict.SUSPICIOUS, '[]', 0.96, "0.1.0")

    def test_history_returns_all(self, client, db):
        self._seed(db)
        resp = client.get("/api/admin/history", headers=AUTH)
        data = resp.json()
        assert data["total"] == 3

    def test_history_filter_verdict(self, client, db):
        self._seed(db)
        resp = client.get("/api/admin/history?verdict=malicious", headers=AUTH)
        data = resp.json()
        assert data["total"] == 1

    def test_history_filter_source(self, client, db):
        self._seed(db)
        resp = client.get("/api/admin/history?source=backfill", headers=AUTH)
        data = resp.json()
        assert data["total"] == 1
        assert data["items"][0]["tx_id"] == "backfill"

    def test_history_search(self, client, db):
        self._seed(db)
        resp = client.get("/api/admin/history?q=tx3", headers=AUTH)
        data = resp.json()
        assert data["total"] == 1

    def test_history_pagination(self, client, db):
        for i in range(30):
            db.save_verdict(f"h{i}", f"tx{i}", Verdict.CLEAN, '[]', 0.0, "0.1.0")
        resp = client.get("/api/admin/history?per_page=10&page=2", headers=AUTH)
        data = resp.json()
        assert data["page"] == 2
        assert data["per_page"] == 10
        assert data["pages"] == 3
        assert len(data["items"]) == 10

    def test_history_export_csv(self, client, db):
        self._seed(db)
        resp = client.get("/api/admin/history/export", headers=AUTH)
        assert resp.status_code == 200
        assert "text/csv" in resp.headers["content-type"]
        assert "scan_history.csv" in resp.headers["content-disposition"]
        assert "content_hash" in resp.text  # header row


class TestSettings:
    def test_settings_returns_config(self, client):
        resp = client.get("/api/admin/settings", headers=AUTH)
        data = resp.json()
        assert data["mode"] == "dry-run"
        assert "rules" in data
        assert "db_stats" in data

    def test_settings_excludes_secrets(self, client):
        resp = client.get("/api/admin/settings", headers=AUTH)
        text = resp.text
        assert "gateway-key" not in text
        assert "test-admin-key" not in text

    def test_training_export(self, client, db):
        db.save_verdict("h1", "tx1", Verdict.MALICIOUS, '["rule1"]', 0.99, "0.1.0")
        db.save_override("h1", "tx1", "confirmed_malicious", "malicious", '["rule1"]', 0.99, "phishing")
        resp = client.get("/api/admin/training-export", headers=AUTH)
        assert resp.status_code == 200
        assert "text/csv" in resp.headers["content-type"]
        assert "confirmed_malicious" in resp.text


class TestContentPreview:
    def test_invalid_tx_id_returns_400(self, client):
        resp = client.get("/api/admin/preview/not-valid!", headers=AUTH)
        assert resp.status_code == 400


class TestAdminOverrides:
    """Test that overrides are enforced by the DB layer."""

    def test_save_and_get_override(self, db, app):
        db.save_override("h1", "tx1", "confirmed_clean", "malicious", '["r1"]', 0.9, "fp")
        o = db.get_override("h1")
        assert o is not None
        assert o.admin_verdict == "confirmed_clean"
        assert o.notes == "fp"

    def test_override_replaces(self, db, app):
        db.save_override("h1", "tx1", "confirmed_clean", "malicious", '[]', 0.9, "first")
        db.save_override("h1", "tx1", "confirmed_malicious", "malicious", '[]', 0.9, "changed")
        o = db.get_override("h1")
        assert o.admin_verdict == "confirmed_malicious"

    def test_list_overrides(self, db, app):
        db.save_override("h1", "tx1", "confirmed_clean", "malicious", '[]', 0.9, "")
        db.save_override("h2", "tx2", "confirmed_malicious", "suspicious", '[]', 0.95, "")
        overrides = db.list_overrides()
        assert len(overrides) == 2

    def test_db_stats(self, db, app):
        db.save_verdict("h1", "tx1", Verdict.CLEAN, '[]', 0.1, "0.1.0")
        db.save_verdict("h2", "tx2", Verdict.MALICIOUS, '["r1"]', 0.99, "0.1.0")
        stats = db.get_db_stats()
        assert stats["total_verdicts"] == 2
        assert stats["verdicts_by_type"]["clean"] == 1
        assert stats["verdicts_by_type"]["malicious"] == 1
