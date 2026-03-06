"""Tests for the FastAPI server endpoints."""

import os
import tempfile
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from src.config import Settings
from src.db import ScannerDB
from src.gateway_client import GatewayClient
from src.metrics import ScanMetrics
from src.rules.engine import RuleEngine
from src.scanner import Scanner
from src.server import build_app


TEST_SETTINGS = Settings(
    gateway_url="http://localhost:3000",
    admin_api_key="test-key",
    scanner_mode="dry-run",
    ml_model_enabled=False,
    db_path=":memory:",
)


@pytest.fixture
def app():
    """Build app with in-memory DB and no ML model."""
    with patch("src.server.load_settings", return_value=TEST_SETTINGS):
        application = build_app(TEST_SETTINGS)
    return application


@pytest.fixture
def client(app):
    with TestClient(app) as c:
        yield c


class TestHealthEndpoint:
    def test_health(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["mode"] == "dry-run"
        assert data["version"] == "0.1.0"


class TestMetricsEndpoint:
    def test_metrics(self, client):
        resp = client.get("/metrics")
        assert resp.status_code == 200
        data = resp.json()
        assert "scans_total" in data
        assert "cache_hits" in data
        assert "queue_depth" in data
        assert "uptime_seconds" in data


class TestScanEndpoint:
    def test_scan_accepts_webhook(self, client):
        resp = client.post("/scan", json={
            "event": "data-cached",
            "data": {
                "id": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "hash": "hash1",
                "contentType": "text/html",
                "dataSize": 1024,
            },
        })
        assert resp.status_code == 202
        assert resp.json() == {"status": "accepted"}

    def test_scan_rejects_invalid_payload(self, client):
        resp = client.post("/scan", json={"bad": "data"})
        assert resp.status_code == 422

    def test_scan_rejects_invalid_tx_id(self, client):
        resp = client.post("/scan", json={
            "event": "data-cached",
            "data": {"id": "too-short"},
        })
        assert resp.status_code == 422

    def test_scan_skips_non_html(self, client):
        resp = client.post("/scan", json={
            "event": "data-cached",
            "data": {
                "id": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
                "contentType": "image/png",
            },
        })
        assert resp.status_code == 202
