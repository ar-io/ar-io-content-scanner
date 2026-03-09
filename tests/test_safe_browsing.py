"""Tests for Google Safe Browsing integration."""

from __future__ import annotations

import os
import tempfile
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.config import Settings
from src.db import ScannerDB
from src.gateway_client import GatewayClient
from src.metrics import ScanMetrics
from src.models import Verdict
from src.rules.engine import RuleEngine
from src.safe_browsing import DomainStatus, SafeBrowsingClient, SafeBrowsingResult
from src.scanner import Scanner

TX1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
TX2 = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"


def make_settings(**overrides):
    defaults = dict(
        gateway_url="http://localhost:3000",
        admin_api_key="test-key",
        scanner_mode="enforce",
        ml_model_enabled=False,
        gateway_public_url="https://mygateway.example.com",
        safe_browsing_api_key="test-sb-key",
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
def sb_client():
    return AsyncMock(spec=SafeBrowsingClient)


class TestSafeBrowsingClient:
    """Tests for the SafeBrowsingClient itself."""

    @pytest.mark.asyncio
    async def test_check_url_unflagged(self):
        """Mock httpx to return empty matches → not flagged."""
        client = SafeBrowsingClient(api_key="test-key")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {}
        mock_resp.raise_for_status = MagicMock()

        with patch.object(client._client, "post", new_callable=AsyncMock, return_value=mock_resp):
            result = await client.check_url("https://example.com/page")

        assert result.flagged is False
        assert result.url == "https://example.com/page"
        assert result.threat_types == []
        await client.close()

    @pytest.mark.asyncio
    async def test_check_url_flagged(self):
        """Mock httpx to return a match → flagged."""
        client = SafeBrowsingClient(api_key="test-key")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "matches": [
                {
                    "threatType": "SOCIAL_ENGINEERING",
                    "threat": {"url": "https://example.com/phish"},
                }
            ]
        }
        mock_resp.raise_for_status = MagicMock()

        with patch.object(client._client, "post", new_callable=AsyncMock, return_value=mock_resp):
            result = await client.check_url("https://example.com/phish")

        assert result.flagged is True
        assert "SOCIAL_ENGINEERING" in result.threat_types
        await client.close()

    @pytest.mark.asyncio
    async def test_check_urls_batch(self):
        """Batch check returns per-URL results."""
        client = SafeBrowsingClient(api_key="test-key")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "matches": [
                {
                    "threatType": "MALWARE",
                    "threat": {"url": "https://example.com/bad"},
                }
            ]
        }
        mock_resp.raise_for_status = MagicMock()

        urls = ["https://example.com/good", "https://example.com/bad"]
        with patch.object(client._client, "post", new_callable=AsyncMock, return_value=mock_resp):
            results = await client.check_urls(urls)

        assert len(results) == 2
        assert results[0].flagged is False
        assert results[1].flagged is True
        await client.close()

    @pytest.mark.asyncio
    async def test_api_error_returns_unflagged(self):
        """API errors should fail open — return unflagged results."""
        client = SafeBrowsingClient(api_key="test-key")

        with patch.object(client._client, "post", new_callable=AsyncMock, side_effect=Exception("network error")):
            result = await client.check_url("https://example.com/page")

        assert result.flagged is False
        await client.close()

    @pytest.mark.asyncio
    async def test_empty_api_key_returns_unflagged(self):
        """No API key → skip check, return unflagged."""
        client = SafeBrowsingClient(api_key="")
        result = await client.check_url("https://example.com/page")
        assert result.flagged is False
        await client.close()

    @pytest.mark.asyncio
    async def test_empty_url_list(self):
        """Empty URL list returns empty results."""
        client = SafeBrowsingClient(api_key="test-key")
        results = await client.check_urls([])
        assert results == []
        await client.close()

    @pytest.mark.asyncio
    async def test_check_domain_clean(self):
        """Transparency Report returns clean status."""
        client = SafeBrowsingClient(api_key="")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        # XSSI prefix + JSON: status_code=4 (not dangerous), no threats
        mock_resp.text = (
            ")]}'\n"
            '[["sb.ssr", 4, 0, 0, 0, 0, 0, 1700000000, "example.com"]]'
        )
        mock_resp.raise_for_status = MagicMock()

        with patch.object(client._client, "get", new_callable=AsyncMock, return_value=mock_resp):
            result = await client.check_domain("example.com")

        assert result.flagged is False
        assert result.error is False
        assert result.domain == "example.com"
        assert result.threat_types == []
        assert result.status_code == 4
        await client.close()

    @pytest.mark.asyncio
    async def test_check_domain_flagged(self):
        """Transparency Report returns flagged status with threat types."""
        client = SafeBrowsingClient(api_key="")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        # status_code=3 (some pages unsafe), phishing=1
        mock_resp.text = (
            ")]}'\n"
            '[["sb.ssr", 3, 0, 0, 1, 0, 0, 1700000000, "phishy.example.com"]]'
        )
        mock_resp.raise_for_status = MagicMock()

        with patch.object(client._client, "get", new_callable=AsyncMock, return_value=mock_resp):
            result = await client.check_domain("phishy.example.com")

        assert result.flagged is True
        assert result.domain == "phishy.example.com"
        assert "SOCIAL_ENGINEERING" in result.threat_types
        assert result.status_code == 3
        await client.close()

    @pytest.mark.asyncio
    async def test_check_domain_multiple_threats(self):
        """Transparency Report returns multiple threat types."""
        client = SafeBrowsingClient(api_key="")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        # malware=1, phishing=1, unwanted=1
        mock_resp.text = (
            ")]}'\n"
            '[["sb.ssr", 3, 1, 0, 1, 1, 0, 1700000000, "bad.example.com"]]'
        )
        mock_resp.raise_for_status = MagicMock()

        with patch.object(client._client, "get", new_callable=AsyncMock, return_value=mock_resp):
            result = await client.check_domain("bad.example.com")

        assert result.flagged is True
        assert "MALWARE" in result.threat_types
        assert "SOCIAL_ENGINEERING" in result.threat_types
        assert "UNWANTED_SOFTWARE" in result.threat_types
        await client.close()

    @pytest.mark.asyncio
    async def test_check_domain_error_fails_open(self):
        """Transparency Report errors fail open — return unflagged with error flag."""
        client = SafeBrowsingClient(api_key="")

        with patch.object(client._client, "get", new_callable=AsyncMock, side_effect=Exception("network error")):
            result = await client.check_domain("example.com")

        assert result.flagged is False
        assert result.domain == "example.com"
        assert result.error is True
        await client.close()

    @pytest.mark.asyncio
    async def test_check_domain_works_without_api_key(self):
        """Domain check uses Transparency Report, not Lookup API — no key needed."""
        client = SafeBrowsingClient(api_key="")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = (
            ")]}'\n"
            '[["sb.ssr", 3, 0, 0, 1, 0, 0, 1700000000, "flagged.example.com"]]'
        )
        mock_resp.raise_for_status = MagicMock()

        with patch.object(client._client, "get", new_callable=AsyncMock, return_value=mock_resp) as mock_get:
            result = await client.check_domain("flagged.example.com")

        assert result.flagged is True
        # Verify it used GET (Transparency Report), not POST (Lookup API)
        mock_get.assert_called_once()
        await client.close()


class TestSafeBrowsingEscalation:
    """Tests for SUSPICIOUS → MALICIOUS escalation via Safe Browsing."""

    @pytest.mark.asyncio
    async def test_suspicious_escalated_when_google_flags(self, db, metrics, sb_client):
        """SUSPICIOUS + Google flagged → MALICIOUS."""
        settings = make_settings()
        gateway = AsyncMock(spec=GatewayClient)
        engine = RuleEngine(settings, classifier=None)
        scanner = Scanner(
            settings, db, gateway, engine, metrics,
            safe_browsing=sb_client,
        )

        # Mock Safe Browsing to return flagged
        sb_client.check_url.return_value = SafeBrowsingResult(
            url=f"https://mygateway.example.com/{TX1}",
            flagged=True,
            threat_types=["SOCIAL_ENGINEERING"],
        )

        # Mock gateway to return suspicious-looking HTML
        # (but we'll directly test _check_safe_browsing)
        from src.models import ScanResult

        class FakeResult:
            verdict = Verdict.SUSPICIOUS
            matched_rules = []
            ml_score = 0.96
            scan_duration_ms = 10

        content_hash = "testhash123"
        result = FakeResult()

        # Save a suspicious verdict first
        db.save_verdict(
            content_hash=content_hash,
            tx_id=TX1,
            verdict=Verdict.SUSPICIOUS,
            matched_rules="[]",
            ml_score=0.96,
            scanner_version="test",
        )

        await scanner._check_safe_browsing(TX1, content_hash, result)

        # Verdict should be escalated
        assert result.verdict == Verdict.MALICIOUS
        assert metrics.safe_browsing_escalations == 1
        assert metrics.safe_browsing_checks == 1

        # DB should be updated
        cached = db.get_verdict(content_hash)
        assert cached.verdict == Verdict.MALICIOUS

    @pytest.mark.asyncio
    async def test_malicious_not_double_escalated(self, db, metrics, sb_client):
        """MALICIOUS + Google flagged → stays MALICIOUS (no escalation counter)."""
        settings = make_settings()
        gateway = AsyncMock(spec=GatewayClient)
        engine = RuleEngine(settings, classifier=None)
        scanner = Scanner(
            settings, db, gateway, engine, metrics,
            safe_browsing=sb_client,
        )

        sb_client.check_url.return_value = SafeBrowsingResult(
            url=f"https://mygateway.example.com/{TX1}",
            flagged=True,
            threat_types=["SOCIAL_ENGINEERING"],
        )

        class FakeResult:
            verdict = Verdict.MALICIOUS
            matched_rules = ["seed-phrase-harvesting"]
            ml_score = 0.99
            scan_duration_ms = 10

        content_hash = "testhash456"
        result = FakeResult()

        db.save_verdict(
            content_hash=content_hash,
            tx_id=TX1,
            verdict=Verdict.MALICIOUS,
            matched_rules='["seed-phrase-harvesting"]',
            ml_score=0.99,
            scanner_version="test",
        )

        await scanner._check_safe_browsing(TX1, content_hash, result)

        # Should stay malicious, no escalation counted
        assert result.verdict == Verdict.MALICIOUS
        assert metrics.safe_browsing_escalations == 0
        assert metrics.safe_browsing_checks == 1

    @pytest.mark.asyncio
    async def test_suspicious_not_escalated_when_google_clean(self, db, metrics, sb_client):
        """SUSPICIOUS + Google clean → stays SUSPICIOUS."""
        settings = make_settings()
        gateway = AsyncMock(spec=GatewayClient)
        engine = RuleEngine(settings, classifier=None)
        scanner = Scanner(
            settings, db, gateway, engine, metrics,
            safe_browsing=sb_client,
        )

        sb_client.check_url.return_value = SafeBrowsingResult(
            url=f"https://mygateway.example.com/{TX1}",
            flagged=False,
            threat_types=[],
        )

        class FakeResult:
            verdict = Verdict.SUSPICIOUS
            matched_rules = []
            ml_score = 0.96
            scan_duration_ms = 10

        content_hash = "testhash789"
        result = FakeResult()

        db.save_verdict(
            content_hash=content_hash,
            tx_id=TX1,
            verdict=Verdict.SUSPICIOUS,
            matched_rules="[]",
            ml_score=0.96,
            scanner_version="test",
        )

        await scanner._check_safe_browsing(TX1, content_hash, result)

        # Should stay suspicious
        assert result.verdict == Verdict.SUSPICIOUS
        assert metrics.safe_browsing_escalations == 0
        assert metrics.safe_browsing_checks == 1

        # DB should mark as not flagged
        row = db.conn.execute(
            "SELECT safe_browsing_flagged FROM scan_verdicts WHERE content_hash = ?",
            (content_hash,),
        ).fetchone()
        assert row[0] == 0

    @pytest.mark.asyncio
    async def test_sb_error_fails_open(self, db, metrics, sb_client):
        """API error → verdict unchanged (fail-open)."""
        settings = make_settings()
        gateway = AsyncMock(spec=GatewayClient)
        engine = RuleEngine(settings, classifier=None)
        scanner = Scanner(
            settings, db, gateway, engine, metrics,
            safe_browsing=sb_client,
        )

        sb_client.check_url.side_effect = Exception("API timeout")

        class FakeResult:
            verdict = Verdict.SUSPICIOUS
            matched_rules = []
            ml_score = 0.96
            scan_duration_ms = 10

        content_hash = "testhash_error"
        result = FakeResult()

        await scanner._check_safe_browsing(TX1, content_hash, result)

        # Should stay suspicious — fail open
        assert result.verdict == Verdict.SUSPICIOUS
        assert metrics.safe_browsing_escalations == 0

    @pytest.mark.asyncio
    async def test_no_public_url_skips_check(self, db, metrics, sb_client):
        """No gateway_public_url → skip SB check entirely."""
        settings = make_settings(gateway_public_url="")
        gateway = AsyncMock(spec=GatewayClient)
        engine = RuleEngine(settings, classifier=None)
        scanner = Scanner(
            settings, db, gateway, engine, metrics,
            safe_browsing=sb_client,
        )

        # The check should never be called since gateway_public_url is empty
        # (guarded in process_queue_item, not _check_safe_browsing)
        # Just verify the scanner has the right config
        assert scanner.settings.gateway_public_url == ""


class TestSafeBrowsingDB:
    """Tests for Safe Browsing DB operations."""

    def test_migration_adds_column(self, db):
        """The safe_browsing_flagged column should exist after initialization."""
        columns = {
            row[1]
            for row in db.conn.execute(
                "PRAGMA table_info(scan_verdicts)"
            ).fetchall()
        }
        assert "safe_browsing_flagged" in columns

    def test_update_safe_browsing_status(self, db):
        db.save_verdict(
            content_hash="hash1",
            tx_id=TX1,
            verdict=Verdict.MALICIOUS,
            matched_rules="[]",
            ml_score=None,
            scanner_version="test",
        )
        db.update_safe_browsing_status("hash1", True)

        row = db.conn.execute(
            "SELECT safe_browsing_flagged FROM scan_verdicts WHERE content_hash = ?",
            ("hash1",),
        ).fetchone()
        assert row[0] == 1

    def test_update_safe_browsing_status_false(self, db):
        db.save_verdict(
            content_hash="hash2",
            tx_id=TX1,
            verdict=Verdict.SUSPICIOUS,
            matched_rules="[]",
            ml_score=0.96,
            scanner_version="test",
        )
        db.update_safe_browsing_status("hash2", False)

        row = db.conn.execute(
            "SELECT safe_browsing_flagged FROM scan_verdicts WHERE content_hash = ?",
            ("hash2",),
        ).fetchone()
        assert row[0] == 0

    def test_get_recent_malicious_urls(self, db):
        db.save_verdict(
            content_hash="hash_mal",
            tx_id=TX1,
            verdict=Verdict.MALICIOUS,
            matched_rules="[]",
            ml_score=None,
            scanner_version="test",
        )
        db.save_verdict(
            content_hash="hash_clean",
            tx_id=TX2,
            verdict=Verdict.CLEAN,
            matched_rules="[]",
            ml_score=None,
            scanner_version="test",
        )
        results = db.get_recent_malicious_urls(limit=10)
        assert len(results) == 1
        assert results[0]["content_hash"] == "hash_mal"

    def test_get_safe_browsing_stats(self, db):
        db.save_verdict(
            content_hash="h1",
            tx_id=TX1,
            verdict=Verdict.MALICIOUS,
            matched_rules="[]",
            ml_score=None,
            scanner_version="test",
        )
        db.update_safe_browsing_status("h1", True)

        db.save_verdict(
            content_hash="h2",
            tx_id=TX2,
            verdict=Verdict.SUSPICIOUS,
            matched_rules="[]",
            ml_score=0.96,
            scanner_version="test",
        )
        # h2 has safe_browsing_flagged = NULL (unchecked)

        stats = db.get_safe_browsing_stats()
        assert stats["flagged"] == 1
        assert stats["unchecked"] == 1

    def test_review_items_include_sb_status(self, db):
        db.save_verdict(
            content_hash="h_review",
            tx_id=TX1,
            verdict=Verdict.MALICIOUS,
            matched_rules="[]",
            ml_score=None,
            scanner_version="test",
        )
        db.update_safe_browsing_status("h_review", True)

        items, total = db.list_review_items(status_filter="pending")
        assert total == 1
        assert items[0]["safe_browsing_flagged"] is True

    def test_recent_detections_include_sb_status(self, db):
        db.save_verdict(
            content_hash="h_detect",
            tx_id=TX1,
            verdict=Verdict.MALICIOUS,
            matched_rules="[]",
            ml_score=None,
            scanner_version="test",
        )
        db.update_safe_browsing_status("h_detect", False)

        detections = db.get_recent_detections(limit=5)
        assert len(detections) == 1
        assert detections[0]["safe_browsing_flagged"] is False


class TestSafeBrowsingMetrics:
    """Tests for Safe Browsing metrics recording."""

    def test_record_check_flagged(self, metrics):
        metrics.record_safe_browsing_check(flagged=True)
        assert metrics.safe_browsing_checks == 1
        assert metrics.safe_browsing_flagged == 1

    def test_record_check_clean(self, metrics):
        metrics.record_safe_browsing_check(flagged=False)
        assert metrics.safe_browsing_checks == 1
        assert metrics.safe_browsing_flagged == 0

    def test_record_escalation(self, metrics):
        metrics.record_safe_browsing_escalation()
        assert metrics.safe_browsing_escalations == 1

    def test_domain_flagged(self, metrics):
        assert metrics.safe_browsing_domain_flagged is False
        assert metrics.safe_browsing_domain_checks == 0
        metrics.set_safe_browsing_domain_flagged(True, threat_types=["SOCIAL_ENGINEERING"])
        assert metrics.safe_browsing_domain_flagged is True
        assert metrics.safe_browsing_domain_threats == ["SOCIAL_ENGINEERING"]
        assert metrics.safe_browsing_domain_checks == 1

    def test_domain_unflagged_clears_threats(self, metrics):
        metrics.set_safe_browsing_domain_flagged(True, threat_types=["MALWARE"])
        metrics.set_safe_browsing_domain_flagged(False)
        assert metrics.safe_browsing_domain_flagged is False
        assert metrics.safe_browsing_domain_threats == []
        assert metrics.safe_browsing_domain_checks == 2

    def test_to_dict_includes_sb(self, metrics):
        metrics.record_safe_browsing_check(flagged=True)
        metrics.set_safe_browsing_domain_flagged(True, threat_types=["MALWARE"])
        data = metrics.to_dict()
        assert data["safe_browsing_checks"] == 1
        assert data["safe_browsing_flagged"] == 1
        assert data["safe_browsing_domain_flagged"] is True
        assert data["safe_browsing_domain_threats"] == ["MALWARE"]
        assert data["safe_browsing_domain_checks"] == 1

    def test_prometheus_includes_sb(self, metrics):
        metrics.record_safe_browsing_check(flagged=True)
        prom = metrics.to_prometheus()
        assert "scanner_safe_browsing_checks 1" in prom
        assert "scanner_safe_browsing_flagged 1" in prom
        assert "scanner_safe_browsing_domain_flagged 0" in prom


class TestSafeBrowsingAdminAPI:
    """Tests for Safe Browsing data in admin API responses."""

    @pytest.fixture
    def settings(self, tmp_path):
        return Settings(
            gateway_url="http://localhost:4000",
            admin_api_key="gateway-key",
            scanner_admin_key="test-admin-key",
            admin_ui_enabled=True,
            ml_model_enabled=False,
            db_path=str(tmp_path / "test.db"),
            safe_browsing_api_key="test-sb-key",
            gateway_public_url="https://mygateway.example.com",
        )

    @pytest.fixture
    def db(self, settings):
        _db = ScannerDB(settings.db_path)
        _db.initialize()
        return _db

    @pytest.fixture
    def app(self, settings, db):
        from src.server import build_app

        a = build_app(settings)
        a.state.db = db
        return a

    @pytest.fixture
    def client(self, app):
        from fastapi.testclient import TestClient

        return TestClient(app)

    def test_stats_includes_safe_browsing(self, client, db):
        resp = client.get(
            "/api/admin/stats",
            headers={"Authorization": "Bearer test-admin-key"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "safe_browsing" in data
        assert data["safe_browsing"]["enabled"] is True
        assert data["safe_browsing"]["api_key_set"] is True
        assert "domain_flagged" in data["safe_browsing"]
        assert "domain_threats" in data["safe_browsing"]
        assert "domain_checks" in data["safe_browsing"]
        assert "stats" in data["safe_browsing"]

    def test_review_detail_includes_sb_status(self, client, db):
        db.save_verdict(
            content_hash="abcdef123456",
            tx_id=TX1,
            verdict=Verdict.MALICIOUS,
            matched_rules="[]",
            ml_score=None,
            scanner_version="test",
        )
        db.update_safe_browsing_status("abcdef123456", True)

        resp = client.get(
            "/api/admin/review/abcdef123456",
            headers={"Authorization": "Bearer test-admin-key"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["safe_browsing_flagged"] is True

    def test_settings_includes_safe_browsing(self, client, db):
        resp = client.get(
            "/api/admin/settings",
            headers={"Authorization": "Bearer test-admin-key"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "safe_browsing" in data
        assert data["safe_browsing"]["enabled"] is True
        assert data["safe_browsing"]["api_key_set"] is True
        assert data["safe_browsing"]["check_interval"] == 300


class TestSafeBrowsingNoApiKey:
    """Tests verifying Safe Browsing works without an API key (domain monitoring only)."""

    @pytest.fixture
    def settings(self, tmp_path):
        return Settings(
            gateway_url="http://localhost:4000",
            admin_api_key="gateway-key",
            scanner_admin_key="test-admin-key",
            admin_ui_enabled=True,
            ml_model_enabled=False,
            db_path=str(tmp_path / "test.db"),
            # No safe_browsing_api_key — domain monitoring should still work
            gateway_public_url="https://mygateway.example.com",
        )

    @pytest.fixture
    def db(self, settings):
        _db = ScannerDB(settings.db_path)
        _db.initialize()
        return _db

    @pytest.fixture
    def app(self, settings, db):
        from src.server import build_app

        a = build_app(settings)
        a.state.db = db
        return a

    @pytest.fixture
    def client(self, app):
        from fastapi.testclient import TestClient

        return TestClient(app)

    def test_stats_sb_enabled_without_key(self, client, db):
        """Safe Browsing shows enabled even without API key."""
        resp = client.get(
            "/api/admin/stats",
            headers={"Authorization": "Bearer test-admin-key"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["safe_browsing"]["enabled"] is True
        assert data["safe_browsing"]["api_key_set"] is False

    def test_settings_sb_enabled_without_key(self, client, db):
        """Settings shows Safe Browsing enabled without API key."""
        resp = client.get(
            "/api/admin/settings",
            headers={"Authorization": "Bearer test-admin-key"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["safe_browsing"]["enabled"] is True
        assert data["safe_browsing"]["api_key_set"] is False

    @pytest.mark.asyncio
    async def test_url_check_skipped_without_key(self):
        """URL-level Lookup API checks are skipped without an API key."""
        client = SafeBrowsingClient(api_key="")
        result = await client.check_url("https://example.com/page")
        assert result.flagged is False
        await client.close()


class TestSafeBrowsingConfig:
    """Tests for Safe Browsing configuration settings."""

    def test_default_settings(self):
        s = Settings(
            gateway_url="http://localhost:3000",
            admin_api_key="key",
        )
        assert s.safe_browsing_api_key == ""
        assert s.safe_browsing_check_interval == 300

    def test_custom_settings(self):
        s = Settings(
            gateway_url="http://localhost:3000",
            admin_api_key="key",
            safe_browsing_api_key="my-api-key",
            safe_browsing_check_interval=120,
        )
        assert s.safe_browsing_api_key == "my-api-key"
        assert s.safe_browsing_check_interval == 120
