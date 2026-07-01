"""Tests for Slack notification support."""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from src.admin.slack_actions import _verify_slack_signature
from src.config import Settings
from src.db import ScannerDB
from src.models import Verdict
from src.notifications.router import NotificationRouter
from src.notifications.slack import SlackNotifier
from src.server import build_app


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def settings(tmp_path):
    return Settings(
        gateway_url="http://localhost:4000",
        admin_api_key="gateway-key",
        scanner_admin_key="test-admin-key",
        admin_ui_enabled=True,
        ml_model_enabled=False,
        db_path=str(tmp_path / "test.db"),
        slack_enabled=True,
        slack_bot_token="xoxb-test-token",
        slack_channel_id="C12345",
        slack_signing_secret="test-signing-secret",
        slack_notification_threshold="malicious",
        gateway_public_url="https://ar-io.example.com",
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


@pytest.fixture
def notifier():
    slack = SlackNotifier(
        bot_token="xoxb-test",
        channel_id="C12345",
        gateway_public_url="https://ar-io.example.com",
    )
    return NotificationRouter(slack=slack, threshold="malicious")


# ---------------------------------------------------------------------------
# Message Formatting
# ---------------------------------------------------------------------------

class TestMessageFormatting:
    def test_malicious_header(self):
        slack = SlackNotifier(
            bot_token="xoxb-test",
            channel_id="C12345",
            gateway_public_url="https://ar-io.example.com",
        )
        blocks = slack._build_blocks(
            verdict="malicious",
            tx_id="abc123" + "x" * 37,
            content_hash="hash123" + "y" * 37,
            matched_rules=["seed-phrase-harvesting"],
            ml_score=0.99,
            action_taken="blocked",
        )
        header = blocks[0]
        assert header["type"] == "header"
        assert "Malicious" in header["text"]["text"]

    def test_suspicious_header(self):
        slack = SlackNotifier(
            bot_token="xoxb-test",
            channel_id="C12345",
        )
        blocks = slack._build_blocks(
            verdict="suspicious",
            tx_id="tx123",
            content_hash="hash123",
            matched_rules=[],
            ml_score=0.96,
        )
        header = blocks[0]
        assert "Suspicious" in header["text"]["text"]

    def test_blocks_contain_actions(self):
        slack = SlackNotifier(
            bot_token="xoxb-test",
            channel_id="C12345",
        )
        blocks = slack._build_blocks(
            verdict="malicious",
            tx_id="tx123",
            content_hash="hash123",
            matched_rules=["rule1"],
            ml_score=0.99,
        )
        actions_block = blocks[2]
        assert actions_block["type"] == "actions"
        action_ids = [e["action_id"] for e in actions_block["elements"]]
        assert "confirm_block" in action_ids
        assert "dismiss_fp" in action_ids
        assert "classify_neutral" in action_ids

    def test_button_value_encodes_hash_and_tx(self):
        slack = SlackNotifier(
            bot_token="xoxb-test",
            channel_id="C12345",
        )
        blocks = slack._build_blocks(
            verdict="malicious",
            tx_id="my_tx_id",
            content_hash="my_content_hash",
            matched_rules=[],
            ml_score=None,
        )
        button = blocks[2]["elements"][0]
        value = json.loads(button["value"])
        assert value["content_hash"] == "my_content_hash"
        assert value["tx_id"] == "my_tx_id"

    def test_tx_link_with_gateway_url(self):
        slack = SlackNotifier(
            bot_token="xoxb-test",
            channel_id="C12345",
            gateway_public_url="https://ar-io.example.com",
        )
        blocks = slack._build_blocks(
            verdict="malicious",
            tx_id="txABC",
            content_hash="hashABC",
            matched_rules=["rule1"],
            ml_score=0.95,
        )
        section = blocks[1]
        tx_field = section["fields"][0]
        assert "https://ar-io.example.com/txABC" in tx_field["text"]

    def test_tx_link_without_gateway_url(self):
        slack = SlackNotifier(
            bot_token="xoxb-test",
            channel_id="C12345",
            gateway_public_url="",
        )
        blocks = slack._build_blocks(
            verdict="malicious",
            tx_id="txABC",
            content_hash="hashABC",
            matched_rules=[],
            ml_score=None,
        )
        section = blocks[1]
        tx_field = section["fields"][0]
        assert "`txABC`" in tx_field["text"]

    def test_ml_score_none_shows_na(self):
        slack = SlackNotifier(
            bot_token="xoxb-test",
            channel_id="C12345",
        )
        blocks = slack._build_blocks(
            verdict="malicious",
            tx_id="tx1",
            content_hash="hash1",
            matched_rules=[],
            ml_score=None,
        )
        section = blocks[1]
        ml_field = section["fields"][3]
        assert "_n/a_" in ml_field["text"]


# ---------------------------------------------------------------------------
# Notification Router Threshold
# ---------------------------------------------------------------------------

class TestNotificationThreshold:
    def test_malicious_threshold_notifies_on_malicious(self):
        router = NotificationRouter(slack=MagicMock(), threshold="malicious")
        assert router._should_notify("malicious") is True

    def test_malicious_threshold_skips_suspicious(self):
        router = NotificationRouter(slack=MagicMock(), threshold="malicious")
        assert router._should_notify("suspicious") is False

    def test_suspicious_threshold_notifies_on_both(self):
        router = NotificationRouter(slack=MagicMock(), threshold="suspicious")
        assert router._should_notify("malicious") is True
        assert router._should_notify("suspicious") is True

    def test_threshold_skips_clean(self):
        router = NotificationRouter(slack=MagicMock(), threshold="suspicious")
        assert router._should_notify("clean") is False

    def test_threshold_skips_skipped(self):
        router = NotificationRouter(slack=MagicMock(), threshold="suspicious")
        assert router._should_notify("skipped") is False


# ---------------------------------------------------------------------------
# Signature Verification
# ---------------------------------------------------------------------------

class TestSignatureVerification:
    def _make_signature(self, secret: str, timestamp: str, body: bytes) -> str:
        sig_basestring = f"v0:{timestamp}:{body.decode('utf-8')}"
        h = hmac.new(
            secret.encode("utf-8"),
            sig_basestring.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return f"v0={h}"

    def test_valid_signature(self):
        secret = "test-secret-key"
        ts = str(int(time.time()))
        body = b"payload=test"
        sig = self._make_signature(secret, ts, body)

        assert _verify_slack_signature(secret, ts, body, sig) is True

    def test_invalid_signature(self):
        secret = "test-secret-key"
        ts = str(int(time.time()))
        body = b"payload=test"

        assert _verify_slack_signature(secret, ts, body, "v0=invalid") is False

    def test_expired_timestamp(self):
        secret = "test-secret-key"
        ts = str(int(time.time()) - 600)  # 10 minutes ago
        body = b"payload=test"
        sig = self._make_signature(secret, ts, body)

        assert _verify_slack_signature(secret, ts, body, sig) is False

    def test_empty_signing_secret(self):
        assert _verify_slack_signature("", "12345", b"body", "v0=abc") is False

    def test_empty_timestamp(self):
        assert _verify_slack_signature("secret", "", b"body", "v0=abc") is False

    def test_empty_signature(self):
        assert _verify_slack_signature("secret", "12345", b"body", "") is False

    def test_non_numeric_timestamp(self):
        assert _verify_slack_signature("secret", "abc", b"body", "v0=abc") is False


# ---------------------------------------------------------------------------
# Slack Action Endpoint
# ---------------------------------------------------------------------------

class TestSlackActionEndpoint:
    def _make_action_payload(
        self,
        action_id: str,
        content_hash: str = "h1",
        tx_id: str = "tx1",
    ) -> dict:
        return {
            "type": "block_actions",
            "user": {"id": "U12345", "name": "testuser"},
            "actions": [
                {
                    "action_id": action_id,
                    "value": json.dumps({
                        "content_hash": content_hash,
                        "tx_id": tx_id,
                    }),
                }
            ],
            "message": {
                "ts": "1234567890.123456",
                "blocks": [
                    {"type": "header", "text": {"type": "plain_text", "text": "Test"}},
                    {"type": "section", "fields": []},
                    {"type": "actions", "elements": []},
                ],
            },
            "response_url": "https://hooks.slack.com/actions/T12345/test",
            "channel": {"id": "C12345"},
        }

    def _sign_request(self, secret: str, body: bytes) -> tuple[str, str]:
        ts = str(int(time.time()))
        sig_basestring = f"v0:{ts}:{body.decode('utf-8')}"
        sig = "v0=" + hmac.new(
            secret.encode("utf-8"),
            sig_basestring.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return ts, sig

    def test_unauthenticated_request_returns_401(self, client):
        resp = client.post(
            "/api/slack/actions",
            content=b"payload={}",
            headers={
                "X-Slack-Request-Timestamp": "0",
                "X-Slack-Signature": "v0=invalid",
            },
        )
        assert resp.status_code == 401

    @patch("src.admin.slack_actions.httpx.AsyncClient")
    def test_confirm_block_action(self, mock_httpx_class, client, db):
        # Seed a verdict
        db.save_verdict("h1", "tx1", Verdict.MALICIOUS, '["rule1"]', 0.99, "0.1.0")

        payload = self._make_action_payload("confirm_block")
        body = f"payload={json.dumps(payload)}".encode("utf-8")
        ts, sig = self._sign_request("test-signing-secret", body)

        # Mock the httpx response_url call
        mock_client_instance = AsyncMock()
        mock_httpx_class.return_value.__aenter__ = AsyncMock(return_value=mock_client_instance)
        mock_httpx_class.return_value.__aexit__ = AsyncMock(return_value=False)

        resp = client.post(
            "/api/slack/actions",
            content=body,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "X-Slack-Request-Timestamp": ts,
                "X-Slack-Signature": sig,
            },
        )
        assert resp.status_code == 200

        # Verify override was saved
        override = db.get_override("h1")
        assert override is not None
        assert override.admin_verdict == "confirmed_malicious"

    @patch("src.admin.slack_actions.httpx.AsyncClient")
    def test_dismiss_action(self, mock_httpx_class, client, db):
        db.save_verdict("h1", "tx1", Verdict.MALICIOUS, '["rule1"]', 0.99, "0.1.0")

        payload = self._make_action_payload("dismiss_fp")
        body = f"payload={json.dumps(payload)}".encode("utf-8")
        ts, sig = self._sign_request("test-signing-secret", body)

        mock_client_instance = AsyncMock()
        mock_httpx_class.return_value.__aenter__ = AsyncMock(return_value=mock_client_instance)
        mock_httpx_class.return_value.__aexit__ = AsyncMock(return_value=False)

        resp = client.post(
            "/api/slack/actions",
            content=body,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "X-Slack-Request-Timestamp": ts,
                "X-Slack-Signature": sig,
            },
        )
        assert resp.status_code == 200

        # Verdict should be updated to CLEAN
        verdict = db.get_verdict("h1")
        assert verdict is not None
        assert verdict.verdict == Verdict.CLEAN

    @patch("src.admin.slack_actions.httpx.AsyncClient")
    def test_classify_neutral_action(self, mock_httpx_class, client, db):
        db.save_verdict("h1", "tx1", Verdict.SUSPICIOUS, '[]', 0.96, "0.1.0")

        payload = self._make_action_payload("classify_neutral")
        body = f"payload={json.dumps(payload)}".encode("utf-8")
        ts, sig = self._sign_request("test-signing-secret", body)

        mock_client_instance = AsyncMock()
        mock_httpx_class.return_value.__aenter__ = AsyncMock(return_value=mock_client_instance)
        mock_httpx_class.return_value.__aexit__ = AsyncMock(return_value=False)

        resp = client.post(
            "/api/slack/actions",
            content=body,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "X-Slack-Request-Timestamp": ts,
                "X-Slack-Signature": sig,
            },
        )
        assert resp.status_code == 200

        # Verdict should be updated to CLEAN
        verdict = db.get_verdict("h1")
        assert verdict is not None
        assert verdict.verdict == Verdict.CLEAN

    def test_missing_content_hash_returns_400(self, client):
        payload = {
            "type": "block_actions",
            "user": {"id": "U12345"},
            "actions": [
                {
                    "action_id": "confirm_block",
                    "value": json.dumps({"tx_id": "tx1"}),  # no content_hash
                }
            ],
        }
        body = f"payload={json.dumps(payload)}".encode("utf-8")
        ts, sig = self._sign_request("test-signing-secret", body)

        resp = client.post(
            "/api/slack/actions",
            content=body,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "X-Slack-Request-Timestamp": ts,
                "X-Slack-Signature": sig,
            },
        )
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Fail-Open Behavior
# ---------------------------------------------------------------------------

class TestFailOpen:
    @pytest.mark.asyncio
    async def test_slack_api_error_does_not_raise(self):
        """Slack send errors should be caught — never block scanning."""
        slack = SlackNotifier(
            bot_token="xoxb-test",
            channel_id="C12345",
        )
        # Mock the httpx client to raise an error
        slack._client = AsyncMock()
        slack._client.post = AsyncMock(side_effect=Exception("Slack API down"))

        result = await slack.send_verdict_alert(
            verdict="malicious",
            tx_id="tx123",
            content_hash="hash123",
            matched_rules=["rule1"],
            ml_score=0.99,
        )
        assert result is False

    @pytest.mark.asyncio
    async def test_notification_router_catches_slack_error(self):
        """NotificationRouter should never propagate Slack errors."""
        slack = AsyncMock(spec=SlackNotifier)
        slack.send_verdict_alert = AsyncMock(
            side_effect=Exception("Connection refused")
        )

        router = NotificationRouter(slack=slack, threshold="malicious")
        # Should not raise
        await router.notify(
            verdict="malicious",
            tx_id="tx123",
            content_hash="hash123",
            matched_rules=["rule1"],
            ml_score=0.99,
        )

    @pytest.mark.asyncio
    async def test_slack_500_returns_false(self):
        """Slack returning a non-ok response should return False, not raise."""
        slack = SlackNotifier(
            bot_token="xoxb-test",
            channel_id="C12345",
        )
        mock_response = MagicMock()
        mock_response.json.return_value = {"ok": False, "error": "channel_not_found"}

        slack._client = AsyncMock()
        slack._client.post = AsyncMock(return_value=mock_response)

        result = await slack.send_verdict_alert(
            verdict="malicious",
            tx_id="tx123",
            content_hash="hash123",
            matched_rules=["rule1"],
            ml_score=0.99,
        )
        assert result is False

    @pytest.mark.asyncio
    async def test_router_skips_when_no_slack(self):
        """Router with no Slack adapter should silently skip."""
        router = NotificationRouter(slack=None, threshold="malicious")
        # Should not raise
        await router.notify(
            verdict="malicious",
            tx_id="tx123",
            content_hash="hash123",
            matched_rules=["rule1"],
            ml_score=0.99,
        )
