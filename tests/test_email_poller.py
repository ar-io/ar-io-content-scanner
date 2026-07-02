"""Tests for M365 email poller."""
from __future__ import annotations

import asyncio
import base64
import json
import tempfile
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from src.db import ScannerDB
from src.email.m365_poller import M365EmailPoller


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SAMPLE_TX_ID = base64.urlsafe_b64encode(b"\xaa" * 32).rstrip(b"=").decode()

TENANT_ID = "test-tenant-id"
CLIENT_ID = "test-client-id"
CLIENT_SECRET = "test-client-secret"
MAILBOX = "abuse@ar.io"


def _make_db() -> ScannerDB:
    """Create an in-memory ScannerDB for testing."""
    db = ScannerDB(":memory:")
    db.initialize()
    return db


def _make_poller(db: ScannerDB | None = None) -> M365EmailPoller:
    if db is None:
        db = _make_db()
    return M365EmailPoller(
        tenant_id=TENANT_ID,
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        mailbox=MAILBOX,
        poll_interval=60,
        db=db,
    )


def _make_graph_message(
    msg_id: str = "msg-1",
    sender: str = "reporter@example.com",
    subject: str = "Abuse report",
    body_content: str = "",
    content_type: str = "html",
) -> dict:
    return {
        "id": msg_id,
        "from": {"emailAddress": {"address": sender}},
        "subject": subject,
        "body": {
            "contentType": content_type,
            "content": body_content,
        },
        "receivedDateTime": "2026-06-29T12:00:00Z",
    }


# ---------------------------------------------------------------------------
# OAuth token acquisition
# ---------------------------------------------------------------------------


class TestGetAccessToken:
    @pytest.mark.asyncio
    async def test_successful_token(self):
        poller = _make_poller()
        mock_response = httpx.Response(
            200,
            json={"access_token": "test-token-123"},
            request=httpx.Request("POST", "https://login.microsoftonline.com/"),
        )

        with patch.object(poller._client, "post", new_callable=AsyncMock, return_value=mock_response):
            token = await poller._get_access_token()

        assert token == "test-token-123"
        await poller._client.aclose()

    @pytest.mark.asyncio
    async def test_failed_token_returns_none(self):
        poller = _make_poller()
        mock_response = httpx.Response(
            401,
            json={"error": "invalid_client"},
            request=httpx.Request("POST", "https://login.microsoftonline.com/"),
        )

        with patch.object(poller._client, "post", new_callable=AsyncMock, return_value=mock_response):
            token = await poller._get_access_token()

        assert token is None
        await poller._client.aclose()

    @pytest.mark.asyncio
    async def test_exception_returns_none(self):
        poller = _make_poller()

        with patch.object(
            poller._client, "post", new_callable=AsyncMock,
            side_effect=httpx.ConnectError("connection refused"),
        ):
            token = await poller._get_access_token()

        assert token is None
        await poller._client.aclose()


# ---------------------------------------------------------------------------
# Fetch unread emails
# ---------------------------------------------------------------------------


class TestFetchUnreadEmails:
    @pytest.mark.asyncio
    async def test_returns_messages(self):
        poller = _make_poller()
        messages = [_make_graph_message()]
        mock_response = httpx.Response(
            200,
            json={"value": messages},
            request=httpx.Request("GET", "https://graph.microsoft.com/"),
        )

        with patch.object(poller._client, "get", new_callable=AsyncMock, return_value=mock_response):
            result = await poller._fetch_unread_emails("token")

        assert len(result) == 1
        assert result[0]["id"] == "msg-1"
        await poller._client.aclose()

    @pytest.mark.asyncio
    async def test_api_error_returns_empty(self):
        poller = _make_poller()
        mock_response = httpx.Response(
            500,
            text="Internal Server Error",
            request=httpx.Request("GET", "https://graph.microsoft.com/"),
        )

        with patch.object(poller._client, "get", new_callable=AsyncMock, return_value=mock_response):
            result = await poller._fetch_unread_emails("token")

        assert result == []
        await poller._client.aclose()

    @pytest.mark.asyncio
    async def test_empty_mailbox(self):
        poller = _make_poller()
        mock_response = httpx.Response(
            200,
            json={"value": []},
            request=httpx.Request("GET", "https://graph.microsoft.com/"),
        )

        with patch.object(poller._client, "get", new_callable=AsyncMock, return_value=mock_response):
            result = await poller._fetch_unread_emails("token")

        assert result == []
        await poller._client.aclose()


# ---------------------------------------------------------------------------
# Mark as read
# ---------------------------------------------------------------------------


class TestMarkAsRead:
    @pytest.mark.asyncio
    async def test_successful_mark(self):
        poller = _make_poller()
        mock_response = httpx.Response(
            200,
            json={},
            request=httpx.Request("PATCH", "https://graph.microsoft.com/"),
        )

        with patch.object(poller._client, "patch", new_callable=AsyncMock, return_value=mock_response) as mock_patch:
            await poller._mark_as_read("token", "msg-1")

        mock_patch.assert_called_once()
        call_kwargs = mock_patch.call_args
        assert "msg-1" in call_kwargs[0][0]  # URL contains message ID
        assert call_kwargs[1]["json"] == {"isRead": True}
        await poller._client.aclose()

    @pytest.mark.asyncio
    async def test_mark_as_read_failure_does_not_raise(self):
        poller = _make_poller()
        mock_response = httpx.Response(
            500,
            text="error",
            request=httpx.Request("PATCH", "https://graph.microsoft.com/"),
        )

        with patch.object(poller._client, "patch", new_callable=AsyncMock, return_value=mock_response):
            # Should not raise
            await poller._mark_as_read("token", "msg-1")

        await poller._client.aclose()


# ---------------------------------------------------------------------------
# Full poll cycle
# ---------------------------------------------------------------------------


class TestPollOnce:
    @pytest.mark.asyncio
    async def test_poll_extracts_and_enqueues(self):
        db = _make_db()
        poller = _make_poller(db)

        body = f'<p>Phishing at https://arweave.net/{SAMPLE_TX_ID}</p>'
        messages = [_make_graph_message(body_content=body, content_type="html")]

        token_response = httpx.Response(
            200,
            json={"access_token": "tok"},
            request=httpx.Request("POST", "https://login.microsoftonline.com/"),
        )
        messages_response = httpx.Response(
            200,
            json={"value": messages},
            request=httpx.Request("GET", "https://graph.microsoft.com/"),
        )
        mark_response = httpx.Response(
            200,
            json={},
            request=httpx.Request("PATCH", "https://graph.microsoft.com/"),
        )

        with patch.object(poller._client, "post", new_callable=AsyncMock, return_value=token_response), \
             patch.object(poller._client, "get", new_callable=AsyncMock, return_value=messages_response), \
             patch.object(poller._client, "patch", new_callable=AsyncMock, return_value=mark_response):
            await poller._poll_once()

        # Verify the TX ID was enqueued
        assert db.queue_depth() == 1
        items = db.dequeue(batch_size=1)
        assert len(items) == 1
        assert items[0].tx_id == SAMPLE_TX_ID
        await poller._client.aclose()

    @pytest.mark.asyncio
    async def test_poll_with_text_body(self):
        db = _make_db()
        poller = _make_poller(db)

        body = f"Phishing at https://arweave.net/{SAMPLE_TX_ID}"
        messages = [_make_graph_message(body_content=body, content_type="text")]

        token_response = httpx.Response(
            200,
            json={"access_token": "tok"},
            request=httpx.Request("POST", "https://login.microsoftonline.com/"),
        )
        messages_response = httpx.Response(
            200,
            json={"value": messages},
            request=httpx.Request("GET", "https://graph.microsoft.com/"),
        )
        mark_response = httpx.Response(
            200,
            json={},
            request=httpx.Request("PATCH", "https://graph.microsoft.com/"),
        )

        with patch.object(poller._client, "post", new_callable=AsyncMock, return_value=token_response), \
             patch.object(poller._client, "get", new_callable=AsyncMock, return_value=messages_response), \
             patch.object(poller._client, "patch", new_callable=AsyncMock, return_value=mark_response):
            await poller._poll_once()

        assert db.queue_depth() == 1
        items = db.dequeue(batch_size=1)
        assert items[0].tx_id == SAMPLE_TX_ID
        await poller._client.aclose()

    @pytest.mark.asyncio
    async def test_poll_no_tx_ids_still_marks_read(self):
        db = _make_db()
        poller = _make_poller(db)

        messages = [_make_graph_message(body_content="No URLs here", content_type="text")]

        token_response = httpx.Response(
            200,
            json={"access_token": "tok"},
            request=httpx.Request("POST", "https://login.microsoftonline.com/"),
        )
        messages_response = httpx.Response(
            200,
            json={"value": messages},
            request=httpx.Request("GET", "https://graph.microsoft.com/"),
        )
        mark_response = httpx.Response(
            200,
            json={},
            request=httpx.Request("PATCH", "https://graph.microsoft.com/"),
        )

        with patch.object(poller._client, "post", new_callable=AsyncMock, return_value=token_response), \
             patch.object(poller._client, "get", new_callable=AsyncMock, return_value=messages_response), \
             patch.object(poller._client, "patch", new_callable=AsyncMock, return_value=mark_response) as mock_mark:
            await poller._poll_once()

        assert db.queue_depth() == 0
        mock_mark.assert_called_once()
        await poller._client.aclose()

    @pytest.mark.asyncio
    async def test_poll_token_failure_aborts_gracefully(self):
        db = _make_db()
        poller = _make_poller(db)

        token_response = httpx.Response(
            401,
            json={"error": "unauthorized"},
            request=httpx.Request("POST", "https://login.microsoftonline.com/"),
        )

        with patch.object(poller._client, "post", new_callable=AsyncMock, return_value=token_response):
            # Should not raise
            await poller._poll_once()

        assert db.queue_depth() == 0
        await poller._client.aclose()

    @pytest.mark.asyncio
    async def test_poll_graph_500_is_fail_open(self):
        db = _make_db()
        poller = _make_poller(db)

        token_response = httpx.Response(
            200,
            json={"access_token": "tok"},
            request=httpx.Request("POST", "https://login.microsoftonline.com/"),
        )
        error_response = httpx.Response(
            500,
            text="Internal Server Error",
            request=httpx.Request("GET", "https://graph.microsoft.com/"),
        )

        with patch.object(poller._client, "post", new_callable=AsyncMock, return_value=token_response), \
             patch.object(poller._client, "get", new_callable=AsyncMock, return_value=error_response):
            # Should not raise
            await poller._poll_once()

        assert db.queue_depth() == 0
        await poller._client.aclose()

    @pytest.mark.asyncio
    async def test_poll_empty_mailbox(self):
        db = _make_db()
        poller = _make_poller(db)

        token_response = httpx.Response(
            200,
            json={"access_token": "tok"},
            request=httpx.Request("POST", "https://login.microsoftonline.com/"),
        )
        empty_response = httpx.Response(
            200,
            json={"value": []},
            request=httpx.Request("GET", "https://graph.microsoft.com/"),
        )

        with patch.object(poller._client, "post", new_callable=AsyncMock, return_value=token_response), \
             patch.object(poller._client, "get", new_callable=AsyncMock, return_value=empty_response):
            await poller._poll_once()

        assert db.queue_depth() == 0
        await poller._client.aclose()

    @pytest.mark.asyncio
    async def test_duplicate_tx_id_not_enqueued_twice(self):
        db = _make_db()
        poller = _make_poller(db)

        body = (
            f'<p>https://arweave.net/{SAMPLE_TX_ID}</p>'
            f'<p>https://ar.io/{SAMPLE_TX_ID}</p>'
        )
        messages = [_make_graph_message(body_content=body, content_type="html")]

        token_response = httpx.Response(
            200,
            json={"access_token": "tok"},
            request=httpx.Request("POST", "https://login.microsoftonline.com/"),
        )
        messages_response = httpx.Response(
            200,
            json={"value": messages},
            request=httpx.Request("GET", "https://graph.microsoft.com/"),
        )
        mark_response = httpx.Response(
            200,
            json={},
            request=httpx.Request("PATCH", "https://graph.microsoft.com/"),
        )

        with patch.object(poller._client, "post", new_callable=AsyncMock, return_value=token_response), \
             patch.object(poller._client, "get", new_callable=AsyncMock, return_value=messages_response), \
             patch.object(poller._client, "patch", new_callable=AsyncMock, return_value=mark_response):
            await poller._poll_once()

        # Should only have 1 item since the TX ID was deduplicated
        assert db.queue_depth() == 1
        await poller._client.aclose()


# ---------------------------------------------------------------------------
# Start / stop lifecycle
# ---------------------------------------------------------------------------


class TestLifecycle:
    @pytest.mark.asyncio
    async def test_start_and_stop(self):
        poller = _make_poller()

        # Mock _poll_loop so it doesn't actually run
        with patch.object(poller, "_poll_loop", new_callable=AsyncMock):
            await poller.start()
            assert poller._running is True
            assert poller._task is not None

            await poller.stop()
            assert poller._running is False
