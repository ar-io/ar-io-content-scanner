"""Microsoft 365 email poller for abuse report intake.

Polls a Microsoft 365 mailbox via the Graph API for unread abuse reports,
extracts Arweave TX IDs, enqueues them for scanning, and marks emails as read.

Uses OAuth2 client credentials flow (app-only, no user login). Requires an
Azure AD app registration with ``Mail.ReadWrite`` application permission.
"""
from __future__ import annotations

import asyncio
import logging

import httpx

from src.db import ScannerDB
from src.email.tx_extractor import extract_all_tx_ids
from src.notifications.router import NotificationRouter

logger = logging.getLogger("scanner.email")

_GRAPH_BASE = "https://graph.microsoft.com/v1.0"
_TOKEN_URL_TEMPLATE = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"


class M365EmailPoller:
    """Polls an M365 mailbox for unread abuse reports and enqueues TX IDs.

    Designed to run as a background asyncio task alongside the scanner's
    worker pool. Fail-open: Graph API errors are logged but never affect
    the scanning pipeline.
    """

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        mailbox: str,
        poll_interval: int,
        db: ScannerDB,
        notifier: NotificationRouter | None = None,
    ):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.mailbox = mailbox
        self.poll_interval = poll_interval
        self.db = db
        self.notifier = notifier

        self._client = httpx.AsyncClient(timeout=httpx.Timeout(30.0))
        self._task: asyncio.Task | None = None
        self._running = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Start the background polling loop."""
        self._running = True
        self._task = asyncio.create_task(
            self._poll_loop(), name="email-poller"
        )
        logger.info(
            "Email poller started",
            extra={
                "mailbox": self.mailbox,
                "poll_interval": self.poll_interval,
            },
        )

    async def stop(self) -> None:
        """Stop the background polling loop and close the HTTP client."""
        self._running = False
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        await self._client.aclose()
        logger.info("Email poller stopped")

    # ------------------------------------------------------------------
    # Polling loop
    # ------------------------------------------------------------------

    async def _poll_loop(self) -> None:
        # Let the scanner initialize first
        await asyncio.sleep(5)

        while self._running:
            try:
                await self._poll_once()
            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("Email poll error")

            try:
                await asyncio.sleep(self.poll_interval)
            except asyncio.CancelledError:
                break

    async def _poll_once(self) -> None:
        """Fetch unread emails, extract TX IDs, enqueue, and mark read."""
        token = await self._get_access_token()
        if token is None:
            return

        messages = await self._fetch_unread_emails(token)
        if not messages:
            return

        logger.info(
            "Processing abuse emails",
            extra={"count": len(messages)},
        )

        for msg in messages:
            msg_id = msg.get("id", "")
            sender = (
                msg.get("from", {})
                .get("emailAddress", {})
                .get("address", "unknown")
            )
            subject = msg.get("subject", "(no subject)")
            # Graph API returns body in one format (text or html).
            # We feed the content to both extraction paths regardless,
            # since extract_all_tx_ids combines text+html and runs all
            # regex strategies on the combined content.
            body_obj = msg.get("body", {})
            body_content = body_obj.get("content", "")
            body_type = body_obj.get("contentType", "").lower()

            # Truncate to prevent memory/CPU issues with huge emails
            MAX_BODY = 1_000_000  # 1MB
            body_content = body_content[:MAX_BODY]

            if body_type == "text":
                text_body, html_body = body_content, ""
            else:
                # html or unknown — treat as HTML, also pass as text
                # since HTML often contains the same URLs as plain text
                text_body, html_body = body_content, body_content

            tx_ids = extract_all_tx_ids(text_body, html_body)

            enqueued = 0
            already_known = 0
            for tx_id in tx_ids:
                if self.db.enqueue(
                    tx_id=tx_id,
                    content_hash=None,
                    content_type=None,
                    data_size=None,
                ):
                    enqueued += 1
                else:
                    # enqueue returns False for both duplicates and DB errors.
                    # Check if it's already in verdict cache (already scanned/blocked)
                    # — if so, it's a known duplicate, not a failure.
                    existing = self.db.get_verdict(tx_id)
                    if existing is not None:
                        already_known += 1

            logger.info(
                "Processed abuse email",
                extra={
                    "sender": sender,
                    "subject": subject,
                    "tx_ids_found": len(tx_ids),
                    "tx_ids_enqueued": enqueued,
                    "message_id": msg_id,
                },
            )

            # Slack notification summary (send even when 0 TX IDs found
            # so operators know the email was processed)
            if self.notifier and hasattr(self.notifier, 'slack') and self.notifier.slack:
                try:
                    # Sanitize sender/subject to prevent Slack mrkdwn injection
                    safe_sender = sender.replace("`", "'").replace("*", "").replace("_", "")
                    safe_subject = subject.replace("`", "'").replace("*", "").replace("_", "")

                    if tx_ids:
                        tx_list = ", ".join(tx_ids[:20])
                        if len(tx_ids) > 20:
                            tx_list += f" ... and {len(tx_ids) - 20} more"
                        text = (
                            f"*Email abuse report processed*\n"
                            f"From: {safe_sender}\n"
                            f"Subject: {safe_subject}\n"
                            f"TX IDs found: {len(tx_ids)} "
                            f"(enqueued: {enqueued})\n"
                            f"```{tx_list}```"
                        )
                    else:
                        text = (
                            f":warning: *Email abuse report — no TX IDs found*\n"
                            f"From: {safe_sender}\n"
                            f"Subject: {safe_subject}\n"
                            f"_Check email manually or update extraction patterns_"
                        )

                    await self.notifier.slack._client.post(
                        "https://slack.com/api/chat.postMessage",
                        json={
                            "channel": self.notifier.slack.channel_id,
                            "text": text,
                        },
                    )
                except Exception:
                    logger.warning(
                        "email_intake_slack_notification_failed",
                        exc_info=True,
                    )

            # Mark as read if we successfully processed the email:
            # - No TX IDs found (nothing to do)
            # - Some TX IDs enqueued (new content to scan)
            # - All TX IDs already known/blocked (duplicates, safe to skip)
            # Only keep unread if TX IDs were found but NONE could be
            # enqueued AND none are already known (real DB failure).
            processed = enqueued + already_known
            if not tx_ids or processed > 0:
                await self._mark_as_read(token, msg_id)
            else:
                logger.warning(
                    "Skipping mark-as-read — TX IDs found but none enqueued or known",
                    extra={"message_id": msg_id, "tx_ids": len(tx_ids)},
                )

    # ------------------------------------------------------------------
    # Graph API helpers
    # ------------------------------------------------------------------

    async def _get_access_token(self) -> str | None:
        """Acquire an OAuth2 access token via client credentials flow."""
        url = _TOKEN_URL_TEMPLATE.format(tenant_id=self.tenant_id)
        try:
            resp = await self._client.post(
                url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "scope": "https://graph.microsoft.com/.default",
                },
            )
            if resp.status_code != 200:
                logger.error(
                    "Failed to acquire Graph API token",
                    extra={
                        "status": resp.status_code,
                        # Never log OAuth response bodies — may echo client_secret
                    },
                )
                return None
            return resp.json().get("access_token")
        except Exception:
            logger.exception("Error acquiring Graph API token")
            return None

    async def _fetch_unread_emails(self, token: str) -> list[dict]:
        """Fetch unread emails from the mailbox via Graph API."""
        url = f"{_GRAPH_BASE}/users/{self.mailbox}/messages"
        try:
            resp = await self._client.get(
                url,
                params={
                    "$filter": "isRead eq false",
                    "$orderby": "receivedDateTime desc",
                    "$top": "50",
                    "$select": "id,from,subject,body,receivedDateTime",
                },
                headers={"Authorization": f"Bearer {token}"},
            )
            if resp.status_code != 200:
                logger.error(
                    "Failed to fetch unread emails",
                    extra={
                        "status": resp.status_code,
                        "body": resp.text[:500],
                    },
                )
                return []
            return resp.json().get("value", [])
        except Exception:
            logger.exception("Error fetching unread emails")
            return []

    async def _mark_as_read(self, token: str, message_id: str) -> None:
        """Mark a message as read via Graph API PATCH."""
        url = f"{_GRAPH_BASE}/users/{self.mailbox}/messages/{message_id}"
        try:
            resp = await self._client.patch(
                url,
                json={"isRead": True},
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                },
            )
            if resp.status_code not in (200, 204):
                logger.error(
                    "Failed to mark email as read",
                    extra={
                        "message_id": message_id,
                        "status": resp.status_code,
                    },
                )
        except Exception:
            logger.exception(
                "Error marking email as read",
                extra={"message_id": message_id},
            )
