"""Microsoft 365 email poller for abuse report intake.

Polls a Microsoft 365 mailbox via the Graph API for unread abuse reports,
extracts Arweave TX IDs, enqueues them for scanning, and marks emails as read.

Trusted senders (configurable via ``EMAIL_INTAKE_TRUSTED_SENDERS``) get
auto-scan + auto-block treatment. Emails from untrusted senders are still
scanned, but results are posted to Slack for manual review — no auto-blocking.
This prevents griefing via the public abuse@ address.

Uses OAuth2 client credentials flow (app-only, no user login). Requires an
Azure AD app registration with ``Mail.ReadWrite`` application permission.
"""
from __future__ import annotations

import asyncio
import fnmatch
import logging

import httpx

from src.config import Settings
from src.db import ScannerDB
from src.email.tx_extractor import extract_all
from src.gateway_client import GatewayClient
from src.notifications.router import NotificationRouter

logger = logging.getLogger("scanner.email")

# Well-known abuse reporters. Used as defaults when
# EMAIL_INTAKE_TRUSTED_SENDERS is not set.
DEFAULT_TRUSTED_SENDERS = (
    # Hosting providers
    "*@hetzner.com",
    "*@hetzner.de",
    "*@ovh.net",
    "*@ovhcloud.com",
    # Anti-phishing / brand protection
    "*@netcraft.com",
    "*@netcraft.co.uk",
    # Google
    "*@google.com",
    # Domain registrars
    "*@namecheap.com",
    "*@cloudflare.com",
    # Internal team
    "*@ar.io",
    "*@ardrive.io",
    "*@pds.inc",
)

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
        gateway: GatewayClient | None = None,
        notifier: NotificationRouter | None = None,
        arns_gateway_domains: tuple[str, ...] = (),
        trusted_senders: tuple[str, ...] = DEFAULT_TRUSTED_SENDERS,
    ):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.mailbox = mailbox
        self.poll_interval = poll_interval
        self.db = db
        self.gateway = gateway
        self.notifier = notifier
        self.arns_gateway_domains = arns_gateway_domains
        self.trusted_senders = tuple(p.lower() for p in trusted_senders)

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
    # Sender trust
    # ------------------------------------------------------------------

    def _is_trusted_sender(self, sender_email: str) -> bool:
        """Check if the sender matches any trusted sender pattern.

        Patterns support fnmatch-style wildcards: ``*@hetzner.com`` matches
        any address at hetzner.com, ``phil@pds.inc`` matches exactly.
        """
        addr = sender_email.lower().strip()
        return any(fnmatch.fnmatch(addr, pattern) for pattern in self.trusted_senders)

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
            body_obj = msg.get("body", {})
            body_content = body_obj.get("content", "")
            body_type = body_obj.get("contentType", "").lower()

            # Truncate to prevent memory/CPU issues with huge emails
            MAX_BODY = 1_000_000  # 1MB
            body_content = body_content[:MAX_BODY]

            if body_type == "text":
                text_body, html_body = body_content, ""
            else:
                text_body, html_body = body_content, body_content

            trusted = self._is_trusted_sender(sender)

            extraction = extract_all(
                text_body, html_body,
                arns_domains=self.arns_gateway_domains or None,
            )
            tx_ids = list(extraction.tx_ids)

            # Resolve ArNS names to TX IDs
            resolved_arns: list[tuple[str, str]] = []  # (name, tx_id)
            if extraction.arns_names and self.gateway:
                for name in extraction.arns_names:
                    try:
                        resolved_tx_id = await self._resolve_arns_name(name)
                        if resolved_tx_id:
                            resolved_arns.append((name, resolved_tx_id))
                            if resolved_tx_id not in tx_ids:
                                tx_ids.append(resolved_tx_id)
                        # Only auto-block ArNS names from trusted senders
                        if trusted:
                            await self.gateway.block_name(
                                name,
                                notes=f"Auto-blocked from abuse email: {subject}",
                            )
                    except Exception:
                        logger.warning(
                            "Failed to resolve/block ArNS name",
                            extra={"name": name},
                            exc_info=True,
                        )

            # Trusted senders: enqueue TX IDs for scanning (auto-block if
            # rules match in enforce mode).
            # Untrusted senders: do NOT enqueue — post to Slack for manual
            # review only. This prevents griefing via the abuse@ address.
            enqueued = 0
            already_known = 0
            if trusted:
                for tx_id in tx_ids:
                    if self.db.enqueue(
                        tx_id=tx_id,
                        content_hash=None,
                        content_type=None,
                        data_size=None,
                    ):
                        enqueued += 1
                    else:
                        existing = self.db.get_verdict(tx_id)
                        if existing is not None:
                            already_known += 1

            logger.info(
                "Processed abuse email",
                extra={
                    "sender": sender,
                    "subject": subject,
                    "trusted": trusted,
                    "tx_ids_found": len(tx_ids),
                    "arns_names_found": len(extraction.arns_names),
                    "arns_resolved": len(resolved_arns),
                    "tx_ids_enqueued": enqueued,
                    "message_id": msg_id,
                },
            )

            # Slack notification
            if self.notifier and hasattr(self.notifier, 'slack') and self.notifier.slack:
                try:
                    safe_sender = sender.replace("`", "'").replace("*", "").replace("_", "")
                    safe_subject = subject.replace("`", "'").replace("*", "").replace("_", "")
                    trust_badge = ":white_check_mark: Trusted" if trusted else ":warning: Untrusted"

                    if tx_ids:
                        tx_list = ", ".join(tx_ids[:20])
                        if len(tx_ids) > 20:
                            tx_list += f" ... and {len(tx_ids) - 20} more"
                        arns_info = ""
                        if resolved_arns:
                            arns_info = "\nArNS names: " + ", ".join(
                                f"{name} → `{tid[:8]}…`"
                                for name, tid in resolved_arns
                            )
                        if trusted:
                            text = (
                                f":white_check_mark: *Abuse report — auto-processing*\n"
                                f"From: {safe_sender} ({trust_badge})\n"
                                f"Subject: {safe_subject}\n"
                                f"TX IDs: {len(tx_ids)} "
                                f"(enqueued: {enqueued}){arns_info}\n"
                                f"```{tx_list}```"
                            )
                        else:
                            text = (
                                f":warning: *Abuse report — manual review required*\n"
                                f"From: {safe_sender} ({trust_badge})\n"
                                f"Subject: {safe_subject}\n"
                                f"TX IDs found: {len(tx_ids)} "
                                f"— *not auto-blocked* (untrusted sender){arns_info}\n"
                                f"```{tx_list}```\n"
                                f"_Use `/admin` dashboard or reply buttons to block._"
                            )
                    else:
                        body_preview = text_body[:500].replace("`", "'").replace("*", "").replace("_", "")
                        text = (
                            f":warning: *Abuse report — no TX IDs found*\n"
                            f"From: {safe_sender} ({trust_badge})\n"
                            f"Subject: {safe_subject}\n"
                            f"_Check email manually or update extraction patterns_\n"
                            f"```{body_preview}```"
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

            # Mark as read
            processed = enqueued + already_known
            if not tx_ids or processed > 0 or not trusted:
                await self._mark_as_read(token, msg_id)
            else:
                logger.warning(
                    "Skipping mark-as-read — TX IDs found but none enqueued or known",
                    extra={"message_id": msg_id, "tx_ids": len(tx_ids)},
                )

    # ------------------------------------------------------------------
    # ArNS resolution
    # ------------------------------------------------------------------

    async def _resolve_arns_name(self, name: str) -> str | None:
        """Resolve an ArNS name to a TX ID via the gateway.

        Calls GET /ar-io/resolver/{name} on the gateway. Returns the TX ID
        if the name resolves, None otherwise.
        """
        if not self.gateway:
            return None
        try:
            resp = await self.gateway._client.get(
                f"/ar-io/resolver/{name}",
            )
            if resp.status_code != 200:
                logger.warning(
                    "ArNS name did not resolve",
                    extra={"name": name, "status": resp.status_code},
                )
                return None
            data = resp.json()
            # The resolver returns txId for the resolved content
            tx_id = data.get("txId") or data.get("processId")
            if tx_id:
                logger.info(
                    "Resolved ArNS name to TX ID",
                    extra={"name": name, "tx_id": tx_id},
                )
            return tx_id
        except Exception:
            logger.warning(
                "Error resolving ArNS name",
                extra={"name": name},
                exc_info=True,
            )
            return None

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
