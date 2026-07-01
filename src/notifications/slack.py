from __future__ import annotations

import json
import logging
from pathlib import Path

import httpx

logger = logging.getLogger("scanner.slack")

SLACK_API_BASE = "https://slack.com/api"


class SlackNotifier:
    """Posts rich Slack notifications when malicious/suspicious content is detected.

    Uses Block Kit for structured messages with interactive buttons.
    Fail-open: Slack errors are logged but never block scanning.
    """

    def __init__(
        self,
        bot_token: str,
        channel_id: str,
        gateway_public_url: str = "",
    ):
        self.bot_token = bot_token
        self.channel_id = channel_id
        self.gateway_public_url = gateway_public_url.rstrip("/")
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(10.0),
            headers={
                "Authorization": f"Bearer {bot_token}",
            },
        )

    async def close(self) -> None:
        await self._client.aclose()

    async def _upload_screenshot(self, screenshot_path: str) -> str | None:
        """Upload a screenshot to Slack and return the permalink.

        Uses the files.getUploadURLExternal + files.completeUploadExternal
        flow (Slack's current file upload API).
        Returns the file ID on success, None on failure.
        """
        path = Path(screenshot_path)
        if not path.is_file():
            return None

        file_size = path.stat().st_size
        filename = path.name

        try:
            # Step 1: Get an upload URL
            resp = await self._client.post(
                f"{SLACK_API_BASE}/files.getUploadURLExternal",
                data={
                    "filename": filename,
                    "length": str(file_size),
                },
            )
            data = resp.json()
            if not data.get("ok"):
                logger.warning(
                    "slack_upload_url_failed",
                    extra={"error": data.get("error", "unknown")},
                )
                return None

            upload_url = data["upload_url"]
            file_id = data["file_id"]

            # Step 2: Upload file content
            with open(path, "rb") as f:
                upload_resp = await self._client.post(
                    upload_url,
                    files={"file": (filename, f, "image/jpeg")},
                )
            if upload_resp.status_code != 200:
                logger.warning(
                    "slack_file_upload_failed",
                    extra={"status": upload_resp.status_code},
                )
                return None

            # Step 3: Complete the upload and share to the channel
            complete_resp = await self._client.post(
                f"{SLACK_API_BASE}/files.completeUploadExternal",
                json={
                    "files": [{"id": file_id, "title": filename}],
                    "channel_id": self.channel_id,
                },
            )
            complete_data = complete_resp.json()
            if not complete_data.get("ok"):
                logger.warning(
                    "slack_upload_complete_failed",
                    extra={"error": complete_data.get("error", "unknown")},
                )
                return None

            return file_id

        except Exception:
            logger.warning("slack_screenshot_upload_error", exc_info=True)
            return None

    def _build_blocks(
        self,
        verdict: str,
        tx_id: str,
        content_hash: str,
        matched_rules: list[str],
        ml_score: float | None,
        action_taken: str | None = None,
    ) -> list[dict]:
        """Build Slack Block Kit blocks for a verdict alert."""
        if verdict == "malicious":
            header_text = "\U0001f6a8 Malicious Content Detected"
        else:
            header_text = "\u26a0\ufe0f Suspicious Content"

        # TX link
        if self.gateway_public_url:
            tx_link = f"<{self.gateway_public_url}/{tx_id}|{tx_id}>"
        else:
            tx_link = f"`{tx_id}`"

        # Rules display
        rules_text = ", ".join(f"`{r}`" for r in matched_rules) if matched_rules else "_none_"

        # ML score display
        ml_text = f"{ml_score:.3f}" if ml_score is not None else "_n/a_"

        # Action display
        action_text = action_taken or "_pending_"

        fields = [
            {"type": "mrkdwn", "text": f"*TX ID:*\n{tx_link}"},
            {"type": "mrkdwn", "text": f"*Verdict:*\n`{verdict}`"},
            {"type": "mrkdwn", "text": f"*Matched Rules:*\n{rules_text}"},
            {"type": "mrkdwn", "text": f"*ML Score:*\n{ml_text}"},
            {"type": "mrkdwn", "text": f"*Content Hash:*\n`{content_hash[:16]}...`"},
            {"type": "mrkdwn", "text": f"*Action:*\n{action_text}"},
        ]

        # Button value payload
        button_value = json.dumps({
            "content_hash": content_hash,
            "tx_id": tx_id,
        })

        blocks: list[dict] = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": header_text, "emoji": True},
            },
            {
                "type": "section",
                "fields": fields,
            },
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Confirm Block", "emoji": True},
                        "style": "danger",
                        "action_id": "confirm_block",
                        "value": button_value,
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Dismiss (FP)", "emoji": True},
                        "action_id": "dismiss_fp",
                        "value": button_value,
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Classify Neutral", "emoji": True},
                        "action_id": "classify_neutral",
                        "value": button_value,
                    },
                ],
            },
        ]

        return blocks

    async def send_verdict_alert(
        self,
        verdict: str,
        tx_id: str,
        content_hash: str,
        matched_rules: list[str],
        ml_score: float | None,
        screenshot_path: str | None = None,
        action_taken: str | None = None,
    ) -> bool:
        """Post a verdict alert to Slack. Returns True on success.

        Fail-open: errors are logged and False is returned, never raised.
        """
        try:
            # Upload screenshot first (if available) so it appears before the alert
            if screenshot_path:
                await self._upload_screenshot(screenshot_path)

            blocks = self._build_blocks(
                verdict=verdict,
                tx_id=tx_id,
                content_hash=content_hash,
                matched_rules=matched_rules,
                ml_score=ml_score,
                action_taken=action_taken,
            )

            # Fallback text for notifications/accessibility
            fallback = (
                f"{'Malicious' if verdict == 'malicious' else 'Suspicious'} "
                f"content detected: {tx_id}"
            )

            resp = await self._client.post(
                f"{SLACK_API_BASE}/chat.postMessage",
                json={
                    "channel": self.channel_id,
                    "text": fallback,
                    "blocks": blocks,
                },
            )

            data = resp.json()
            if not data.get("ok"):
                logger.error(
                    "slack_post_failed",
                    extra={
                        "error": data.get("error", "unknown"),
                        "tx_id": tx_id,
                    },
                )
                return False

            logger.info(
                "slack_alert_sent",
                extra={
                    "tx_id": tx_id,
                    "verdict": verdict,
                    "channel": self.channel_id,
                    "ts": data.get("ts"),
                },
            )
            return True

        except Exception:
            logger.error(
                "slack_send_error",
                extra={"tx_id": tx_id},
                exc_info=True,
            )
            return False

    async def update_message(
        self,
        channel: str,
        ts: str,
        text: str,
        blocks: list[dict] | None = None,
    ) -> bool:
        """Update an existing Slack message (e.g., replace buttons with status)."""
        try:
            payload: dict = {
                "channel": channel,
                "ts": ts,
                "text": text,
            }
            if blocks is not None:
                payload["blocks"] = blocks

            resp = await self._client.post(
                f"{SLACK_API_BASE}/chat.update",
                json=payload,
            )
            data = resp.json()
            if not data.get("ok"):
                logger.warning(
                    "slack_update_failed",
                    extra={"error": data.get("error", "unknown"), "ts": ts},
                )
                return False
            return True
        except Exception:
            logger.warning("slack_update_error", exc_info=True)
            return False
