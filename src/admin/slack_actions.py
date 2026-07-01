from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
from urllib.parse import parse_qs

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

from src.admin.actions import classify_neutral, confirm_block, dismiss_false_positive
from src.notifications.slack import SlackNotifier

logger = logging.getLogger("scanner.slack_actions")


def _verify_slack_signature(
    signing_secret: str,
    timestamp: str,
    body: bytes,
    signature: str,
) -> bool:
    """Verify a Slack request signature.

    Slack signs requests using HMAC-SHA256 with the signing secret.
    See: https://api.slack.com/authentication/verifying-requests-from-slack
    """
    if not signing_secret or not timestamp or not signature:
        return False

    # Reject requests older than 5 minutes to prevent replay attacks
    try:
        ts = int(timestamp)
    except (ValueError, TypeError):
        return False

    if abs(time.time() - ts) > 300:
        return False

    sig_basestring = f"v0:{timestamp}:{body.decode('utf-8')}"
    expected = (
        "v0="
        + hmac.new(
            signing_secret.encode("utf-8"),
            sig_basestring.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
    )

    return hmac.compare_digest(expected, signature)


def build_slack_actions_router(app_state) -> APIRouter:
    """Build the Slack interactive actions router.

    Handles button clicks from Slack Block Kit messages sent by SlackNotifier.
    """
    _state = app_state
    settings = app_state.settings
    router = APIRouter(prefix="/api/slack")

    @router.post("/actions")
    async def handle_slack_action(request: Request):
        body = await request.body()

        # Verify Slack request signature
        timestamp = request.headers.get("X-Slack-Request-Timestamp", "")
        signature = request.headers.get("X-Slack-Signature", "")

        if not _verify_slack_signature(
            settings.slack_signing_secret,
            timestamp,
            body,
            signature,
        ):
            raise HTTPException(status_code=401, detail="Invalid signature")

        # Parse the URL-encoded payload
        try:
            parsed = parse_qs(body.decode("utf-8"))
            payload_str = parsed.get("payload", [""])[0]
            payload = json.loads(payload_str)
        except (json.JSONDecodeError, KeyError, IndexError):
            raise HTTPException(status_code=400, detail="Invalid payload")

        # Extract action details
        actions = payload.get("actions", [])
        if not actions:
            return JSONResponse(content={"ok": True})

        action = actions[0]
        action_id = action.get("action_id", "")

        try:
            value = json.loads(action.get("value", "{}"))
        except json.JSONDecodeError:
            raise HTTPException(status_code=400, detail="Invalid action value")

        content_hash = value.get("content_hash", "")
        tx_id = value.get("tx_id", "")

        if not content_hash:
            raise HTTPException(status_code=400, detail="Missing content_hash")

        db = _state.db
        gateway = _state.gateway

        # Route to the appropriate action handler
        if action_id == "confirm_block":
            result = await confirm_block(
                content_hash=content_hash,
                db=db,
                gateway=gateway,
                scanner_mode=settings.scanner_mode,
                notes="Confirmed via Slack",
            )
            status_emoji = "\u2705" if result.blocked else "\u26a0\ufe0f"
            status_text = f"{status_emoji} *Confirmed* by <@{_get_user_id(payload)}>"
            if result.blocked:
                status_text += " — content blocked"

        elif action_id == "dismiss_fp":
            result = await dismiss_false_positive(
                content_hash=content_hash,
                db=db,
                gateway=gateway,
                scanner_mode=settings.scanner_mode,
                notes="Dismissed via Slack",
            )
            status_text = f"\u274c *Dismissed* by <@{_get_user_id(payload)}>"
            if result.unblocked:
                status_text += " — content unblocked"

        elif action_id == "classify_neutral":
            result = await classify_neutral(
                content_hash=content_hash,
                db=db,
                gateway=gateway,
                scanner_mode=settings.scanner_mode,
                notes="Classified neutral via Slack",
            )
            status_text = f"\U0001f7f0 *Classified neutral* by <@{_get_user_id(payload)}>"

        else:
            logger.warning(
                "slack_unknown_action",
                extra={"action_id": action_id},
            )
            return JSONResponse(content={"ok": True})

        if not result.success:
            status_text = f"\u26a0\ufe0f Action failed: {result.message}"

        # Update the original Slack message to replace buttons with status
        await _update_message_with_status(
            payload=payload,
            status_text=status_text,
        )

        logger.info(
            "slack_action_handled",
            extra={
                "action_id": action_id,
                "content_hash": content_hash,
                "tx_id": tx_id,
                "user": _get_user_id(payload),
                "success": result.success,
            },
        )

        # Slack expects a 200 OK with empty body or acknowledgement
        return JSONResponse(content={"ok": True})

    return router


def _get_user_id(payload: dict) -> str:
    """Extract the Slack user ID from an interaction payload."""
    user = payload.get("user", {})
    return user.get("id", "unknown")


async def _update_message_with_status(
    payload: dict,
    status_text: str,
) -> None:
    """Replace the action buttons in the original message with a status line.

    Uses the response_url from the Slack payload for immediate in-place update
    without needing the bot token.
    """
    response_url = payload.get("response_url")
    if not response_url:
        return

    original_message = payload.get("message", {})
    original_blocks = original_message.get("blocks", [])

    # Replace the actions block with a context block showing the result
    updated_blocks = []
    for block in original_blocks:
        if block.get("type") == "actions":
            updated_blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": status_text},
            })
        else:
            updated_blocks.append(block)

    try:
        import httpx

        async with httpx.AsyncClient(timeout=httpx.Timeout(5.0)) as client:
            await client.post(
                response_url,
                json={
                    "replace_original": True,
                    "blocks": updated_blocks,
                    "text": status_text,
                },
            )
    except Exception:
        logger.warning("slack_message_update_failed", exc_info=True)
