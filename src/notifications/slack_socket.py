from __future__ import annotations

import asyncio
import logging

from slack_sdk.socket_mode import SocketModeClient
from slack_sdk.socket_mode.request import SocketModeRequest
from slack_sdk.socket_mode.response import SocketModeResponse
from slack_sdk.web import WebClient

from src.admin.slack_actions import handle_slack_interactivity

logger = logging.getLogger("scanner.slack_socket")


class SlackSocketListener:
    """Handle Slack interactivity over Socket Mode (an outbound WebSocket).

    Socket Mode dials OUT to Slack (``apps.connections.open`` -> ``wss://``), so
    there is **no inbound port and no public callback URL** — an alternative to
    exposing ``POST /api/slack/actions`` on the internet. Button clicks arrive
    over the connection and are dispatched to the same
    ``handle_slack_interactivity`` used by the HTTP endpoint.

    Enabled when ``SLACK_ENABLED=true`` and ``SLACK_APP_TOKEN`` (an
    ``xapp-`` app-level token with the ``connections:write`` scope) is set.
    """

    def __init__(self, app_token: str, bot_token: str, app_state) -> None:
        self._state = app_state
        self._loop: asyncio.AbstractEventLoop | None = None
        self._client = SocketModeClient(
            app_token=app_token,
            web_client=WebClient(token=bot_token or None),
        )
        self._client.socket_mode_request_listeners.append(self._on_request)

    async def start(self) -> None:
        """Open the outbound Socket Mode connection."""
        self._loop = asyncio.get_running_loop()
        # connect() calls apps.connections.open and starts the receive loop in a
        # background thread; run it off the event loop to avoid blocking startup.
        await self._loop.run_in_executor(None, self._client.connect)
        logger.info("slack_socket_connected")

    async def close(self) -> None:
        try:
            await asyncio.get_running_loop().run_in_executor(
                None, self._client.close
            )
        except Exception:
            logger.warning("slack_socket_close_error", exc_info=True)

    def _on_request(
        self, client: SocketModeClient, req: SocketModeRequest
    ) -> None:
        # Ack every envelope immediately — Slack retries un-acked ones.
        client.send_socket_mode_response(
            SocketModeResponse(envelope_id=req.envelope_id)
        )

        if req.type != "interactive":
            return
        payload = req.payload or {}
        if payload.get("type") != "block_actions":
            return
        if self._loop is None:
            return

        # This callback runs in the SDK's background thread. Dispatch the async
        # handler onto the main event loop (where the httpx/db clients live).
        future = asyncio.run_coroutine_threadsafe(
            handle_slack_interactivity(payload, self._state), self._loop
        )

        def _log_result(fut: "asyncio.Future") -> None:
            try:
                fut.result()
            except Exception:
                logger.error("slack_socket_dispatch_error", exc_info=True)

        future.add_done_callback(_log_result)
