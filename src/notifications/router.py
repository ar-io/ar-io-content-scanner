from __future__ import annotations

import logging

from src.notifications.slack import SlackNotifier

logger = logging.getLogger("scanner.notifications")


class NotificationRouter:
    """Dispatches notifications to enabled adapters.

    Currently supports Slack. Additional adapters (email, PagerDuty, etc.)
    can be added by registering them here.
    """

    def __init__(
        self,
        slack: SlackNotifier | None = None,
        threshold: str = "malicious",
    ):
        self.slack = slack
        self.threshold = threshold  # "malicious" or "suspicious"

    def _should_notify(self, verdict: str) -> bool:
        """Check if the verdict meets the notification threshold."""
        if self.threshold == "suspicious":
            return verdict in ("malicious", "suspicious")
        # Default: malicious only
        return verdict == "malicious"

    async def notify(
        self,
        verdict: str,
        tx_id: str,
        content_hash: str,
        matched_rules: list[str],
        ml_score: float | None,
        screenshot_path: str | None = None,
        action_taken: str | None = None,
    ) -> None:
        """Send notifications to all enabled adapters.

        Fail-open: adapter errors are logged but never raised.
        """
        if not self._should_notify(verdict):
            return

        if self.slack:
            try:
                await self.slack.send_verdict_alert(
                    verdict=verdict,
                    tx_id=tx_id,
                    content_hash=content_hash,
                    matched_rules=matched_rules,
                    ml_score=ml_score,
                    screenshot_path=screenshot_path,
                    action_taken=action_taken,
                )
            except Exception:
                logger.error(
                    "notification_slack_error",
                    extra={"tx_id": tx_id},
                    exc_info=True,
                )

    async def close(self) -> None:
        if self.slack:
            await self.slack.close()
