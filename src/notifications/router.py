from __future__ import annotations

import logging

from src.notifications.aggregator import BurstAlertAggregator
from src.notifications.slack import SlackNotifier

logger = logging.getLogger("scanner.notifications")

# Actions that mean the content was cleanly handled with no human action left.
_HANDLED_ACTIONS = ("blocked", "blocked_by_id")


class NotificationRouter:
    """Dispatches notifications to enabled adapters.

    Currently supports Slack. Additional adapters (email, PagerDuty, etc.)
    can be added by registering them here.
    """

    def __init__(
        self,
        slack: SlackNotifier | None = None,
        threshold: str = "malicious",
        *,
        aggregation_enabled: bool = True,
        aggregation_burst_threshold: int = 5,
        aggregation_window_s: float = 60.0,
        aggregation_flush_interval_s: float = 60.0,
    ):
        self.slack = slack
        self.threshold = threshold  # "malicious" or "suspicious"
        # Burst rollup for auto-blocked (handled) alerts only. Never sees
        # actionable alerts — those are dispatched individually in notify().
        self._aggregator: BurstAlertAggregator | None = None
        if slack is not None and aggregation_enabled:
            self._aggregator = BurstAlertAggregator(
                send_individual=self._send_individual,
                send_rollup=self._send_rollup,
                burst_threshold=aggregation_burst_threshold,
                window_s=aggregation_window_s,
                flush_interval_s=aggregation_flush_interval_s,
            )

    def start(self) -> None:
        """Start the background rollup flusher (call once, inside the loop)."""
        if self._aggregator is not None:
            self._aggregator.start()

    async def _send_individual(self, alert: dict) -> None:
        if not self.slack:
            return
        try:
            await self.slack.send_verdict_alert(**alert)
        except Exception:
            logger.error(
                "notification_slack_error",
                extra={"tx_id": alert.get("tx_id")},
                exc_info=True,
            )

    async def _send_rollup(self, count: int, breakdown: dict) -> None:
        if not self.slack:
            return
        try:
            await self.slack.send_burst_rollup(count, breakdown)
        except Exception:
            logger.error("notification_rollup_error", exc_info=True)

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
        if not self.slack:
            return

        alert = {
            "verdict": verdict,
            "tx_id": tx_id,
            "content_hash": content_hash,
            "matched_rules": matched_rules,
            "ml_score": ml_score,
            "screenshot_path": screenshot_path,
            "action_taken": action_taken,
        }

        # Only cleanly auto-blocked malicious content is eligible for burst
        # aggregation — it is already handled and needs no operator action.
        # Suspicious verdicts, dry-run (still-serving) malicious, and failed
        # blocks are ALWAYS sent individually so a flood can never bury an
        # alert that requires a human.
        handled = verdict == "malicious" and action_taken in _HANDLED_ACTIONS
        if self._aggregator is not None and handled:
            try:
                await self._aggregator.submit(alert)
                return
            except Exception:
                logger.error(
                    "notification_aggregator_error",
                    extra={"tx_id": tx_id},
                    exc_info=True,
                )
                # fail-open: fall through to an immediate individual send

        await self._send_individual(alert)

    async def notify_domain_flagged(
        self,
        domain: str,
        threat_types: list[str],
        flagged: bool,
        culprits: list[dict] | None = None,
    ) -> None:
        """Dispatch a gateway-domain Safe Browsing alert.

        Always sent when Slack is configured — a flagged gateway domain is a
        critical, operator-level event regardless of the verdict notification
        threshold. Fail-open: adapter errors are logged but never raised.
        """
        if not self.slack:
            return
        try:
            await self.slack.send_domain_alert(
                domain=domain,
                threat_types=threat_types,
                flagged=flagged,
                culprits=culprits,
            )
        except Exception:
            logger.error(
                "notification_domain_slack_error",
                extra={"domain": domain},
                exc_info=True,
            )

    async def close(self) -> None:
        if self._aggregator is not None:
            await self._aggregator.close()  # flushes any pending rollup
        if self.slack:
            await self.slack.close()
