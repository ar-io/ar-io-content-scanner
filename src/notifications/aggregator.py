from __future__ import annotations

import asyncio
import collections
import logging
import time
from typing import Awaitable, Callable

logger = logging.getLogger("scanner.notifications")


class BurstAlertAggregator:
    """Coalesces high-volume *handled* verdict alerts into periodic rollups.

    Auto-blocked malicious content is already dealt with, so one Slack message
    per item during a flood is pure noise. This sends each alert individually
    until more than ``burst_threshold`` arrive within ``window_s``; beyond that
    it coalesces them and a background task emits a single rollup summary every
    ``flush_interval_s`` (e.g. "98 malicious auto-blocked in the last minute").

    IMPORTANT — only alerts that need no human action should be routed here.
    Suspicious verdicts, dry-run (unblocked) malicious, and failed blocks must
    be sent individually and immediately by the caller; this class never sees
    them. That invariant is what keeps aggregation from hiding actionable state.

    Rollup counts are exact. Not thread-safe: single asyncio loop only.
    """

    def __init__(
        self,
        *,
        send_individual: Callable[[dict], Awaitable[None]],
        send_rollup: Callable[[int, dict], Awaitable[None]],
        burst_threshold: int = 5,
        window_s: float = 60.0,
        flush_interval_s: float = 60.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._send_individual = send_individual
        self._send_rollup = send_rollup
        self._burst_threshold = max(1, int(burst_threshold))
        self._window_s = float(window_s)
        self._flush_interval_s = float(flush_interval_s)
        self._clock = clock
        self._events: collections.deque[float] = collections.deque()
        self._pending: collections.Counter[str] = collections.Counter()
        self._pending_total = 0
        self._task: asyncio.Task | None = None

    def _prune(self, now: float) -> None:
        cutoff = now - self._window_s
        while self._events and self._events[0] < cutoff:
            self._events.popleft()

    async def submit(self, alert: dict) -> None:
        """Record a handled (auto-blocked) alert.

        Below the burst threshold the alert is sent individually right away (so
        the start of a wave is still visible); above it the alert is coalesced
        into the pending rollup.
        """
        now = self._clock()
        self._prune(now)
        self._events.append(now)
        if len(self._events) <= self._burst_threshold:
            await self._send_individual(alert)
            return
        rules = alert.get("matched_rules") or []
        key = ", ".join(rules) if rules else str(alert.get("verdict", "malicious"))
        self._pending[key] += 1
        self._pending_total += 1

    async def flush(self) -> None:
        """Emit the pending rollup, if any. Idempotent when nothing is pending."""
        if self._pending_total <= 0:
            return
        total = self._pending_total
        breakdown = dict(self._pending)
        self._pending.clear()
        self._pending_total = 0
        try:
            await self._send_rollup(total, breakdown)
        except Exception:
            logger.error("alert_rollup_send_failed", exc_info=True)

    async def _flush_loop(self) -> None:
        while True:
            await asyncio.sleep(self._flush_interval_s)
            await self.flush()

    def start(self) -> None:
        if self._task is None:
            self._task = asyncio.create_task(self._flush_loop())

    async def close(self) -> None:
        """Stop the flusher and emit any pending rollup.

        Flush happens after the task is fully cancelled (not inside the
        cancellation handler), so the final rollup can't be interrupted.
        """
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        await self.flush()
