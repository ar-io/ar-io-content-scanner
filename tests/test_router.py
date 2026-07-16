"""Tests for NotificationRouter alert classification.

The safety-critical property: only cleanly auto-blocked malicious content is
ever aggregated. Suspicious verdicts, dry-run (still-serving) malicious, and
failed blocks must always be delivered individually so a burst cannot bury an
alert that needs a human.
"""
from __future__ import annotations

from src.notifications.router import NotificationRouter


class _FakeSlack:
    def __init__(self) -> None:
        self.individual: list[dict] = []
        self.rollups: list[tuple[int, dict]] = []

    async def send_verdict_alert(self, **kw) -> bool:
        self.individual.append(kw)
        return True

    async def send_burst_rollup(self, count, breakdown) -> bool:
        self.rollups.append((count, dict(breakdown)))
        return True

    async def close(self) -> None:
        pass


def _router(threshold="suspicious", **kw):
    slack = _FakeSlack()
    return NotificationRouter(slack=slack, threshold=threshold, **kw), slack


async def _notify(r, verdict, action):
    await r.notify(
        verdict=verdict,
        tx_id="tx",
        content_hash="h",
        matched_rules=["drainer-loader"],
        ml_score=0.01,
        action_taken=action,
    )


async def test_suspicious_never_aggregated():
    r, slack = _router(aggregation_enabled=True, aggregation_burst_threshold=1)
    for _ in range(10):
        await _notify(r, "suspicious", "dry_run")
    assert len(slack.individual) == 10   # every one delivered
    await r.close()
    assert slack.rollups == []


async def test_malicious_dry_run_never_aggregated():
    r, slack = _router(aggregation_burst_threshold=1)
    for _ in range(10):
        await _notify(r, "malicious", "dry_run")   # still serving -> needs action
    assert len(slack.individual) == 10
    await r.close()
    assert slack.rollups == []


async def test_block_failed_never_aggregated():
    r, slack = _router(aggregation_burst_threshold=1)
    for _ in range(5):
        await _notify(r, "malicious", "block_failed")
    assert len(slack.individual) == 5
    await r.close()
    assert slack.rollups == []


async def test_blocked_malicious_aggregates_in_burst():
    r, slack = _router(aggregation_burst_threshold=2)
    for _ in range(6):
        await _notify(r, "malicious", "blocked")
    assert len(slack.individual) == 2         # first 2 individual
    await r.close()                           # flush pending
    assert slack.rollups == [(4, {"drainer-loader": 4})]


async def test_blocked_by_id_is_also_handled():
    r, slack = _router(aggregation_burst_threshold=1)
    for _ in range(4):
        await _notify(r, "malicious", "blocked_by_id")
    assert len(slack.individual) == 1
    await r.close()
    assert slack.rollups == [(3, {"drainer-loader": 3})]


async def test_aggregation_disabled_all_individual():
    r, slack = _router(aggregation_enabled=False)
    for _ in range(10):
        await _notify(r, "malicious", "blocked")
    assert len(slack.individual) == 10
    assert slack.rollups == []
    await r.close()


async def test_threshold_gating_unchanged():
    # threshold=malicious -> suspicious must not notify at all
    r, slack = _router(threshold="malicious")
    await _notify(r, "suspicious", "dry_run")
    assert slack.individual == []
    assert slack.rollups == []
    await r.close()
