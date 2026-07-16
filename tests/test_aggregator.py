"""Tests for the burst-rollup alert aggregator.

Deterministic: an injected clock and recording callbacks, and flush() driven
directly so no real time passes.
"""
from __future__ import annotations

from src.notifications.aggregator import BurstAlertAggregator


class _Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t

    def advance(self, dt: float) -> None:
        self.t += dt


def _make(clock=None, burst_threshold=3, window_s=60.0, flush_interval_s=60.0):
    individual: list[dict] = []
    rollups: list[tuple[int, dict]] = []

    async def send_individual(alert):
        individual.append(alert)

    async def send_rollup(count, breakdown):
        rollups.append((count, dict(breakdown)))

    agg = BurstAlertAggregator(
        send_individual=send_individual,
        send_rollup=send_rollup,
        burst_threshold=burst_threshold,
        window_s=window_s,
        flush_interval_s=flush_interval_s,
        clock=clock or _Clock(),
    )
    return agg, individual, rollups


def _alert(rule="drainer-loader", tx="tx"):
    return {
        "verdict": "malicious",
        "tx_id": tx,
        "matched_rules": [rule],
        "action_taken": "blocked",
    }


async def test_below_threshold_all_individual_no_rollup():
    agg, ind, roll = _make(burst_threshold=3)
    for i in range(3):
        await agg.submit(_alert(tx=f"t{i}"))
    await agg.flush()
    assert len(ind) == 3
    assert roll == []


async def test_above_threshold_coalesces_exact_count():
    agg, ind, roll = _make(burst_threshold=3, window_s=60)
    for i in range(10):
        await agg.submit(_alert(tx=f"t{i}"))
    assert len(ind) == 3          # first 3 individual
    assert roll == []             # nothing flushed yet
    await agg.flush()
    assert roll == [(7, {"drainer-loader": 7})]   # remaining 7 coalesced
    await agg.flush()             # idempotent
    assert len(roll) == 1


async def test_rollup_breakdown_by_rule():
    agg, ind, roll = _make(burst_threshold=1, window_s=60)
    await agg.submit(_alert(rule="drainer-loader"))          # individual
    await agg.submit(_alert(rule="drainer-loader"))          # coalesced
    await agg.submit(_alert(rule="external-credential-form"))
    await agg.submit(_alert(rule="drainer-loader"))
    await agg.flush()
    assert roll == [(3, {"drainer-loader": 2, "external-credential-form": 1})]


async def test_window_prunes_and_resumes_individual():
    clock = _Clock()
    agg, ind, roll = _make(clock=clock, burst_threshold=2, window_s=10)
    await agg.submit(_alert(tx="a"))   # individual
    await agg.submit(_alert(tx="b"))   # individual
    await agg.submit(_alert(tx="c"))   # 3rd in window -> coalesced
    assert len(ind) == 2
    clock.advance(11)                  # window elapses; old events prune
    await agg.submit(_alert(tx="d"))   # count back under threshold -> individual
    assert len(ind) == 3
    await agg.flush()
    assert roll == [(1, {"drainer-loader": 1})]   # only 'c' was coalesced


async def test_flush_empty_is_noop():
    agg, ind, roll = _make()
    await agg.flush()
    assert roll == []


async def test_close_without_started_task_flushes_pending():
    agg, ind, roll = _make(burst_threshold=1)
    await agg.submit(_alert())   # individual
    await agg.submit(_alert())   # coalesced (pending)
    await agg.close()            # no task started -> must flush
    assert roll == [(1, {"drainer-loader": 1})]


async def test_start_then_close_flushes_on_shutdown():
    # Long flush interval so the loop never fires on its own; close() must
    # still flush the pending rollup via the cancellation path.
    agg, ind, roll = _make(burst_threshold=1, flush_interval_s=1000)
    agg.start()
    await agg.submit(_alert())   # individual
    await agg.submit(_alert())   # coalesced (pending)
    await agg.close()
    assert roll == [(1, {"drainer-loader": 1})]
