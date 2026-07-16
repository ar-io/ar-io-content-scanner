"""Tests for shared admin actions (confirm_block / dismiss).

Focus: an explicit admin confirmation must block the gateway regardless of
SCANNER_MODE. dry-run only suppresses *automatic* blocks from the scan
pipeline; a human clicking Block (Slack/dashboard) is authoritative, mirroring
POST /api/admin/block which blocks unconditionally.
"""
from __future__ import annotations

import pytest

from src.admin.actions import confirm_block
from src.db import ScannerDB
from src.models import Verdict


class _FakeGateway:
    def __init__(self) -> None:
        self.block_calls: list[tuple[str, str, tuple[str, ...]]] = []

    async def block_data(self, tx_id, content_hash, rules, notes=None) -> bool:
        self.block_calls.append((tx_id, content_hash, tuple(rules)))
        return True

    async def fetch_content(self, tx_id, max_bytes=None):
        return None  # skip training-data export


@pytest.fixture
def db(tmp_path):
    _db = ScannerDB(str(tmp_path / "scanner.db"))
    _db.initialize()
    return _db


async def test_confirm_block_blocks_in_dry_run(db, tmp_path):
    """The regression this fixes: Slack 'Block' recorded the override but the
    content kept serving because the gateway block was gated behind enforce."""
    db.save_verdict("h1", "tx1", Verdict.MALICIOUS, '["drainer-loader"]', 0.01, "0.1.0")
    gw = _FakeGateway()

    result = await confirm_block(
        "h1", db, gw,
        scanner_mode="dry-run",
        notes="Confirmed via Slack",
        training_data_dir=str(tmp_path / "training"),
    )

    assert result.success is True
    assert result.blocked is True
    assert gw.block_calls == [("tx1", "h1", ("drainer-loader",))]
    assert db.get_override("h1").admin_verdict == "confirmed_malicious"


async def test_confirm_block_blocks_in_enforce(db, tmp_path):
    db.save_verdict("h2", "tx2", Verdict.MALICIOUS, '["drainer-loader"]', 0.01, "0.1.0")
    gw = _FakeGateway()

    result = await confirm_block(
        "h2", db, gw,
        scanner_mode="enforce",
        training_data_dir=str(tmp_path / "training"),
    )

    assert result.blocked is True
    assert len(gw.block_calls) == 1


async def test_confirm_block_missing_verdict_is_safe(db, tmp_path):
    gw = _FakeGateway()
    result = await confirm_block(
        "nope", db, gw,
        scanner_mode="dry-run",
        training_data_dir=str(tmp_path / "training"),
    )
    assert result.success is False
    assert gw.block_calls == []
