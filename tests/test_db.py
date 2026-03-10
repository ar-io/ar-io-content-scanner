"""Tests for the scanner database layer."""

import os
import tempfile

import pytest

from src.db import ScannerDB
from src.models import Verdict


@pytest.fixture
def db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    database = ScannerDB(path)
    database.initialize()
    yield database
    database.close()
    os.unlink(path)


class TestVerdictCache:
    def test_save_and_retrieve(self, db):
        db.save_verdict(
            content_hash="abc123",
            tx_id="tx1",
            verdict=Verdict.MALICIOUS,
            matched_rules='["seed-phrase"]',
            ml_score=0.99,
            scanner_version="0.1.0",
        )
        cached = db.get_verdict("abc123")
        assert cached is not None
        assert cached.verdict == Verdict.MALICIOUS
        assert cached.ml_score == 0.99
        assert cached.tx_id == "tx1"

    def test_missing_verdict_returns_none(self, db):
        assert db.get_verdict("nonexistent") is None

    def test_upsert_replaces_existing(self, db):
        db.save_verdict("h1", "tx1", Verdict.CLEAN, "[]", None, "0.1.0")
        db.save_verdict("h1", "tx2", Verdict.MALICIOUS, '["r1"]', 0.5, "0.1.0")
        cached = db.get_verdict("h1")
        assert cached.verdict == Verdict.MALICIOUS
        assert cached.tx_id == "tx2"

    def test_save_verdict_preserves_safe_browsing_flag(self, db):
        """save_verdict should not clear safe_browsing_flagged on upsert."""
        db.save_verdict("h1", "tx1", Verdict.SUSPICIOUS, "[]", 0.9, "0.1.0")
        db.update_safe_browsing_status("h1", True)
        # Verify flag is set
        row = db.conn.execute(
            "SELECT safe_browsing_flagged FROM scan_verdicts WHERE content_hash = ?",
            ("h1",),
        ).fetchone()
        assert row[0] == 1
        # Re-save verdict (simulates re-scan or feed import)
        db.save_verdict("h1", "tx1", Verdict.MALICIOUS, '["r1"]', 0.9, "0.2.0")
        # Flag should still be set
        row = db.conn.execute(
            "SELECT safe_browsing_flagged FROM scan_verdicts WHERE content_hash = ?",
            ("h1",),
        ).fetchone()
        assert row[0] == 1


class TestQueue:
    def test_enqueue_and_dequeue(self, db):
        assert db.enqueue("tx1", "hash1", "text/html", 1024) is True
        items = db.dequeue(batch_size=1)
        assert len(items) == 1
        assert items[0].tx_id == "tx1"
        assert items[0].content_hash == "hash1"

    def test_dequeue_empty_returns_empty(self, db):
        assert db.dequeue() == []

    def test_duplicate_tx_ignored(self, db):
        db.enqueue("tx1", "h1", None, None)
        db.enqueue("tx1", "h1", None, None)  # duplicate
        items = db.dequeue(batch_size=10)
        assert len(items) == 1

    def test_mark_done_removes_item(self, db):
        db.enqueue("tx1", None, None, None)
        items = db.dequeue()
        db.mark_done(items[0].id)
        assert db.queue_depth() == 0

    def test_mark_failed(self, db):
        db.enqueue("tx1", None, None, None)
        items = db.dequeue()
        db.mark_failed(items[0].id)
        # Failed items should not appear in pending count
        assert db.queue_depth() == 0

    def test_reset_processing(self, db):
        db.enqueue("tx1", None, None, None)
        db.dequeue()  # moves to 'processing'
        assert db.queue_depth() == 0  # not pending
        reset = db.reset_processing()
        assert reset == 1
        assert db.queue_depth() == 1  # back to pending

    def test_queue_depth(self, db):
        db.enqueue("tx1", None, None, None)
        db.enqueue("tx2", None, None, None)
        assert db.queue_depth() == 2

    def test_purge_old(self, db):
        db.enqueue("tx1", None, None, None)
        # Use negative age so cutoff is in the future, purging everything
        purged = db.purge_old(max_age_seconds=-1)
        assert purged == 1
