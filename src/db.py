from __future__ import annotations

import logging
import sqlite3
import time
from dataclasses import dataclass

from src.models import Verdict

logger = logging.getLogger("scanner.db")


@dataclass
class CachedVerdict:
    content_hash: str
    tx_id: str
    verdict: Verdict
    matched_rules: str  # JSON array
    ml_score: float | None
    scanned_at: int
    scanner_version: str


@dataclass
class QueueRow:
    id: int
    tx_id: str
    content_hash: str | None
    content_type: str | None
    data_size: int | None
    received_at: int


class ScannerDB:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._conn: sqlite3.Connection | None = None

    def initialize(self) -> None:
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS scan_verdicts (
                content_hash TEXT PRIMARY KEY,
                tx_id TEXT NOT NULL,
                verdict TEXT NOT NULL,
                matched_rules TEXT,
                ml_score REAL,
                scanned_at INTEGER NOT NULL,
                scanner_version TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS scan_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tx_id TEXT NOT NULL,
                content_hash TEXT,
                content_type TEXT,
                data_size INTEGER,
                received_at INTEGER NOT NULL,
                status TEXT DEFAULT 'pending',
                UNIQUE(tx_id)
            );

            CREATE INDEX IF NOT EXISTS idx_queue_status
                ON scan_queue(status, received_at);
            """
        )
        self._conn.commit()
        logger.info("Database initialized", extra={"db_path": self.db_path})

    @property
    def conn(self) -> sqlite3.Connection:
        assert self._conn is not None, "Database not initialized"
        return self._conn

    def has_verdict(self, content_hash: str) -> bool:
        row = self.conn.execute(
            "SELECT 1 FROM scan_verdicts WHERE content_hash = ? LIMIT 1",
            (content_hash,),
        ).fetchone()
        return row is not None

    def get_verdict(self, content_hash: str) -> CachedVerdict | None:
        row = self.conn.execute(
            "SELECT content_hash, tx_id, verdict, matched_rules, ml_score, "
            "scanned_at, scanner_version FROM scan_verdicts WHERE content_hash = ?",
            (content_hash,),
        ).fetchone()
        if row is None:
            return None
        return CachedVerdict(
            content_hash=row[0],
            tx_id=row[1],
            verdict=Verdict(row[2]),
            matched_rules=row[3],
            ml_score=row[4],
            scanned_at=row[5],
            scanner_version=row[6],
        )

    def save_verdict(
        self,
        content_hash: str,
        tx_id: str,
        verdict: Verdict,
        matched_rules: str,
        ml_score: float | None,
        scanner_version: str,
    ) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO scan_verdicts "
            "(content_hash, tx_id, verdict, matched_rules, ml_score, "
            "scanned_at, scanner_version) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                content_hash,
                tx_id,
                verdict.value,
                matched_rules,
                ml_score,
                int(time.time()),
                scanner_version,
            ),
        )
        self.conn.commit()

    def enqueue(
        self,
        tx_id: str,
        content_hash: str | None,
        content_type: str | None,
        data_size: int | None,
    ) -> bool:
        try:
            cursor = self.conn.execute(
                "INSERT OR IGNORE INTO scan_queue "
                "(tx_id, content_hash, content_type, data_size, received_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (tx_id, content_hash, content_type, data_size, int(time.time())),
            )
            self.conn.commit()
            return cursor.rowcount > 0
        except sqlite3.Error:
            logger.exception("Failed to enqueue", extra={"tx_id": tx_id})
            return False

    def dequeue(self, batch_size: int = 1) -> list[QueueRow]:
        rows = self.conn.execute(
            "SELECT id, tx_id, content_hash, content_type, data_size, received_at "
            "FROM scan_queue WHERE status = 'pending' "
            "ORDER BY received_at LIMIT ?",
            (batch_size,),
        ).fetchall()
        if not rows:
            return []
        ids = [r[0] for r in rows]
        placeholders = ",".join("?" * len(ids))
        self.conn.execute(
            f"UPDATE scan_queue SET status = 'processing' WHERE id IN ({placeholders})",
            ids,
        )
        self.conn.commit()
        return [
            QueueRow(
                id=r[0],
                tx_id=r[1],
                content_hash=r[2],
                content_type=r[3],
                data_size=r[4],
                received_at=r[5],
            )
            for r in rows
        ]

    def mark_done(self, queue_id: int) -> None:
        self.conn.execute(
            "DELETE FROM scan_queue WHERE id = ?", (queue_id,)
        )
        self.conn.commit()

    def mark_failed(self, queue_id: int) -> None:
        self.conn.execute(
            "UPDATE scan_queue SET status = 'failed' WHERE id = ?", (queue_id,)
        )
        self.conn.commit()

    def reset_processing(self) -> int:
        cursor = self.conn.execute(
            "UPDATE scan_queue SET status = 'pending' WHERE status = 'processing'"
        )
        self.conn.commit()
        return cursor.rowcount

    def purge_old(self, max_age_seconds: int = 3600) -> int:
        cutoff = int(time.time()) - max_age_seconds
        cursor = self.conn.execute(
            "DELETE FROM scan_queue WHERE received_at < ?", (cutoff,)
        )
        self.conn.commit()
        return cursor.rowcount

    def queue_depth(self) -> int:
        row = self.conn.execute(
            "SELECT COUNT(*) FROM scan_queue WHERE status = 'pending'"
        ).fetchone()
        return row[0] if row else 0

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None
