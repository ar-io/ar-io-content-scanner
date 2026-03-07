from __future__ import annotations

import logging
import sqlite3
import time
from dataclasses import dataclass

from src.models import AdminOverride, Verdict

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

            CREATE TABLE IF NOT EXISTS admin_overrides (
                content_hash TEXT PRIMARY KEY,
                tx_id TEXT NOT NULL,
                admin_verdict TEXT NOT NULL,
                original_verdict TEXT NOT NULL,
                original_rules TEXT,
                original_ml_score REAL,
                notes TEXT DEFAULT '',
                created_at INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_verdicts_verdict
                ON scan_verdicts(verdict, scanned_at);
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
        # Atomic: UPDATE with subquery selects and marks rows in one
        # statement, preventing TOCTOU races across connections.
        cursor = self.conn.execute(
            "UPDATE scan_queue SET status = 'processing' "
            "WHERE id IN ("
            "  SELECT id FROM scan_queue WHERE status = 'pending' "
            "  ORDER BY received_at LIMIT ?"
            ")",
            (batch_size,),
        )
        if cursor.rowcount == 0:
            return []
        rows = self.conn.execute(
            "SELECT id, tx_id, content_hash, content_type, data_size, received_at "
            "FROM scan_queue WHERE status = 'processing' "
            "ORDER BY received_at LIMIT ?",
            (batch_size,),
        ).fetchall()
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

    def reset_failed(self, max_age_seconds: int = 600) -> int:
        """Reset failed items to pending for retry.

        Only resets items received within max_age_seconds to limit retries.
        Older failed items are left for purge_old to clean up.
        """
        cutoff = int(time.time()) - max_age_seconds
        cursor = self.conn.execute(
            "UPDATE scan_queue SET status = 'pending' "
            "WHERE status = 'failed' AND received_at > ?",
            (cutoff,),
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

    # --- Admin override methods ---

    def save_override(
        self,
        content_hash: str,
        tx_id: str,
        admin_verdict: str,
        original_verdict: str,
        original_rules: str,
        original_ml_score: float | None,
        notes: str,
    ) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO admin_overrides "
            "(content_hash, tx_id, admin_verdict, original_verdict, "
            "original_rules, original_ml_score, notes, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                content_hash,
                tx_id,
                admin_verdict,
                original_verdict,
                original_rules,
                original_ml_score,
                notes,
                int(time.time()),
            ),
        )
        self.conn.commit()

    def get_override(self, content_hash: str) -> AdminOverride | None:
        row = self.conn.execute(
            "SELECT content_hash, tx_id, admin_verdict, original_verdict, "
            "original_rules, original_ml_score, notes, created_at "
            "FROM admin_overrides WHERE content_hash = ?",
            (content_hash,),
        ).fetchone()
        if row is None:
            return None
        return AdminOverride(
            content_hash=row[0],
            tx_id=row[1],
            admin_verdict=row[2],
            original_verdict=row[3],
            original_rules=row[4],
            original_ml_score=row[5],
            notes=row[6],
            created_at=row[7],
        )

    def update_verdict(self, content_hash: str, new_verdict: Verdict) -> None:
        self.conn.execute(
            "UPDATE scan_verdicts SET verdict = ? WHERE content_hash = ?",
            (new_verdict.value, content_hash),
        )
        self.conn.commit()

    # --- Admin query methods ---

    def get_recent_detections(self, limit: int = 10) -> list[dict]:
        rows = self.conn.execute(
            "SELECT v.content_hash, v.tx_id, v.verdict, v.matched_rules, "
            "v.ml_score, v.scanned_at, v.scanner_version, "
            "o.admin_verdict "
            "FROM scan_verdicts v "
            "LEFT JOIN admin_overrides o ON v.content_hash = o.content_hash "
            "WHERE v.verdict IN ('malicious', 'suspicious') "
            "ORDER BY v.scanned_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [
            {
                "content_hash": r[0],
                "tx_id": r[1],
                "verdict": r[2],
                "matched_rules": r[3],
                "ml_score": r[4],
                "scanned_at": r[5],
                "scanner_version": r[6],
                "admin_status": r[7],
            }
            for r in rows
        ]

    def list_review_items(
        self,
        query: str = "",
        verdict_filter: str = "all",
        status_filter: str = "pending",
        sort: str = "newest",
        page: int = 1,
        per_page: int = 25,
    ) -> tuple[list[dict], int]:
        conditions = ["v.verdict IN ('malicious', 'suspicious')"]
        params: list = []

        if query:
            conditions.append(
                "(v.tx_id LIKE ? OR v.content_hash LIKE ?)"
            )
            like = f"%{query}%"
            params.extend([like, like])

        if verdict_filter in ("malicious", "suspicious"):
            conditions.append("v.verdict = ?")
            params.append(verdict_filter)

        if status_filter == "pending":
            conditions.append("o.content_hash IS NULL")
        elif status_filter == "confirmed":
            conditions.append("o.admin_verdict = 'confirmed_malicious'")
        elif status_filter == "dismissed":
            conditions.append("o.admin_verdict = 'confirmed_clean'")

        where = " AND ".join(conditions)

        order = "v.scanned_at DESC"
        if sort == "oldest":
            order = "v.scanned_at ASC"
        elif sort == "ml_score_desc":
            order = "v.ml_score DESC"

        count_row = self.conn.execute(
            f"SELECT COUNT(*) FROM scan_verdicts v "
            f"LEFT JOIN admin_overrides o ON v.content_hash = o.content_hash "
            f"WHERE {where}",
            params,
        ).fetchone()
        total = count_row[0] if count_row else 0

        offset = (page - 1) * per_page
        rows = self.conn.execute(
            f"SELECT v.content_hash, v.tx_id, v.verdict, v.matched_rules, "
            f"v.ml_score, v.scanned_at, v.scanner_version, "
            f"o.admin_verdict, o.notes "
            f"FROM scan_verdicts v "
            f"LEFT JOIN admin_overrides o ON v.content_hash = o.content_hash "
            f"WHERE {where} "
            f"ORDER BY {order} LIMIT ? OFFSET ?",
            params + [per_page, offset],
        ).fetchall()

        items = [
            {
                "content_hash": r[0],
                "tx_id": r[1],
                "verdict": r[2],
                "matched_rules": r[3],
                "ml_score": r[4],
                "scanned_at": r[5],
                "scanner_version": r[6],
                "admin_override": r[7],
                "admin_notes": r[8],
            }
            for r in rows
        ]
        return items, total

    def list_history(
        self,
        query: str = "",
        verdict_filter: str = "all",
        source_filter: str = "all",
        period: str = "all",
        page: int = 1,
        per_page: int = 25,
    ) -> tuple[list[dict], int]:
        conditions: list[str] = []
        params: list = []

        if query:
            conditions.append(
                "(v.tx_id LIKE ? OR v.content_hash LIKE ?)"
            )
            like = f"%{query}%"
            params.extend([like, like])

        if verdict_filter != "all":
            conditions.append("v.verdict = ?")
            params.append(verdict_filter)

        if source_filter == "webhook":
            conditions.append("v.tx_id != 'backfill'")
        elif source_filter == "backfill":
            conditions.append("v.tx_id = 'backfill'")

        if period != "all":
            seconds = {"24h": 86400, "7d": 604800, "30d": 2592000}.get(period)
            if seconds:
                conditions.append("v.scanned_at > ?")
                params.append(int(time.time()) - seconds)

        where = "WHERE " + " AND ".join(conditions) if conditions else ""

        count_row = self.conn.execute(
            f"SELECT COUNT(*) FROM scan_verdicts v "
            f"LEFT JOIN admin_overrides o ON v.content_hash = o.content_hash "
            f"{where}",
            params,
        ).fetchone()
        total = count_row[0] if count_row else 0

        offset = (page - 1) * per_page
        rows = self.conn.execute(
            f"SELECT v.content_hash, v.tx_id, v.verdict, v.matched_rules, "
            f"v.ml_score, v.scanned_at, v.scanner_version, "
            f"o.admin_verdict "
            f"FROM scan_verdicts v "
            f"LEFT JOIN admin_overrides o ON v.content_hash = o.content_hash "
            f"{where} "
            f"ORDER BY v.scanned_at DESC LIMIT ? OFFSET ?",
            params + [per_page, offset],
        ).fetchall()

        items = [
            {
                "content_hash": r[0],
                "tx_id": r[1],
                "verdict": r[2],
                "matched_rules": r[3],
                "ml_score": r[4],
                "scanned_at": r[5],
                "scanner_version": r[6],
                "admin_status": r[7],
            }
            for r in rows
        ]
        return items, total

    def get_db_stats(self) -> dict:
        verdicts = self.conn.execute(
            "SELECT verdict, COUNT(*) FROM scan_verdicts GROUP BY verdict"
        ).fetchall()
        verdicts_by_type = {r[0]: r[1] for r in verdicts}

        overrides = self.conn.execute(
            "SELECT admin_verdict, COUNT(*) FROM admin_overrides GROUP BY admin_verdict"
        ).fetchall()
        overrides_by_type = {r[0]: r[1] for r in overrides}

        total_verdicts = sum(verdicts_by_type.values())
        total_overrides = sum(overrides_by_type.values())

        import os

        db_size = 0
        try:
            db_size = os.path.getsize(self.db_path)
        except OSError:
            pass

        return {
            "total_verdicts": total_verdicts,
            "verdicts_by_type": verdicts_by_type,
            "total_overrides": total_overrides,
            "overrides_by_type": overrides_by_type,
            "queue_depth": self.queue_depth(),
            "db_size_bytes": db_size,
        }

    def list_overrides(self) -> list[dict]:
        rows = self.conn.execute(
            "SELECT content_hash, tx_id, admin_verdict, original_verdict, "
            "original_rules, original_ml_score, notes, created_at "
            "FROM admin_overrides ORDER BY created_at DESC"
        ).fetchall()
        return [
            {
                "content_hash": r[0],
                "tx_id": r[1],
                "admin_verdict": r[2],
                "original_verdict": r[3],
                "original_rules": r[4],
                "original_ml_score": r[5],
                "notes": r[6],
                "created_at": r[7],
            }
            for r in rows
        ]

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None
