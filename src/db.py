from __future__ import annotations

import logging
import os
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
    source: str = "local"


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
                scanner_version TEXT NOT NULL,
                source TEXT NOT NULL DEFAULT 'local'
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

            CREATE TABLE IF NOT EXISTS feed_sync_state (
                peer_url TEXT PRIMARY KEY,
                last_scanned_at INTEGER NOT NULL DEFAULT 0,
                last_content_hash TEXT NOT NULL DEFAULT '',
                last_sync_at INTEGER NOT NULL DEFAULT 0,
                imported_count INTEGER NOT NULL DEFAULT 0,
                last_error TEXT DEFAULT '',
                consecutive_errors INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS scanner_state (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            );
            """
        )
        self._conn.commit()

        # Migrations
        columns = {
            row[1]
            for row in self._conn.execute(
                "PRAGMA table_info(scan_verdicts)"
            ).fetchall()
        }
        if "source" not in columns:
            self._conn.execute(
                "ALTER TABLE scan_verdicts ADD COLUMN source TEXT NOT NULL DEFAULT 'local'"
            )
            self._conn.commit()
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_verdicts_source_scanned "
            "ON scan_verdicts(source, scanned_at)"
        )
        self._conn.commit()
        if "safe_browsing_flagged" not in columns:
            self._conn.execute(
                "ALTER TABLE scan_verdicts ADD COLUMN safe_browsing_flagged INTEGER"
            )
            self._conn.commit()
        if "blocked" not in columns:
            self._conn.execute(
                "ALTER TABLE scan_verdicts ADD COLUMN blocked INTEGER NOT NULL DEFAULT 0"
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
            "scanned_at, scanner_version, source "
            "FROM scan_verdicts WHERE content_hash = ?",
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
            source=row[7] if row[7] else "local",
        )

    def save_verdict(
        self,
        content_hash: str,
        tx_id: str,
        verdict: Verdict,
        matched_rules: str,
        ml_score: float | None,
        scanner_version: str,
        source: str = "local",
    ) -> None:
        # Use INSERT ... ON CONFLICT to preserve safe_browsing_flagged.
        # Plain INSERT OR REPLACE would delete and re-insert the row,
        # silently nulling columns not in the INSERT list.
        self.conn.execute(
            "INSERT INTO scan_verdicts "
            "(content_hash, tx_id, verdict, matched_rules, ml_score, "
            "scanned_at, scanner_version, source) VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(content_hash) DO UPDATE SET "
            "tx_id = excluded.tx_id, verdict = excluded.verdict, "
            "matched_rules = excluded.matched_rules, ml_score = excluded.ml_score, "
            "scanned_at = excluded.scanned_at, scanner_version = excluded.scanner_version, "
            "source = excluded.source",
            (
                content_hash,
                tx_id,
                verdict.value,
                matched_rules,
                ml_score,
                int(time.time()),
                scanner_version,
                source,
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
        # Use a unique tag per dequeue call so concurrent callers cannot
        # pick up each other's rows in the follow-up SELECT.
        tag = f"processing:{os.urandom(4).hex()}"
        cursor = self.conn.execute(
            "UPDATE scan_queue SET status = ? "
            "WHERE id IN ("
            "  SELECT id FROM scan_queue WHERE status = 'pending' "
            "  ORDER BY received_at LIMIT ?"
            ")",
            (tag, batch_size),
        )
        if cursor.rowcount == 0:
            return []
        rows = self.conn.execute(
            "SELECT id, tx_id, content_hash, content_type, data_size, received_at "
            "FROM scan_queue WHERE status = ? "
            "ORDER BY received_at LIMIT ?",
            (tag, batch_size),
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
            "UPDATE scan_queue SET status = 'pending' WHERE status LIKE 'processing%'"
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

    def delete_override(self, content_hash: str) -> bool:
        cursor = self.conn.execute(
            "DELETE FROM admin_overrides WHERE content_hash = ?",
            (content_hash,),
        )
        self.conn.commit()
        return cursor.rowcount > 0

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
            "o.admin_verdict, v.safe_browsing_flagged "
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
                "safe_browsing_flagged": bool(r[8]) if r[8] is not None else None,
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
        conditions: list[str] = []
        params: list = []

        if status_filter == "pending":
            conditions.append("v.verdict IN ('malicious', 'suspicious')")
            conditions.append("o.content_hash IS NULL")
        elif status_filter == "confirmed":
            conditions.append("o.admin_verdict = 'confirmed_malicious'")
        elif status_filter == "dismissed":
            conditions.append("o.admin_verdict = 'confirmed_clean'")
        else:
            # "all": show flagged items + any with overrides (including dismissed→CLEAN)
            conditions.append(
                "(v.verdict IN ('malicious', 'suspicious') OR o.content_hash IS NOT NULL)"
            )

        if query:
            conditions.append(
                "(v.tx_id LIKE ? OR v.content_hash LIKE ?)"
            )
            like = f"%{query}%"
            params.extend([like, like])

        if verdict_filter in ("malicious", "suspicious"):
            conditions.append("v.verdict = ?")
            params.append(verdict_filter)

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
            f"o.admin_verdict, o.notes, v.safe_browsing_flagged, v.blocked "
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
                "safe_browsing_flagged": bool(r[9]) if r[9] is not None else None,
                "blocked": bool(r[10]) if r[10] is not None else False,
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
        sort: str = "newest",
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

        if verdict_filter == "all":
            # Exclude skipped by default — they're cache markers, not real scans
            conditions.append("v.verdict != 'skipped'")
        elif verdict_filter != "all_including_skipped":
            conditions.append("v.verdict = ?")
            params.append(verdict_filter)

        if source_filter == "webhook":
            conditions.append("v.source = 'local' AND v.tx_id != 'backfill'")
        elif source_filter == "backfill":
            conditions.append("v.tx_id = 'backfill'")
        elif source_filter == "feed":
            conditions.append("v.source != 'local'")

        if period != "all":
            seconds = {"24h": 86400, "7d": 604800, "30d": 2592000}.get(period)
            if seconds:
                conditions.append("v.scanned_at > ?")
                params.append(int(time.time()) - seconds)

        where = "WHERE " + " AND ".join(conditions) if conditions else ""

        order = "v.scanned_at DESC"
        if sort == "oldest":
            order = "v.scanned_at ASC"
        elif sort == "ml_score_desc":
            order = "v.ml_score DESC"

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
            f"o.admin_verdict, v.source "
            f"FROM scan_verdicts v "
            f"LEFT JOIN admin_overrides o ON v.content_hash = o.content_hash "
            f"{where} "
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
                "admin_status": r[7],
                "source": r[8],
            }
            for r in rows
        ]
        return items, total

    # --- Key-value state persistence ---

    def save_state(self, key: str, value: str) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO scanner_state (key, value, updated_at) "
            "VALUES (?, ?, ?)",
            (key, value, int(time.time())),
        )
        self.conn.commit()

    def save_states_batch(self, states: dict[str, str]) -> None:
        """Save multiple key-value pairs in a single transaction."""
        now = int(time.time())
        for key, value in states.items():
            self.conn.execute(
                "INSERT OR REPLACE INTO scanner_state (key, value, updated_at) "
                "VALUES (?, ?, ?)",
                (key, value, now),
            )
        self.conn.commit()

    def get_state(self, key: str, default: str = "0") -> str:
        row = self.conn.execute(
            "SELECT value FROM scanner_state WHERE key = ?", (key,)
        ).fetchone()
        return row[0] if row else default

    def get_dashboard_counts(self) -> dict:
        """Persistent counts for the dashboard stat cards."""
        row = self.conn.execute(
            "SELECT "
            "  SUM(CASE WHEN verdict != 'skipped' THEN 1 ELSE 0 END), "
            "  SUM(CASE WHEN verdict = 'malicious' THEN 1 ELSE 0 END), "
            "  SUM(CASE WHEN verdict = 'suspicious' THEN 1 ELSE 0 END) "
            "FROM scan_verdicts"
        ).fetchone()
        scans_total = row[0] or 0
        malicious = row[1] or 0
        suspicious = row[2] or 0

        # Pending review = malicious/suspicious without an admin override
        pending_row = self.conn.execute(
            "SELECT COUNT(*) FROM scan_verdicts v "
            "LEFT JOIN admin_overrides o ON v.content_hash = o.content_hash "
            "WHERE v.verdict IN ('malicious', 'suspicious') "
            "AND o.content_hash IS NULL"
        ).fetchone()
        pending_review = pending_row[0] if pending_row else 0

        return {
            "scans_total": scans_total,
            "malicious": malicious,
            "suspicious": suspicious,
            "pending_review": pending_review,
        }

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

    # --- Verdict feed methods ---

    def get_verdict_for_feed(self, content_hash: str) -> dict | None:
        """Look up a single local verdict for the feed API.

        Returns None if not found or if it's a non-local/skipped verdict.
        """
        row = self.conn.execute(
            "SELECT v.content_hash, v.tx_id, v.verdict, v.matched_rules, "
            "v.ml_score, v.scanned_at, v.scanner_version, "
            "o.admin_verdict "
            "FROM scan_verdicts v "
            "LEFT JOIN admin_overrides o ON v.content_hash = o.content_hash "
            "WHERE v.content_hash = ? AND v.source = 'local' "
            "AND v.verdict != 'skipped'",
            (content_hash,),
        ).fetchone()
        if row is None:
            return None
        return {
            "content_hash": row[0],
            "tx_id": row[1],
            "verdict": row[2],
            "matched_rules": row[3],
            "ml_score": row[4],
            "scanned_at": row[5],
            "scanner_version": row[6],
            "admin_override": row[7],
        }

    def get_verdicts_feed(
        self,
        since: int = 0,
        after_hash: str = "",
        limit: int = 100,
    ) -> list[dict]:
        """Return local verdicts for the feed API, with cursor-based pagination.

        Only exports source='local' rows to prevent echo loops.
        Uses (scanned_at, content_hash) as a stable cursor.
        """
        if after_hash:
            rows = self.conn.execute(
                "SELECT v.content_hash, v.tx_id, v.verdict, v.matched_rules, "
                "v.ml_score, v.scanned_at, v.scanner_version, "
                "o.admin_verdict "
                "FROM scan_verdicts v "
                "LEFT JOIN admin_overrides o ON v.content_hash = o.content_hash "
                "WHERE v.source = 'local' AND v.verdict != 'skipped' "
                "AND (v.scanned_at > ? OR (v.scanned_at = ? AND v.content_hash > ?)) "
                "ORDER BY v.scanned_at ASC, v.content_hash ASC "
                "LIMIT ?",
                (since, since, after_hash, limit),
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT v.content_hash, v.tx_id, v.verdict, v.matched_rules, "
                "v.ml_score, v.scanned_at, v.scanner_version, "
                "o.admin_verdict "
                "FROM scan_verdicts v "
                "LEFT JOIN admin_overrides o ON v.content_hash = o.content_hash "
                "WHERE v.source = 'local' AND v.verdict != 'skipped' "
                "AND v.scanned_at >= ? "
                "ORDER BY v.scanned_at ASC, v.content_hash ASC "
                "LIMIT ?",
                (since, limit),
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
                "admin_override": r[7],
            }
            for r in rows
        ]

    def get_feed_sync_state(self, peer_url: str) -> dict | None:
        row = self.conn.execute(
            "SELECT peer_url, last_scanned_at, last_content_hash, "
            "last_sync_at, imported_count, last_error, consecutive_errors "
            "FROM feed_sync_state WHERE peer_url = ?",
            (peer_url,),
        ).fetchone()
        if row is None:
            return None
        return {
            "peer_url": row[0],
            "last_scanned_at": row[1],
            "last_content_hash": row[2],
            "last_sync_at": row[3],
            "imported_count": row[4],
            "last_error": row[5],
            "consecutive_errors": row[6],
        }

    def save_feed_sync_state(
        self,
        peer_url: str,
        last_scanned_at: int,
        last_content_hash: str,
        imported_count_delta: int = 0,
        error: str | None = None,
    ) -> None:
        now = int(time.time())
        if error is not None:
            self.conn.execute(
                "INSERT INTO feed_sync_state "
                "(peer_url, last_scanned_at, last_content_hash, last_sync_at, "
                "imported_count, last_error, consecutive_errors) "
                "VALUES (?, ?, ?, ?, 0, ?, 1) "
                "ON CONFLICT(peer_url) DO UPDATE SET "
                "last_sync_at = ?, last_error = ?, "
                "consecutive_errors = consecutive_errors + 1",
                (peer_url, 0, "", now, error, now, error),
            )
        else:
            self.conn.execute(
                "INSERT INTO feed_sync_state "
                "(peer_url, last_scanned_at, last_content_hash, last_sync_at, "
                "imported_count, last_error, consecutive_errors) "
                "VALUES (?, ?, ?, ?, ?, '', 0) "
                "ON CONFLICT(peer_url) DO UPDATE SET "
                "last_scanned_at = ?, last_content_hash = ?, last_sync_at = ?, "
                "imported_count = imported_count + ?, "
                "last_error = '', consecutive_errors = 0",
                (
                    peer_url, last_scanned_at, last_content_hash, now,
                    imported_count_delta,
                    last_scanned_at, last_content_hash, now,
                    imported_count_delta,
                ),
            )
        self.conn.commit()

    def list_feed_sync_states(self) -> list[dict]:
        rows = self.conn.execute(
            "SELECT peer_url, last_scanned_at, last_content_hash, "
            "last_sync_at, imported_count, last_error, consecutive_errors "
            "FROM feed_sync_state ORDER BY peer_url"
        ).fetchall()
        return [
            {
                "peer_url": r[0],
                "last_scanned_at": r[1],
                "last_content_hash": r[2],
                "last_sync_at": r[3],
                "imported_count": r[4],
                "last_error": r[5],
                "consecutive_errors": r[6],
            }
            for r in rows
        ]

    def get_feed_import_stats(self) -> dict:
        row = self.conn.execute(
            "SELECT COUNT(*) FROM scan_verdicts WHERE source != 'local'"
        ).fetchone()
        total = row[0] if row else 0

        by_source = self.conn.execute(
            "SELECT source, COUNT(*) FROM scan_verdicts "
            "WHERE source != 'local' GROUP BY source"
        ).fetchall()

        return {
            "total_imported": total,
            "by_source": {r[0]: r[1] for r in by_source},
        }

    # --- Safe Browsing methods ---

    def mark_blocked(self, content_hash: str) -> None:
        self.conn.execute(
            "UPDATE scan_verdicts SET blocked = 1 "
            "WHERE content_hash = ?",
            (content_hash,),
        )
        self.conn.commit()

    def mark_unblocked(self, content_hash: str) -> None:
        self.conn.execute(
            "UPDATE scan_verdicts SET blocked = 0 "
            "WHERE content_hash = ?",
            (content_hash,),
        )
        self.conn.commit()

    def update_safe_browsing_status(
        self, content_hash: str, flagged: bool
    ) -> None:
        self.conn.execute(
            "UPDATE scan_verdicts SET safe_browsing_flagged = ? "
            "WHERE content_hash = ?",
            (1 if flagged else 0, content_hash),
        )
        self.conn.commit()

    def get_recent_malicious_urls(self, limit: int = 50) -> list[dict]:
        """Get recent MALICIOUS/SUSPICIOUS verdicts with TX IDs for SB checking."""
        rows = self.conn.execute(
            "SELECT content_hash, tx_id, verdict, safe_browsing_flagged "
            "FROM scan_verdicts "
            "WHERE verdict IN ('malicious', 'suspicious') "
            "AND tx_id != 'backfill' "
            "ORDER BY scanned_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [
            {
                "content_hash": r[0],
                "tx_id": r[1],
                "verdict": r[2],
                "safe_browsing_flagged": r[3],
            }
            for r in rows
        ]

    def get_safe_browsing_stats(self) -> dict:
        """Get Safe Browsing status counts."""
        row = self.conn.execute(
            "SELECT "
            "  SUM(CASE WHEN safe_browsing_flagged = 1 THEN 1 ELSE 0 END), "
            "  SUM(CASE WHEN safe_browsing_flagged = 0 THEN 1 ELSE 0 END), "
            "  SUM(CASE WHEN safe_browsing_flagged IS NULL AND verdict IN ('malicious', 'suspicious') THEN 1 ELSE 0 END) "
            "FROM scan_verdicts"
        ).fetchone()
        return {
            "flagged": row[0] or 0,
            "clean": row[1] or 0,
            "unchecked": row[2] or 0,
        }

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None
