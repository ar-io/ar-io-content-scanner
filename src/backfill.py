"""Proactive filesystem sweep of gateway contiguous data.

Walks the gateway's contiguous data directory, identifies HTML files,
and scans them through the same rule engine + ML pipeline used for
webhook-driven scans. Results are cached in the verdict DB so files
are only scanned once.

For malicious hits in enforce mode, queries the gateway's data.db
(read-only) to map content hashes back to TX IDs for blocking.
"""
from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import sqlite3
import time

from src.config import Settings
from src.db import ScannerDB
from src.gateway_client import GatewayClient
from src.metrics import ScanMetrics
from src.ml.features import parse_html
from src.models import Verdict
from src.rules.engine import RuleEngine
from src.scanner import looks_like_html

logger = logging.getLogger("scanner.backfill")


def b64url_encode(data: bytes) -> str:
    """Encode bytes to base64url without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(s: str) -> bytes:
    """Decode base64url string (without padding) to bytes."""
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


class GatewayDBReader:
    """Read-only access to the gateway's data.db for hash-to-TX-ID lookups."""

    def __init__(self, db_path: str):
        self._conn = sqlite3.connect(
            "file:{}?mode=ro".format(db_path),
            uri=True,
            check_same_thread=False,
        )
        self._conn.execute("PRAGMA busy_timeout=5000")

    def get_tx_ids_for_hash(self, data_hash_bytes: bytes) -> list:
        """Return base64url TX IDs that reference the given content hash."""
        rows = self._conn.execute(
            "SELECT id FROM contiguous_data_ids "
            "WHERE contiguous_data_hash = ?",
            (data_hash_bytes,),
        ).fetchall()
        return [b64url_encode(row[0]) for row in rows]

    def close(self) -> None:
        self._conn.close()


class BackfillScanner:
    def __init__(
        self,
        settings: Settings,
        db: ScannerDB,
        engine: RuleEngine,
        gateway: GatewayClient,
        metrics: ScanMetrics,
    ):
        self.settings = settings
        self.db = db
        self.engine = engine
        self.gateway = gateway
        self.metrics = metrics

    def _open_gateway_db(self) -> GatewayDBReader | None:
        path = self.settings.backfill_gateway_db_path
        if not path or not os.path.isfile(path):
            return None
        try:
            return GatewayDBReader(path)
        except Exception:
            logger.exception(
                "backfill_gateway_db_open_failed", extra={"path": path}
            )
            return None

    def _iter_files(self):
        """Walk contiguous data directory. Yields (filepath, hash_str) tuples."""
        data_dir = os.path.join(self.settings.backfill_data_path, "data")
        if not os.path.isdir(data_dir):
            logger.warning(
                "backfill_data_dir_not_found", extra={"path": data_dir}
            )
            return

        real_data_dir = os.path.realpath(data_dir)
        for bucket1 in sorted(os.listdir(data_dir)):
            bucket1_path = os.path.join(data_dir, bucket1)
            if not os.path.isdir(bucket1_path):
                continue
            for bucket2 in sorted(os.listdir(bucket1_path)):
                bucket2_path = os.path.join(bucket1_path, bucket2)
                if not os.path.isdir(bucket2_path):
                    continue
                for filename in sorted(os.listdir(bucket2_path)):
                    # Path traversal protection: reject filenames with
                    # path separators or parent directory references
                    if os.sep in filename or filename.startswith("."):
                        continue
                    filepath = os.path.join(bucket2_path, filename)
                    # Verify resolved path stays within the data directory
                    if not os.path.realpath(filepath).startswith(
                        real_data_dir
                    ):
                        continue
                    if os.path.isfile(filepath):
                        yield (filepath, filename)

    def _read_head(self, filepath: str) -> bytes | None:
        try:
            with open(filepath, "rb") as f:
                return f.read(512)
        except OSError:
            return None

    def _read_file(self, filepath: str) -> bytes | None:
        try:
            with open(filepath, "rb") as f:
                return f.read(self.settings.max_scan_bytes)
        except OSError:
            return None

    def _lookup_tx_ids(
        self, gateway_db: GatewayDBReader | None, hash_str: str
    ) -> list:
        """Look up TX IDs for a content hash via the gateway DB."""
        if gateway_db is None:
            return []
        try:
            hash_bytes = b64url_decode(hash_str)
            return gateway_db.get_tx_ids_for_hash(hash_bytes)
        except Exception:
            logger.warning(
                "backfill_txid_lookup_failed",
                extra={"content_hash": hash_str},
            )
            return []

    async def sweep(self) -> dict:
        """Run one full sweep of the contiguous data directory."""
        start_time = time.monotonic()

        stats = {
            "total_files": 0,
            "skipped_cached": 0,
            "skipped_not_html": 0,
            "scanned": 0,
            "malicious": 0,
            "suspicious": 0,
            "clean": 0,
            "blocked": 0,
            "errors": 0,
        }

        rate = self.settings.backfill_rate
        delay = 1.0 / rate if rate > 0 else 0.2

        gateway_db = self._open_gateway_db()

        logger.info(
            "backfill_sweep_started",
            extra={
                "data_path": self.settings.backfill_data_path,
                "rate": rate,
                "gateway_db_available": gateway_db is not None,
            },
        )

        loop = asyncio.get_running_loop()

        try:
            files = await loop.run_in_executor(None, lambda: list(self._iter_files()))
            stats["total_files"] = len(files)

            processed = 0
            total = stats["total_files"]
            # Log progress adaptively: every 5% or at least every 100 files
            log_interval = max(100, total // 20) if total > 0 else 100
            for filepath, hash_str in files:
                try:
                    await self._process_file(
                        filepath, hash_str, gateway_db, stats, loop
                    )
                    processed += 1
                    if processed % log_interval == 0 or processed == total:
                        elapsed = time.monotonic() - start_time
                        rate_actual = processed / elapsed if elapsed > 0 else 0
                        eta = (
                            int((total - processed) / rate_actual)
                            if rate_actual > 0
                            else 0
                        )
                        pct = round(processed / total * 100, 1) if total > 0 else 0
                        logger.info(
                            "backfill_progress",
                            extra={
                                "processed": processed,
                                "total": total,
                                "percent": pct,
                                "scanned": stats["scanned"],
                                "malicious": stats["malicious"],
                                "skipped_cached": stats["skipped_cached"],
                                "files_per_sec": round(rate_actual, 1),
                                "eta_seconds": eta,
                            },
                        )
                    await asyncio.sleep(delay)
                except asyncio.CancelledError:
                    raise
                except Exception:
                    logger.exception(
                        "backfill_file_error",
                        extra={"filepath": filepath},
                    )
                    stats["errors"] += 1
        finally:
            if gateway_db:
                gateway_db.close()

        elapsed = time.monotonic() - start_time
        stats["elapsed_seconds"] = int(elapsed)

        logger.info("backfill_sweep_complete", extra=stats)
        self.metrics.record_backfill_sweep(stats)

        # Persist backfill stats to DB so they survive restarts
        try:
            prev_scanned = int(self.db.get_state("backfill_files_scanned", "0"))
            prev_malicious = int(self.db.get_state("backfill_malicious_found", "0"))
            prev_sweeps = int(self.db.get_state("backfill_sweeps_completed", "0"))
            self.db.save_state(
                "backfill_files_scanned",
                str(prev_scanned + stats["scanned"] + stats["skipped_not_html"]),
            )
            self.db.save_state(
                "backfill_malicious_found",
                str(prev_malicious + stats["malicious"]),
            )
            self.db.save_state("backfill_sweeps_completed", str(prev_sweeps + 1))
            self.db.save_state("backfill_last_sweep_at", str(int(time.time())))
        except Exception:
            logger.warning("backfill_state_persist_failed")

        return stats

    async def _process_file(
        self,
        filepath: str,
        hash_str: str,
        gateway_db: GatewayDBReader | None,
        stats: dict,
        loop: asyncio.AbstractEventLoop,
    ) -> None:
        # 1. Already scanned?
        if self.db.has_verdict(hash_str):
            stats["skipped_cached"] += 1
            return

        # 1b. Admin override?
        override = self.db.get_override(hash_str)
        if override is not None:
            if override.admin_verdict == "confirmed_clean":
                self.db.save_verdict(
                    content_hash=hash_str,
                    tx_id="backfill",
                    verdict=Verdict.CLEAN,
                    matched_rules="[]",
                    ml_score=None,
                    scanner_version=self.settings.scanner_version,
                )
                stats["clean"] += 1
                return
            elif override.admin_verdict == "confirmed_malicious":
                tx_ids = self._lookup_tx_ids(gateway_db, hash_str)
                tx_id = tx_ids[0] if tx_ids else "backfill"
                self.db.save_verdict(
                    content_hash=hash_str,
                    tx_id=tx_id,
                    verdict=Verdict.MALICIOUS,
                    matched_rules=override.original_rules or "[]",
                    ml_score=None,
                    scanner_version=self.settings.scanner_version,
                )
                if self.settings.scanner_mode == "enforce" and tx_ids:
                    rules = json.loads(override.original_rules or "[]")
                    for tid in tx_ids:
                        success = await self.gateway.block_data(
                            tid, hash_str, rules
                        )
                        self.metrics.record_block(success)
                stats["malicious"] += 1
                return

        # 2. Content-sniff for HTML
        head = await loop.run_in_executor(None, self._read_head, filepath)
        if head is None:
            stats["errors"] += 1
            return

        if not looks_like_html(head):
            stats["skipped_not_html"] += 1
            try:
                self.db.save_verdict(
                    content_hash=hash_str,
                    tx_id="backfill",
                    verdict=Verdict.SKIPPED,
                    matched_rules="[]",
                    ml_score=None,
                    scanner_version=self.settings.scanner_version,
                )
            except Exception:
                pass
            return

        # 3. Read full file
        content = await loop.run_in_executor(
            None, self._read_file, filepath
        )
        if content is None:
            stats["errors"] += 1
            return

        # 4. Parse and scan
        html = content.decode("utf-8", errors="replace")
        soup = await loop.run_in_executor(None, parse_html, html)
        result = await loop.run_in_executor(
            None, self.engine.evaluate, html, soup
        )

        # 5. Look up TX IDs for malicious and suspicious hits
        tx_id = "backfill"
        tx_ids = []
        if result.verdict in (Verdict.MALICIOUS, Verdict.SUSPICIOUS):
            tx_ids = self._lookup_tx_ids(gateway_db, hash_str)
            if tx_ids:
                tx_id = tx_ids[0]

        # 6. Cache verdict
        try:
            self.db.save_verdict(
                content_hash=hash_str,
                tx_id=tx_id,
                verdict=result.verdict,
                matched_rules=json.dumps(result.matched_rules),
                ml_score=result.ml_score,
                scanner_version=self.settings.scanner_version,
            )
        except Exception:
            logger.warning(
                "backfill_verdict_cache_failed",
                extra={"content_hash": hash_str},
            )

        self.metrics.record_scan(result.verdict, result.scan_duration_ms)
        stats["scanned"] += 1

        # 7. Handle verdict
        if result.verdict == Verdict.MALICIOUS:
            stats["malicious"] += 1

            # Block all TX IDs in enforce mode
            file_blocked = 0
            if self.settings.scanner_mode == "enforce" and tx_ids:
                for tid in tx_ids:
                    success = await self.gateway.block_data(
                        tid, hash_str, result.matched_rules
                    )
                    self.metrics.record_block(success)
                    if success:
                        file_blocked += 1
                        stats["blocked"] += 1

            action = "dry_run"
            if self.settings.scanner_mode == "enforce":
                if not tx_ids:
                    action = "no_tx_ids"
                elif file_blocked > 0:
                    action = "blocked"
                else:
                    action = "block_failed"

            logger.warning(
                "backfill_malicious",
                extra={
                    "content_hash": hash_str,
                    "tx_id": tx_id,
                    "tx_ids_count": len(tx_ids),
                    "rules": result.matched_rules,
                    "ml_score": result.ml_score,
                    "action": action,
                },
            )

        elif result.verdict == Verdict.SUSPICIOUS:
            stats["suspicious"] += 1
            logger.warning(
                "backfill_suspicious",
                extra={
                    "content_hash": hash_str,
                    "ml_score": result.ml_score,
                },
            )

        else:
            stats["clean"] += 1
