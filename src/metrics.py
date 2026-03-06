from __future__ import annotations

import threading
import time

from src.models import Verdict


class ScanMetrics:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.scans_total = 0
        self.scans_by_verdict: dict[str, int] = {
            "clean": 0,
            "suspicious": 0,
            "malicious": 0,
        }
        self.scans_skipped_not_html = 0
        self.cache_hits = 0
        self.cache_misses = 0
        self.blocks_sent = 0
        self.blocks_failed = 0
        self._total_scan_ms = 0
        self.start_time = time.time()
        # Backfill metrics
        self.backfill_files_scanned = 0
        self.backfill_malicious_found = 0
        self.backfill_last_sweep_at = 0
        self.backfill_sweeps_completed = 0

    def record_scan(self, verdict: Verdict, scan_ms: int) -> None:
        with self._lock:
            self.scans_total += 1
            if verdict.value in self.scans_by_verdict:
                self.scans_by_verdict[verdict.value] += 1
            self._total_scan_ms += scan_ms

    def record_skip(self) -> None:
        with self._lock:
            self.scans_skipped_not_html += 1

    def record_cache_hit(self) -> None:
        with self._lock:
            self.cache_hits += 1

    def record_cache_miss(self) -> None:
        with self._lock:
            self.cache_misses += 1

    def record_block(self, success: bool) -> None:
        with self._lock:
            if success:
                self.blocks_sent += 1
            else:
                self.blocks_failed += 1

    def record_backfill_sweep(self, stats: dict) -> None:
        with self._lock:
            self.backfill_files_scanned += stats.get("scanned", 0)
            self.backfill_files_scanned += stats.get("skipped_not_html", 0)
            self.backfill_malicious_found += stats.get("malicious", 0)
            self.backfill_last_sweep_at = int(time.time())
            self.backfill_sweeps_completed += 1

    def to_dict(self) -> dict:
        with self._lock:
            avg_scan_ms = (
                self._total_scan_ms / self.scans_total
                if self.scans_total > 0
                else 0
            )
            return {
                "scans_total": self.scans_total,
                "scans_by_verdict": dict(self.scans_by_verdict),
                "scans_skipped_not_html": self.scans_skipped_not_html,
                "cache_hits": self.cache_hits,
                "cache_misses": self.cache_misses,
                "blocks_sent": self.blocks_sent,
                "blocks_failed": self.blocks_failed,
                "avg_scan_ms": round(avg_scan_ms, 1),
                "queue_depth": 0,  # filled by caller
                "uptime_seconds": int(time.time() - self.start_time),
                "backfill_files_scanned": self.backfill_files_scanned,
                "backfill_malicious_found": self.backfill_malicious_found,
                "backfill_last_sweep_at": self.backfill_last_sweep_at,
                "backfill_sweeps_completed": self.backfill_sweeps_completed,
            }
