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
        self.last_webhook_at: float = 0
        # Feed metrics
        self.feed_verdicts_imported = 0
        self.feed_verdicts_exported = 0
        self.feed_poll_errors = 0
        self.feed_on_demand_hits = 0
        self.feed_on_demand_misses = 0
        # Safe Browsing metrics
        self.safe_browsing_checks = 0
        self.safe_browsing_flagged = 0
        self.safe_browsing_escalations = 0
        self.safe_browsing_errors = 0
        self.safe_browsing_domain_flagged = False
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

    def record_webhook(self) -> None:
        with self._lock:
            self.last_webhook_at = time.time()

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

    def record_feed_import(self) -> None:
        with self._lock:
            self.feed_verdicts_imported += 1

    def record_feed_export(self, count: int = 1) -> None:
        with self._lock:
            self.feed_verdicts_exported += count

    def record_feed_poll_error(self) -> None:
        with self._lock:
            self.feed_poll_errors += 1

    def record_feed_on_demand(self, hit: bool) -> None:
        with self._lock:
            if hit:
                self.feed_on_demand_hits += 1
            else:
                self.feed_on_demand_misses += 1

    def record_safe_browsing_check(self, flagged: bool) -> None:
        with self._lock:
            self.safe_browsing_checks += 1
            if flagged:
                self.safe_browsing_flagged += 1
            self._sb_dirty = True

    def record_safe_browsing_escalation(self) -> None:
        with self._lock:
            self.safe_browsing_escalations += 1
            self._sb_dirty = True

    def record_safe_browsing_error(self) -> None:
        with self._lock:
            self.safe_browsing_errors += 1
            self._sb_dirty = True

    def get_safe_browsing_snapshot(self) -> dict:
        """Return current SB counters for persistence."""
        with self._lock:
            self._sb_dirty = False
            return {
                "checks": self.safe_browsing_checks,
                "flagged": self.safe_browsing_flagged,
                "escalations": self.safe_browsing_escalations,
                "errors": self.safe_browsing_errors,
            }

    @property
    def sb_dirty(self) -> bool:
        return getattr(self, "_sb_dirty", False)

    def set_safe_browsing_domain_flagged(self, flagged: bool) -> None:
        with self._lock:
            self.safe_browsing_domain_flagged = flagged

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
                "last_webhook_at": int(self.last_webhook_at),
                "backfill_files_scanned": self.backfill_files_scanned,
                "backfill_malicious_found": self.backfill_malicious_found,
                "backfill_last_sweep_at": self.backfill_last_sweep_at,
                "backfill_sweeps_completed": self.backfill_sweeps_completed,
                "feed_verdicts_imported": self.feed_verdicts_imported,
                "feed_verdicts_exported": self.feed_verdicts_exported,
                "feed_poll_errors": self.feed_poll_errors,
                "feed_on_demand_hits": self.feed_on_demand_hits,
                "feed_on_demand_misses": self.feed_on_demand_misses,
                "safe_browsing_checks": self.safe_browsing_checks,
                "safe_browsing_flagged": self.safe_browsing_flagged,
                "safe_browsing_escalations": self.safe_browsing_escalations,
                "safe_browsing_errors": self.safe_browsing_errors,
                "safe_browsing_domain_flagged": self.safe_browsing_domain_flagged,
            }

    def to_prometheus(self, queue_depth: int = 0) -> str:
        with self._lock:
            lines = []
            lines.append("# HELP scanner_scans_total Total scans performed")
            lines.append("# TYPE scanner_scans_total counter")
            lines.append(f"scanner_scans_total {self.scans_total}")
            lines.append("# HELP scanner_scans_by_verdict Scans by verdict")
            lines.append("# TYPE scanner_scans_by_verdict counter")
            for verdict, count in self.scans_by_verdict.items():
                lines.append(
                    f'scanner_scans_by_verdict{{verdict="{verdict}"}} {count}'
                )
            lines.append("# HELP scanner_scans_skipped Non-HTML skips")
            lines.append("# TYPE scanner_scans_skipped counter")
            lines.append(f"scanner_scans_skipped {self.scans_skipped_not_html}")
            lines.append("# HELP scanner_cache_hits Cache hit count")
            lines.append("# TYPE scanner_cache_hits counter")
            lines.append(f"scanner_cache_hits {self.cache_hits}")
            lines.append("# HELP scanner_cache_misses Cache miss count")
            lines.append("# TYPE scanner_cache_misses counter")
            lines.append(f"scanner_cache_misses {self.cache_misses}")
            lines.append("# HELP scanner_blocks_sent Successful blocks")
            lines.append("# TYPE scanner_blocks_sent counter")
            lines.append(f"scanner_blocks_sent {self.blocks_sent}")
            lines.append("# HELP scanner_blocks_failed Failed blocks")
            lines.append("# TYPE scanner_blocks_failed counter")
            lines.append(f"scanner_blocks_failed {self.blocks_failed}")
            avg = (
                round(self._total_scan_ms / self.scans_total, 1)
                if self.scans_total > 0
                else 0
            )
            lines.append(
                "# HELP scanner_avg_scan_ms Average scan duration in ms"
            )
            lines.append("# TYPE scanner_avg_scan_ms gauge")
            lines.append(f"scanner_avg_scan_ms {avg}")
            lines.append("# HELP scanner_queue_depth Pending queue items")
            lines.append("# TYPE scanner_queue_depth gauge")
            lines.append(f"scanner_queue_depth {queue_depth}")
            lines.append(
                "# HELP scanner_uptime_seconds Seconds since start"
            )
            lines.append("# TYPE scanner_uptime_seconds gauge")
            lines.append(
                f"scanner_uptime_seconds {int(time.time() - self.start_time)}"
            )
            lines.append(
                "# HELP scanner_last_webhook_at "
                "Unix timestamp of last webhook received"
            )
            lines.append("# TYPE scanner_last_webhook_at gauge")
            lines.append(
                f"scanner_last_webhook_at {int(self.last_webhook_at)}"
            )
            lines.append(
                "# HELP scanner_backfill_files_scanned "
                "Total backfill files processed"
            )
            lines.append("# TYPE scanner_backfill_files_scanned counter")
            lines.append(
                f"scanner_backfill_files_scanned {self.backfill_files_scanned}"
            )
            lines.append(
                "# HELP scanner_backfill_malicious_found "
                "Malicious files found by backfill"
            )
            lines.append("# TYPE scanner_backfill_malicious_found counter")
            lines.append(
                f"scanner_backfill_malicious_found "
                f"{self.backfill_malicious_found}"
            )
            lines.append(
                "# HELP scanner_feed_verdicts_imported "
                "Verdicts imported from peers"
            )
            lines.append("# TYPE scanner_feed_verdicts_imported counter")
            lines.append(
                f"scanner_feed_verdicts_imported {self.feed_verdicts_imported}"
            )
            lines.append(
                "# HELP scanner_feed_verdicts_exported "
                "Verdicts served to peers"
            )
            lines.append("# TYPE scanner_feed_verdicts_exported counter")
            lines.append(
                f"scanner_feed_verdicts_exported {self.feed_verdicts_exported}"
            )
            lines.append(
                "# HELP scanner_feed_poll_errors Feed poll error count"
            )
            lines.append("# TYPE scanner_feed_poll_errors counter")
            lines.append(
                f"scanner_feed_poll_errors {self.feed_poll_errors}"
            )
            lines.append(
                "# HELP scanner_feed_on_demand_hits "
                "On-demand peer lookups that returned a verdict"
            )
            lines.append("# TYPE scanner_feed_on_demand_hits counter")
            lines.append(
                f"scanner_feed_on_demand_hits {self.feed_on_demand_hits}"
            )
            lines.append(
                "# HELP scanner_feed_on_demand_misses "
                "On-demand peer lookups with no result"
            )
            lines.append("# TYPE scanner_feed_on_demand_misses counter")
            lines.append(
                f"scanner_feed_on_demand_misses {self.feed_on_demand_misses}"
            )
            lines.append(
                "# HELP scanner_safe_browsing_checks "
                "Total Safe Browsing API checks"
            )
            lines.append("# TYPE scanner_safe_browsing_checks counter")
            lines.append(
                f"scanner_safe_browsing_checks {self.safe_browsing_checks}"
            )
            lines.append(
                "# HELP scanner_safe_browsing_flagged "
                "URLs flagged by Safe Browsing"
            )
            lines.append("# TYPE scanner_safe_browsing_flagged counter")
            lines.append(
                f"scanner_safe_browsing_flagged {self.safe_browsing_flagged}"
            )
            lines.append(
                "# HELP scanner_safe_browsing_escalations "
                "Suspicious verdicts escalated to malicious via Safe Browsing"
            )
            lines.append("# TYPE scanner_safe_browsing_escalations counter")
            lines.append(
                f"scanner_safe_browsing_escalations "
                f"{self.safe_browsing_escalations}"
            )
            lines.append(
                "# HELP scanner_safe_browsing_errors "
                "Safe Browsing API errors"
            )
            lines.append("# TYPE scanner_safe_browsing_errors counter")
            lines.append(
                f"scanner_safe_browsing_errors {self.safe_browsing_errors}"
            )
            lines.append(
                "# HELP scanner_safe_browsing_domain_flagged "
                "Whether the gateway domain is flagged by Safe Browsing"
            )
            lines.append("# TYPE scanner_safe_browsing_domain_flagged gauge")
            lines.append(
                f"scanner_safe_browsing_domain_flagged "
                f"{1 if self.safe_browsing_domain_flagged else 0}"
            )
            lines.append("")
            return "\n".join(lines)
