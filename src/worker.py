from __future__ import annotations

import asyncio
import logging

from src.backfill import BackfillScanner
from src.config import Settings
from src.db import ScannerDB
from src.feed.poller import FeedPoller
from src.gateway_client import GatewayClient
from src.metrics import ScanMetrics
from src.models import Verdict
from src.safe_browsing import SafeBrowsingClient
from src.scanner import Scanner

logger = logging.getLogger("scanner.worker")


class WorkerPool:
    def __init__(
        self,
        scanner: Scanner,
        db: ScannerDB,
        concurrency: int = 2,
        backfill: BackfillScanner | None = None,
        feed_poller: FeedPoller | None = None,
        safe_browsing: SafeBrowsingClient | None = None,
        gateway: GatewayClient | None = None,
        settings: Settings | None = None,
        metrics: ScanMetrics | None = None,
    ):
        self.scanner = scanner
        self.db = db
        self.concurrency = concurrency
        self.backfill = backfill
        self.feed_poller = feed_poller
        self.safe_browsing = safe_browsing
        self.gateway = gateway
        self.settings = settings
        self.metrics = metrics
        self._tasks: list[asyncio.Task] = []
        self._running = False

    async def start(self) -> None:
        # Reset any items stuck in 'processing' from a previous crash
        reset = self.db.reset_processing()
        if reset > 0:
            logger.info(
                "Reset stuck queue items",
                extra={"count": reset},
            )

        # Restore all persisted metrics from database
        if self.metrics:
            self.metrics.load_from_db(self.db)

        self._running = True

        for i in range(self.concurrency):
            task = asyncio.create_task(
                self._worker_loop(i), name=f"scan-worker-{i}"
            )
            self._tasks.append(task)

        # Periodic cleanup task
        self._tasks.append(
            asyncio.create_task(
                self._cleanup_loop(), name="queue-cleanup"
            )
        )

        if self.backfill is not None:
            self._tasks.append(
                asyncio.create_task(
                    self._backfill_loop(), name="backfill-sweep"
                )
            )

        if self.feed_poller is not None:
            self._tasks.append(
                asyncio.create_task(
                    self._feed_poll_loop(), name="feed-poll"
                )
            )

        self._tasks.append(
            asyncio.create_task(
                self._safe_browsing_monitor_loop(),
                name="safe-browsing-monitor",
            )
        )

        logger.info(
            "Worker pool started",
            extra={
                "concurrency": self.concurrency,
                "backfill": self.backfill is not None,
            },
        )

    async def stop(self) -> None:
        self._running = False
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()
        logger.info("Worker pool stopped")

    async def _worker_loop(self, worker_id: int) -> None:
        while self._running:
            try:
                items = self.db.dequeue(batch_size=1)
                if not items:
                    await asyncio.sleep(0.5)
                    continue

                item = items[0]
                try:
                    await self.scanner.process_queue_item(item)
                    self.db.mark_done(item.id)
                except Exception:
                    logger.exception(
                        "Scan failed",
                        extra={
                            "worker_id": worker_id,
                            "tx_id": item.tx_id,
                        },
                    )
                    self.db.mark_failed(item.id)
            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception(
                    "Worker error",
                    extra={"worker_id": worker_id},
                )
                await asyncio.sleep(1)

    async def _backfill_loop(self) -> None:
        # Let webhook workers initialize first
        await asyncio.sleep(5)

        while self._running:
            try:
                await self.backfill.sweep()

                interval = self.backfill.settings.backfill_interval_hours
                if interval <= 0:
                    logger.info("Backfill one-shot sweep complete")
                    break

                logger.info(
                    "Backfill sleeping",
                    extra={"next_sweep_hours": interval},
                )
                await asyncio.sleep(interval * 3600)
            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("Backfill sweep error")
                await asyncio.sleep(60)

    async def _feed_poll_loop(self) -> None:
        """Periodically poll peers for new verdicts."""
        await asyncio.sleep(10)  # let workers initialize first

        while self._running:
            try:
                await self.feed_poller.poll_all()
                await asyncio.sleep(
                    self.feed_poller.settings.verdict_feed_poll_interval
                )
            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("Feed poll error")
                await asyncio.sleep(60)

    async def _safe_browsing_monitor_loop(self) -> None:
        """Periodically check gateway domain + recent malicious URLs."""
        await asyncio.sleep(15)  # let workers initialize first

        gateway_url = (
            self.settings.gateway_public_url if self.settings else ""
        )
        if not gateway_url:
            logger.warning(
                "Safe Browsing monitor disabled: GATEWAY_PUBLIC_URL not set. "
                "Set it to enable periodic domain + URL monitoring."
            )
            return

        from urllib.parse import urlparse
        parsed = urlparse(gateway_url)
        domain = parsed.hostname or parsed.netloc

        logger.info(
            "Safe Browsing monitor started",
            extra={
                "domain": domain,
                "check_interval": self.settings.safe_browsing_check_interval,
            },
        )

        while self._running:
            try:
                # Check site-level domain status via Transparency Report
                domain_status = await self.safe_browsing.check_domain(domain)

                if self.metrics and not domain_status.error:
                    self.metrics.set_safe_browsing_domain_flagged(
                        domain_status.flagged,
                        threat_types=domain_status.threat_types,
                    )

                if domain_status.flagged:
                    logger.error(
                        "GATEWAY DOMAIN FLAGGED by Google Safe Browsing",
                        extra={
                            "domain": domain,
                            "threat_types": domain_status.threat_types,
                            "status_code": domain_status.status_code,
                        },
                    )

                # Check recent malicious content URLs via Lookup API
                # (requires SAFE_BROWSING_API_KEY)
                all_recent = self.db.get_recent_malicious_urls(limit=50)
                recent = [
                    item for item in all_recent if item["tx_id"]
                ]
                if recent and self.safe_browsing.api_key:
                    content_urls = [
                        f"{gateway_url}/{item['tx_id']}" for item in recent
                    ]
                    results = await self.safe_browsing.check_urls(content_urls)
                    for item, sb_result in zip(recent, results):
                        if self.metrics:
                            self.metrics.record_safe_browsing_check(
                                sb_result.flagged
                            )
                        self.db.update_safe_browsing_status(
                            item["content_hash"], sb_result.flagged
                        )
                        # Escalate SUSPICIOUS→MALICIOUS when Google corroborates
                        if (
                            sb_result.flagged
                            and item["verdict"] == "suspicious"
                        ):
                            self.db.update_verdict(
                                item["content_hash"], Verdict.MALICIOUS
                            )
                            if self.metrics:
                                self.metrics.record_safe_browsing_escalation()
                            logger.warning(
                                "safe_browsing_monitor_escalation",
                                extra={
                                    "content_hash": item["content_hash"],
                                    "tx_id": item["tx_id"],
                                },
                            )
                            # Block if in enforce mode
                            if (
                                self.settings
                                and self.settings.scanner_mode == "enforce"
                                and self.gateway
                            ):
                                success = await self.gateway.block_data(
                                    item["tx_id"],
                                    item["content_hash"],
                                    [],
                                )
                                if self.metrics:
                                    self.metrics.record_block(success)

                urls_checked = (
                    len(recent) if recent and self.safe_browsing.api_key
                    else 0
                )
                logger.info(
                    "safe_browsing_check_complete",
                    extra={
                        "domain_flagged": domain_status.flagged,
                        "domain_error": domain_status.error,
                        "domain_threats": domain_status.threat_types,
                        "content_urls_checked": urls_checked,
                    },
                )

                await asyncio.sleep(
                    self.settings.safe_browsing_check_interval
                )

            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("Safe Browsing monitor error")
                await asyncio.sleep(60)

    async def _cleanup_loop(self) -> None:
        while self._running:
            try:
                await asyncio.sleep(60)
                purged = self.db.purge_old(max_age_seconds=3600)
                if purged > 0:
                    logger.info(
                        "Purged old queue items",
                        extra={"count": purged},
                    )
                retried = self.db.reset_failed(max_age_seconds=600)
                if retried > 0:
                    logger.info(
                        "Reset failed items for retry",
                        extra={"count": retried},
                    )
                # Persist all metrics to DB
                if self.metrics:
                    self.metrics.persist_to_db(self.db)
            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("Cleanup error")
