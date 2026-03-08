from __future__ import annotations

import asyncio
import logging

from src.backfill import BackfillScanner
from src.config import Settings
from src.db import ScannerDB
from src.feed.poller import FeedPoller
from src.metrics import ScanMetrics
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
        settings: Settings | None = None,
        metrics: ScanMetrics | None = None,
    ):
        self.scanner = scanner
        self.db = db
        self.concurrency = concurrency
        self.backfill = backfill
        self.feed_poller = feed_poller
        self.safe_browsing = safe_browsing
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

        if self.safe_browsing is not None:
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
                    await asyncio.sleep(0.1)
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

        # Build domain URL variants — Google may flag http vs https differently
        from urllib.parse import urlparse
        parsed = urlparse(gateway_url)
        domain = parsed.hostname or parsed.netloc
        domain_variants = list(dict.fromkeys([
            f"https://{domain}/",
            f"http://{domain}/",
            f"https://{domain}",
            f"http://{domain}",
        ]))

        logger.info(
            "Safe Browsing monitor started",
            extra={
                "domain": domain,
                "check_interval": self.settings.safe_browsing_check_interval,
                "domain_variants": len(domain_variants),
            },
        )

        while self._running:
            try:
                # Check domain variants first
                urls_to_check: list[str] = list(domain_variants)
                num_domain_urls = len(urls_to_check)

                # Batch-check recent malicious verdict URLs
                all_recent = self.db.get_recent_malicious_urls(limit=50)
                recent = [
                    item for item in all_recent if item["tx_id"]
                ]
                for item in recent:
                    urls_to_check.append(
                        f"{gateway_url}/{item['tx_id']}"
                    )

                results = await self.safe_browsing.check_urls(urls_to_check)

                # Check if any domain variant is flagged
                domain_results = results[:num_domain_urls]
                domain_flagged = any(r.flagged for r in domain_results)
                flagged_variants = [
                    r for r in domain_results if r.flagged
                ]

                if self.metrics:
                    self.metrics.set_safe_browsing_domain_flagged(
                        domain_flagged
                    )

                if domain_flagged:
                    logger.error(
                        "GATEWAY DOMAIN FLAGGED by Google Safe Browsing",
                        extra={
                            "domain": domain,
                            "flagged_urls": [r.url for r in flagged_variants],
                            "threat_types": [
                                t for r in flagged_variants
                                for t in r.threat_types
                            ],
                        },
                    )
                else:
                    logger.info(
                        "safe_browsing_check_complete",
                        extra={
                            "domain_flagged": False,
                            "urls_checked": len(urls_to_check),
                            "content_urls": len(recent),
                        },
                    )

                # Update per-content SB status (skip domain results)
                content_results = results[num_domain_urls:]
                for item, sb_result in zip(recent, content_results):
                    if self.metrics:
                        self.metrics.record_safe_browsing_check(
                            sb_result.flagged
                        )
                    self.db.update_safe_browsing_status(
                        item["content_hash"], sb_result.flagged
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
