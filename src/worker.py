from __future__ import annotations

import asyncio
import logging

from src.backfill import BackfillScanner
from src.db import ScannerDB
from src.scanner import Scanner

logger = logging.getLogger("scanner.worker")


class WorkerPool:
    def __init__(
        self,
        scanner: Scanner,
        db: ScannerDB,
        concurrency: int = 2,
        backfill: BackfillScanner | None = None,
    ):
        self.scanner = scanner
        self.db = db
        self.concurrency = concurrency
        self.backfill = backfill
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
            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("Cleanup error")
