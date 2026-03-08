from __future__ import annotations

import json
import logging

from src.config import Settings
from src.db import ScannerDB
from src.feed.client import FeedClient
from src.gateway_client import GatewayClient
from src.metrics import ScanMetrics
from src.models import Verdict

logger = logging.getLogger("scanner.feed.poller")


class FeedPoller:
    """Polls peer scanners for new verdicts and imports them locally."""

    def __init__(
        self,
        settings: Settings,
        db: ScannerDB,
        client: FeedClient,
        gateway: GatewayClient,
        metrics: ScanMetrics,
    ):
        self.settings = settings
        self.db = db
        self.client = client
        self.gateway = gateway
        self.metrics = metrics

    def _should_import(self, verdict_str: str) -> bool:
        """Check if a verdict should be imported based on trust mode."""
        if self.settings.verdict_feed_trust_mode == "all":
            return verdict_str != "skipped"
        return verdict_str == "malicious"

    async def poll_peer(self, peer_url: str) -> dict:
        """Poll a single peer for new verdicts. Returns stats dict.

        Drains all available pages (follows has_more) up to a safety
        limit to avoid unbounded loops.
        """
        stats = {"imported": 0, "skipped": 0, "error": None}
        max_pages = 50  # safety limit
        page_imported = 0  # track per-page for sync state delta

        sync_state = self.db.get_feed_sync_state(peer_url)
        since = sync_state["last_scanned_at"] if sync_state else 0
        after_hash = sync_state["last_content_hash"] if sync_state else ""

        for _page in range(max_pages):
            result = await self.client.fetch_feed(
                peer_url, since=since, after_hash=after_hash, limit=100
            )

            if result is None:
                error_msg = "peer unreachable"
                self.db.save_feed_sync_state(
                    peer_url,
                    last_scanned_at=since,
                    last_content_hash=after_hash,
                    error=error_msg,
                )
                self.metrics.record_feed_poll_error()
                stats["error"] = error_msg
                logger.warning(
                    "feed_poll_failed",
                    extra={"peer": peer_url, "error": error_msg},
                )
                return stats

            verdicts = result.get("verdicts", [])
            cursor = result.get("cursor")
            page_imported = 0

            for v in verdicts:
                content_hash = v.get("content_hash", "")
                verdict_str = v.get("verdict", "")

                if not content_hash or not verdict_str:
                    stats["skipped"] += 1
                    continue

                if not self._should_import(verdict_str):
                    stats["skipped"] += 1
                    continue

                # Skip if we already have a local verdict for this hash
                if self.db.has_verdict(content_hash):
                    stats["skipped"] += 1
                    continue

                # Skip if admin has dismissed this hash locally
                override = self.db.get_override(content_hash)
                if override and override.admin_verdict == "confirmed_clean":
                    stats["skipped"] += 1
                    continue

                # Import the verdict
                try:
                    verdict_enum = Verdict(verdict_str)
                except ValueError:
                    stats["skipped"] += 1
                    continue

                tx_id = v.get("tx_id", "")
                matched_rules = v.get("matched_rules", "[]")
                ml_score = v.get("ml_score")

                self.db.save_verdict(
                    content_hash=content_hash,
                    tx_id=tx_id,
                    verdict=verdict_enum,
                    matched_rules=matched_rules if isinstance(matched_rules, str) else json.dumps(matched_rules),
                    ml_score=ml_score,
                    scanner_version=f"peer:{peer_url}",
                    source=peer_url,
                )
                self.metrics.record_feed_import()
                stats["imported"] += 1
                page_imported += 1

                # Block locally if malicious and in enforce mode
                if (
                    verdict_enum == Verdict.MALICIOUS
                    and self.settings.scanner_mode == "enforce"
                    and tx_id
                ):
                    try:
                        rules = matched_rules if isinstance(matched_rules, list) else json.loads(matched_rules)
                    except (json.JSONDecodeError, TypeError):
                        rules = []
                    success = await self.gateway.block_data(
                        tx_id, content_hash, rules
                    )
                    self.metrics.record_block(success)

                logger.info(
                    "feed_verdict_imported",
                    extra={
                        "peer": peer_url,
                        "content_hash": content_hash,
                        "verdict": verdict_str,
                    },
                )

            # Update sync cursor after each page
            if cursor:
                since = cursor.get("scanned_at", since)
                after_hash = cursor.get("content_hash", after_hash)
                self.db.save_feed_sync_state(
                    peer_url,
                    last_scanned_at=since,
                    last_content_hash=after_hash,
                    imported_count_delta=page_imported,
                )
            elif not verdicts:
                # No new verdicts, update last_sync_at only
                self.db.save_feed_sync_state(
                    peer_url,
                    last_scanned_at=since,
                    last_content_hash=after_hash,
                    imported_count_delta=0,
                )

            # Stop if no more pages
            if not result.get("has_more", False):
                break

        if stats["imported"] > 0:
            logger.info(
                "feed_poll_complete",
                extra={
                    "peer": peer_url,
                    "imported": stats["imported"],
                    "skipped": stats["skipped"],
                },
            )

        return stats

    async def poll_all(self) -> None:
        """Poll all configured peers for new verdicts."""
        for peer_url in self.settings.verdict_feed_urls:
            try:
                await self.poll_peer(peer_url)
            except Exception:
                logger.exception(
                    "feed_poll_peer_error",
                    extra={"peer": peer_url},
                )
                self.metrics.record_feed_poll_error()
