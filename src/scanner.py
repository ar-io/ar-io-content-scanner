from __future__ import annotations

import asyncio
import json
import logging
import re

from bs4 import BeautifulSoup

from src.config import Settings
from src.db import ScannerDB
from src.gateway_client import GatewayClient
from src.ipfs import gateway_public_path
from src.metrics import ScanMetrics
from src.ml.features import parse_html
from src.models import ScanResult, Verdict, WebhookData, WebhookPayload
from src.rules.engine import RuleEngine
from src.db import QueueRow
from src.screenshot import ScreenshotService

# Optional feed client import — only used if configured
try:
    from src.feed.client import FeedClient
except ImportError:
    FeedClient = None  # type: ignore[assignment,misc]

# Optional Safe Browsing import
try:
    from src.safe_browsing import SafeBrowsingClient
except ImportError:
    SafeBrowsingClient = None  # type: ignore[assignment,misc]

# Optional dispatcher import
try:
    from src.scanners.dispatcher import ScanDispatcher
except ImportError:
    ScanDispatcher = None  # type: ignore[assignment,misc]

# Optional notification router import
try:
    from src.notifications.router import NotificationRouter
except ImportError:
    NotificationRouter = None  # type: ignore[assignment,misc]

logger = logging.getLogger("scanner.core")

# DOM manipulation patterns that indicate JS will modify page structure.
# Used by _needs_rendered_scan() to decide whether a second-pass render is needed.
_DOM_MANIPULATION_RE = re.compile(
    r"document\.write|\.innerHTML|createElement|appendChild|"
    r"insertBefore|\.outerHTML|replaceChild|insertAdjacentHTML|"
    r"\.append\(|\.prepend\(|setAttribute\(",
)


def _needs_rendered_scan(html: str, soup: BeautifulSoup, result: ScanResult) -> bool:
    """Decide whether a page needs a rendered DOM second-pass scan.

    Returns True when all of:
    1. Static rules returned CLEAN (already-flagged pages don't need re-scan)
    2. Page has <script> tags
    3. Scripts contain DOM manipulation patterns
    4. Sparse static content (little visible text or few body elements)
    """
    if result.verdict != Verdict.CLEAN:
        return False

    scripts = soup.find_all("script")
    if not scripts:
        return False

    script_text = " ".join(s.get_text() for s in scripts)
    if not _DOM_MANIPULATION_RE.search(script_text):
        return False

    # Check for sparse static content (excluding script/style text)
    # Build visible text by joining non-script/style element text
    visible_parts = []
    for element in soup.find_all(string=True):
        if element.parent and element.parent.name not in ("script", "style"):
            text = element.strip()
            if text:
                visible_parts.append(text)
    visible_text = " ".join(visible_parts)
    if len(visible_text) < 200:
        return True

    body = soup.find("body")
    if body:
        non_script_tags = [t for t in body.find_all(True) if t.name != "script"]
        if len(non_script_tags) < 10:
            return True

    return False

HTML_SIGNATURES = [
    b"<!doctype html",
    b"<html",
    b"<head",
    b"<body",
    b"<script",
    b"<iframe",
    b"<div",
    b"<form",
    b"<meta",
]


def looks_like_html(content: bytes) -> bool:
    head = content[:512].lstrip()
    if head.startswith(b"\xef\xbb\xbf"):
        head = head[3:]
    head = head.lower()
    # Strip XML declaration (<?xml ...?>) — XHTML pages start with this
    # before the <html> or <!DOCTYPE> tag.
    if head.startswith(b"<?xml"):
        end = head.find(b"?>")
        if end != -1:
            head = head[end + 2:].lstrip()
    return any(head.startswith(sig) for sig in HTML_SIGNATURES)


def is_html_content_type(content_type: str | None) -> bool | None:
    """Returns True if HTML, False if definitely not, None if unknown."""
    if content_type is None:
        return None
    ct = content_type.lower().split(";")[0].strip()
    if not ct:
        return None
    if ct in ("text/html", "application/xhtml+xml"):
        return True
    if ct in ("application/octet-stream", "text/plain"):
        return None
    return False


class Scanner:
    def __init__(
        self,
        settings: Settings,
        db: ScannerDB,
        gateway: GatewayClient,
        engine: RuleEngine,
        metrics: ScanMetrics,
        screenshot: ScreenshotService | None = None,
        feed_client: FeedClient | None = None,
        safe_browsing: SafeBrowsingClient | None = None,
        dispatcher: ScanDispatcher | None = None,
        notifier: NotificationRouter | None = None,
    ):
        self.settings = settings
        self.db = db
        self.gateway = gateway
        self.engine = engine
        self.metrics = metrics
        self.screenshot = screenshot
        self.feed_client = feed_client
        self.safe_browsing = safe_browsing
        self.dispatcher = dispatcher
        self.notifier = notifier

    async def _capture_screenshot(self, tx_id: str, content_hash: str) -> None:
        try:
            await self.screenshot.capture(tx_id, content_hash)
        except Exception:
            logger.warning(
                "screenshot_capture_failed",
                extra={"tx_id": tx_id},
            )

    async def _rendered_dom_scan(
        self,
        tx_id: str,
        loop: asyncio.AbstractEventLoop,
        timeout_s: float,
        static_result: ScanResult,
    ) -> ScanResult:
        """Render page in Playwright and re-run rules on the rendered DOM."""
        rendered_html = await self.screenshot.render_dom(
            tx_id, timeout_ms=self.settings.scan_timeout_ms,
        )
        if not rendered_html:
            return static_result

        rendered_soup = await asyncio.wait_for(
            loop.run_in_executor(None, parse_html, rendered_html),
            timeout=timeout_s,
        )
        rendered_result = await asyncio.wait_for(
            loop.run_in_executor(
                None, self.engine.evaluate,
                rendered_html, rendered_soup,
            ),
            timeout=timeout_s,
        )
        self.metrics.record_rendered_scan(
            detected=rendered_result.verdict != Verdict.CLEAN,
        )
        if rendered_result.verdict != Verdict.CLEAN:
            rendered_result.matched_rules = [
                f"rendered:{r}" for r in rendered_result.matched_rules
            ]
            logger.warning(
                "rendered_dom_detection",
                extra={
                    "tx_id": tx_id,
                    "verdict": rendered_result.verdict.value,
                    "rules": rendered_result.matched_rules,
                    "ml_score": rendered_result.ml_score,
                },
            )
            return rendered_result
        return static_result

    async def _check_safe_browsing(
        self,
        tx_id: str,
        content_hash: str | None,
        result: ScanResult,
    ) -> None:
        """Check a URL against Google Safe Browsing after scan verdict.

        If SUSPICIOUS and Google flags it, escalate to MALICIOUS.
        Updates the safe_browsing_flagged column in scan_verdicts.
        """
        url = f"{self.settings.gateway_public_url}{gateway_public_path(tx_id)}"
        try:
            sb_result = await self.safe_browsing.check_url(url)
            self.metrics.record_safe_browsing_check(sb_result.flagged)

            if content_hash:
                self.db.update_safe_browsing_status(
                    content_hash, sb_result.flagged
                )

            if sb_result.flagged and result.verdict == Verdict.SUSPICIOUS:
                # Escalate: two independent signals (our rules + Google)
                result.verdict = Verdict.MALICIOUS
                self.metrics.record_safe_browsing_escalation()
                if content_hash:
                    self.db.update_verdict(content_hash, Verdict.MALICIOUS)
                logger.warning(
                    "safe_browsing_escalation",
                    extra={
                        "tx_id": tx_id,
                        "content_hash": content_hash,
                        "threat_types": sb_result.threat_types,
                    },
                )
            elif sb_result.flagged:
                logger.info(
                    "safe_browsing_corroborated",
                    extra={
                        "tx_id": tx_id,
                        "threat_types": sb_result.threat_types,
                    },
                )
        except Exception:
            self.metrics.record_safe_browsing_error()
            logger.warning(
                "safe_browsing_check_failed",
                extra={"tx_id": tx_id},
                exc_info=True,
            )

    def _should_accept_peer_verdict(self, verdict_str: str) -> bool:
        """Check if a peer verdict should be accepted based on trust mode."""
        if self.settings.verdict_feed_trust_mode == "all":
            return verdict_str != "skipped"
        return verdict_str == "malicious"

    async def _check_peers(self, content_hash: str) -> dict | None:
        """Query all peers concurrently for a verdict. Returns first match."""
        async def _query(peer_url: str) -> dict | None:
            result = await self.feed_client.lookup_verdict(peer_url, content_hash)
            if result is not None:
                result["_peer_url"] = peer_url
            return result

        tasks = [
            _query(peer_url)
            for peer_url in self.settings.verdict_feed_urls
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Prefer MALICIOUS verdicts, then any valid verdict
        best = None
        for r in results:
            if isinstance(r, Exception) or r is None:
                continue
            if r.get("verdict") == "malicious":
                return r
            if best is None:
                best = r
        return best

    async def process_webhook(self, payload: WebhookPayload) -> None:
        data = payload.data
        self.metrics.record_webhook()

        if payload.event not in self.settings.webhook_events:
            return

        # Fast path: skip non-HTML content types (unless a content scanner wants them)
        html_check = is_html_content_type(data.contentType)
        if html_check is False:
            # Check if a content scanner handles this type
            has_scanner = (
                self.dispatcher
                and data.contentType
                and self.dispatcher.registry.has_scanners_for_type(data.contentType)
            )
            if not has_scanner:
                logger.debug(
                    "scan_skipped",
                    extra={
                        "tx_id": data.id,
                        "reason": "not_html",
                        "content_type": data.contentType,
                    },
                )
                self.metrics.record_skip()
                return

        # Skip large files with unknown content type (unlikely HTML)
        if html_check is None and data.dataSize and data.dataSize > 524288:
            # Unless a content scanner might want it
            has_scanner = (
                self.dispatcher
                and self.dispatcher.registry.accepts_any_non_html()
            )
            if not has_scanner:
                logger.debug(
                    "scan_skipped",
                    extra={
                        "tx_id": data.id,
                        "reason": "unknown_type_too_large",
                        "data_size": data.dataSize,
                    },
                )
                self.metrics.record_skip()
                return

        # Check verdict cache by hash
        if data.hash:
            cached = self.db.get_verdict(data.hash)
            if cached is not None:
                self.metrics.record_cache_hit()
                logger.debug(
                    "cache_hit",
                    extra={
                        "tx_id": data.id,
                        "cached_verdict": cached.verdict.value,
                    },
                )
                # If cached as malicious and we're enforcing, block this new tx
                if (
                    cached.verdict == Verdict.MALICIOUS
                    and self.settings.scanner_mode == "enforce"
                ):
                    try:
                        rules = json.loads(cached.matched_rules or "[]")
                    except (json.JSONDecodeError, TypeError):
                        rules = []
                    await self.gateway.block_data(
                        data.id,
                        data.hash,
                        rules,
                    )
                return

        # Enqueue for async scanning — indexed events are delayed to give
        # the gateway's data indexer time to save parent bundle relationships
        # that make /raw/:id resolution work.
        if payload.event != "data-cached":
            delay = self.settings.webhook_index_delay
            asyncio.create_task(
                self._delayed_enqueue(data, delay)
            )
        else:
            enqueued = self.db.enqueue(
                tx_id=data.id,
                content_hash=data.hash,
                content_type=data.contentType,
                data_size=data.dataSize,
            )
            if enqueued:
                logger.debug("enqueued", extra={"tx_id": data.id})

    async def _delayed_enqueue(self, data: WebhookData, delay: int) -> None:
        """Enqueue after a delay — used for indexed events."""
        await asyncio.sleep(delay)
        enqueued = self.db.enqueue(
            tx_id=data.id,
            content_hash=data.hash,
            content_type=data.contentType,
            data_size=data.dataSize,
        )
        if enqueued:
            logger.debug(
                "enqueued_after_delay",
                extra={"tx_id": data.id, "delay_s": delay},
            )

    async def process_queue_item(self, item: QueueRow) -> None:
        tx_id = item.tx_id
        content_hash = item.content_hash

        # Check admin overrides before scanning
        if content_hash:
            override = self.db.get_override(content_hash)
            if override is not None:
                if override.admin_verdict == "confirmed_clean":
                    self.db.save_verdict(
                        content_hash=content_hash,
                        tx_id=tx_id,
                        verdict=Verdict.CLEAN,
                        matched_rules="[]",
                        ml_score=None,
                        scanner_version=self.settings.scanner_version,
                    )
                    logger.info(
                        "scan_skipped_admin_override",
                        extra={"tx_id": tx_id, "override": "confirmed_clean"},
                    )
                    return
                elif override.admin_verdict == "confirmed_malicious":
                    self.db.save_verdict(
                        content_hash=content_hash,
                        tx_id=tx_id,
                        verdict=Verdict.MALICIOUS,
                        matched_rules=override.original_rules or "[]",
                        ml_score=None,
                        scanner_version=self.settings.scanner_version,
                    )
                    if self.settings.scanner_mode == "enforce":
                        try:
                            rules = json.loads(override.original_rules or "[]")
                        except (json.JSONDecodeError, TypeError):
                            rules = []
                        success = await self.gateway.block_data(
                            tx_id,
                            content_hash,
                            rules,
                        )
                        self.metrics.record_block(success)
                        if success:
                            self.db.mark_blocked(content_hash)
                    logger.warning(
                        "scan_admin_override_malicious",
                        extra={"tx_id": tx_id, "override": "confirmed_malicious"},
                    )
                    return

        # On-demand peer lookup before fetching content
        if (
            content_hash
            and self.feed_client
            and self.settings.verdict_feed_on_demand
            and self.settings.verdict_feed_urls
        ):
            peer_verdict = await self._check_peers(content_hash)
            if peer_verdict is not None:
                verdict_str = peer_verdict.get("verdict", "")
                if self._should_accept_peer_verdict(verdict_str):
                    try:
                        verdict_enum = Verdict(verdict_str)
                    except ValueError:
                        logger.warning(
                            "peer_invalid_verdict",
                            extra={"verdict": verdict_str, "content_hash": content_hash},
                        )
                        self.metrics.record_feed_on_demand(hit=False)
                        # Fall through to local scan
                    else:
                        matched_rules = peer_verdict.get("matched_rules", "[]")
                        if isinstance(matched_rules, list):
                            matched_rules = json.dumps(matched_rules)
                        peer_url = peer_verdict.get("_peer_url", "peer")

                        self.db.save_verdict(
                            content_hash=content_hash,
                            tx_id=tx_id,
                            verdict=verdict_enum,
                            matched_rules=matched_rules,
                            ml_score=peer_verdict.get("ml_score"),
                            scanner_version=f"peer:{peer_url}",
                            source=peer_url,
                        )
                        self.metrics.record_feed_on_demand(hit=True)

                        if (
                            verdict_enum == Verdict.MALICIOUS
                            and self.settings.scanner_mode == "enforce"
                        ):
                            try:
                                rules = json.loads(matched_rules)
                            except (json.JSONDecodeError, TypeError):
                                rules = []
                            success = await self.gateway.block_data(
                                tx_id, content_hash, rules
                            )
                            self.metrics.record_block(success)
                            if success:
                                self.db.mark_blocked(content_hash)

                        logger.info(
                            "peer_verdict_used",
                            extra={
                                "tx_id": tx_id,
                                "peer": peer_url,
                                "verdict": verdict_str,
                            },
                        )
                        return
            self.metrics.record_feed_on_demand(hit=False)

        # Fetch content from gateway
        content = await self.gateway.fetch_content(tx_id)
        if content is None:
            logger.info(
                "fetch_unavailable",
                extra={"tx_id": tx_id, "content_hash": content_hash},
            )
            return

        # Determine if content is HTML or a type a content scanner handles
        effective_content_type = item.content_type
        ct_check = is_html_content_type(item.content_type)

        if ct_check is True:
            is_html = True
        elif ct_check is False:
            is_html = False
        else:
            # Unknown content type — sniff the bytes
            is_html = looks_like_html(content)
            if not is_html and self.dispatcher:
                from src.scanners.sniff import sniff_content_type

                effective_content_type = sniff_content_type(content[:512])

        # Route to appropriate scanning tier
        if is_html:
            self.metrics.record_cache_miss()

            # Parse and scan — run CPU-bound work off the event loop
            html = content.decode("utf-8", errors="replace")
            loop = asyncio.get_running_loop()
            timeout_s = self.settings.scan_timeout_ms / 1000
            soup: BeautifulSoup = await asyncio.wait_for(
                loop.run_in_executor(None, parse_html, html),
                timeout=timeout_s,
            )
            result = await asyncio.wait_for(
                loop.run_in_executor(None, self.engine.evaluate, html, soup),
                timeout=timeout_s,
            )

            # Check data: URI / srcdoc iframes for embedded phishing
            if result.verdict == Verdict.CLEAN:
                from src.rules.iframe_scanner import extract_iframe_content

                iframe_htmls = extract_iframe_content(soup)
                for iframe_html in iframe_htmls:
                    iframe_soup = await asyncio.wait_for(
                        loop.run_in_executor(None, parse_html, iframe_html),
                        timeout=timeout_s,
                    )
                    iframe_result = await asyncio.wait_for(
                        loop.run_in_executor(
                            None, self.engine.evaluate, iframe_html, iframe_soup,
                        ),
                        timeout=timeout_s,
                    )
                    if iframe_result.verdict != Verdict.CLEAN:
                        iframe_result.matched_rules = [
                            f"iframe:{r}" for r in iframe_result.matched_rules
                        ]
                        result = iframe_result
                        logger.warning(
                            "iframe_content_detection",
                            extra={
                                "tx_id": tx_id,
                                "verdict": result.verdict.value,
                                "rules": result.matched_rules,
                            },
                        )
                        break

            # Rendered DOM two-pass scan: if static scan is CLEAN but page
            # looks like a JS shell, render in Playwright and re-run rules.
            # Wrapped in a safety timeout so a Playwright hang can't block
            # a worker forever.
            if (
                result.verdict == Verdict.CLEAN
                and self.settings.rendered_dom_scan_enabled
                and self.screenshot
                and self.screenshot.available
                and _needs_rendered_scan(html, soup, result)
            ):
                try:
                    result = await asyncio.wait_for(
                        self._rendered_dom_scan(tx_id, loop, timeout_s, result),
                        timeout=timeout_s + 15,  # render + parse + evaluate
                    )
                except asyncio.TimeoutError:
                    logger.warning(
                        "rendered_dom_scan_timeout",
                        extra={"tx_id": tx_id},
                    )
        elif (
            self.dispatcher
            and effective_content_type
            and self.dispatcher.registry.has_scanners_for_type(effective_content_type)
        ):
            self.metrics.record_cache_miss()
            self.metrics.record_content_scan()

            from src.scanners.base import ContentMetadata

            metadata = ContentMetadata(
                tx_id=tx_id,
                content_hash=content_hash,
                data_size=len(content),
            )
            result = await self.dispatcher.evaluate_content(
                content, effective_content_type, metadata,
            )
        else:
            # Not HTML and no content scanner — skip
            logger.debug(
                "scan_skipped",
                extra={
                    "tx_id": tx_id,
                    "reason": "content_sniff_not_html",
                },
            )
            self.metrics.record_skip()
            if content_hash:
                self.db.save_verdict(
                    content_hash=content_hash,
                    tx_id=tx_id,
                    verdict=Verdict.SKIPPED,
                    matched_rules="[]",
                    ml_score=None,
                    scanner_version=self.settings.scanner_version,
                )
            return

        # Cache verdict
        if content_hash:
            try:
                self.db.save_verdict(
                    content_hash=content_hash,
                    tx_id=tx_id,
                    verdict=result.verdict,
                    matched_rules=json.dumps(result.matched_rules),
                    ml_score=result.ml_score,
                    scanner_version=self.settings.scanner_version,
                )
            except Exception:
                logger.warning(
                    "verdict_cache_failed",
                    extra={"tx_id": tx_id, "content_hash": content_hash},
                )

        self.metrics.record_scan(result.verdict, result.scan_duration_ms)

        # Safe Browsing corroboration: check flagged content against Google
        # before blocking. Escalate SUSPICIOUS→MALICIOUS if Google agrees.
        # Requires SAFE_BROWSING_API_KEY for the Lookup API.
        if (
            result.verdict in (Verdict.MALICIOUS, Verdict.SUSPICIOUS)
            and self.safe_browsing
            and self.safe_browsing.api_key
            and self.settings.gateway_public_url
        ):
            await self._check_safe_browsing(
                tx_id, content_hash, result
            )

        # Capture screenshot BEFORE blocking — in enforce mode the gateway
        # will return "Not Found" after blocking, so the screenshot must be
        # taken while the content is still accessible.
        # Only for HTML content — screenshots use Playwright which renders HTML.
        if (
            result.verdict in (Verdict.MALICIOUS, Verdict.SUSPICIOUS)
            and content_hash
            and self.screenshot
            and is_html
        ):
            await self._capture_screenshot(tx_id, content_hash)

        # Take action
        action = "passed"
        if result.verdict == Verdict.MALICIOUS:
            if self.settings.scanner_mode == "enforce" and content_hash:
                success = await self.gateway.block_data(
                    tx_id, content_hash, result.matched_rules
                )
                self.metrics.record_block(success)
                if success:
                    self.db.mark_blocked(content_hash)
                action = "blocked" if success else "block_failed"
            elif self.settings.scanner_mode == "enforce" and not content_hash:
                # No content hash (e.g., TX ID from email intake or tx-indexed
                # webhook). Block by TX ID alone — the gateway's block endpoint
                # accepts either id or hash. Use tx_id as the hash key for DB
                # bookkeeping consistency (same approach as manual-block).
                success = await self.gateway.block_data(
                    tx_id, tx_id, result.matched_rules
                )
                self.metrics.record_block(success)
                if success:
                    self.db.mark_blocked(tx_id)
                action = "blocked_by_id" if success else "block_failed"
            else:
                action = "dry_run"

        log_level = (
            logging.WARNING
            if result.verdict in (Verdict.MALICIOUS, Verdict.SUSPICIOUS)
            else logging.INFO
        )
        logger.log(
            log_level,
            "scan_complete",
            extra={
                "tx_id": tx_id,
                "verdict": result.verdict.value,
                "rules": result.matched_rules,
                "ml_score": result.ml_score,
                "scan_ms": result.scan_duration_ms,
                "action": action,
            },
        )

        # Send notifications (after verdict saved, action taken, screenshot captured)
        if (
            self.notifier
            and content_hash
            and result.verdict in (Verdict.MALICIOUS, Verdict.SUSPICIOUS)
        ):
            screenshot_path = None
            if self.screenshot:
                ss_path = self.screenshot.get_path(content_hash)
                if ss_path is not None:
                    screenshot_path = str(ss_path)
            try:
                await self.notifier.notify(
                    verdict=result.verdict.value,
                    tx_id=tx_id,
                    content_hash=content_hash,
                    matched_rules=result.matched_rules,
                    ml_score=result.ml_score,
                    screenshot_path=screenshot_path,
                    action_taken=action,
                )
            except Exception:
                logger.warning(
                    "notification_failed",
                    extra={"tx_id": tx_id},
                    exc_info=True,
                )
