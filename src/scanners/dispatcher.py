from __future__ import annotations

import asyncio
import logging
import time

from bs4 import BeautifulSoup

from src.models import ScanResult, Verdict
from src.rules.engine import RuleEngine
from src.scanners.base import ContentMetadata, ContentScannerResult
from src.scanners.registry import ContentScannerRegistry

logger = logging.getLogger("scanner.dispatcher")

# Verdict severity for picking the highest
_SEVERITY = {
    Verdict.CLEAN: 0,
    Verdict.SKIPPED: 0,
    Verdict.SUSPICIOUS: 1,
    Verdict.MALICIOUS: 2,
}


class ScanDispatcher:
    """Routes content to the appropriate scanning tier.

    - HTML content → RuleEngine (Tier 1, existing)
    - Non-HTML content → ContentScannerRegistry (Tier 2, pluggable)
    """

    def __init__(
        self,
        engine: RuleEngine,
        registry: ContentScannerRegistry,
    ) -> None:
        self.engine = engine
        self.registry = registry

    def evaluate_html(self, html: str, soup: BeautifulSoup) -> ScanResult:
        """Delegate to the existing rule engine. No behavior change."""
        return self.engine.evaluate(html, soup)

    async def evaluate_content(
        self,
        content: bytes,
        content_type: str,
        metadata: ContentMetadata,
    ) -> ScanResult:
        """Run matching content scanners concurrently, return highest severity."""
        start = time.monotonic()

        scanners = self.registry.get_scanners_for_type(content_type)
        if not scanners:
            return ScanResult(verdict=Verdict.CLEAN, scan_duration_ms=0)

        async def _run(scanner) -> ContentScannerResult | None:
            try:
                return await scanner.evaluate(content, content_type, metadata)
            except Exception:
                logger.warning(
                    "content_scanner_error",
                    extra={"scanner": scanner.name, "tx_id": metadata.tx_id},
                    exc_info=True,
                )
                return None

        results = await asyncio.gather(*[_run(s) for s in scanners])

        # Pick highest severity verdict from successful results
        best_verdict = Verdict.CLEAN
        matched_rules: list[str] = []

        for r in results:
            if r is None:
                continue
            if r.triggered:
                matched_rules.append(r.scanner_name)
            severity = _SEVERITY.get(r.verdict, 0)
            if severity > _SEVERITY.get(best_verdict, 0):
                best_verdict = r.verdict

        elapsed_ms = int((time.monotonic() - start) * 1000)

        return ScanResult(
            verdict=best_verdict,
            matched_rules=matched_rules,
            ml_score=None,
            scan_duration_ms=elapsed_ms,
        )
