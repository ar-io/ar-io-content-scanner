from __future__ import annotations

import fnmatch
import logging

from src.scanners.base import ContentScanner

logger = logging.getLogger("scanner.registry")


class ContentScannerRegistry:
    """Registry of content scanners, matched by MIME type."""

    def __init__(self) -> None:
        self._scanners: list[ContentScanner] = []

    def register(self, scanner: ContentScanner) -> None:
        self._scanners.append(scanner)
        logger.info(
            "content_scanner_registered",
            extra={
                "scanner_name": scanner.name,
                "content_types": sorted(scanner.supported_content_types),
            },
        )

    @property
    def scanner_names(self) -> list[str]:
        return [s.name for s in self._scanners]

    def get_scanners_for_type(self, content_type: str) -> list[ContentScanner]:
        """Return scanners whose supported_content_types match the given MIME type."""
        ct = content_type.lower().split(";")[0].strip()
        matched: list[ContentScanner] = []
        for scanner in self._scanners:
            for pattern in scanner.supported_content_types:
                if fnmatch.fnmatch(ct, pattern.lower()):
                    matched.append(scanner)
                    break
        return matched

    def has_scanners_for_type(self, content_type: str) -> bool:
        return len(self.get_scanners_for_type(content_type)) > 0

    def accepts_any_non_html(self) -> bool:
        """True if any registered scanner handles non-HTML types."""
        html_types = {"text/html", "application/xhtml+xml"}
        for scanner in self._scanners:
            for pattern in scanner.supported_content_types:
                if pattern.lower() not in html_types:
                    return True
        return False
