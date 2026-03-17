from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from src.models import Verdict


@dataclass
class ContentMetadata:
    """Metadata about the content being scanned."""

    tx_id: str
    content_hash: str | None = None
    data_size: int | None = None


@dataclass
class ContentScannerResult:
    """Result from a single content scanner."""

    scanner_name: str
    triggered: bool
    verdict: Verdict
    signals: dict[str, Any] = field(default_factory=dict)


class ContentScanner(ABC):
    """Abstract base class for pluggable content scanners.

    Implementations handle specific content types (images, PDFs, etc.)
    and can call external APIs asynchronously.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique scanner name, e.g. 'csam-detection'."""

    @property
    @abstractmethod
    def supported_content_types(self) -> set[str]:
        """MIME type patterns this scanner handles.

        Supports wildcards via fnmatch, e.g. {"image/*", "video/*"}.
        """

    @abstractmethod
    async def evaluate(
        self,
        content: bytes,
        content_type: str,
        metadata: ContentMetadata,
    ) -> ContentScannerResult:
        """Scan content and return a result."""
