from __future__ import annotations

from src.models import Verdict
from src.scanners.base import ContentMetadata, ContentScanner, ContentScannerResult


class ExampleImageScanner(ContentScanner):
    """Reference implementation of a content scanner for images.

    Always returns CLEAN — this is a disabled-by-default stub that
    demonstrates the pattern for developers adding real scanners
    (e.g., CSAM detection, steganography analysis).

    Enable with SCANNER_EXAMPLE_IMAGE=true for testing.
    """

    @property
    def name(self) -> str:
        return "example-image"

    @property
    def supported_content_types(self) -> set[str]:
        return {"image/*"}

    async def evaluate(
        self,
        content: bytes,
        content_type: str,
        metadata: ContentMetadata,
    ) -> ContentScannerResult:
        return ContentScannerResult(
            scanner_name=self.name,
            triggered=False,
            verdict=Verdict.CLEAN,
            signals={"size": len(content), "content_type": content_type},
        )
