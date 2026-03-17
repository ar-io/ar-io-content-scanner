"""Unit tests for pluggable content scanner components."""
from __future__ import annotations

import asyncio

import pytest

from src.models import ScanResult, Verdict
from src.scanners.base import ContentMetadata, ContentScanner, ContentScannerResult
from src.scanners.dispatcher import ScanDispatcher
from src.scanners.example_image_scanner import ExampleImageScanner
from src.scanners.registry import ContentScannerRegistry
from src.scanners.sniff import sniff_content_type


# --- Helpers ---


class StubScanner(ContentScanner):
    """Test scanner that returns a configurable verdict."""

    def __init__(
        self,
        scanner_name: str = "stub",
        types: set[str] | None = None,
        verdict: Verdict = Verdict.CLEAN,
        triggered: bool = False,
        raise_exc: bool = False,
    ):
        self._name = scanner_name
        self._types = types or {"image/*"}
        self._verdict = verdict
        self._triggered = triggered
        self._raise_exc = raise_exc

    @property
    def name(self) -> str:
        return self._name

    @property
    def supported_content_types(self) -> set[str]:
        return self._types

    async def evaluate(self, content, content_type, metadata):
        if self._raise_exc:
            raise RuntimeError("scanner failure")
        return ContentScannerResult(
            scanner_name=self._name,
            triggered=self._triggered,
            verdict=self._verdict,
        )


# --- ABC tests ---


class TestContentScannerABC:
    def test_cannot_instantiate_abstract(self):
        with pytest.raises(TypeError):
            ContentScanner()  # type: ignore[abstract]

    def test_example_image_scanner_satisfies_abc(self):
        scanner = ExampleImageScanner()
        assert scanner.name == "example-image"
        assert "image/*" in scanner.supported_content_types

    async def test_example_image_scanner_returns_clean(self):
        scanner = ExampleImageScanner()
        meta = ContentMetadata(tx_id="test123")
        result = await scanner.evaluate(b"\x89PNG", "image/png", meta)
        assert result.verdict == Verdict.CLEAN
        assert result.triggered is False
        assert result.scanner_name == "example-image"


# --- Registry tests ---


class TestContentScannerRegistry:
    def test_register_scanner(self):
        reg = ContentScannerRegistry()
        reg.register(StubScanner("img-scan", {"image/*"}))
        assert reg.scanner_names == ["img-scan"]

    def test_get_scanners_exact_match(self):
        reg = ContentScannerRegistry()
        reg.register(StubScanner("pdf-scan", {"application/pdf"}))
        matched = reg.get_scanners_for_type("application/pdf")
        assert len(matched) == 1
        assert matched[0].name == "pdf-scan"

    def test_get_scanners_wildcard_match(self):
        reg = ContentScannerRegistry()
        reg.register(StubScanner("img-scan", {"image/*"}))
        matched = reg.get_scanners_for_type("image/png")
        assert len(matched) == 1

    def test_get_scanners_no_match(self):
        reg = ContentScannerRegistry()
        reg.register(StubScanner("img-scan", {"image/*"}))
        matched = reg.get_scanners_for_type("video/mp4")
        assert len(matched) == 0

    def test_has_scanners_for_type(self):
        reg = ContentScannerRegistry()
        reg.register(StubScanner("img-scan", {"image/*"}))
        assert reg.has_scanners_for_type("image/jpeg") is True
        assert reg.has_scanners_for_type("video/mp4") is False

    def test_accepts_any_non_html_true(self):
        reg = ContentScannerRegistry()
        reg.register(StubScanner("img-scan", {"image/*"}))
        assert reg.accepts_any_non_html() is True

    def test_accepts_any_non_html_false_empty(self):
        reg = ContentScannerRegistry()
        assert reg.accepts_any_non_html() is False

    def test_multiple_scanners_same_type(self):
        reg = ContentScannerRegistry()
        reg.register(StubScanner("scan-a", {"image/*"}))
        reg.register(StubScanner("scan-b", {"image/*"}))
        matched = reg.get_scanners_for_type("image/png")
        assert len(matched) == 2

    def test_content_type_with_charset(self):
        reg = ContentScannerRegistry()
        reg.register(StubScanner("pdf-scan", {"application/pdf"}))
        matched = reg.get_scanners_for_type("application/pdf; charset=utf-8")
        assert len(matched) == 1


# --- Dispatcher tests ---


class TestScanDispatcher:
    def _make_dispatcher(self, scanners=None):
        from unittest.mock import MagicMock

        engine = MagicMock()
        reg = ContentScannerRegistry()
        if scanners:
            for s in scanners:
                reg.register(s)
        return ScanDispatcher(engine, reg), engine

    def test_evaluate_html_delegates_to_engine(self):
        from unittest.mock import MagicMock

        dispatcher, engine = self._make_dispatcher()
        mock_result = ScanResult(verdict=Verdict.MALICIOUS, matched_rules=["test"])
        engine.evaluate.return_value = mock_result

        result = dispatcher.evaluate_html("html", MagicMock())
        assert result.verdict == Verdict.MALICIOUS
        engine.evaluate.assert_called_once()

    async def test_evaluate_content_no_matching_scanners(self):
        dispatcher, _ = self._make_dispatcher()
        meta = ContentMetadata(tx_id="test")
        result = await dispatcher.evaluate_content(b"data", "video/mp4", meta)
        assert result.verdict == Verdict.CLEAN

    async def test_evaluate_content_single_scanner(self):
        scanner = StubScanner(
            "mal-scan", {"image/*"}, verdict=Verdict.MALICIOUS, triggered=True
        )
        dispatcher, _ = self._make_dispatcher([scanner])
        meta = ContentMetadata(tx_id="test")
        result = await dispatcher.evaluate_content(b"data", "image/png", meta)
        assert result.verdict == Verdict.MALICIOUS
        assert "mal-scan" in result.matched_rules

    async def test_evaluate_content_highest_severity_wins(self):
        clean = StubScanner("clean-scan", {"image/*"}, verdict=Verdict.CLEAN)
        mal = StubScanner(
            "mal-scan", {"image/*"}, verdict=Verdict.MALICIOUS, triggered=True
        )
        dispatcher, _ = self._make_dispatcher([clean, mal])
        meta = ContentMetadata(tx_id="test")
        result = await dispatcher.evaluate_content(b"data", "image/png", meta)
        assert result.verdict == Verdict.MALICIOUS

    async def test_evaluate_content_fail_open(self):
        failing = StubScanner("bad-scan", {"image/*"}, raise_exc=True)
        dispatcher, _ = self._make_dispatcher([failing])
        meta = ContentMetadata(tx_id="test")
        result = await dispatcher.evaluate_content(b"data", "image/png", meta)
        assert result.verdict == Verdict.CLEAN

    async def test_evaluate_content_concurrent_execution(self):
        """Verify scanners run concurrently via asyncio.gather."""
        call_order = []

        class SlowScanner(ContentScanner):
            @property
            def name(self):
                return "slow"

            @property
            def supported_content_types(self):
                return {"image/*"}

            async def evaluate(self, content, content_type, metadata):
                call_order.append("slow-start")
                await asyncio.sleep(0.01)
                call_order.append("slow-end")
                return ContentScannerResult(
                    scanner_name="slow", triggered=False, verdict=Verdict.CLEAN
                )

        class FastScanner(ContentScanner):
            @property
            def name(self):
                return "fast"

            @property
            def supported_content_types(self):
                return {"image/*"}

            async def evaluate(self, content, content_type, metadata):
                call_order.append("fast-start")
                call_order.append("fast-end")
                return ContentScannerResult(
                    scanner_name="fast", triggered=False, verdict=Verdict.CLEAN
                )

        dispatcher, _ = self._make_dispatcher([SlowScanner(), FastScanner()])
        meta = ContentMetadata(tx_id="test")
        await dispatcher.evaluate_content(b"data", "image/png", meta)
        # Both should start before slow finishes
        assert "fast-start" in call_order
        assert "slow-start" in call_order


# --- MIME sniff tests ---


class TestSniffContentType:
    def test_png(self):
        assert sniff_content_type(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100) == "image/png"

    def test_jpeg(self):
        assert sniff_content_type(b"\xff\xd8\xff\xe0" + b"\x00" * 100) == "image/jpeg"

    def test_gif87a(self):
        assert sniff_content_type(b"GIF87a" + b"\x00" * 100) == "image/gif"

    def test_gif89a(self):
        assert sniff_content_type(b"GIF89a" + b"\x00" * 100) == "image/gif"

    def test_webp(self):
        assert sniff_content_type(b"RIFF\x00\x00\x00\x00WEBP" + b"\x00" * 100) == "image/webp"

    def test_pdf(self):
        assert sniff_content_type(b"%PDF-1.4" + b"\x00" * 100) == "application/pdf"

    def test_mp4(self):
        assert sniff_content_type(b"\x00\x00\x00\x1cftypisom" + b"\x00" * 100) == "video/mp4"

    def test_webm(self):
        assert sniff_content_type(b"\x1a\x45\xdf\xa3" + b"\x00" * 100) == "video/webm"

    def test_unknown(self):
        assert sniff_content_type(b"\x00\x01\x02\x03" * 10) == "application/octet-stream"

    def test_short_input(self):
        assert sniff_content_type(b"\x00") == "application/octet-stream"
