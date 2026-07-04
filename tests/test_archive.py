"""Tests for SingleFile/SingleFileZ archive decoding.

Covers the decode helpers directly and the end-to-end path through
process_queue_item: a benign archive scans CLEAN (no wrapper false positive),
and — critically — a MALICIOUS archived page is detected and blocked instead of
hiding inside the wrapper. Zip bombs and corrupt/non-archive input fall back to
scanning the wrapper (fail-open).
"""
from __future__ import annotations

import io
import os
import tempfile
import zipfile

import pytest
from unittest.mock import AsyncMock

from src.archive import (
    ARCHIVE_MAX_ENTRIES,
    extract_singlefile_html,
    is_singlefile_archive,
    looks_like_singlefile_head,
)
from src.config import Settings
from src.db import QueueRow, ScannerDB
from src.gateway_client import GatewayClient
from src.metrics import ScanMetrics
from src.models import Verdict
from src.rules.engine import RuleEngine
from src.scanner import Scanner

from tests.fixtures import CLEAN_HTML, EXTERNAL_FORM_PHISHING


# --- helpers -----------------------------------------------------------------

def make_singlefilez(inner_html: str, *, extra_entries: dict | None = None) -> bytes:
    """Build a real SingleFileZ-style HTML+ZIP polyglot.

    An HTML shell carrying the ``data-sfz`` marker, immediately followed by a
    ZIP whose ``index.html`` is the real page. Structurally identical (for our
    detection + extraction purposes) to what SingleFileZ produces.
    """
    shell = (
        b'<!DOCTYPE html><html data-sfz><head><meta charset=utf-8></head>'
        b'<body hidden><div>Please wait...</div></body></html>\n'
    )
    buf = io.BytesIO()
    buf.write(shell)
    with zipfile.ZipFile(buf, "a", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.html", inner_html)
        zf.writestr("manifest.json", '{"originalUrl":"https://example.com/"}')
        for name, data in (extra_entries or {}).items():
            zf.writestr(name, data)
    return buf.getvalue()


def _settings(**overrides) -> Settings:
    defaults = dict(
        gateway_url="http://localhost:3000",
        admin_api_key="test-key",
        scanner_admin_key="admin-key",
        ml_model_enabled=False,
        scanner_mode="enforce",
        rendered_dom_scan_enabled=False,
        archive_decode_enabled=True,
    )
    defaults.update(overrides)
    return Settings(**defaults)


def _make_scanner(fetch_bytes: bytes, **settings_overrides):
    fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    db = ScannerDB(db_path)
    db.initialize()
    gateway = AsyncMock(spec=GatewayClient)
    gateway.fetch_content = AsyncMock(return_value=fetch_bytes)
    s = _settings(**settings_overrides)
    scanner = Scanner(s, db, gateway, RuleEngine(s), ScanMetrics())
    return scanner, db, gateway


def _item() -> QueueRow:
    return QueueRow(
        id=1,
        tx_id="A" * 43,
        content_hash="wrapperhash",
        content_type="text/html",
        data_size=4096,
        received_at=0,
    )


# --- unit: detection + extraction -------------------------------------------

class TestArchiveHelpers:
    def test_detects_singlefilez(self):
        assert is_singlefile_archive(make_singlefilez(CLEAN_HTML)) is True

    def test_plain_html_is_not_archive(self):
        assert is_singlefile_archive(CLEAN_HTML.encode()) is False

    def test_plain_zip_is_not_archive(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("index.html", CLEAN_HTML)
        assert is_singlefile_archive(buf.getvalue()) is False  # no HTML head/marker

    def test_empty_is_not_archive(self):
        assert is_singlefile_archive(b"") is False

    def test_extract_returns_inner_html(self):
        out = extract_singlefile_html(make_singlefilez(CLEAN_HTML))
        assert out is not None
        assert "My Arweave Blog Post" in out

    def test_extract_corrupt_returns_none(self):
        # HTML head + marker but a truncated/garbage ZIP tail
        junk = b'<!DOCTYPE html><html data-sfz></html>PK\x05\x06corrupt'
        assert extract_singlefile_html(junk) is None

    def test_extract_rejects_too_many_entries(self):
        extras = {f"r{i}.txt": b"x" for i in range(ARCHIVE_MAX_ENTRIES + 5)}
        blob = make_singlefilez(CLEAN_HTML, extra_entries=extras)
        assert extract_singlefile_html(blob) is None

    def test_extract_rejects_zip_bomb_ratio(self):
        # One highly-compressible entry that blows the ratio cap.
        bomb = make_singlefilez(CLEAN_HTML, extra_entries={"big.txt": b"0" * 5_000_000})
        assert extract_singlefile_html(bomb) is None


# --- end-to-end: through process_queue_item ---------------------------------

@pytest.mark.asyncio
class TestArchiveScanning:
    async def test_benign_archive_scanned_clean(self):
        scanner, db, gateway = _make_scanner(make_singlefilez(CLEAN_HTML))
        await scanner.process_queue_item(_item())
        cached = db.get_verdict("wrapperhash")
        assert cached is not None
        assert cached.verdict == Verdict.CLEAN
        gateway.block_data.assert_not_called()
        assert scanner.metrics.archive_decodes == 1

    async def test_malicious_archive_detected_and_blocked(self):
        # The whole point: a phishing page hidden inside an archive must be
        # detected (and blocked in enforce mode), not masked by the wrapper.
        scanner, db, gateway = _make_scanner(
            make_singlefilez(EXTERNAL_FORM_PHISHING)
        )
        await scanner.process_queue_item(_item())
        cached = db.get_verdict("wrapperhash")
        assert cached is not None
        assert cached.verdict == Verdict.MALICIOUS
        # Blocked by the wrapper's TX id / hash
        gateway.block_data.assert_called_once()
        assert scanner.metrics.archive_decodes == 1

    async def test_decode_disabled_scans_wrapper(self):
        scanner, db, gateway = _make_scanner(
            make_singlefilez(EXTERNAL_FORM_PHISHING),
            archive_decode_enabled=False,
        )
        await scanner.process_queue_item(_item())
        # Wrapper shell has no phishing signals → CLEAN, and no decode counted.
        cached = db.get_verdict("wrapperhash")
        assert cached is not None
        assert cached.verdict == Verdict.CLEAN
        assert scanner.metrics.archive_decodes == 0

    async def test_zip_bomb_falls_back_to_wrapper(self):
        bomb = make_singlefilez(
            EXTERNAL_FORM_PHISHING,
            extra_entries={"big.txt": b"0" * 5_000_000},
        )
        scanner, db, gateway = _make_scanner(bomb)
        await scanner.process_queue_item(_item())
        # Extraction refused → wrapper scanned (CLEAN), no crash, no decode.
        cached = db.get_verdict("wrapperhash")
        assert cached is not None
        assert cached.verdict == Verdict.CLEAN
        assert scanner.metrics.archive_decodes == 0

    async def test_plain_html_unaffected(self):
        scanner, db, gateway = _make_scanner(CLEAN_HTML.encode())
        await scanner.process_queue_item(_item())
        cached = db.get_verdict("wrapperhash")
        assert cached is not None
        assert cached.verdict == Verdict.CLEAN
        assert scanner.metrics.archive_decodes == 0

    async def test_large_archive_refetched_past_scan_cap(self):
        # THE REAL-WORLD CASE: a malicious archive larger than MAX_SCAN_BYTES.
        # The first fetch is truncated (ZIP tail lost) so the head marker is
        # present but is_singlefile_archive(truncated) is False. The scanner
        # must re-fetch the full file to decode it — otherwise the phishing
        # page hides behind the wrapper.
        # Incompressible padding so the archive genuinely exceeds the cap
        # (zeros would DEFLATE away to nothing).
        full = make_singlefilez(
            EXTERNAL_FORM_PHISHING,
            extra_entries={"pad.bin": os.urandom(400_000)},
        )
        cap = 262144
        assert len(full) > cap
        truncated = full[:cap]
        assert looks_like_singlefile_head(truncated) is True
        assert is_singlefile_archive(truncated) is False  # tail lost

        fd, db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        db = ScannerDB(db_path)
        db.initialize()
        s = _settings(max_scan_bytes=cap)
        gateway = AsyncMock(spec=GatewayClient)

        # Mock fetch: capped call returns truncated, uncapped call returns full.
        async def fake_fetch(tx_id, max_bytes=None):
            return full if (max_bytes and max_bytes > cap) else truncated
        gateway.fetch_content = AsyncMock(side_effect=fake_fetch)

        scanner = Scanner(s, db, gateway, RuleEngine(s), ScanMetrics())
        await scanner.process_queue_item(_item())

        cached = db.get_verdict("wrapperhash")
        assert cached is not None
        assert cached.verdict == Verdict.MALICIOUS  # decoded + detected
        gateway.block_data.assert_called_once()
        assert scanner.metrics.archive_decodes == 1
        # Confirm the re-fetch actually happened with the larger cap.
        assert any(
            call.kwargs.get("max_bytes", 0) > cap
            for call in gateway.fetch_content.call_args_list
        )

    async def test_non_archive_does_not_trigger_refetch(self):
        # A normal page must not cause a second (expensive) full fetch.
        scanner, db, gateway = _make_scanner(CLEAN_HTML.encode())
        await scanner.process_queue_item(_item())
        assert gateway.fetch_content.call_count == 1
