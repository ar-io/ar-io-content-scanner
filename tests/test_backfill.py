"""Tests for the backfill filesystem sweep scanner."""
from __future__ import annotations

import asyncio
import base64
import os
import sqlite3
import tempfile

import pytest

from src.backfill import BackfillScanner, GatewayDBReader, b64url_decode, b64url_encode
from src.config import Settings
from src.db import ScannerDB
from src.metrics import ScanMetrics
from src.models import Verdict
from src.rules.engine import RuleEngine

from tests.fixtures import (
    CLEAN_HTML,
    EXTERNAL_FORM_PHISHING,
    NOT_HTML_CONTENT,
    SEED_PHRASE_PHISHING,
)


# --- Helpers ---


def make_hash_str(index: int) -> str:
    """Create a deterministic 43-char base64url string for testing."""
    raw = bytes([index % 256]) * 32
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def place_file(data_dir: str, hash_str: str, content: bytes) -> str:
    """Create a file in the bucket structure: data/{h[0:2]}/{h[2:4]}/{hash_str}."""
    bucket1 = hash_str[:2]
    bucket2 = hash_str[2:4]
    dirpath = os.path.join(data_dir, "data", bucket1, bucket2)
    os.makedirs(dirpath, exist_ok=True)
    filepath = os.path.join(dirpath, hash_str)
    with open(filepath, "wb") as f:
        f.write(content)
    return filepath


def create_gateway_db(db_path: str, mappings: dict) -> None:
    """Create a minimal gateway data.db with hash->TX ID mappings.

    mappings: {hash_str: [tx_id_str, ...]}
    """
    conn = sqlite3.connect(db_path)
    conn.execute(
        """CREATE TABLE contiguous_data_ids (
            id BLOB PRIMARY KEY,
            contiguous_data_hash BLOB
        )"""
    )
    for hash_str, tx_ids in mappings.items():
        hash_bytes = b64url_decode(hash_str)
        for tx_id_str in tx_ids:
            tx_bytes = b64url_decode(tx_id_str)
            conn.execute(
                "INSERT INTO contiguous_data_ids (id, contiguous_data_hash) VALUES (?, ?)",
                (tx_bytes, hash_bytes),
            )
    conn.commit()
    conn.close()


def make_settings(
    tmpdir: str,
    gateway_db_path: str = "",
    mode: str = "dry-run",
    rate: int = 100,
) -> Settings:
    return Settings(
        gateway_url="http://unused",
        admin_api_key="unused",
        scanner_mode=mode,
        db_path=os.path.join(tmpdir, "scanner.db"),
        backfill_enabled=True,
        backfill_data_path=tmpdir,
        backfill_gateway_db_path=gateway_db_path,
        backfill_rate=rate,
        backfill_interval_hours=0,
    )


class FakeGatewayClient:
    """Minimal stand-in for GatewayClient that records block_data calls."""

    def __init__(self) -> None:
        self.blocked: list = []

    async def block_data(
        self, tx_id: str, content_hash: str, matched_rules: list
    ) -> bool:
        self.blocked.append(
            {"tx_id": tx_id, "hash": content_hash, "rules": matched_rules}
        )
        return True

    async def close(self) -> None:
        pass


# --- Tests ---


class TestB64UrlHelpers:
    def test_roundtrip(self):
        original = b"\x00\x01\x02\xff" * 8
        encoded = b64url_encode(original)
        assert b64url_decode(encoded) == original

    def test_no_padding(self):
        encoded = b64url_encode(b"\x00" * 32)
        assert "=" not in encoded
        assert len(encoded) == 43


class TestGatewayDBReader:
    def test_get_tx_ids_for_hash(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "data.db")
            hash1 = make_hash_str(1)
            tx1 = make_hash_str(10)
            tx2 = make_hash_str(11)
            create_gateway_db(db_path, {hash1: [tx1, tx2]})

            reader = GatewayDBReader(db_path)
            hash_bytes = b64url_decode(hash1)
            tx_ids = reader.get_tx_ids_for_hash(hash_bytes)
            reader.close()

            assert len(tx_ids) == 2
            assert tx1 in tx_ids
            assert tx2 in tx_ids

    def test_no_results(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "data.db")
            create_gateway_db(db_path, {})

            reader = GatewayDBReader(db_path)
            tx_ids = reader.get_tx_ids_for_hash(b"\x00" * 32)
            reader.close()

            assert tx_ids == []


class TestBackfillSweep:
    def _make_env(self, mode="dry-run"):
        """Create temp dirs, DB, engine, and return all components."""
        tmpdir = tempfile.mkdtemp()
        gateway_db_path = os.path.join(tmpdir, "gateway_data.db")

        settings = make_settings(
            tmpdir, gateway_db_path=gateway_db_path, mode=mode
        )
        db = ScannerDB(settings.db_path)
        db.initialize()
        engine = RuleEngine(settings)
        gateway = FakeGatewayClient()
        metrics = ScanMetrics()
        scanner = BackfillScanner(settings, db, engine, gateway, metrics)

        return tmpdir, gateway_db_path, settings, db, engine, gateway, metrics, scanner

    def test_empty_directory(self):
        tmpdir, _, _, db, _, _, metrics, scanner = self._make_env()
        # No data/ subdirectory at all
        stats = asyncio.get_event_loop().run_until_complete(scanner.sweep())
        assert stats["total_files"] == 0
        assert stats["scanned"] == 0
        db.close()

    def test_skips_non_html(self):
        tmpdir, _, _, db, _, _, metrics, scanner = self._make_env()

        hash_str = make_hash_str(1)
        place_file(tmpdir, hash_str, b'{"json": true}')

        stats = asyncio.get_event_loop().run_until_complete(scanner.sweep())

        assert stats["total_files"] == 1
        assert stats["skipped_not_html"] == 1
        assert stats["scanned"] == 0
        # Should be cached as SKIPPED
        assert db.has_verdict(hash_str)
        cached = db.get_verdict(hash_str)
        assert cached.verdict == Verdict.SKIPPED
        db.close()

    def test_scans_clean_html(self):
        tmpdir, _, _, db, _, _, metrics, scanner = self._make_env()

        hash_str = make_hash_str(2)
        place_file(tmpdir, hash_str, CLEAN_HTML.encode())

        stats = asyncio.get_event_loop().run_until_complete(scanner.sweep())

        assert stats["total_files"] == 1
        assert stats["scanned"] == 1
        assert stats["clean"] == 1
        assert db.has_verdict(hash_str)
        cached = db.get_verdict(hash_str)
        assert cached.verdict == Verdict.CLEAN
        db.close()

    def test_detects_malicious_html(self):
        tmpdir, _, _, db, _, _, metrics, scanner = self._make_env()

        hash_str = make_hash_str(3)
        place_file(tmpdir, hash_str, SEED_PHRASE_PHISHING.encode())

        stats = asyncio.get_event_loop().run_until_complete(scanner.sweep())

        assert stats["scanned"] == 1
        assert stats["malicious"] == 1
        cached = db.get_verdict(hash_str)
        assert cached.verdict == Verdict.MALICIOUS
        assert "seed-phrase-harvesting" in cached.matched_rules
        db.close()

    def test_skips_already_cached(self):
        tmpdir, _, settings, db, _, _, metrics, scanner = self._make_env()

        hash_str = make_hash_str(4)
        place_file(tmpdir, hash_str, SEED_PHRASE_PHISHING.encode())

        # Pre-populate the verdict cache
        db.save_verdict(
            content_hash=hash_str,
            tx_id="pre-existing",
            verdict=Verdict.MALICIOUS,
            matched_rules='["seed-phrase-harvesting"]',
            ml_score=None,
            scanner_version="0.1.0",
        )

        stats = asyncio.get_event_loop().run_until_complete(scanner.sweep())

        assert stats["total_files"] == 1
        assert stats["skipped_cached"] == 1
        assert stats["scanned"] == 0
        db.close()

    def test_second_sweep_skips_everything(self):
        tmpdir, _, _, db, _, _, metrics, scanner = self._make_env()

        h1 = make_hash_str(5)
        h2 = make_hash_str(6)
        place_file(tmpdir, h1, CLEAN_HTML.encode())
        place_file(tmpdir, h2, b"\x89PNG\r\n\x1a\n fake png")

        # First sweep scans everything
        stats1 = asyncio.get_event_loop().run_until_complete(scanner.sweep())
        assert stats1["scanned"] == 1
        assert stats1["skipped_not_html"] == 1
        assert stats1["skipped_cached"] == 0

        # Second sweep: all cached
        stats2 = asyncio.get_event_loop().run_until_complete(scanner.sweep())
        assert stats2["scanned"] == 0
        assert stats2["skipped_not_html"] == 0
        assert stats2["skipped_cached"] == 2
        db.close()

    def test_mixed_content(self):
        tmpdir, _, _, db, _, _, metrics, scanner = self._make_env()

        h_clean = make_hash_str(10)
        h_phish = make_hash_str(11)
        h_json = make_hash_str(12)
        h_ext = make_hash_str(13)

        place_file(tmpdir, h_clean, CLEAN_HTML.encode())
        place_file(tmpdir, h_phish, SEED_PHRASE_PHISHING.encode())
        place_file(tmpdir, h_json, b'{"not": "html"}')
        place_file(tmpdir, h_ext, EXTERNAL_FORM_PHISHING.encode())

        stats = asyncio.get_event_loop().run_until_complete(scanner.sweep())

        assert stats["total_files"] == 4
        assert stats["scanned"] == 3  # clean + 2 phishing
        assert stats["skipped_not_html"] == 1
        assert stats["malicious"] == 2
        assert stats["clean"] == 1

        assert db.get_verdict(h_clean).verdict == Verdict.CLEAN
        assert db.get_verdict(h_phish).verdict == Verdict.MALICIOUS
        assert db.get_verdict(h_json).verdict == Verdict.SKIPPED
        assert db.get_verdict(h_ext).verdict == Verdict.MALICIOUS
        db.close()

    def test_blocking_in_enforce_mode(self):
        tmpdir, gw_db_path, _, db, _, gateway, metrics, scanner = (
            self._make_env(mode="enforce")
        )

        hash_str = make_hash_str(20)
        tx_id_str = make_hash_str(21)

        place_file(tmpdir, hash_str, SEED_PHRASE_PHISHING.encode())
        create_gateway_db(gw_db_path, {hash_str: [tx_id_str]})

        stats = asyncio.get_event_loop().run_until_complete(scanner.sweep())

        assert stats["malicious"] == 1
        assert stats["blocked"] == 1
        assert len(gateway.blocked) == 1
        assert gateway.blocked[0]["tx_id"] == tx_id_str
        assert gateway.blocked[0]["hash"] == hash_str
        db.close()

    def test_enforce_without_gateway_db(self):
        """Malicious hit in enforce mode but no gateway DB — can't block."""
        tmpdir = tempfile.mkdtemp()
        settings = make_settings(tmpdir, gateway_db_path="", mode="enforce")
        db = ScannerDB(settings.db_path)
        db.initialize()
        engine = RuleEngine(settings)
        gateway = FakeGatewayClient()
        metrics = ScanMetrics()
        scanner = BackfillScanner(settings, db, engine, gateway, metrics)

        hash_str = make_hash_str(30)
        place_file(tmpdir, hash_str, SEED_PHRASE_PHISHING.encode())

        stats = asyncio.get_event_loop().run_until_complete(scanner.sweep())

        assert stats["malicious"] == 1
        assert stats["blocked"] == 0
        assert len(gateway.blocked) == 0
        # But verdict is still cached
        assert db.get_verdict(hash_str).verdict == Verdict.MALICIOUS
        db.close()

    def test_multiple_tx_ids_per_hash(self):
        """Same content hash referenced by multiple TX IDs — all get blocked."""
        tmpdir, gw_db_path, _, db, _, gateway, metrics, scanner = (
            self._make_env(mode="enforce")
        )

        hash_str = make_hash_str(40)
        tx1 = make_hash_str(41)
        tx2 = make_hash_str(42)
        tx3 = make_hash_str(43)

        place_file(tmpdir, hash_str, SEED_PHRASE_PHISHING.encode())
        create_gateway_db(gw_db_path, {hash_str: [tx1, tx2, tx3]})

        stats = asyncio.get_event_loop().run_until_complete(scanner.sweep())

        assert stats["malicious"] == 1
        assert stats["blocked"] == 3
        assert len(gateway.blocked) == 3
        blocked_tx_ids = {b["tx_id"] for b in gateway.blocked}
        assert blocked_tx_ids == {tx1, tx2, tx3}
        db.close()

    def test_metrics_updated(self):
        tmpdir, _, _, db, _, _, metrics, scanner = self._make_env()

        place_file(tmpdir, make_hash_str(50), CLEAN_HTML.encode())
        place_file(tmpdir, make_hash_str(51), SEED_PHRASE_PHISHING.encode())
        place_file(tmpdir, make_hash_str(52), b"not html")

        asyncio.get_event_loop().run_until_complete(scanner.sweep())

        assert metrics.backfill_sweeps_completed == 1
        assert metrics.backfill_files_scanned == 3  # 2 scanned + 1 skipped_not_html
        assert metrics.backfill_malicious_found == 1
        assert metrics.scans_total == 2  # only actual scans
        db.close()

    def test_dry_run_does_not_block(self):
        tmpdir, gw_db_path, _, db, _, gateway, metrics, scanner = (
            self._make_env(mode="dry-run")
        )

        hash_str = make_hash_str(60)
        tx_id_str = make_hash_str(61)

        place_file(tmpdir, hash_str, SEED_PHRASE_PHISHING.encode())
        create_gateway_db(gw_db_path, {hash_str: [tx_id_str]})

        stats = asyncio.get_event_loop().run_until_complete(scanner.sweep())

        assert stats["malicious"] == 1
        assert stats["blocked"] == 0
        assert len(gateway.blocked) == 0
        db.close()
