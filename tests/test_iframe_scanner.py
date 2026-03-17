"""Tests for iframe content extraction utility."""
from __future__ import annotations

import base64

from src.ml.features import parse_html
from src.rules.iframe_scanner import extract_iframe_content


class TestExtractIframeContent:
    def test_data_uri_base64_iframe(self):
        inner = "<html><body><h1>Phishing</h1></body></html>"
        encoded = base64.b64encode(inner.encode()).decode()
        html = f'<html><body><iframe src="data:text/html;base64,{encoded}"></iframe></body></html>'
        soup = parse_html(html)
        results = extract_iframe_content(soup)
        assert len(results) == 1
        assert "<h1>Phishing</h1>" in results[0]

    def test_data_uri_plain_iframe(self):
        html = '<html><body><iframe src="data:text/html,%3Ch1%3EHello%3C%2Fh1%3E"></iframe></body></html>'
        soup = parse_html(html)
        results = extract_iframe_content(soup)
        assert len(results) == 1
        assert "<h1>Hello</h1>" in results[0]

    def test_srcdoc_iframe(self):
        html = """<html><body><iframe srcdoc="<h1>Phantom</h1><input type='password'>"></iframe></body></html>"""
        soup = parse_html(html)
        results = extract_iframe_content(soup)
        assert len(results) == 1
        assert "Phantom" in results[0]
        assert "password" in results[0]

    def test_regular_url_iframe_ignored(self):
        html = '<html><body><iframe src="https://example.com/page"></iframe></body></html>'
        soup = parse_html(html)
        results = extract_iframe_content(soup)
        assert len(results) == 0

    def test_no_iframes(self):
        html = "<html><body><p>Hello</p></body></html>"
        soup = parse_html(html)
        results = extract_iframe_content(soup)
        assert len(results) == 0

    def test_malformed_base64_handled(self):
        html = '<html><body><iframe src="data:text/html;base64,!!!invalid!!!"></iframe></body></html>'
        soup = parse_html(html)
        results = extract_iframe_content(soup)
        assert len(results) == 0

    def test_srcdoc_takes_priority_over_src(self):
        html = '<html><body><iframe srcdoc="<p>from srcdoc</p>" src="https://example.com"></iframe></body></html>'
        soup = parse_html(html)
        results = extract_iframe_content(soup)
        assert len(results) == 1
        assert "from srcdoc" in results[0]

    def test_multiple_iframes(self):
        inner1 = base64.b64encode(b"<p>first</p>").decode()
        inner2 = base64.b64encode(b"<p>second</p>").decode()
        html = f"""<html><body>
        <iframe src="data:text/html;base64,{inner1}"></iframe>
        <iframe src="data:text/html;base64,{inner2}"></iframe>
        </body></html>"""
        soup = parse_html(html)
        results = extract_iframe_content(soup)
        assert len(results) == 2

    def test_data_uri_base64_case_insensitive(self):
        """BASE64 in uppercase should still be decoded."""
        inner = "<html><body><h1>Test</h1></body></html>"
        encoded = base64.b64encode(inner.encode()).decode()
        html = f'<html><body><iframe src="data:text/html;BASE64,{encoded}"></iframe></body></html>'
        soup = parse_html(html)
        results = extract_iframe_content(soup)
        assert len(results) == 1
        assert "<h1>Test</h1>" in results[0]

    def test_data_uri_with_charset(self):
        inner = "<p>test</p>"
        encoded = base64.b64encode(inner.encode()).decode()
        html = f'<html><body><iframe src="data:text/html;charset=utf-8;base64,{encoded}"></iframe></body></html>'
        soup = parse_html(html)
        results = extract_iframe_content(soup)
        assert len(results) == 1
        assert "test" in results[0]
