"""Tests for ML feature extraction."""

from src.ml.features import HtmlFeatures, extract_features, parse_html

from tests.fixtures import (
    CLEAN_HTML,
    EXTERNAL_FORM_PHISHING,
    SEED_PHRASE_PHISHING,
)


class TestFeatureExtraction:
    def test_clean_html_features(self):
        features = extract_features(CLEAN_HTML)
        assert features.num_input_fields == 0
        assert features.num_forms == 0
        assert features.has_password_field is False
        assert features.has_obfuscated_script is False

    def test_phishing_html_features(self):
        features = extract_features(SEED_PHRASE_PHISHING)
        assert features.num_input_fields == 12
        assert features.num_forms == 1
        assert features.has_form_with_action is True
        assert features.crypto_keywords > 0

    def test_password_detection(self):
        features = extract_features(EXTERNAL_FORM_PHISHING)
        assert features.has_password_field is True

    def test_feature_vector_length(self):
        features = extract_features(CLEAN_HTML)
        vector = features.to_vector()
        assert len(vector) == 17

    def test_title_analysis(self):
        html = '<html><head><title>Sign In</title></head><body></body></html>'
        features = extract_features(html)
        assert features.has_signin_in_title is True
        assert features.has_generic_title is True  # < 15 chars

    def test_suspicious_title(self):
        html = '<html><head><title>Verify Your Account</title></head><body></body></html>'
        features = extract_features(html)
        assert features.has_suspicious_title is True

    def test_obfuscated_script_detection(self):
        html = """<html><body>
        <script>document.write(unescape('%3Cscript%3E'));</script>
        </body></html>"""
        features = extract_features(html)
        assert features.has_obfuscated_script is True

    def test_parse_html_returns_soup(self):
        soup = parse_html(CLEAN_HTML)
        assert soup.find("title").get_text() == "My Arweave Blog Post"

    def test_extract_with_prebuilt_soup(self):
        soup = parse_html(CLEAN_HTML)
        features = extract_features(CLEAN_HTML, soup)
        assert features.num_input_fields == 0


class TestHtmlFeatures:
    def test_to_vector_order(self):
        f = HtmlFeatures(
            num_input_fields=1,
            num_buttons=2,
            num_forms=3,
            num_tags_within_body=4,
            has_form_with_post=True,
            has_form_with_action=False,
            has_password_field=True,
            has_obfuscated_script=False,
            all_flagged_keywords=5,
            whitelisted_keywords=6,
            title_length=7,
            has_password_in_title=True,
            has_signin_in_title=False,
            has_suspicious_title=True,
            crypto_keywords=8,
            wallet_keywords=9,
            has_generic_title=False,
        )
        v = f.to_vector()
        assert v == [1, 2, 3, 4, True, False, True, False, 5, 6, 7, True, False, True, 8, 9, False]
