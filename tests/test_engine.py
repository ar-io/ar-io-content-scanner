"""Tests for the rule engine verdict combination logic."""

from unittest.mock import MagicMock, patch

from src.config import Settings
from src.ml.features import parse_html
from src.models import Verdict
from src.rules.engine import RuleEngine

from tests.fixtures import (
    CLEAN_HTML,
    EXTERNAL_FORM_PHISHING,
    SEED_PHRASE_PHISHING,
)

# Minimal settings for testing with all rules enabled
TEST_SETTINGS = Settings(
    gateway_url="http://localhost:3000",
    admin_api_key="test-key",
    rule_seed_phrase=True,
    rule_external_credential_form=True,
    rule_wallet_impersonation=True,
    rule_obfuscated_loader=True,
)


class TestRuleEngine:
    def test_clean_html_returns_clean(self):
        engine = RuleEngine(TEST_SETTINGS, classifier=None)
        soup = parse_html(CLEAN_HTML)
        result = engine.evaluate(CLEAN_HTML, soup)
        assert result.verdict == Verdict.CLEAN
        assert result.matched_rules == []
        assert result.ml_score is None

    def test_phishing_returns_malicious(self):
        engine = RuleEngine(TEST_SETTINGS, classifier=None)
        soup = parse_html(SEED_PHRASE_PHISHING)
        result = engine.evaluate(SEED_PHRASE_PHISHING, soup)
        assert result.verdict == Verdict.MALICIOUS
        assert len(result.matched_rules) > 0

    def test_external_form_detected(self):
        engine = RuleEngine(TEST_SETTINGS, classifier=None)
        soup = parse_html(EXTERNAL_FORM_PHISHING)
        result = engine.evaluate(EXTERNAL_FORM_PHISHING, soup)
        assert result.verdict == Verdict.MALICIOUS
        assert "external-credential-form" in result.matched_rules

    def test_ml_alone_never_blocks(self):
        """ML score >= 0.95 on clean rules should be SUSPICIOUS, not MALICIOUS."""
        mock_classifier = MagicMock()
        mock_classifier.predict_score.return_value = 0.99

        engine = RuleEngine(TEST_SETTINGS, classifier=mock_classifier)
        soup = parse_html(CLEAN_HTML)
        result = engine.evaluate(CLEAN_HTML, soup)
        assert result.verdict == Verdict.SUSPICIOUS
        assert result.ml_score == 0.99

    def test_ml_below_threshold_stays_clean(self):
        mock_classifier = MagicMock()
        mock_classifier.predict_score.return_value = 0.5

        engine = RuleEngine(TEST_SETTINGS, classifier=mock_classifier)
        soup = parse_html(CLEAN_HTML)
        result = engine.evaluate(CLEAN_HTML, soup)
        assert result.verdict == Verdict.CLEAN
        assert result.ml_score == 0.5

    def test_rules_plus_ml_stays_malicious(self):
        """Rule match + any ML score = MALICIOUS."""
        mock_classifier = MagicMock()
        mock_classifier.predict_score.return_value = 0.1

        engine = RuleEngine(TEST_SETTINGS, classifier=mock_classifier)
        soup = parse_html(SEED_PHRASE_PHISHING)
        result = engine.evaluate(SEED_PHRASE_PHISHING, soup)
        assert result.verdict == Verdict.MALICIOUS

    def test_disabled_rules(self):
        settings = Settings(
            gateway_url="http://localhost:3000",
            admin_api_key="test-key",
            rule_seed_phrase=False,
            rule_external_credential_form=False,
            rule_wallet_impersonation=False,
            rule_obfuscated_loader=False,
        )
        engine = RuleEngine(settings, classifier=None)
        assert len(engine.rules) == 0
        soup = parse_html(SEED_PHRASE_PHISHING)
        result = engine.evaluate(SEED_PHRASE_PHISHING, soup)
        assert result.verdict == Verdict.CLEAN

    def test_scan_duration_recorded(self):
        engine = RuleEngine(TEST_SETTINGS, classifier=None)
        soup = parse_html(CLEAN_HTML)
        result = engine.evaluate(CLEAN_HTML, soup)
        assert result.scan_duration_ms >= 0
