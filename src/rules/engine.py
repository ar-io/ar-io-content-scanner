from __future__ import annotations

import logging
import time

from bs4 import BeautifulSoup

from src.config import Settings
from src.ml.classifier import PhishingClassifier
from src.ml.features import extract_features
from src.models import ScanResult, Verdict
from src.rules.base import Rule
from src.rules.external_form import ExternalFormRule
from src.rules.obfuscated_loader import ObfuscatedLoaderRule
from src.rules.seed_phrase import SeedPhraseRule
from src.rules.wallet_impersonation import WalletImpersonationRule

logger = logging.getLogger("scanner.engine")


class RuleEngine:
    def __init__(
        self,
        settings: Settings,
        classifier: PhishingClassifier | None = None,
    ):
        self.classifier = classifier
        self.rules: list[Rule] = []

        if settings.rule_seed_phrase:
            self.rules.append(SeedPhraseRule())
        if settings.rule_external_credential_form:
            self.rules.append(ExternalFormRule())
        if settings.rule_wallet_impersonation:
            self.rules.append(WalletImpersonationRule())
        if settings.rule_obfuscated_loader:
            self.rules.append(ObfuscatedLoaderRule())

        logger.info(
            "Rule engine initialized",
            extra={
                "rules_enabled": [r.name for r in self.rules],
                "ml_enabled": classifier is not None,
            },
        )

    def evaluate(self, html: str, soup: BeautifulSoup) -> ScanResult:
        start = time.monotonic()

        # Run all enabled rules
        rule_results = [rule.evaluate(html, soup) for rule in self.rules]
        triggered = [r for r in rule_results if r.triggered]

        rule_verdict = Verdict.MALICIOUS if triggered else Verdict.CLEAN

        # ML model scoring
        ml_score: float | None = None
        if self.classifier is not None:
            features = extract_features(html, soup)
            ml_score = self.classifier.predict_score(features)

        # Verdict combination matrix:
        #   MALICIOUS + any ML  -> MALICIOUS
        #   CLEAN + ML >= 0.95  -> SUSPICIOUS (ML alone never blocks)
        #   CLEAN + ML < 0.95   -> CLEAN
        if rule_verdict == Verdict.MALICIOUS:
            final = Verdict.MALICIOUS
        elif ml_score is not None and ml_score >= 0.95:
            final = Verdict.SUSPICIOUS
        else:
            final = Verdict.CLEAN

        elapsed_ms = int((time.monotonic() - start) * 1000)

        return ScanResult(
            verdict=final,
            matched_rules=[r.rule_name for r in triggered],
            ml_score=ml_score,
            scan_duration_ms=elapsed_ms,
        )
