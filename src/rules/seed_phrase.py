"""Rule 1: Seed Phrase Harvesting

Signals (both required):
  A. 8+ text input elements
  B. Seed phrase terminology in visible text

No legitimate wallet asks users to type seed phrases into a web page.
"""

import re

from bs4 import BeautifulSoup

from src.models import RuleResult
from src.rules.base import Rule

SEED_TERMS = [
    r"recovery\s*phrase",
    r"seed\s*phrase",
    r"mnemonic",
    r"secret\s*words",
    r"backup\s*phrase",
    r"secret\s*phrase",
    r"word\s*#?\s*\d+",
    r"12[\s\-]?word",
    r"24[\s\-]?word",
]


class SeedPhraseRule(Rule):
    @property
    def name(self) -> str:
        return "seed-phrase-harvesting"

    def evaluate(self, html: str, soup: BeautifulSoup) -> RuleResult:
        # Signal A: 8+ text input elements
        text_inputs = soup.find_all(
            "input",
            attrs={
                "type": lambda t: t is None
                or t.lower() in ("text", "password", "")
            },
        )
        input_count = len(text_inputs)
        signal_a = input_count >= 8

        # Signal B: seed phrase terminology in visible text
        visible_text = soup.get_text(separator=" ", strip=True).lower()
        matched_terms = [
            term
            for term in SEED_TERMS
            if re.search(term, visible_text)
        ]
        signal_b = len(matched_terms) > 0

        return RuleResult(
            rule_name=self.name,
            triggered=signal_a and signal_b,
            signals={
                "input_count": input_count,
                "seed_terms_found": matched_terms,
            },
        )
