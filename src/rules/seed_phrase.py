"""Rule 1: Seed Phrase Harvesting

Signals (both required):
  A. 6+ text-like input elements (including textarea and contenteditable
     proxies that phishing kits use to evade <input>-only detection)
  B. Seed phrase terminology in visible text

No legitimate wallet asks users to type seed phrases into a web page.
"""
from __future__ import annotations

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
    r"recovery\s*key",
    r"secret\s*backup",
]

# Threshold lowered from 8 to 6.  Phishing kits that use 7 text fields
# (one per partial mnemonic line plus a "paste all" box) previously
# slipped under the radar.  Combined with the mandatory seed-phrase
# terminology signal, 6 keeps false-positive risk low.
INPUT_THRESHOLD = 6


class SeedPhraseRule(Rule):
    @property
    def name(self) -> str:
        return "seed-phrase-harvesting"

    def evaluate(self, html: str, soup: BeautifulSoup) -> RuleResult:
        # Signal A: 6+ text-like input elements
        # Count real <input> fields (text, password, or missing type)
        text_inputs = soup.find_all(
            "input",
            attrs={
                "type": lambda t: t is None
                or t.lower() in ("text", "password", "")
            },
        )
        input_count = len(text_inputs)

        # Also count <textarea> and contenteditable elements as input
        # proxies — phishing kits style these to look like text fields
        textarea_count = len(soup.find_all("textarea"))
        editable_count = len(
            soup.find_all(attrs={"contenteditable": "true"})
        )
        total_inputs = input_count + textarea_count + editable_count

        signal_a = total_inputs >= INPUT_THRESHOLD

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
                "textarea_count": textarea_count,
                "editable_count": editable_count,
                "total_inputs": total_inputs,
                "seed_terms_found": matched_terms,
            },
        )
