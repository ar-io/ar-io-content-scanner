from __future__ import annotations

"""Rule 4: Obfuscated DOM Loader

Signals (both required):
  A. Script using DOM injection (document.write, innerHTML, eval) with
     encoding functions (unescape, atob, decodeURIComponent, fromCharCode)
  B. Heavy encoding indicators: long base64 strings, hex escapes, or
     fromCharCode chains

Catches phishing kits that encode their payload to evade static analysis.
"""

import re

from bs4 import BeautifulSoup

from src.models import RuleResult
from src.rules.base import Rule

DOM_INJECTION_PATTERNS = [
    r"document\.write\s*\(",
    r"\.innerHTML\s*=",
    r"eval\s*\(",
]

ENCODING_FUNCTIONS = [
    r"unescape\s*\(",
    r"atob\s*\(",
    r"decodeURIComponent\s*\(",
    r"String\.fromCharCode",
]

BASE64_PATTERN = r"[A-Za-z0-9+/=]{100,8192}"
HEX_ESCAPE_PATTERN = r"(?:\\x[0-9a-fA-F]{2}){10,1000}"
CHAR_CODE_CHAIN = r"String\.fromCharCode\([^)]{20,4096}\)"


class ObfuscatedLoaderRule(Rule):
    @property
    def name(self) -> str:
        return "obfuscated-loader"

    def evaluate(self, html: str, soup: BeautifulSoup) -> RuleResult:
        scripts = soup.find_all("script")

        # Signal A: script with DOM injection + encoding
        signal_a = False
        injection_found: list[str] = []
        encoding_found: list[str] = []

        for script in scripts:
            text = script.string or ""
            matched_injection = [
                p for p in DOM_INJECTION_PATTERNS if re.search(p, text)
            ]
            matched_encoding = [
                p for p in ENCODING_FUNCTIONS if re.search(p, text)
            ]
            if matched_injection and matched_encoding:
                signal_a = True
                injection_found.extend(matched_injection)
                encoding_found.extend(matched_encoding)
                break

        # Signal B: heavy encoding indicators
        all_scripts_text = " ".join(s.string or "" for s in scripts)
        has_long_base64 = bool(re.search(BASE64_PATTERN, all_scripts_text))
        has_hex_escapes = bool(re.search(HEX_ESCAPE_PATTERN, all_scripts_text))
        has_charcode_chain = bool(
            re.search(CHAR_CODE_CHAIN, all_scripts_text)
        )
        signal_b = has_long_base64 or has_hex_escapes or has_charcode_chain

        return RuleResult(
            rule_name=self.name,
            triggered=signal_a and signal_b,
            signals={
                "dom_injection_patterns": injection_found,
                "encoding_functions": encoding_found,
                "has_long_base64": has_long_base64,
                "has_hex_escapes": has_hex_escapes,
                "has_charcode_chain": has_charcode_chain,
            },
        )
