from __future__ import annotations

"""Rule 4: Obfuscated DOM Loader

Signals (both required):
  A. Script using DOM injection (document.write, innerHTML, eval — including
     bracket-notation variants) with encoding functions (unescape, atob,
     decodeURIComponent, fromCharCode — including bracket variants).
     Scripts identified as bundler output (webpack, Parcel, Rollup, etc.)
     are exempt — bundlers legitimately use eval() for source maps.
  B. Heavy encoding indicators: long base64 strings, hex escapes, unicode
     escapes, or fromCharCode chains

Catches phishing kits that encode their payload to evade static analysis.
"""

import re

from bs4 import BeautifulSoup

from src.models import RuleResult
from src.rules.base import Rule

# DOM injection patterns — dot notation and bracket notation variants
DOM_INJECTION_PATTERNS = [
    r"document\.write\s*\(",
    r"""document\s*\[\s*[\"']write[\"']\s*\]""",
    r"\.innerHTML\s*[+]?=",
    r"""\[\s*[\"']innerHTML[\"']\s*\]\s*[+]?=""",
    r"\beval\s*\(",
    r"""\[\s*[\"']eval[\"']\s*\]""",
    r"\bFunction\s*\(",  # Function("code")() is eval equivalent
]

# Encoding functions — dot notation and bracket notation variants
ENCODING_FUNCTIONS = [
    r"\bunescape\s*\(",
    r"""\[\s*[\"']unescape[\"']\s*\]""",
    r"\batob\s*\(",
    r"""\[\s*[\"']atob[\"']\s*\]""",
    r"\bdecodeURIComponent\s*\(",
    r"""\[\s*[\"']decodeURIComponent[\"']\s*\]""",
    r"String\.fromCharCode",
    r"""String\s*\[\s*[\"']fromCharCode[\"']\s*\]""",
]

# Bundler signatures — if any of these appear in a script, it's bundler
# output (webpack, Parcel, Rollup, etc.), not hand-crafted obfuscation.
# Phishing kits never ship module infrastructure.
BUNDLER_SIGNATURES = [
    r"__webpack_require__",
    r"__webpack_modules__",
    r"__webpack_exports__",
    r"webpackChunk\w*",
    r"webpackJsonp",
    r"parcelRequire",
    r"__NEXT_DATA__",
    r"__vite_ssr_import__",
    r"__vite_ssr_dynamic_import__",
    r"__turbopack_modules__",
    r"__turbopack_require__",
    r"System\.register\s*\(",
]

BASE64_PATTERN = r"[A-Za-z0-9+/=]{100,8192}"
# URL-safe base64 variant (uses - and _ instead of + and /)
BASE64_URLSAFE_PATTERN = r"[A-Za-z0-9\-_=]{100,8192}"
HEX_ESCAPE_PATTERN = r"(?:\\x[0-9a-fA-F]{2}){10,1000}"
# Unicode escapes: \u0048\u0065\u006C\u006C\u006F
UNICODE_ESCAPE_PATTERN = r"(?:\\u[0-9a-fA-F]{4}){10,500}"
# Match fromCharCode with 4+ numeric literals — real obfuscation encodes
# strings as comma-separated integers: fromCharCode(104,116,116,112)
# This excludes library code like jQuery which uses variable expressions:
# fromCharCode(n >> 10 | 55296, 1023 & n | 56320)
CHAR_CODE_CHAIN = r"String\.fromCharCode\(\s*\d+\s*(?:,\s*\d+\s*){3,}\)"
# Bracket-notation variant of the above
CHAR_CODE_CHAIN_BRACKET = (
    r"""String\s*\[\s*[\"']fromCharCode[\"']\s*\]\(\s*\d+\s*(?:,\s*\d+\s*){3,}\)"""
)


class ObfuscatedLoaderRule(Rule):
    @property
    def name(self) -> str:
        return "obfuscated-loader"

    def evaluate(self, html: str, soup: BeautifulSoup) -> RuleResult:
        scripts = soup.find_all("script")

        # Signal A: script with DOM injection + encoding
        # Scripts with bundler signatures are exempt — bundlers like webpack
        # legitimately use eval() for dev source maps and innerHTML for DOM
        # manipulation. Phishing kits use hand-crafted obfuscation instead.
        signal_a = False
        is_bundler = False
        injection_found: list[str] = []
        encoding_found: list[str] = []

        for script in scripts:
            text = script.get_text()
            if any(re.search(p, text) for p in BUNDLER_SIGNATURES):
                is_bundler = True
                continue
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

        # Also check raw HTML for bundler patterns — when HTML is truncated
        # mid-script (e.g. large webpack bundles exceeding MAX_SCAN_BYTES),
        # BeautifulSoup may not parse the script content, but the bundler
        # boilerplate is still present in the raw HTML string.
        if not is_bundler:
            is_bundler = any(re.search(p, html) for p in BUNDLER_SIGNATURES)

        # Signal B: heavy encoding indicators
        all_scripts_text = " ".join(s.get_text() for s in scripts)
        has_long_base64 = bool(
            re.search(BASE64_PATTERN, all_scripts_text)
            or re.search(BASE64_URLSAFE_PATTERN, all_scripts_text)
        )
        has_hex_escapes = bool(re.search(HEX_ESCAPE_PATTERN, all_scripts_text))
        has_unicode_escapes = bool(
            re.search(UNICODE_ESCAPE_PATTERN, all_scripts_text)
        )
        has_charcode_chain = bool(
            re.search(CHAR_CODE_CHAIN, all_scripts_text)
            or re.search(CHAR_CODE_CHAIN_BRACKET, all_scripts_text)
        )
        signal_b = (
            has_long_base64
            or has_hex_escapes
            or has_unicode_escapes
            or has_charcode_chain
        )

        return RuleResult(
            rule_name=self.name,
            triggered=signal_a and signal_b and not is_bundler,
            signals={
                "dom_injection_patterns": injection_found,
                "encoding_functions": encoding_found,
                "has_long_base64": has_long_base64,
                "has_hex_escapes": has_hex_escapes,
                "has_unicode_escapes": has_unicode_escapes,
                "has_charcode_chain": has_charcode_chain,
                "is_bundler": is_bundler,
            },
        )
