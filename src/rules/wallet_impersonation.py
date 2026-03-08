"""Rule 3: Wallet UI Impersonation with Credential Capture

Signals (both required):
  A. Known crypto brand name in title, h1-h3, or img alt text
     (with Unicode normalization to catch homoglyph attacks)
  B. Credential capture: password-like inputs (including proxies) or
     key-phrase terminology near inputs

Real wallet UIs render as browser extension popups, not in-page HTML forms.
"""
from __future__ import annotations

import re
import unicodedata

from bs4 import BeautifulSoup

from src.models import RuleResult
from src.rules.base import Rule
from src.rules.utils import has_password_like_input as _has_password_like_input_full

WALLET_BRANDS = [
    "metamask",
    "phantom",
    "ledger",
    "trezor",
    "trust wallet",
    "coinbase wallet",
    "exodus",
    "rabby",
    "walletconnect",
    "blockchain.com",
    "crypto.com",
    "binance",
    "keplr",
    "solflare",
    "backpack",
    "rainbow",
]

KEY_PHRASES = [
    "private key",
    "enter your phrase",
    "enter phrase",
    "enter your seed",
    "secret recovery",
    "import wallet",
    "recovery phrase",
    "seed phrase",
]

# Common Cyrillic/Greek/other homoglyphs that look identical to Latin chars.
# These are the characters most abused in brand impersonation.
_HOMOGLYPH_MAP = str.maketrans({
    "\u0430": "a",  # Cyrillic а
    "\u0435": "e",  # Cyrillic е
    "\u043e": "o",  # Cyrillic о
    "\u0440": "p",  # Cyrillic р
    "\u0441": "c",  # Cyrillic с
    "\u0443": "y",  # Cyrillic у (looks like y)
    "\u0445": "x",  # Cyrillic х
    "\u0456": "i",  # Cyrillic і
    "\u0458": "j",  # Cyrillic ј
    "\u04bb": "h",  # Cyrillic һ
    "\u0410": "A",  # Cyrillic А
    "\u0412": "B",  # Cyrillic В
    "\u0415": "E",  # Cyrillic Е
    "\u041a": "K",  # Cyrillic К
    "\u041c": "M",  # Cyrillic М
    "\u041d": "H",  # Cyrillic Н
    "\u041e": "O",  # Cyrillic О
    "\u0420": "P",  # Cyrillic Р
    "\u0421": "C",  # Cyrillic С
    "\u0422": "T",  # Cyrillic Т
    "\u0425": "X",  # Cyrillic Х
    "\u03bf": "o",  # Greek ο
    "\u03b1": "a",  # Greek α
    "\u03b5": "e",  # Greek ε
})


def _normalize_text(text: str) -> str:
    """Normalize text for brand matching.

    - Replaces common Cyrillic/Greek homoglyphs with their Latin equivalents.
    - NFKD decomposition collapses fullwidth chars and other compatibility forms.
    - Strips soft hyphens, zero-width chars, and combining marks.
    - Collapses whitespace so "Meta Mask" matches "metamask".
    """
    # Replace known homoglyphs first (NFKD doesn't handle cross-script)
    text = text.translate(_HOMOGLYPH_MAP)
    # NFKD decomposes fullwidth and other compatibility characters
    text = unicodedata.normalize("NFKD", text)
    # Strip combining marks (accents left after decomposition)
    text = "".join(c for c in text if unicodedata.category(c) != "Mn")
    # Strip zero-width and soft-hyphen characters
    text = re.sub(r"[\u00ad\u200b\u200c\u200d\ufeff]", "", text)
    # Collapse whitespace for split-brand matching (e.g. "Meta Mask")
    text = re.sub(r"\s+", "", text)
    return text.lower()


def _has_password_like_input(soup: BeautifulSoup) -> bool:
    """Detect password inputs including proxy elements."""
    found, _ = _has_password_like_input_full(soup)
    return found


class WalletImpersonationRule(Rule):
    @property
    def name(self) -> str:
        return "wallet-impersonation"

    def evaluate(self, html: str, soup: BeautifulSoup) -> RuleResult:
        # Signal A: brand name in prominent elements (with normalization)
        prominent_text = ""
        for tag in soup.find_all(["title", "h1", "h2", "h3"]):
            prominent_text += " " + tag.get_text()
        for img in soup.find_all("img", alt=True):
            prominent_text += " " + img["alt"]

        prominent_normalized = _normalize_text(prominent_text)
        matched_brands = [
            brand
            for brand in WALLET_BRANDS
            # Normalize brand too (strip spaces) for consistent comparison
            if brand.replace(" ", "") in prominent_normalized
        ]
        signal_a = len(matched_brands) > 0

        # Signal B: credential capture — password input (including proxies)
        has_password = _has_password_like_input(soup)
        visible_text = soup.get_text().lower()
        matched_phrases = [
            p for p in KEY_PHRASES if p in visible_text
        ]
        # Key phrases strengthen the signal but require a password input to
        # confirm credential capture. Pages that merely discuss crypto
        # terminology (blogs, dApps) often mention "seed phrase" or "private
        # key" without actually harvesting credentials. The seed-phrase rule
        # separately covers 6+ text inputs with seed terminology.
        signal_b = has_password

        return RuleResult(
            rule_name=self.name,
            triggered=signal_a and signal_b,
            signals={
                "matched_brands": matched_brands,
                "has_password_input": has_password,
                "matched_key_phrases": matched_phrases,
            },
        )
