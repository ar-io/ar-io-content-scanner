"""Rule 3: Wallet UI Impersonation with Credential Capture

Signals (both required):
  A. Known crypto brand name in title, h1-h3, or img alt text
  B. Credential capture: password inputs or key-phrase terminology near inputs

Real wallet UIs render as browser extension popups, not in-page HTML forms.
"""

from bs4 import BeautifulSoup

from src.models import RuleResult
from src.rules.base import Rule

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


class WalletImpersonationRule(Rule):
    @property
    def name(self) -> str:
        return "wallet-impersonation"

    def evaluate(self, html: str, soup: BeautifulSoup) -> RuleResult:
        # Signal A: brand name in prominent elements
        prominent_text = ""
        for tag in soup.find_all(["title", "h1", "h2", "h3"]):
            prominent_text += " " + tag.get_text()
        for img in soup.find_all("img", alt=True):
            prominent_text += " " + img["alt"]

        prominent_lower = prominent_text.lower()
        matched_brands = [
            brand for brand in WALLET_BRANDS if brand in prominent_lower
        ]
        signal_a = len(matched_brands) > 0

        # Signal B: credential capture elements
        has_password = bool(
            soup.find("input", attrs={"type": "password"})
        )
        visible_text = soup.get_text().lower()
        matched_phrases = [
            p for p in KEY_PHRASES if p in visible_text
        ]
        # Key phrases strengthen the signal but require a password input to
        # confirm credential capture. Pages that merely discuss crypto
        # terminology (blogs, dApps) often mention "seed phrase" or "private
        # key" without actually harvesting credentials. The seed-phrase rule
        # separately covers 8+ text inputs with seed terminology.
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
