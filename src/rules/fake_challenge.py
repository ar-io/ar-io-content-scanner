"""Rule 5: Fake browser / connection-verification cloak pages.

Fake Cloudflare "checking your connection" / "browser verification"
interstitials are credential-phishing CLOAK gates: they impersonate a
security challenge and redirect to (or front) a credential-harvest page.
They carry no password field of their own, so the external-credential-form
rule does not catch them — they score high on the ML model but land as
ML-only "suspicious" and get *served*.

On Arweave (permanent storage) there is no legitimate reason to host a live
security-challenge interstitial, and these kits carry distinctive artifacts:

  - the verbatim sentence "... needs to review the security of your connection
    before proceeding" (real Cloudflare wording differs),
  - a fake "did you know ... the first botnet in 2003 took over ..." trivia
    line unique to one widespread kit,
  - a "browser check in progress" + "detected unusual traffic from your
    network" / "confirm that you're not a robot" combination,
  - Portuguese-localised variants of the same.

The two `_UNIQUE_SIGNATURES` are near-zero-false-positive on their own. The
broader `_CLOAK_PHRASES` (which a genuinely-archived real Cloudflare page
could share) require a second `_CORROBORATOR` before triggering, so a single
generic phrase never blocks by itself.
"""

from __future__ import annotations

import re

from bs4 import BeautifulSoup

from src.models import RuleResult
from src.rules.base import Rule

# One match is enough — these strings do not appear on legitimate pages.
_UNIQUE_SIGNATURES = (
    "needs to review the security of your connection before proceeding",
    "the first botnet in 2003 took over",
)

# Cloak phrases that a real (archived) challenge page could also contain —
# require a corroborator before triggering.
_CLOAK_PHRASES = (
    "browser check in progress",
    "checking if the site connection is secure",
    "checking your browser before",
    "verificação do navegador em andamento",
)

_CORROBORATORS = (
    "detected unusual traffic from your network",
    "detectamos um tráfego incomum da sua rede",
    "confirm that you're not a robot",
    "this page will help confirm",
)


class FakeChallengeRule(Rule):
    @property
    def name(self) -> str:
        return "fake-challenge-page"

    def evaluate(self, html: str, soup: BeautifulSoup) -> RuleResult:
        # Collapse whitespace so newline-wrapped phrases still match.
        text = re.sub(r"\s+", " ", soup.get_text(separator=" ")).lower()

        unique = [s for s in _UNIQUE_SIGNATURES if s in text]
        cloak = [s for s in _CLOAK_PHRASES if s in text]
        corroborators = [s for s in _CORROBORATORS if s in text]

        triggered = bool(unique) or (bool(cloak) and bool(corroborators))

        return RuleResult(
            rule_name=self.name,
            triggered=triggered,
            signals={
                "unique_signatures": unique,
                "cloak_phrases": cloak,
                "corroborators": corroborators,
            },
        )
