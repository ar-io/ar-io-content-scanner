"""Rule 2: Credential Exfiltration via External Communication

Signals (both required):
  A. Password-like input on the page — either a real <input type=password>,
     or password-like proxy elements (contenteditable, textarea with
     password-related naming)
  B. External data transmission — either:
     - Form action is an absolute URL (http/https), OR
     - Scripts contain strong JS exfiltration patterns ($.ajax, $.post,
       XMLHttpRequest, sendBeacon, WebSocket, Image exfil) alongside
       an external URL, OR
     - Scripts use fetch() with credential-accessing code (.value,
       FormData) alongside an external URL

On Arweave there is no server backend. A password field combined with
external data transmission is submitting credentials to a collector.
Real-world phishing kits commonly use JS-based exfil ($.ajax/$.post)
rather than HTML form actions to bypass naive form-action scanners.

Note: bare fetch() is NOT treated as exfiltration because it's used
by virtually every modern web app for routine API calls.
"""

from __future__ import annotations

from bs4 import BeautifulSoup

from src.models import RuleResult
from src.rules.base import Rule
from src.rules.utils import has_external_data_transmission, has_password_like_input


class ExternalFormRule(Rule):
    @property
    def name(self) -> str:
        return "external-credential-form"

    def evaluate(self, html: str, soup: BeautifulSoup) -> RuleResult:
        # Signal A: password-like input anywhere on the page
        has_password, password_kind = has_password_like_input(soup)
        signal_a = has_password

        # Signal B: external data transmission
        signal_b, exfil_details = has_external_data_transmission(soup)

        return RuleResult(
            rule_name=self.name,
            triggered=signal_a and signal_b,
            signals={
                "has_password_input": has_password,
                "password_input_kind": password_kind,
                **exfil_details,
            },
        )
