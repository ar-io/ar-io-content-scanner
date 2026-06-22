"""Rule 6: Known credential-harvest kit templates.

Several widespread webmail / single-sign-on phishing kits exfiltrate
credentials with obfuscated or JS-based transmission that the
external-credential-form rule's exfil detection can miss, so they slip
through as ML-only "suspicious" and get *served*.

This rule pins the distinctive, near-zero-false-positive template strings of
those kits. Every signature is gated on a credential context — a password-like
input, or the kit's own pre-filled error state ("Invalid Password! Please
enter your correct password") — so a bare mention of a brand never matches.
"""

from __future__ import annotations

import re

from bs4 import BeautifulSoup

from src.models import RuleResult
from src.rules.base import Rule
from src.rules.utils import has_password_like_input


class CredentialKitRule(Rule):
    @property
    def name(self) -> str:
        return "credential-phishing-kit"

    def evaluate(self, html: str, soup: BeautifulSoup) -> RuleResult:
        # Collapse whitespace so newline-wrapped phrases still match.
        text = re.sub(r"\s+", " ", soup.get_text(separator=" ")).lower()
        title = ""
        if soup.title and soup.title.string:
            title = re.sub(r"\s+", " ", soup.title.string).lower()
        blob = f"{title} {text}"

        has_pw, _ = has_password_like_input(soup)
        # The kit's pre-filled error state is itself a credential context.
        kit_error = "invalid password" in text and "enter your correct password" in text
        cred_context = has_pw or kit_error

        signatures: list[str] = []

        # "Webmail Portal Access" harvest kit.
        if "webmail portal access" in blob and cred_context:
            signatures.append("webmail-portal-access")

        # Generic webmail kit error string (kit-specific phrasing).
        if kit_error:
            signatures.append("invalid-password-prompt")

        # "loading mail settings ..." redirect/loader interstitial.
        if "loading mail settings" in text:
            signatures.append("loading-mail-settings")

        # Zimbra Web Client login clone.
        if "zimbra web client sign in" in blob and has_pw:
            signatures.append("zimbra-login-clone")

        # Office365 / Outlook "Sign in to your account" redirector kit: the
        # visible form is injected client-side (so has_password is often False),
        # but it carries a Microsoft-login brand reference AND hand-rolled JS
        # obfuscation (atob/eval/fromCharCode) that real Microsoft login pages
        # do not use — that pairing is the near-zero-FP anchor.
        low_html = html.lower()
        o365_brand = any(
            b in low_html
            for b in ("office365", "outlook", "msftauth", "login.microsoftonline")
        )
        obfuscated = bool(re.search(r"atob\(|eval\(|fromcharcode", low_html))
        if "sign in to your account" in blob and o365_brand and obfuscated:
            signatures.append("o365-signin-redirector")

        return RuleResult(
            rule_name=self.name,
            triggered=bool(signatures),
            signals={
                "matched_signatures": signatures,
                "has_password_input": has_pw,
                "kit_error_state": kit_error,
            },
        )
