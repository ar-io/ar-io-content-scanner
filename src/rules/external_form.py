"""Rule 2: Credential Exfiltration via External Communication

Signals (both required):
  A. Password input on the page
  B. External data transmission — either:
     - Form action is an absolute URL (http/https), OR
     - Scripts contain strong JS exfiltration patterns ($.ajax, $.post,
       XMLHttpRequest) alongside an external URL, OR
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

import re

from bs4 import BeautifulSoup

from src.models import RuleResult
from src.rules.base import Rule

# Strong exfil patterns: these are explicitly data-sending functions
# that are highly suspicious on static Arweave pages
STRONG_EXFIL_PATTERNS = [
    r"\$\s*\.\s*ajax\s*\(",
    r"\$\s*\.\s*post\s*\(",
    r"\bXMLHttpRequest\b",
]

# Patterns that indicate script code is reading credential input values
# (used to corroborate fetch() as credential exfiltration)
CREDENTIAL_ACCESS_PATTERNS = [
    r"\.value\b",        # reading input.value
    r"\bFormData\b",     # packaging form data
]

EXTERNAL_URL_PATTERN = r"https?://[^\s\"'`)>]{1,2048}"


class ExternalFormRule(Rule):
    @property
    def name(self) -> str:
        return "external-credential-form"

    def evaluate(self, html: str, soup: BeautifulSoup) -> RuleResult:
        # Signal A: password input anywhere on the page
        has_password = bool(
            soup.find("input", attrs={"type": "password"})
        )
        signal_a = has_password

        # Signal B path 1: form action is an absolute URL
        external_actions = []
        for form in soup.find_all("form"):
            action = form.get("action", "")
            if action.startswith(("http://", "https://")):
                external_actions.append(action)

        # Signal B path 2: JS exfiltration patterns in scripts
        strong_exfil_found = []
        fetch_with_creds = False
        js_has_external_url = False

        if not external_actions:
            all_script_text = " ".join(
                s.get_text() for s in soup.find_all("script")
            )
            if all_script_text.strip():
                # Check strong exfil patterns ($.ajax, $.post, XHR)
                for pattern in STRONG_EXFIL_PATTERNS:
                    if re.search(pattern, all_script_text):
                        strong_exfil_found.append(pattern)

                # Check fetch() with credential-accessing code
                if not strong_exfil_found:
                    has_fetch = bool(
                        re.search(r"\bfetch\s*\(", all_script_text)
                    )
                    if has_fetch:
                        has_cred_access = any(
                            re.search(p, all_script_text)
                            for p in CREDENTIAL_ACCESS_PATTERNS
                        )
                        if has_cred_access:
                            fetch_with_creds = True

                # Check for external URL in scripts
                if strong_exfil_found or fetch_with_creds:
                    js_has_external_url = bool(
                        re.search(EXTERNAL_URL_PATTERN, all_script_text)
                    )

        signal_b = (
            bool(external_actions)
            or (bool(strong_exfil_found) and js_has_external_url)
            or (fetch_with_creds and js_has_external_url)
        )

        return RuleResult(
            rule_name=self.name,
            triggered=signal_a and signal_b,
            signals={
                "has_password_input": has_password,
                "external_form_actions": external_actions,
                "strong_exfil_patterns": strong_exfil_found,
                "fetch_with_creds": fetch_with_creds,
                "js_has_external_url": js_has_external_url,
            },
        )
