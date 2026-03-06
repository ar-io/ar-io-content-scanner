"""Rule 2: Credential Exfiltration via External Communication

Signals (both required):
  A. Password input on the page
  B. External data transmission — either:
     - Form action is an absolute URL (http/https), OR
     - Scripts contain JS exfiltration patterns ($.ajax, $.post, fetch,
       XMLHttpRequest) alongside an external URL

On Arweave there is no server backend. A password field combined with
external data transmission is submitting credentials to a collector.
Real-world phishing kits commonly use JS-based exfil ($.ajax/$.post)
rather than HTML form actions to bypass naive form-action scanners.
"""

from __future__ import annotations

import re

from bs4 import BeautifulSoup

from src.models import RuleResult
from src.rules.base import Rule

JS_EXFIL_PATTERNS = [
    r"\$\s*\.\s*ajax\s*\(",
    r"\$\s*\.\s*post\s*\(",
    r"\bfetch\s*\(",
    r"\bXMLHttpRequest\b",
    r"\$\s*\.\s*get\s*\(",
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
        js_exfil_found = []
        js_has_external_url = False
        if not external_actions:
            all_script_text = " ".join(s.string or "" for s in soup.find_all("script"))
            if all_script_text.strip():
                for pattern in JS_EXFIL_PATTERNS:
                    if re.search(pattern, all_script_text):
                        js_exfil_found.append(pattern)
                if js_exfil_found:
                    js_has_external_url = bool(
                        re.search(EXTERNAL_URL_PATTERN, all_script_text)
                    )

        signal_b = bool(external_actions) or (bool(js_exfil_found) and js_has_external_url)

        return RuleResult(
            rule_name=self.name,
            triggered=signal_a and signal_b,
            signals={
                "has_password_input": has_password,
                "external_form_actions": external_actions,
                "js_exfil_patterns": js_exfil_found,
                "js_has_external_url": js_has_external_url,
            },
        )
