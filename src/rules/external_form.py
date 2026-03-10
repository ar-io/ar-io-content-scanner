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

import re

from bs4 import BeautifulSoup

from src.models import RuleResult
from src.rules.base import Rule
from src.rules.utils import has_password_like_input

# Strong exfil patterns: explicitly data-sending functions that are
# highly suspicious on static Arweave pages.  Includes bracket-notation
# variants (e.g. $["ajax"]) and fire-and-forget APIs.
STRONG_EXFIL_PATTERNS = [
    r"\$\s*\.\s*ajax\s*\(",                 # $.ajax(
    r"\$\s*\[\s*[\"']ajax[\"']\s*\]",       # $["ajax"] / $['ajax']
    r"\$\s*\.\s*post\s*\(",                 # $.post(
    r"\$\s*\[\s*[\"']post[\"']\s*\]",       # $["post"] / $['post']
    r"\bXMLHttpRequest\b",                   # new XMLHttpRequest
    r"""\[\s*[\"']XMLHttpRequest[\"']\s*\]""",  # window["XMLHttpRequest"]
    r"\bnavigator\s*\.\s*sendBeacon\s*\(",   # navigator.sendBeacon(
    r"\bnew\s+WebSocket\s*\(",               # new WebSocket(
    r"\bnew\s+Image\s*\(\s*\)\s*\.\s*src\s*=",  # new Image().src =
]

# Patterns that indicate script code is reading credential input values
# (used to corroborate fetch() as credential exfiltration).
# Matches DOM element lookups followed by .value access, but NOT plain
# variable.value (e.g. slider.value, volume.value) which is common in
# legitimate apps. On static Arweave pages, reading form input values
# via DOM APIs and exfiltrating them externally is inherently suspicious.
CREDENTIAL_ACCESS_PATTERNS = [
    # getElementById("x").value or getElementById("x")["value"]
    r"""getElementById\s*\([^)]+\)\s*\.?\s*(?:\[\s*['"]\s*)?value""",
    # querySelector/querySelectorAll("x").value
    r"""querySelector\w*\s*\([^)]+\)\s*\.?\s*(?:\[\s*['"]\s*)?value""",
    # getElementsByName/ClassName/TagName("x")[n].value
    r"""getElementsBy\w+\s*\([^)]+\)\s*(?:\[\d+\]\s*)?\.?\s*(?:\[\s*['"]\s*)?value""",
    # FormData packaging form data — inherently captures all fields
    r"\bFormData\b",
    # jQuery val() — $("selector").val()
    r"""\$\s*\([^)]+\)\s*\.\s*val\s*\(""",
]

EXTERNAL_URL_PATTERN = r"(?:https?|wss?)://[^\s\"'`)>]{1,2048}"


class ExternalFormRule(Rule):
    @property
    def name(self) -> str:
        return "external-credential-form"

    def evaluate(self, html: str, soup: BeautifulSoup) -> RuleResult:
        # Signal A: password-like input anywhere on the page
        has_password, password_kind = has_password_like_input(soup)
        signal_a = has_password

        # Signal B path 1: form action is an absolute URL
        external_actions = []
        for form in soup.find_all("form"):
            action = form.get("action", "")
            if action.startswith(("http://", "https://", "//")):
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
                # Check strong exfil patterns
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
                "password_input_kind": password_kind,
                "external_form_actions": external_actions,
                "strong_exfil_patterns": strong_exfil_found,
                "fetch_with_creds": fetch_with_creds,
                "js_has_external_url": js_has_external_url,
            },
        )
