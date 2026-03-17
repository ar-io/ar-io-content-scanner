from __future__ import annotations

import re

from bs4 import BeautifulSoup

# Attribute names/values that indicate a password-like purpose.
# Uses letter boundaries ((?<![a-zA-Z]) / (?![a-zA-Z])) instead of \b
# to avoid substring matches like "compass", "bypass", "passenger" while
# still matching underscored compound names like "password_input" or
# "user_password" (since \b treats _ as a word character).
_PASSWORD_ATTR_RE = re.compile(
    r"(?<![a-zA-Z])(?:pass(?:word|wd|code)?|pwd|passwd|secret.?key|private.?key)(?![a-zA-Z])",
    re.IGNORECASE,
)


def has_password_like_input(soup: BeautifulSoup) -> tuple[bool, str]:
    """Detect password inputs including proxy elements that mimic them.

    Returns (found, description) for signal reporting.
    """
    # Standard password input
    if soup.find("input", attrs={"type": "password"}):
        return True, "input[type=password]"

    # Textarea with password-related naming
    for ta in soup.find_all("textarea"):
        attrs_text = " ".join(
            " ".join(ta.get(a)) if isinstance(ta.get(a), list) else str(ta.get(a, ""))
            for a in ("name", "id", "placeholder", "class")
        )
        if _PASSWORD_ATTR_RE.search(attrs_text):
            return True, "textarea[password-named]"

    # Contenteditable element with password-related naming
    for el in soup.find_all(attrs={"contenteditable": "true"}):
        attrs_text = " ".join(
            " ".join(el.get(a)) if isinstance(el.get(a), list) else str(el.get(a, ""))
            for a in ("id", "class", "data-placeholder", "aria-label")
        )
        if _PASSWORD_ATTR_RE.search(attrs_text):
            return True, "contenteditable[password-named]"

    return False, ""


# --- Shared exfiltration detection ---

# Strong exfil patterns: explicitly data-sending functions that are
# highly suspicious on static Arweave pages.
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
    r"\bnew\s+RTCPeerConnection\s*\(",         # WebRTC data exfil
    r"\bnavigator\s*\.\s*serviceWorker\s*\.\s*register\s*\(",  # SW registration
]

CREDENTIAL_ACCESS_PATTERNS = [
    r"""getElementById\s*\([^)]+\)\s*\.?\s*(?:\[\s*['"]\s*)?value""",
    r"""querySelector\w*\s*\([^)]+\)\s*\.?\s*(?:\[\s*['"]\s*)?value""",
    r"""getElementsBy\w+\s*\([^)]+\)\s*(?:\[\d+\]\s*)?\.?\s*(?:\[\s*['"]\s*)?value""",
    r"\bFormData\b",
    r"""\$\s*\([^)]+\)\s*\.\s*val\s*\(""",
]

EXTERNAL_URL_PATTERN = r"(?:https?|wss?)://[^\s\"'`)>]{1,2048}"


def has_external_data_transmission(soup: BeautifulSoup) -> tuple[bool, dict]:
    """Detect external data transmission via form actions or JS exfiltration.

    Returns (found, details_dict) where details_dict contains:
    - external_form_actions: list of absolute form action URLs
    - strong_exfil_patterns: list of matched JS exfil patterns
    - fetch_with_creds: bool
    - js_has_external_url: bool
    """
    external_actions: list[str] = []
    for form in soup.find_all("form"):
        action = form.get("action", "")
        if action.startswith(("http://", "https://", "//")):
            external_actions.append(action)

    strong_exfil_found: list[str] = []
    fetch_with_creds = False
    js_has_external_url = False

    if not external_actions:
        all_script_text = " ".join(
            s.get_text() for s in soup.find_all("script")
        )
        if all_script_text.strip():
            for pattern in STRONG_EXFIL_PATTERNS:
                if re.search(pattern, all_script_text):
                    strong_exfil_found.append(pattern)

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

            if strong_exfil_found or fetch_with_creds:
                js_has_external_url = bool(
                    re.search(EXTERNAL_URL_PATTERN, all_script_text)
                )

    found = (
        bool(external_actions)
        or (bool(strong_exfil_found) and js_has_external_url)
        or (fetch_with_creds and js_has_external_url)
    )

    details = {
        "external_form_actions": external_actions,
        "strong_exfil_patterns": strong_exfil_found,
        "fetch_with_creds": fetch_with_creds,
        "js_has_external_url": js_has_external_url,
    }
    return found, details
