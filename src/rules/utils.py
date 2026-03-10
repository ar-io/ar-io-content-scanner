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
