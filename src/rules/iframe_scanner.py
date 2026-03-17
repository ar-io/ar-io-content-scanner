"""Extract HTML content from data: URI and srcdoc iframes.

Phishing kits can hide the entire attack inside an iframe with a base64-encoded
data: URI or srcdoc attribute, making the outer HTML appear clean to rule evaluation.
This utility extracts that embedded content so it can be scanned separately.
"""
from __future__ import annotations

import base64
import logging
import re
from urllib.parse import unquote

from bs4 import BeautifulSoup

logger = logging.getLogger("scanner.iframe")

# Match data:text/html with optional charset and base64 encoding
_DATA_HTML_RE = re.compile(
    r"^data:text/html(?:;charset=[^;,]+)?(?:;base64)?,",
    re.IGNORECASE,
)


def extract_iframe_content(soup: BeautifulSoup) -> list[str]:
    """Extract HTML content from data: URI and srcdoc iframes.

    Returns a list of HTML strings, one per iframe with extractable content.
    Does not recurse into nested iframes (single level only).
    """
    results: list[str] = []

    for iframe in soup.find_all("iframe"):
        # srcdoc takes priority over src
        srcdoc = iframe.get("srcdoc")
        if srcdoc and isinstance(srcdoc, str) and srcdoc.strip():
            results.append(srcdoc)
            continue

        src = iframe.get("src")
        if not src or not isinstance(src, str):
            continue

        src = src.strip()
        if not _DATA_HTML_RE.match(src):
            continue

        try:
            if ";base64," in src.lower():
                # data:text/html;base64,ENCODED
                _, encoded = src.split(";base64,", 1)
                html_bytes = base64.b64decode(encoded)
                results.append(html_bytes.decode("utf-8", errors="replace"))
            elif "," in src:
                # data:text/html,URL_ENCODED_HTML
                _, raw = src.split(",", 1)
                results.append(unquote(raw))
        except Exception:
            logger.debug("iframe_decode_failed", extra={"src_prefix": src[:50]})

    return results
