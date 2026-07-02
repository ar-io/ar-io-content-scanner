"""Extract Arweave TX IDs from abuse report email content.

Ports the extraction logic from the legacy suspected-txs Lambda (JavaScript)
to Python. Three strategies in priority order:

1. URL-based extraction (gateway URLs like arweave.net/<txid>)
2. Sandbox subdomain extraction (base32-encoded TX IDs in subdomains)
3. Standalone TX ID fallback (bare 43-char base64url strings)

URL + sandbox extraction is tried first. Standalone is only used as a fallback
when no URL/sandbox matches are found, since standalone matching can produce
false positives from DKIM signatures and other email header fragments.
"""
from __future__ import annotations

import base64
import re


# ---------------------------------------------------------------------------
# Base32 sandbox decoding helpers
# ---------------------------------------------------------------------------

_BASE32_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567"


def _base32_decode(encoded: str) -> bytes | None:
    """Decode a base32 (RFC 4648 lowercase) string to bytes.

    Returns None if the input contains invalid characters.
    """
    cleaned = encoded.lower()
    output: list[int] = []
    bits = 0
    value = 0

    for char in cleaned:
        idx = _BASE32_ALPHABET.find(char)
        if idx == -1:
            return None
        value = (value << 5) | idx
        bits += 5
        if bits >= 8:
            bits -= 8
            output.append((value >> bits) & 0xFF)

    return bytes(output)


def _to_base64url(data: bytes) -> str:
    """Encode bytes to base64url without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


# ---------------------------------------------------------------------------
# URL-based TX ID extraction
# ---------------------------------------------------------------------------

# Each gateway domain pattern captures a 43-char base64url TX ID from the path.
# The TX ID must be followed by a terminator: #, ?, /, whitespace, quote,
# angle bracket, or end of string.
_GATEWAY_URL_PATTERNS: list[re.Pattern[str]] = [
    re.compile(
        r"arweave\.net/([a-zA-Z0-9_-]{43})(?=[#?/\s\"'<>]|$)"
    ),
    re.compile(
        r"ar\.io/([a-zA-Z0-9_-]{43})(?=[#?/\s\"'<>]|$)"
    ),
    re.compile(
        r"ar-io\.net/([a-zA-Z0-9_-]{43})(?=[#?/\s\"'<>]|$)"
    ),
    re.compile(
        r"ar-io\.dev/([a-zA-Z0-9_-]{43})(?=[#?/\s\"'<>]|$)"
    ),
    re.compile(
        r"ardrive\.net/([a-zA-Z0-9_-]{43})(?=[#?/\s\"'<>]|$)"
    ),
    re.compile(
        r"turbo-gateway\.com/([a-zA-Z0-9_-]{43})(?=[#?/\s\"'<>]|$)"
    ),
    re.compile(
        r"ar://([a-zA-Z0-9_-]{43})(?=[#?/\s\"'<>]|$)"
    ),
]


def extract_tx_ids_from_urls(content: str) -> list[str]:
    """Extract TX IDs from known Arweave gateway URLs.

    Matches TX IDs in URL paths for all supported gateway domains
    and the ar:// protocol.
    """
    tx_ids: set[str] = set()
    for pattern in _GATEWAY_URL_PATTERNS:
        for match in pattern.finditer(content):
            tx_ids.add(match.group(1))
    return list(tx_ids)


# ---------------------------------------------------------------------------
# Sandbox subdomain extraction
# ---------------------------------------------------------------------------

# Matches 52-char base32 subdomains of gateway domains.
# Handles both normal dots and defanged [.] notation common in abuse reports.
_SANDBOX_PATTERN = re.compile(
    r"\b([a-z2-7]{52})"
    r"(?:\[\.\]|\.)"
    r"(?:turbo-gateway|arweave|ar-io|ardrive|ar)"
    r"(?:\[\.\]|\.)"
    r"(?:com|net|dev|io)\b",
    re.IGNORECASE,
)


def extract_tx_ids_from_sandbox_subdomains(content: str) -> list[str]:
    """Extract TX IDs from sandbox subdomains (base32-encoded).

    Sandbox URLs encode 32-byte TX IDs as 52-char base32 subdomains:
        <52-char-base32>.turbo-gateway.com

    Also handles defanged URLs: turbo-gateway[.]com
    """
    tx_ids: set[str] = set()
    for match in _SANDBOX_PATTERN.finditer(content):
        base32_str = match.group(1).lower()
        decoded = _base32_decode(base32_str)
        if decoded is not None and len(decoded) == 32:
            tx_id = _to_base64url(decoded)
            if len(tx_id) == 43:
                tx_ids.add(tx_id)
    return list(tx_ids)


# ---------------------------------------------------------------------------
# Standalone TX ID fallback
# ---------------------------------------------------------------------------

_STANDALONE_PATTERN = re.compile(
    r"[/\n ][a-zA-Z0-9_-]{43}(?![a-zA-Z0-9_-])"
)


def extract_standalone_tx_ids(content: str) -> list[str]:
    """Extract standalone 43-char base64url TX IDs.

    Matches TX IDs preceded by ``/``, newline, or space. This is a
    low-confidence fallback -- it may match DKIM fragments and other
    non-TX-ID strings in email headers.

    The leading delimiter is stripped to return bare TX IDs.
    """
    matches = _STANDALONE_PATTERN.findall(content)
    if not matches:
        return []

    tx_ids: list[str] = []
    for entry in matches:
        # Remove newline/space prefix
        cleaned = entry.replace("\n", "").replace(" ", "")
        # Remove everything up to and including the last /
        cleaned = re.sub(r".*/", "", cleaned)
        tx_ids.append(cleaned)
    return tx_ids


# ---------------------------------------------------------------------------
# Combined extraction
# ---------------------------------------------------------------------------


def extract_all_tx_ids(text: str, html: str = "") -> list[str]:
    """Extract TX IDs from email content using all strategies.

    Combines ``text`` and ``html`` bodies, then:
    1. Tries URL-based extraction (highest confidence)
    2. Tries sandbox subdomain extraction
    3. If any URL/sandbox matches found, returns those (deduplicated)
    4. Otherwise falls back to standalone extraction (may have false positives)

    Returns a deduplicated list of TX IDs.
    """
    combined = f"{text}\n{html}"

    # URL-based extraction (most reliable)
    url_tx_ids = extract_tx_ids_from_urls(combined)

    # Sandbox subdomain extraction
    sandbox_tx_ids = extract_tx_ids_from_sandbox_subdomains(combined)

    combined_url_tx_ids = url_tx_ids + sandbox_tx_ids

    if combined_url_tx_ids:
        # Deduplicate while preserving order
        seen: set[str] = set()
        result: list[str] = []
        for tx_id in combined_url_tx_ids:
            if tx_id not in seen:
                seen.add(tx_id)
                result.append(tx_id)
        return result

    # Fallback: standalone regex for emails with bare TX IDs
    standalone_tx_ids = extract_standalone_tx_ids(combined)

    # Deduplicate
    seen = set()
    result = []
    for tx_id in standalone_tx_ids:
        if tx_id not in seen:
            seen.add(tx_id)
            result.append(tx_id)
    return result
