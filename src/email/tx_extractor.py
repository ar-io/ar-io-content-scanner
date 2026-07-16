"""Extract Arweave TX IDs from abuse report email content.

Ports the extraction logic from the legacy suspected-txs Lambda (JavaScript)
to Python. Four strategies in priority order:

1. URL-based extraction (gateway URLs like arweave.net/<txid>)
2. ArNS name extraction (subdomain URLs like angelferno.ar.io — returns names,
   which the caller resolves to TX IDs via the gateway)
3. Sandbox subdomain extraction (base32-encoded TX IDs in subdomains)
4. Standalone TX ID fallback (bare 43-char base64url strings)

URL + ArNS + sandbox extraction is tried first. Standalone is only used as a
fallback when no other matches are found, since standalone matching can produce
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
# ArNS name extraction
# ---------------------------------------------------------------------------

# Default gateway domains that serve ArNS names as subdomains.
# Overridden at runtime via Settings.arns_gateway_domains.
_DEFAULT_ARNS_DOMAINS = ("ar.io", "turbo-gateway.com", "ardrive.net", "ar-io.dev")


def _build_arns_pattern(domains: tuple[str, ...]) -> re.Pattern[str]:
    """Build a regex that matches ArNS subdomains on the given gateway domains.

    Matches URLs like:
        http://angelferno.ar.io
        https://something.turbo-gateway.com/path
        angelferno[.]ar[.]io  (defanged)

    Excludes:
        - 52-char base32 sandbox subdomains (handled by sandbox extraction)
        - Bare domain with no subdomain (e.g., ar.io itself)
    """
    escaped = [d.replace(".", r"(?:\[\.\]|\.)") for d in domains]
    domain_alt = "|".join(escaped)
    return re.compile(
        r"(?:https?://|//)?([a-zA-Z0-9][a-zA-Z0-9_-]{0,50})"  # ArNS name (1-51 chars, not 52 = sandbox)
        r"(?:\[\.\]|\.)"  # dot or defanged dot
        r"(?:" + domain_alt + r")"
        r"(?=[/\s\"'<>#?]|$)",  # terminator
        re.IGNORECASE,
    )


_ARNS_PATTERN = _build_arns_pattern(_DEFAULT_ARNS_DOMAINS)


def extract_arns_names(
    content: str,
    domains: tuple[str, ...] | None = None,
) -> list[str]:
    """Extract ArNS names from URLs with gateway subdomains.

    Returns a list of ArNS names (NOT TX IDs). The caller must resolve
    these to TX IDs via the gateway's ``/ar-io/resolver/{name}`` endpoint.

    Args:
        content: Email body text to search.
        domains: Gateway domains to match. Defaults to common ar.io domains.
    """
    pattern = (
        _build_arns_pattern(domains) if domains is not None else _ARNS_PATTERN
    )
    names: set[str] = set()
    for match in pattern.finditer(content):
        name = match.group(1).lower()
        # Skip 52-char matches (those are sandbox subdomains, not ArNS)
        if len(name) == 52:
            continue
        names.add(name)
    return list(names)


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


class ExtractionResult:
    """Result of TX ID / ArNS name extraction from an email."""

    __slots__ = ("tx_ids", "arns_names")

    def __init__(self, tx_ids: list[str], arns_names: list[str]):
        self.tx_ids = tx_ids
        self.arns_names = arns_names


def extract_all(
    text: str,
    html: str = "",
    arns_domains: tuple[str, ...] | None = None,
) -> ExtractionResult:
    """Extract TX IDs and ArNS names from email content.

    Combines ``text`` and ``html`` bodies, then:
    1. Tries URL-based extraction (highest confidence)
    2. Tries ArNS name extraction (subdomain URLs like angelferno.ar.io)
    3. Tries sandbox subdomain extraction (base32-encoded TX IDs)
    4. If any URL/sandbox matches found, returns those + ArNS names
    5. Otherwise falls back to standalone extraction (may have false positives)

    Returns an ``ExtractionResult`` with deduplicated TX IDs and ArNS names.
    ArNS names need to be resolved to TX IDs by the caller via the gateway.
    """
    combined = f"{text}\n{html}"

    # URL-based extraction (most reliable)
    url_tx_ids = extract_tx_ids_from_urls(combined)

    # ArNS name extraction
    arns_names = extract_arns_names(combined, domains=arns_domains)

    # Sandbox subdomain extraction
    sandbox_tx_ids = extract_tx_ids_from_sandbox_subdomains(combined)

    combined_url_tx_ids = url_tx_ids + sandbox_tx_ids

    if combined_url_tx_ids or arns_names:
        seen: set[str] = set()
        result: list[str] = []
        for tx_id in combined_url_tx_ids:
            if tx_id not in seen:
                seen.add(tx_id)
                result.append(tx_id)
        return ExtractionResult(tx_ids=result, arns_names=arns_names)

    # Fallback: standalone regex for emails with bare TX IDs
    standalone_tx_ids = extract_standalone_tx_ids(combined)

    seen: set[str] = set()
    result: list[str] = []
    for tx_id in standalone_tx_ids:
        if tx_id not in seen:
            seen.add(tx_id)
            result.append(tx_id)
    return ExtractionResult(tx_ids=result, arns_names=[])


def extract_all_tx_ids(text: str, html: str = "") -> list[str]:
    """Legacy wrapper — returns only TX IDs (no ArNS names).

    Kept for backward compatibility. New callers should use ``extract_all()``.
    """
    return extract_all(text, html).tx_ids
