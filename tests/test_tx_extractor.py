"""Tests for TX ID extraction from abuse report emails."""
from __future__ import annotations

import base64

import pytest

from src.email.tx_extractor import (
    extract_all_tx_ids,
    extract_standalone_tx_ids,
    extract_tx_ids_from_sandbox_subdomains,
    extract_tx_ids_from_urls,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# A valid 43-char base64url TX ID (32 bytes of 0xAA)
SAMPLE_TX_ID = base64.urlsafe_b64encode(b"\xaa" * 32).rstrip(b"=").decode()
assert len(SAMPLE_TX_ID) == 43

# A second distinct TX ID (32 bytes of 0xBB)
SAMPLE_TX_ID_2 = base64.urlsafe_b64encode(b"\xbb" * 32).rstrip(b"=").decode()
assert len(SAMPLE_TX_ID_2) == 43


def _base32_encode_tx(tx_id: str) -> str:
    """Encode a base64url TX ID to a 52-char base32 subdomain."""
    padding = 4 - len(tx_id) % 4
    if padding != 4:
        padded = tx_id + "=" * padding
    else:
        padded = tx_id
    raw = base64.urlsafe_b64decode(padded)
    return base64.b32encode(raw).decode().lower().rstrip("=")


SAMPLE_BASE32 = _base32_encode_tx(SAMPLE_TX_ID)
assert len(SAMPLE_BASE32) == 52


# ---------------------------------------------------------------------------
# URL extraction
# ---------------------------------------------------------------------------


class TestUrlExtraction:
    def test_arweave_net(self):
        content = f"Please review https://arweave.net/{SAMPLE_TX_ID} for phishing"
        result = extract_tx_ids_from_urls(content)
        assert SAMPLE_TX_ID in result

    def test_ar_io(self):
        content = f"See https://ar.io/{SAMPLE_TX_ID}#section"
        result = extract_tx_ids_from_urls(content)
        assert SAMPLE_TX_ID in result

    def test_ar_io_net(self):
        content = f"URL: https://ar-io.net/{SAMPLE_TX_ID}?v=1"
        result = extract_tx_ids_from_urls(content)
        assert SAMPLE_TX_ID in result

    def test_ar_io_dev(self):
        content = f"https://ar-io.dev/{SAMPLE_TX_ID}/index.html"
        result = extract_tx_ids_from_urls(content)
        assert SAMPLE_TX_ID in result

    def test_ardrive_net(self):
        content = f"https://ardrive.net/{SAMPLE_TX_ID} is malicious"
        result = extract_tx_ids_from_urls(content)
        assert SAMPLE_TX_ID in result

    def test_turbo_gateway_com(self):
        content = f'<a href="https://turbo-gateway.com/{SAMPLE_TX_ID}">link</a>'
        result = extract_tx_ids_from_urls(content)
        assert SAMPLE_TX_ID in result

    def test_ar_protocol(self):
        content = f"ar://{SAMPLE_TX_ID}"
        result = extract_tx_ids_from_urls(content)
        assert SAMPLE_TX_ID in result

    def test_ar_protocol_with_query(self):
        content = f"ar://{SAMPLE_TX_ID}?format=html"
        result = extract_tx_ids_from_urls(content)
        assert SAMPLE_TX_ID in result

    def test_multiple_domains(self):
        content = (
            f"https://arweave.net/{SAMPLE_TX_ID}\n"
            f"https://ar.io/{SAMPLE_TX_ID_2}"
        )
        result = extract_tx_ids_from_urls(content)
        assert SAMPLE_TX_ID in result
        assert SAMPLE_TX_ID_2 in result

    def test_html_entities_in_urls(self):
        content = f'href="https://arweave.net/{SAMPLE_TX_ID}"'
        result = extract_tx_ids_from_urls(content)
        assert SAMPLE_TX_ID in result

    def test_url_followed_by_angle_bracket(self):
        content = f"<https://arweave.net/{SAMPLE_TX_ID}>"
        result = extract_tx_ids_from_urls(content)
        assert SAMPLE_TX_ID in result

    def test_url_followed_by_single_quote(self):
        content = f"'https://arweave.net/{SAMPLE_TX_ID}'"
        result = extract_tx_ids_from_urls(content)
        assert SAMPLE_TX_ID in result

    def test_no_match_short_id(self):
        content = "https://arweave.net/short"
        result = extract_tx_ids_from_urls(content)
        assert result == []

    def test_no_match_long_id(self):
        content = f"https://arweave.net/{SAMPLE_TX_ID}X"
        result = extract_tx_ids_from_urls(content)
        # Should not match because the 44th char makes it non-matching
        assert result == []

    def test_no_match_unknown_domain(self):
        content = f"https://example.com/{SAMPLE_TX_ID}"
        result = extract_tx_ids_from_urls(content)
        assert result == []


# ---------------------------------------------------------------------------
# Sandbox subdomain extraction
# ---------------------------------------------------------------------------


class TestSandboxSubdomainExtraction:
    def test_turbo_gateway_sandbox(self):
        content = f"https://{SAMPLE_BASE32}.turbo-gateway.com/path"
        result = extract_tx_ids_from_sandbox_subdomains(content)
        assert SAMPLE_TX_ID in result

    def test_arweave_net_sandbox(self):
        content = f"https://{SAMPLE_BASE32}.arweave.net"
        result = extract_tx_ids_from_sandbox_subdomains(content)
        assert SAMPLE_TX_ID in result

    def test_ar_io_dev_sandbox(self):
        content = f"https://{SAMPLE_BASE32}.ar-io.dev/index.html"
        result = extract_tx_ids_from_sandbox_subdomains(content)
        assert SAMPLE_TX_ID in result

    def test_ardrive_io_sandbox(self):
        content = f"https://{SAMPLE_BASE32}.ardrive.io"
        result = extract_tx_ids_from_sandbox_subdomains(content)
        assert SAMPLE_TX_ID in result

    def test_ar_com_sandbox(self):
        content = f"https://{SAMPLE_BASE32}.ar.com"
        result = extract_tx_ids_from_sandbox_subdomains(content)
        assert SAMPLE_TX_ID in result

    def test_defanged_url(self):
        content = f"{SAMPLE_BASE32}[.]turbo-gateway[.]com"
        result = extract_tx_ids_from_sandbox_subdomains(content)
        assert SAMPLE_TX_ID in result

    def test_defanged_url_mixed(self):
        content = f"{SAMPLE_BASE32}.turbo-gateway[.]com"
        result = extract_tx_ids_from_sandbox_subdomains(content)
        assert SAMPLE_TX_ID in result

    def test_case_insensitive(self):
        upper = SAMPLE_BASE32.upper()
        content = f"https://{upper}.turbo-gateway.com"
        result = extract_tx_ids_from_sandbox_subdomains(content)
        assert SAMPLE_TX_ID in result

    def test_invalid_base32_chars(self):
        # base32 only uses a-z and 2-7, not 0, 1, 8, 9
        bad = "0" * 52
        content = f"https://{bad}.turbo-gateway.com"
        result = extract_tx_ids_from_sandbox_subdomains(content)
        assert result == []

    def test_wrong_length_subdomain(self):
        content = f"https://{'a' * 51}.turbo-gateway.com"
        result = extract_tx_ids_from_sandbox_subdomains(content)
        assert result == []


# ---------------------------------------------------------------------------
# Standalone TX ID extraction
# ---------------------------------------------------------------------------


class TestStandaloneExtraction:
    def test_preceded_by_slash(self):
        content = f"/{SAMPLE_TX_ID}"
        result = extract_standalone_tx_ids(content)
        assert SAMPLE_TX_ID in result

    def test_preceded_by_newline(self):
        content = f"some text\n{SAMPLE_TX_ID}\nmore text"
        result = extract_standalone_tx_ids(content)
        assert SAMPLE_TX_ID in result

    def test_preceded_by_space(self):
        content = f"TX ID: {SAMPLE_TX_ID} here"
        result = extract_standalone_tx_ids(content)
        assert SAMPLE_TX_ID in result

    def test_no_match_at_start_of_string(self):
        content = f"{SAMPLE_TX_ID}"
        result = extract_standalone_tx_ids(content)
        assert result == []

    def test_no_match_longer_string(self):
        # 44 chars should not match
        content = f" {SAMPLE_TX_ID}X"
        result = extract_standalone_tx_ids(content)
        assert result == []

    def test_multiple_standalone(self):
        content = f" {SAMPLE_TX_ID}\n{SAMPLE_TX_ID_2}"
        result = extract_standalone_tx_ids(content)
        assert SAMPLE_TX_ID in result
        assert SAMPLE_TX_ID_2 in result

    def test_empty_content(self):
        result = extract_standalone_tx_ids("")
        assert result == []


# ---------------------------------------------------------------------------
# Combined extraction (extract_all_tx_ids)
# ---------------------------------------------------------------------------


class TestExtractAllTxIds:
    def test_url_preferred_over_standalone(self):
        """When URLs are present, standalone matches are NOT used."""
        content = (
            f"https://arweave.net/{SAMPLE_TX_ID}\n"
            f" {SAMPLE_TX_ID_2}"
        )
        result = extract_all_tx_ids(content)
        assert SAMPLE_TX_ID in result
        # SAMPLE_TX_ID_2 is only in standalone -- should NOT be included
        # when URL matches exist
        assert SAMPLE_TX_ID_2 not in result

    def test_sandbox_preferred_over_standalone(self):
        content = (
            f"{SAMPLE_BASE32}.turbo-gateway.com\n"
            f" {SAMPLE_TX_ID_2}"
        )
        result = extract_all_tx_ids(content)
        assert SAMPLE_TX_ID in result
        assert SAMPLE_TX_ID_2 not in result

    def test_url_and_sandbox_combined(self):
        content = (
            f"https://arweave.net/{SAMPLE_TX_ID}\n"
            f"{SAMPLE_BASE32}.turbo-gateway.com"
        )
        result = extract_all_tx_ids(content)
        assert SAMPLE_TX_ID in result

    def test_fallback_to_standalone(self):
        content = f" {SAMPLE_TX_ID}"
        result = extract_all_tx_ids(content)
        assert SAMPLE_TX_ID in result

    def test_deduplication(self):
        content = (
            f"https://arweave.net/{SAMPLE_TX_ID}\n"
            f"https://ar.io/{SAMPLE_TX_ID}"
        )
        result = extract_all_tx_ids(content)
        assert result.count(SAMPLE_TX_ID) == 1

    def test_deduplication_standalone(self):
        content = f" {SAMPLE_TX_ID}\n{SAMPLE_TX_ID}"
        result = extract_all_tx_ids(content)
        assert result.count(SAMPLE_TX_ID) == 1

    def test_empty_content(self):
        result = extract_all_tx_ids("", "")
        assert result == []

    def test_no_tx_ids(self):
        result = extract_all_tx_ids("This is a normal email with no TX IDs")
        assert result == []

    def test_text_and_html_combined(self):
        text = f"See https://arweave.net/{SAMPLE_TX_ID}"
        html = f'<a href="https://ar.io/{SAMPLE_TX_ID_2}">link</a>'
        result = extract_all_tx_ids(text, html)
        assert SAMPLE_TX_ID in result
        assert SAMPLE_TX_ID_2 in result

    def test_dkim_false_positive_avoided_when_urls_present(self):
        """DKIM signatures look like base64url strings but are not TX IDs.
        When URL matches exist, standalone (which would catch DKIM) is skipped."""
        dkim_fragment = "a" * 43  # looks like a TX ID
        content = (
            f"https://arweave.net/{SAMPLE_TX_ID}\n"
            f" {dkim_fragment}"
        )
        result = extract_all_tx_ids(content)
        assert SAMPLE_TX_ID in result
        assert dkim_fragment not in result

    def test_defanged_sandbox_url(self):
        content = f"{SAMPLE_BASE32}[.]turbo-gateway[.]com"
        result = extract_all_tx_ids(content)
        assert SAMPLE_TX_ID in result

    def test_ar_protocol_in_html(self):
        html = f'<p>ar://{SAMPLE_TX_ID}</p>'
        result = extract_all_tx_ids("", html)
        assert SAMPLE_TX_ID in result

    def test_mixed_url_and_standalone_only_returns_urls(self):
        """When both URL-based and standalone matches exist,
        only URL-based results are returned."""
        standalone_only = base64.urlsafe_b64encode(b"\xcc" * 32).rstrip(b"=").decode()
        content = (
            f"https://arweave.net/{SAMPLE_TX_ID}\n"
            f"\n{standalone_only}"
        )
        result = extract_all_tx_ids(content)
        assert SAMPLE_TX_ID in result
        assert standalone_only not in result
