"""Tests for webhook payload normalization."""
from __future__ import annotations

import base64

import pytest

from src.models import (
    WebhookData,
    WebhookPayload,
    _b64url_decode,
    _extract_content_type_from_tags,
    _safe_int,
)

TX1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"


def _b64url_encode(s: str) -> str:
    return base64.urlsafe_b64encode(s.encode()).decode().rstrip("=")


class TestB64urlDecode:
    def test_decode_padded(self):
        assert _b64url_decode("aGVsbG8") == "hello"

    def test_decode_known_arweave_tag(self):
        encoded = _b64url_encode("Content-Type")
        assert _b64url_decode(encoded) == "Content-Type"

    def test_decode_with_url_safe_chars(self):
        encoded = _b64url_encode("text/html")
        assert _b64url_decode(encoded) == "text/html"


class TestSafeInt:
    def test_int_passthrough(self):
        assert _safe_int(1024) == 1024

    def test_string_to_int(self):
        assert _safe_int("1024") == 1024

    def test_none_returns_none(self):
        assert _safe_int(None) is None

    def test_invalid_string_returns_none(self):
        assert _safe_int("not-a-number") is None

    def test_float_truncates(self):
        assert _safe_int(10.9) == 10


class TestContentTypeExtraction:
    def test_extract_content_type(self):
        tags = [
            {"name": _b64url_encode("Content-Type"), "value": _b64url_encode("text/html")},
        ]
        assert _extract_content_type_from_tags(tags) == "text/html"

    def test_case_insensitive(self):
        tags = [
            {"name": _b64url_encode("content-type"), "value": _b64url_encode("image/png")},
        ]
        assert _extract_content_type_from_tags(tags) == "image/png"

    def test_no_content_type_tag(self):
        tags = [
            {"name": _b64url_encode("App-Name"), "value": _b64url_encode("MyApp")},
        ]
        assert _extract_content_type_from_tags(tags) is None

    def test_empty_tags(self):
        assert _extract_content_type_from_tags([]) is None

    def test_malformed_tag_skipped(self):
        tags = [
            {"name": "!!!invalid-base64", "value": "also-bad"},
            {"name": _b64url_encode("Content-Type"), "value": _b64url_encode("text/html")},
        ]
        assert _extract_content_type_from_tags(tags) == "text/html"

    def test_multiple_tags_returns_first_match(self):
        tags = [
            {"name": _b64url_encode("App-Name"), "value": _b64url_encode("MyApp")},
            {"name": _b64url_encode("Content-Type"), "value": _b64url_encode("application/json")},
        ]
        assert _extract_content_type_from_tags(tags) == "application/json"


class TestPayloadNormalization:
    def test_data_cached_passthrough(self):
        payload = WebhookPayload.model_validate({
            "event": "data-cached",
            "data": {
                "id": TX1,
                "hash": "abc123",
                "dataSize": 1024,
                "contentType": "text/html",
                "cachedAt": 1700000000,
            },
        })
        assert payload.data.id == TX1
        assert payload.data.hash == "abc123"
        assert payload.data.dataSize == 1024
        assert payload.data.contentType == "text/html"
        assert payload.data.cachedAt == 1700000000

    def test_ans104_data_item_normalization(self):
        payload = WebhookPayload.model_validate({
            "event": "ans104-data-item-indexed",
            "data": {
                "id": TX1,
                "data_hash": "hash123",
                "data_size": 2048,
                "content_type": "text/html",
                "owner_address": "some-owner",
                "parent_id": "some-parent",
                "root_tx_id": "some-root",
            },
        })
        assert payload.data.id == TX1
        assert payload.data.hash == "hash123"
        assert payload.data.dataSize == 2048
        assert payload.data.contentType == "text/html"

    def test_ans104_null_hash(self):
        payload = WebhookPayload.model_validate({
            "event": "ans104-data-item-indexed",
            "data": {
                "id": TX1,
                "data_hash": None,
                "data_size": 512,
                "content_type": "application/json",
            },
        })
        assert payload.data.hash is None

    def test_ans104_extra_fields_ignored(self):
        """Extra fields from the gateway payload are dropped during normalization."""
        payload = WebhookPayload.model_validate({
            "event": "ans104-data-item-indexed",
            "data": {
                "id": TX1,
                "data_hash": "h1",
                "data_size": 100,
                "content_type": "text/html",
                "owner_address": "addr",
                "parent_id": "pid",
                "root_tx_id": "rtx",
                "signature": "sig",
                "anchor": "anc",
                "tags": [],
            },
        })
        assert payload.data.id == TX1
        assert payload.data.hash == "h1"

    def test_tx_indexed_normalization(self):
        ct_name = _b64url_encode("Content-Type")
        ct_value = _b64url_encode("text/html")
        payload = WebhookPayload.model_validate({
            "event": "tx-indexed",
            "data": {
                "id": TX1,
                "data_size": "4096",
                "data_root": "some-merkle-root",
                "tags": [{"name": ct_name, "value": ct_value}],
                "owner": "some-owner",
                "signature": "sig",
            },
        })
        assert payload.data.id == TX1
        assert payload.data.hash is None  # data_root is NOT a content hash
        assert payload.data.dataSize == 4096
        assert payload.data.contentType == "text/html"

    def test_tx_indexed_no_content_type_tag(self):
        payload = WebhookPayload.model_validate({
            "event": "tx-indexed",
            "data": {
                "id": TX1,
                "data_size": "1024",
                "tags": [
                    {"name": _b64url_encode("App-Name"), "value": _b64url_encode("MyApp")},
                ],
            },
        })
        assert payload.data.contentType is None

    def test_tx_indexed_data_size_string_to_int(self):
        payload = WebhookPayload.model_validate({
            "event": "tx-indexed",
            "data": {"id": TX1, "data_size": "999", "tags": []},
        })
        assert payload.data.dataSize == 999

    def test_tx_indexed_missing_data_size(self):
        payload = WebhookPayload.model_validate({
            "event": "tx-indexed",
            "data": {"id": TX1, "tags": []},
        })
        assert payload.data.dataSize is None

    def test_unknown_event_passthrough(self):
        """Unknown events like block-indexed pass data through as-is."""
        payload = WebhookPayload.model_validate({
            "event": "block-indexed",
            "data": {"id": TX1},
        })
        assert payload.event == "block-indexed"
        assert payload.data.id == TX1

    def test_data_cached_with_webhookdata_object(self):
        """Existing code constructing WebhookPayload with WebhookData still works."""
        payload = WebhookPayload(
            event="data-cached",
            data=WebhookData(id=TX1, hash="h1", contentType="text/html"),
        )
        assert payload.data.hash == "h1"

    def test_ans104_missing_data_hash_key(self):
        """data_hash key absent (not just null) normalizes to hash=None."""
        payload = WebhookPayload.model_validate({
            "event": "ans104-data-item-indexed",
            "data": {
                "id": TX1,
                "data_size": 100,
                "content_type": "text/html",
            },
        })
        assert payload.data.hash is None

    def test_ans104_negative_data_size_rejected(self):
        """Negative data_size is rejected by field validator."""
        with pytest.raises(Exception):
            WebhookPayload.model_validate({
                "event": "ans104-data-item-indexed",
                "data": {
                    "id": TX1,
                    "data_hash": "h1",
                    "data_size": -100,
                    "content_type": "text/html",
                },
            })

    def test_tx_indexed_invalid_base64_tags_end_to_end(self):
        """Invalid base64 tags don't crash normalization, contentType is None."""
        payload = WebhookPayload.model_validate({
            "event": "tx-indexed",
            "data": {
                "id": TX1,
                "data_size": "1024",
                "tags": [{"name": "!!!invalid", "value": "also-bad"}],
            },
        })
        assert payload.data.contentType is None
        assert payload.data.dataSize == 1024
