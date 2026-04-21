from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any

from pydantic import BaseModel, field_validator, model_validator

from src.ipfs import is_ipfs_cid

# Arweave IDs: 43-character base64url strings
_BASE64URL_43 = re.compile(r"^[A-Za-z0-9_-]{43}$")
# Upper bound so a malformed long string can't be accepted as a CID.
_MAX_ID_LENGTH = 128


def _b64url_decode(s: str) -> str:
    """Decode a base64url string (no padding) to UTF-8."""
    padded = s + "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(padded).decode("utf-8", errors="replace")


def _extract_content_type_from_tags(tags: list[dict[str, Any]]) -> str | None:
    """Extract Content-Type value from base64url-encoded Arweave tags."""
    for tag in tags:
        try:
            name = _b64url_decode(tag.get("name", ""))
            if name.lower() == "content-type":
                return _b64url_decode(tag.get("value", ""))
        except Exception:
            continue
    return None


def _safe_int(v: Any) -> int | None:
    """Coerce a value to int, returning None on failure."""
    if v is None:
        return None
    try:
        return int(v)
    except (ValueError, TypeError):
        return None


class WebhookData(BaseModel):
    id: str
    hash: str | None = None
    dataSize: int | None = None
    contentType: str | None = None
    cachedAt: int | None = None

    @field_validator("id")
    @classmethod
    def id_must_be_valid(cls, v: str) -> str:
        if _BASE64URL_43.match(v):
            return v
        if len(v) <= _MAX_ID_LENGTH and is_ipfs_cid(v):
            return v
        raise ValueError(
            "id must be a 43-character base64url Arweave ID or an IPFS CID"
        )

    @field_validator("hash")
    @classmethod
    def hash_must_be_bounded(cls, v: str | None) -> str | None:
        if v is not None and len(v) > 64:
            raise ValueError("hash must be at most 64 characters")
        return v

    @field_validator("dataSize")
    @classmethod
    def data_size_non_negative(cls, v: int | None) -> int | None:
        if v is not None and v < 0:
            raise ValueError("dataSize must be non-negative")
        return v


class WebhookPayload(BaseModel):
    event: str
    data: WebhookData

    @model_validator(mode="before")
    @classmethod
    def normalize_indexed_events(cls, values: Any) -> Any:
        """Normalize indexed event payloads into WebhookData shape."""
        if not isinstance(values, dict):
            return values
        event = values.get("event", "")
        data = values.get("data")
        if not isinstance(data, dict):
            return values

        if event == "ans104-data-item-indexed":
            values["data"] = {
                "id": data.get("id"),
                "hash": data.get("data_hash"),
                "dataSize": _safe_int(data.get("data_size")),
                "contentType": data.get("content_type"),
            }
        elif event == "tx-indexed":
            values["data"] = {
                "id": data.get("id"),
                "hash": None,
                "dataSize": _safe_int(data.get("data_size")),
                "contentType": _extract_content_type_from_tags(
                    data.get("tags", [])
                ),
            }

        return values


class Verdict(str, Enum):
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    SKIPPED = "skipped"


class RuleResult(BaseModel):
    rule_name: str
    triggered: bool
    signals: dict[str, Any] = {}


class ScanResult(BaseModel):
    verdict: Verdict
    matched_rules: list[str] = []
    ml_score: float | None = None
    scan_duration_ms: int = 0


@dataclass
class AdminOverride:
    content_hash: str
    tx_id: str
    admin_verdict: str  # 'confirmed_malicious' or 'confirmed_clean'
    original_verdict: str
    original_rules: str  # JSON array
    original_ml_score: float | None
    notes: str
    created_at: int
