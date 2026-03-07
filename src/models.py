from __future__ import annotations

import re
from enum import Enum
from typing import Any

from pydantic import BaseModel, field_validator

# Arweave IDs: 43-character base64url strings
_BASE64URL_43 = re.compile(r"^[A-Za-z0-9_-]{43}$")


class WebhookData(BaseModel):
    id: str
    hash: str | None = None
    dataSize: int | None = None
    contentType: str | None = None
    cachedAt: int | None = None

    @field_validator("id")
    @classmethod
    def id_must_be_valid(cls, v: str) -> str:
        if not _BASE64URL_43.match(v):
            raise ValueError("id must be a 43-character base64url string")
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
