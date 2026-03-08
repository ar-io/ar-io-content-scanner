from __future__ import annotations

import logging
import re
import time
from collections import defaultdict

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from src.feed.auth import require_verdict_api_key

logger = logging.getLogger("scanner.feed")

_HASH_PATTERN = re.compile(r"^[A-Za-z0-9_+/=-]{1,64}$")

# Simple in-memory rate limiter: max requests per IP per window
_RATE_LIMIT = 60
_RATE_WINDOW = 60  # seconds
_request_log: dict[str, list[float]] = defaultdict(list)


def _check_rate_limit(client_ip: str) -> None:
    now = time.time()
    cutoff = now - _RATE_WINDOW
    timestamps = _request_log[client_ip]
    # Prune old entries
    active = [t for t in timestamps if t > cutoff]
    if len(active) >= _RATE_LIMIT:
        _request_log[client_ip] = active
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    if active:
        active.append(now)
        _request_log[client_ip] = active
    else:
        # No recent requests from this IP — clean up the entry and start fresh
        _request_log.pop(client_ip, None)
        _request_log[client_ip] = [now]


def build_feed_router(app_state) -> APIRouter:
    """Build the verdict feed API router."""
    settings = app_state.settings
    _state = app_state

    router = APIRouter()
    auth = require_verdict_api_key(settings.verdict_api_key)

    @router.get("/api/verdicts/{content_hash}")
    async def get_verdict(
        content_hash: str,
        request: Request,
        _key: str = Depends(auth),
    ):
        _check_rate_limit(request.client.host if request.client else "unknown")

        if not _HASH_PATTERN.match(content_hash):
            raise HTTPException(status_code=400, detail="Invalid content hash")

        db = _state.db
        result = db.get_verdict_for_feed(content_hash)

        if result is None:
            raise HTTPException(status_code=404, detail="Not found")

        _state.metrics.record_feed_export()
        return result

    @router.get("/api/verdicts")
    async def list_verdicts(
        request: Request,
        since: int = Query(0, ge=0),
        after_hash: str = Query(""),
        limit: int = Query(100, ge=1, le=1000),
        _key: str = Depends(auth),
    ):
        _check_rate_limit(request.client.host if request.client else "unknown")

        if after_hash and not _HASH_PATTERN.match(after_hash):
            raise HTTPException(status_code=400, detail="Invalid after_hash")

        db = _state.db
        items = db.get_verdicts_feed(
            since=since, after_hash=after_hash, limit=limit
        )

        cursor = None
        has_more = len(items) == limit
        if items:
            last = items[-1]
            cursor = {
                "scanned_at": last["scanned_at"],
                "content_hash": last["content_hash"],
            }

        _state.metrics.record_feed_export(len(items))
        return {
            "verdicts": items,
            "cursor": cursor,
            "has_more": has_more,
        }

    return router
