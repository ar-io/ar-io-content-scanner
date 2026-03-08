from __future__ import annotations

import logging
from dataclasses import dataclass

import httpx

logger = logging.getLogger("scanner.safe_browsing")

LOOKUP_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"


@dataclass
class SafeBrowsingResult:
    """Result of a Safe Browsing check for a single URL."""
    url: str
    flagged: bool
    threat_types: list[str]  # e.g. ["SOCIAL_ENGINEERING", "MALWARE"]


class SafeBrowsingClient:
    """Google Safe Browsing Lookup API v4 client.

    Fail-open design: API errors never affect scanning behavior.
    All errors are logged and return unflagged results.
    """

    def __init__(self, api_key: str, timeout_ms: int = 5000) -> None:
        self.api_key = api_key
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(timeout_ms / 1000),
        )

    async def check_urls(self, urls: list[str]) -> list[SafeBrowsingResult]:
        """Check multiple URLs against Google Safe Browsing.

        Returns a SafeBrowsingResult per input URL. On API error,
        returns all-unflagged results (fail-open).
        """
        if not urls or not self.api_key:
            return [SafeBrowsingResult(url=u, flagged=False, threat_types=[]) for u in urls]

        # Build threat entries
        threat_entries = [{"url": u} for u in urls]

        body = {
            "client": {
                "clientId": "ario-content-scanner",
                "clientVersion": "1.0",
            },
            "threatInfo": {
                "threatTypes": [
                    "SOCIAL_ENGINEERING",
                    "MALWARE",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION",
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": threat_entries,
            },
        }

        try:
            resp = await self._client.post(
                LOOKUP_URL,
                params={"key": self.api_key},
                json=body,
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception:
            logger.warning(
                "safe_browsing_api_error",
                exc_info=True,
                extra={"url_count": len(urls)},
            )
            return [SafeBrowsingResult(url=u, flagged=False, threat_types=[]) for u in urls]

        # Parse matches
        matches = data.get("matches") or []
        flagged_map: dict[str, list[str]] = {}
        for match in matches:
            url = match.get("threat", {}).get("url", "")
            threat_type = match.get("threatType", "")
            if url:
                flagged_map.setdefault(url, []).append(threat_type)

        results = []
        for u in urls:
            threats = flagged_map.get(u, [])
            results.append(SafeBrowsingResult(
                url=u,
                flagged=len(threats) > 0,
                threat_types=threats,
            ))

        if flagged_map:
            logger.warning(
                "safe_browsing_flagged",
                extra={
                    "flagged_count": len(flagged_map),
                    "urls": list(flagged_map.keys()),
                },
            )

        return results

    async def check_url(self, url: str) -> SafeBrowsingResult:
        """Check a single URL. Convenience wrapper around check_urls."""
        results = await self.check_urls([url])
        return results[0]

    async def close(self) -> None:
        await self._client.aclose()
