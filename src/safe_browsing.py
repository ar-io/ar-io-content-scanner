from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field

import httpx

logger = logging.getLogger("scanner.safe_browsing")

LOOKUP_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
TRANSPARENCY_URL = (
    "https://transparencyreport.google.com"
    "/transparencyreport/api/v3/safebrowsing/status"
)

# Transparency Report response positions
_TR_STATUS = 1
_TR_MALWARE = 2
_TR_PHISHING = 4
_TR_UNWANTED = 5


@dataclass
class SafeBrowsingResult:
    """Result of a Safe Browsing check for a single URL."""
    url: str
    flagged: bool
    threat_types: list[str]  # e.g. ["SOCIAL_ENGINEERING", "MALWARE"]


@dataclass
class DomainStatus:
    """Site-level Safe Browsing status from Google Transparency Report."""
    domain: str
    flagged: bool
    threat_types: list[str] = field(default_factory=list)
    status_code: int = 0  # 1=no data, 3=some pages unsafe, 4=not dangerous


class SafeBrowsingClient:
    """Google Safe Browsing client.

    Uses the Lookup API v4 for individual URL checks (requires API key)
    and the Transparency Report for site-level domain status (no key needed).

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
        except Exception as exc:
            detail = ""
            if hasattr(exc, "response") and exc.response is not None:
                detail = f" status={exc.response.status_code}"
                try:
                    detail += f" body={exc.response.text[:200]}"
                except Exception:
                    pass
            logger.warning(
                "safe_browsing_api_error",
                exc_info=True,
                extra={
                    "url_count": len(urls),
                    "error": str(exc) + detail,
                },
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

    async def check_domain(self, domain: str) -> DomainStatus:
        """Check site-level status via Google Transparency Report.

        Uses an undocumented but stable endpoint that returns the same
        data shown on transparencyreport.google.com/safe-browsing/search.
        No API key required.
        """
        try:
            resp = await self._client.get(
                TRANSPARENCY_URL,
                params={"site": domain},
                headers={
                    "User-Agent": (
                        "Mozilla/5.0 (compatible; ario-content-scanner/1.0)"
                    ),
                },
            )
            resp.raise_for_status()
            # Response starts with ")]}'" XSSI prefix, then JSON on next line
            text = resp.text
            if text.startswith(")]}'"):
                text = text[text.index("\n") + 1:]
            data = json.loads(text)

            # data is [[\"sb.ssr\", status, malware, ?, phishing, unwanted, ?, ts, domain]]
            row = data[0]
            status_code = row[_TR_STATUS]
            threats = []
            if row[_TR_MALWARE]:
                threats.append("MALWARE")
            if row[_TR_PHISHING]:
                threats.append("SOCIAL_ENGINEERING")
            if row[_TR_UNWANTED]:
                threats.append("UNWANTED_SOFTWARE")

            flagged = len(threats) > 0

            return DomainStatus(
                domain=domain,
                flagged=flagged,
                threat_types=threats,
                status_code=status_code,
            )
        except Exception:
            logger.warning(
                "transparency_report_check_failed",
                exc_info=True,
                extra={"domain": domain},
            )
            return DomainStatus(domain=domain, flagged=False)

    async def close(self) -> None:
        await self._client.aclose()
