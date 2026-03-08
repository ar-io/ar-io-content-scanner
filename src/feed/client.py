from __future__ import annotations

import logging

import httpx

logger = logging.getLogger("scanner.feed.client")


class FeedClient:
    """HTTP client for querying peer verdict feed APIs."""

    def __init__(self, api_key: str, timeout_ms: int = 5000):
        self.api_key = api_key
        timeout = httpx.Timeout(timeout_ms / 1000)
        self._client = httpx.AsyncClient(timeout=timeout)

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.api_key}"}

    async def fetch_feed(
        self,
        peer_url: str,
        since: int = 0,
        after_hash: str = "",
        limit: int = 100,
    ) -> dict | None:
        """Fetch paginated verdicts from a peer. Returns None on error."""
        try:
            params: dict[str, str | int] = {"since": since, "limit": limit}
            if after_hash:
                params["after_hash"] = after_hash
            resp = await self._client.get(
                f"{peer_url}/api/verdicts",
                params=params,
                headers=self._headers(),
            )
            if resp.status_code != 200:
                logger.warning(
                    "feed_fetch_failed",
                    extra={
                        "peer": peer_url,
                        "status_code": resp.status_code,
                    },
                )
                return None
            return resp.json()
        except (httpx.HTTPError, Exception) as e:
            logger.warning(
                "feed_fetch_error",
                extra={"peer": peer_url, "error": str(e)},
            )
            return None

    async def lookup_verdict(
        self, peer_url: str, content_hash: str
    ) -> dict | None:
        """Look up a single verdict from a peer. Returns None on error/miss."""
        try:
            resp = await self._client.get(
                f"{peer_url}/api/verdicts/{content_hash}",
                headers=self._headers(),
            )
            if resp.status_code == 404:
                return None
            if resp.status_code != 200:
                logger.warning(
                    "feed_lookup_failed",
                    extra={
                        "peer": peer_url,
                        "content_hash": content_hash,
                        "status_code": resp.status_code,
                    },
                )
                return None
            return resp.json()
        except (httpx.HTTPError, Exception) as e:
            logger.warning(
                "feed_lookup_error",
                extra={
                    "peer": peer_url,
                    "content_hash": content_hash,
                    "error": str(e),
                },
            )
            return None

    async def close(self) -> None:
        await self._client.aclose()
