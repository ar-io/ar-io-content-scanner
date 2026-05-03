from __future__ import annotations

import asyncio
import logging

import httpx

from src.edge_cache import EdgeCacheRevalidator
from src.ipfs import gateway_fetch_path

logger = logging.getLogger("scanner.gateway")


class GatewayClient:
    def __init__(
        self,
        gateway_url: str,
        admin_api_key: str,
        max_bytes: int = 262144,
        timeout_ms: int = 10000,
        edge_cache: EdgeCacheRevalidator | None = None,
    ):
        self.gateway_url = gateway_url
        self.admin_api_key = admin_api_key
        self.max_bytes = max_bytes
        self.edge_cache = edge_cache
        timeout = httpx.Timeout(timeout_ms / 1000)
        self._client = httpx.AsyncClient(
            base_url=gateway_url, timeout=timeout
        )

    async def fetch_content(self, tx_id: str) -> bytes | None:
        path = gateway_fetch_path(tx_id)
        try:
            async with self._client.stream("GET", path) as resp:
                if resp.status_code != 200:
                    logger.warning(
                        "Failed to fetch content",
                        extra={
                            "tx_id": tx_id,
                            "status_code": resp.status_code,
                        },
                    )
                    return None

                chunks = []
                total = 0
                async for chunk in resp.aiter_bytes(chunk_size=8192):
                    remaining = self.max_bytes - total
                    if remaining <= 0:
                        break
                    chunks.append(chunk[:remaining])
                    total += len(chunks[-1])

                return b"".join(chunks)
        except httpx.HTTPError as e:
            logger.warning(
                "HTTP error fetching content",
                extra={
                    "tx_id": tx_id,
                    "error": str(e),
                    "error_type": type(e).__name__,
                },
            )
            return None

    async def block_data(
        self,
        tx_id: str,
        content_hash: str,
        matched_rules: list[str],
        *,
        notes: str | None = None,
    ) -> bool:
        if notes is None:
            notes = f"Auto-blocked: {', '.join(matched_rules)}"
        for attempt in range(2):
            try:
                resp = await self._client.put(
                    "/ar-io/admin/block-data",
                    json={
                        "id": tx_id,
                        "hash": content_hash,
                        "source": "content-scanner",
                        "notes": notes,
                    },
                    headers={
                        "Authorization": f"Bearer {self.admin_api_key}",
                    },
                )
                success = 200 <= resp.status_code < 300
                if success:
                    logger.info(
                        "block_sent",
                        extra={
                            "tx_id": tx_id,
                            "content_hash": content_hash,
                            "gateway_response": resp.status_code,
                        },
                    )
                    if self.edge_cache is not None:
                        await self.edge_cache.revalidate(tx_id)
                    return True
                logger.error(
                    "block_failed",
                    extra={
                        "tx_id": tx_id,
                        "status_code": resp.status_code,
                        "body": resp.text,
                        "attempt": attempt + 1,
                    },
                )
            except httpx.HTTPError as e:
                logger.error(
                    "block_error",
                    extra={
                        "tx_id": tx_id,
                        "error": str(e),
                        "attempt": attempt + 1,
                    },
                )
            if attempt == 0:
                await asyncio.sleep(2)
        return False

    async def unblock_data(
        self,
        tx_id: str,
        content_hash: str,
    ) -> bool:
        for attempt in range(2):
            try:
                resp = await self._client.request(
                    "DELETE",
                    "/ar-io/admin/block-data",
                    json={
                        "id": tx_id,
                        "hash": content_hash,
                        "source": "content-scanner",
                        "notes": "Admin dismissed as false positive",
                    },
                    headers={
                        "Authorization": f"Bearer {self.admin_api_key}",
                    },
                )
                success = 200 <= resp.status_code < 300
                if success:
                    logger.info(
                        "unblock_sent",
                        extra={
                            "tx_id": tx_id,
                            "content_hash": content_hash,
                            "gateway_response": resp.status_code,
                        },
                    )
                    if self.edge_cache is not None:
                        await self.edge_cache.revalidate(tx_id)
                    return True
                logger.error(
                    "unblock_failed",
                    extra={
                        "tx_id": tx_id,
                        "status_code": resp.status_code,
                        "body": resp.text,
                        "attempt": attempt + 1,
                    },
                )
            except httpx.HTTPError as e:
                logger.error(
                    "unblock_error",
                    extra={
                        "tx_id": tx_id,
                        "error": str(e),
                        "attempt": attempt + 1,
                    },
                )
            if attempt == 0:
                await asyncio.sleep(2)
        return False

    async def close(self) -> None:
        await self._client.aclose()
        if self.edge_cache is not None:
            await self.edge_cache.close()
