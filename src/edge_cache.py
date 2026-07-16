from __future__ import annotations

import base64
import logging
from dataclasses import dataclass

import httpx

from src.ipfs import gateway_public_path, is_ipfs_cid

logger = logging.getLogger("scanner.edge_cache")


def arweave_sandbox_subdomain(content_id: str) -> str | None:
    """Return the origin-isolation sandbox subdomain label for an Arweave ID.

    ar.io serves data-item/transaction content from an origin-isolated
    subdomain ``base32(rawTxId).<gateway-domain>`` (RFC 4648 base32, lowercase,
    unpadded). An HTTP cache in front of the gateway keys that response under
    the sandbox host, which is distinct from the base-host ``/raw/{id}`` and
    ``/{id}`` keys — so a block must revalidate it separately or the sandbox
    keeps serving the pre-block 200 until its TTL expires.

    Returns the subdomain label only (no domain), or ``None`` when
    ``content_id`` is not a 32-byte Arweave ID (e.g. an IPFS CID).
    """
    try:
        raw = base64.urlsafe_b64decode(content_id + "=" * (-len(content_id) % 4))
    except (ValueError, TypeError):
        return None
    if len(raw) != 32:  # Arweave tx / data-item ids are 32 bytes
        return None
    return base64.b32encode(raw).decode("ascii").rstrip("=").lower()


@dataclass(frozen=True)
class EdgeCacheConfig:
    enabled: bool
    url_base: str
    headers: tuple[tuple[str, str], ...]
    arweave_paths: tuple[str, ...]
    ipfs_paths: tuple[str, ...]
    timeout_ms: int


def parse_headers(raw: str) -> tuple[tuple[str, str], ...]:
    """Parse "Key: Value, Key2: Value2" into a tuple of (k, v) pairs.

    Header names and values are stripped; empty entries are skipped. Bad
    entries (no colon) are logged and dropped.
    """
    out: list[tuple[str, str]] = []
    for raw_pair in raw.split(","):
        pair = raw_pair.strip()
        if not pair:
            continue
        if ":" not in pair:
            logger.warning("Skipping malformed header entry", extra={"entry": pair})
            continue
        name, _, value = pair.partition(":")
        name = name.strip()
        value = value.strip()
        if not name:
            logger.warning("Skipping header with empty name", extra={"entry": pair})
            continue
        out.append((name, value))
    return tuple(out)


def parse_paths(raw: str) -> tuple[str, ...]:
    """Split a comma-separated path-template list, dropping empties."""
    return tuple(p.strip() for p in raw.split(",") if p.strip())


class EdgeCacheRevalidator:
    """Best-effort cache busting after a content block.

    After the gateway accepts a `block-data` call, fire one GET per configured
    path template at a public origin. The request carries cache-bypass headers
    (Cache-Control: no-cache by default, plus X-Cache-Bypass for nginx-style
    setups) so any edge cache in front revalidates against the gateway and
    learns about the new 451.

    Failures are logged and counted, never raised — the gateway-side block has
    already succeeded by the time this runs, so the worst case is the existing
    cached entry stays around until its natural TTL.
    """

    def __init__(
        self,
        config: EdgeCacheConfig,
        metrics=None,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.config = config
        self.metrics = metrics
        if client is not None:
            self._client = client
            self._owns_client = False
        elif config.enabled:
            self._client = httpx.AsyncClient(
                base_url=config.url_base,
                timeout=httpx.Timeout(config.timeout_ms / 1000),
            )
            self._owns_client = True
        else:
            self._client = None
            self._owns_client = False

    def _paths_for(self, content_id: str) -> tuple[str, ...]:
        templates = (
            self.config.ipfs_paths
            if is_ipfs_cid(content_id)
            else self.config.arweave_paths
        )
        return tuple(t.replace("{id}", content_id) for t in templates)

    def _host_header(self) -> str | None:
        """The public host the edge keys its cache on, from the Host header
        (case-insensitive). Needed to construct the sandbox subdomain."""
        for name, value in self.config.headers:
            if name.lower() == "host":
                return value
        return None

    async def _fire(self, content_id: str, path: str, headers: dict) -> None:
        """Issue one cache-bypass GET; log and count, never raise."""
        try:
            resp = await self._client.get(path, headers=headers)
            logger.info(
                "edge_cache_revalidated",
                extra={
                    "content_id": content_id,
                    "path": path,
                    "host": headers.get("Host"),
                    "status_code": resp.status_code,
                },
            )
            # 451 is the success case (block now visible at the edge);
            # 2xx, 3xx, 4xx all count as "we forced a revalidation".
            if self.metrics is not None:
                self.metrics.record_edge_cache_revalidation("ok")
        except httpx.HTTPError as e:
            logger.warning(
                "edge_cache_revalidation_failed",
                extra={
                    "content_id": content_id,
                    "path": path,
                    "host": headers.get("Host"),
                    "error": str(e),
                    "error_type": type(e).__name__,
                },
            )
            if self.metrics is not None:
                self.metrics.record_edge_cache_revalidation("fail")

    async def revalidate(self, content_id: str) -> None:
        if not self.config.enabled:
            if self.metrics is not None:
                self.metrics.record_edge_cache_revalidation("disabled")
            return
        if self._client is None:
            return

        headers = dict(self.config.headers)
        for path in self._paths_for(content_id):
            await self._fire(content_id, path, headers)

        # Also bust the origin-isolated sandbox subdomain for Arweave content.
        # The base-host paths above (e.g. /raw/{id}, /{id}) do not touch the
        # base32(txId).<domain> host the gateway redirects HTML to, so without
        # this the sandbox keeps serving the pre-block 200 until TTL. Requires a
        # Host header to identify the public domain nginx keys on.
        base_domain = self._host_header()
        sandbox = (
            None if is_ipfs_cid(content_id)
            else arweave_sandbox_subdomain(content_id)
        )
        if base_domain and sandbox:
            sandbox_headers = dict(headers)
            sandbox_headers["Host"] = f"{sandbox}.{base_domain}"
            await self._fire(content_id, f"/{content_id}", sandbox_headers)

    async def close(self) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()


def fallback_public_path(content_id: str) -> str:
    """Public-facing default path for a content id (kept for reference)."""
    return gateway_public_path(content_id)
