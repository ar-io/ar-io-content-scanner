"""Tests for GatewayClient fetch path routing (Arweave vs IPFS)."""
from __future__ import annotations

import httpx
import pytest

from src.gateway_client import GatewayClient

CIDV1 = "bafkreigbk3hjz6oyiywqf7eknthwc2osvt5xi6b6igwljn2qrxkthqgrp4"
CIDV0 = "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"
ARWEAVE = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"


async def _fetch_with_transport(content_id: str) -> str:
    """Run fetch_content with a MockTransport and return the path that was hit."""
    captured: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["path"] = request.url.path
        return httpx.Response(200, content=b"<html></html>")

    client = GatewayClient(
        gateway_url="http://gateway.test",
        admin_api_key="k",
    )
    # Replace the real transport with a MockTransport
    await client._client.aclose()
    client._client = httpx.AsyncClient(
        base_url="http://gateway.test",
        transport=httpx.MockTransport(handler),
    )
    try:
        await client.fetch_content(content_id)
    finally:
        await client.close()
    return captured["path"]


class TestFetchPathRouting:
    @pytest.mark.asyncio
    async def test_arweave_id_uses_raw_path(self):
        path = await _fetch_with_transport(ARWEAVE)
        assert path == f"/raw/{ARWEAVE}"

    @pytest.mark.asyncio
    async def test_cidv1_uses_ipfs_path(self):
        path = await _fetch_with_transport(CIDV1)
        assert path == f"/ipfs/{CIDV1}"

    @pytest.mark.asyncio
    async def test_cidv0_uses_ipfs_path(self):
        path = await _fetch_with_transport(CIDV0)
        assert path == f"/ipfs/{CIDV0}"


class TestBlockDataPassesIdVerbatim:
    @pytest.mark.asyncio
    async def test_block_uses_cid_as_id_field(self):
        captured: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["method"] = request.method
            captured["path"] = request.url.path
            import json
            captured["body"] = json.loads(request.content)
            return httpx.Response(200, json={"ok": True})

        client = GatewayClient(
            gateway_url="http://gateway.test",
            admin_api_key="k",
        )
        await client._client.aclose()
        client._client = httpx.AsyncClient(
            base_url="http://gateway.test",
            transport=httpx.MockTransport(handler),
        )
        try:
            ok = await client.block_data(CIDV1, "h" * 64, ["rule"])
        finally:
            await client.close()

        assert ok is True
        assert captured["method"] == "PUT"
        assert captured["path"] == "/ar-io/admin/block-data"
        # CID passes through unchanged in the id field
        assert captured["body"]["id"] == CIDV1


class TestUnblockDataHitsUnblockEndpoint:
    @pytest.mark.asyncio
    async def test_unblock_uses_put_unblock_data(self):
        """Regression: unblock must call PUT /ar-io/admin/unblock-data. It
        previously called DELETE /ar-io/admin/block-data, which the gateway
        never implemented, so dismissals never lifted the block."""
        captured: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["method"] = request.method
            captured["path"] = request.url.path
            import json

            captured["body"] = json.loads(request.content)
            return httpx.Response(200, json={"message": "Content unblocked"})

        client = GatewayClient(gateway_url="http://gateway.test", admin_api_key="k")
        await client._client.aclose()
        client._client = httpx.AsyncClient(
            base_url="http://gateway.test",
            transport=httpx.MockTransport(handler),
        )
        try:
            ok = await client.unblock_data("tx-id-123", "h" * 64)
        finally:
            await client.close()

        assert ok is True
        assert captured["method"] == "PUT"
        assert captured["path"] == "/ar-io/admin/unblock-data"
        assert captured["body"]["id"] == "tx-id-123"
        assert captured["body"]["hash"] == "h" * 64
