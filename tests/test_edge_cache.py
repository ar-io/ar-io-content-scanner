"""Tests for the edge-cache revalidation helper."""
from __future__ import annotations

import httpx

from src.edge_cache import (
    EdgeCacheConfig,
    EdgeCacheRevalidator,
    parse_headers,
    parse_paths,
)


ARWEAVE_ID = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
CIDV1 = "bafkreigbk3hjz6oyiywqf7eknthwc2osvt5xi6b6igwljn2qrxkthqgrp4"


class _RecordingMetrics:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def record_edge_cache_revalidation(self, result: str) -> None:
        self.calls.append(result)


def _config(**overrides) -> EdgeCacheConfig:
    base = dict(
        enabled=True,
        url_base="http://gateway.test",
        headers=(("Cache-Control", "no-cache"), ("X-Cache-Bypass", "1")),
        arweave_paths=("/raw/{id}", "/{id}"),
        ipfs_paths=("/ipfs/{id}",),
        timeout_ms=5000,
    )
    base.update(overrides)
    return EdgeCacheConfig(**base)


def _make_client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        base_url="http://gateway.test",
        transport=httpx.MockTransport(handler),
    )


# ---- parse_headers ----

def test_parse_headers_basic() -> None:
    out = parse_headers("Cache-Control: no-cache, X-Cache-Bypass: 1")
    assert out == (("Cache-Control", "no-cache"), ("X-Cache-Bypass", "1"))


def test_parse_headers_handles_whitespace_and_empty() -> None:
    out = parse_headers("  Foo  :   bar  , ,Baz:qux ")
    assert out == (("Foo", "bar"), ("Baz", "qux"))


def test_parse_headers_skips_malformed() -> None:
    # Missing colon is dropped; valid entries survive.
    out = parse_headers("Good: yes, malformed_no_colon, Other: ok")
    assert out == (("Good", "yes"), ("Other", "ok"))


def test_parse_paths_strips_and_drops_empty() -> None:
    assert parse_paths("/raw/{id}, , /{id}  ") == ("/raw/{id}", "/{id}")


# ---- EdgeCacheRevalidator ----

async def test_disabled_makes_no_requests() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(200)

    metrics = _RecordingMetrics()
    revalidator = EdgeCacheRevalidator(
        _config(enabled=False),
        metrics=metrics,
        client=_make_client(handler),
    )
    await revalidator.revalidate(ARWEAVE_ID)
    await revalidator.close()
    assert seen == []
    assert metrics.calls == ["disabled"]


async def test_arweave_id_uses_arweave_paths_with_headers() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(451)

    metrics = _RecordingMetrics()
    revalidator = EdgeCacheRevalidator(
        _config(),
        metrics=metrics,
        client=_make_client(handler),
    )
    await revalidator.revalidate(ARWEAVE_ID)
    await revalidator.close()
    assert [r.url.path for r in requests] == [
        f"/raw/{ARWEAVE_ID}",
        f"/{ARWEAVE_ID}",
    ]
    for r in requests:
        assert r.method == "GET"
        assert r.headers.get("cache-control") == "no-cache"
        assert r.headers.get("x-cache-bypass") == "1"
    assert metrics.calls == ["ok", "ok"]


async def test_ipfs_id_uses_ipfs_paths() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(451)

    revalidator = EdgeCacheRevalidator(
        _config(),
        client=_make_client(handler),
    )
    await revalidator.revalidate(CIDV1)
    await revalidator.close()
    assert [r.url.path for r in requests] == [f"/ipfs/{CIDV1}"]


async def test_http_error_does_not_raise_and_counts_fail() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom", request=request)

    metrics = _RecordingMetrics()
    revalidator = EdgeCacheRevalidator(
        _config(),
        metrics=metrics,
        client=_make_client(handler),
    )
    await revalidator.revalidate(ARWEAVE_ID)  # must not raise
    await revalidator.close()
    assert metrics.calls == ["fail", "fail"]


async def test_metrics_optional() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(451)

    revalidator = EdgeCacheRevalidator(
        _config(),
        client=_make_client(handler),
    )
    await revalidator.revalidate(ARWEAVE_ID)  # no metrics passed; must not crash
    await revalidator.close()


async def test_block_data_triggers_revalidation() -> None:
    """End-to-end-ish: a successful block_data fires the revalidator."""
    from src.gateway_client import GatewayClient

    revalidation_paths: list[str] = []

    def edge_handler(request: httpx.Request) -> httpx.Response:
        revalidation_paths.append(request.url.path)
        return httpx.Response(451)

    revalidator = EdgeCacheRevalidator(
        _config(),
        client=_make_client(edge_handler),
    )

    def gateway_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True})

    gateway = GatewayClient(
        gateway_url="http://gateway.test",
        admin_api_key="k",
        edge_cache=revalidator,
    )
    await gateway._client.aclose()
    gateway._client = httpx.AsyncClient(
        base_url="http://gateway.test",
        transport=httpx.MockTransport(gateway_handler),
    )

    ok = await gateway.block_data(ARWEAVE_ID, "deadbeef", ["test_rule"])
    assert ok is True
    assert revalidation_paths == [f"/raw/{ARWEAVE_ID}", f"/{ARWEAVE_ID}"]

    await gateway.close()
