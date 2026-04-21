"""Tests for IPFS CID detection and path routing."""
from __future__ import annotations

from src.ipfs import gateway_fetch_path, gateway_public_path, is_ipfs_cid

CIDV1 = "bafkreigbk3hjz6oyiywqf7eknthwc2osvt5xi6b6igwljn2qrxkthqgrp4"
CIDV0 = "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"
ARWEAVE = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"


class TestIsIpfsCid:
    def test_cidv1_base32(self):
        assert is_ipfs_cid(CIDV1) is True

    def test_cidv0_base58(self):
        assert is_ipfs_cid(CIDV0) is True

    def test_arweave_id_rejected(self):
        assert is_ipfs_cid(ARWEAVE) is False

    def test_arweave_id_starting_with_baf_rejected(self):
        # Arweave base64url can start with "baf"; still 43 chars so must not
        # be treated as a CIDv1.
        arweave_baf = "baf" + "A" * 40
        assert len(arweave_baf) == 43
        assert is_ipfs_cid(arweave_baf) is False

    def test_empty(self):
        assert is_ipfs_cid("") is False
        assert is_ipfs_cid(None) is False

    def test_qm_wrong_length_rejected(self):
        # "Qm" prefix but shorter than CIDv0 — not a CID.
        assert is_ipfs_cid("QmShort") is False


class TestGatewayFetchPath:
    def test_cidv1_uses_ipfs_path(self):
        assert gateway_fetch_path(CIDV1) == f"/ipfs/{CIDV1}"

    def test_cidv0_uses_ipfs_path(self):
        assert gateway_fetch_path(CIDV0) == f"/ipfs/{CIDV0}"

    def test_arweave_uses_raw_path(self):
        assert gateway_fetch_path(ARWEAVE) == f"/raw/{ARWEAVE}"


class TestGatewayPublicPath:
    def test_cid_uses_ipfs_prefix(self):
        assert gateway_public_path(CIDV1) == f"/ipfs/{CIDV1}"

    def test_arweave_served_at_root(self):
        assert gateway_public_path(ARWEAVE) == f"/{ARWEAVE}"
