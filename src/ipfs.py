from __future__ import annotations

# IPFS CID detection.
#
# Arweave TX IDs are always 43-char base64url; IPFS CIDs are longer and use
# a different alphabet, so a prefix + length check is enough to tell them
# apart without pulling in a full multibase/CID parser.

_CIDV1_PREFIX = "baf"  # multibase 'b' (base32 lowercase) + version 1 start
_CIDV0_PREFIX = "Qm"   # base58btc, sha2-256, fixed 46 chars
_CIDV0_LENGTH = 46
_ARWEAVE_ID_LENGTH = 43


def is_ipfs_cid(content_id: str | None) -> bool:
    """Return True if the id looks like an IPFS CIDv0 or CIDv1.

    This is a conservative prefix+length check. It rejects 43-char Arweave
    IDs that happen to start with "baf" (base64url allows it) by requiring
    CIDv1 strings to be longer than the Arweave ID length.
    """
    if not content_id:
        return False
    if content_id.startswith(_CIDV1_PREFIX) and len(content_id) > _ARWEAVE_ID_LENGTH:
        return True
    if content_id.startswith(_CIDV0_PREFIX) and len(content_id) == _CIDV0_LENGTH:
        return True
    return False


def gateway_fetch_path(content_id: str) -> str:
    """Return the gateway path to fetch content for a given id.

    IPFS CIDs resolve at /ipfs/{CID}; Arweave TX IDs resolve at /raw/{id}.
    """
    if is_ipfs_cid(content_id):
        return f"/ipfs/{content_id}"
    return f"/raw/{content_id}"


def gateway_public_path(content_id: str) -> str:
    """Return the path suffix for a public-facing gateway URL.

    IPFS CIDs are served at /ipfs/{CID}; Arweave TX IDs are served at /{id}
    (the gateway resolves bare IDs at the root path).
    """
    if is_ipfs_cid(content_id):
        return f"/ipfs/{content_id}"
    return f"/{content_id}"
