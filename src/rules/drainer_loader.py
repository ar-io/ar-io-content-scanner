"""Rule 8: remote-payload wallet-drainer loaders (the inline sibling of
``external-script-drainer``).

Instead of a ``<script src>`` to a clearnet host, the drainer ships as a
near-empty "Loading…" cloak shell whose inline bootstrap:

  1. reads a live payload host from an **on-chain dead-drop** — it queries a
     hardcoded wallet's recent transactions over public Solana/EVM RPC
     endpoints and base64-decodes a memo to get the current host,
  2. ``fetch()`` es the real drainer HTML/JS from that host, then
  3. injects it into the DOM and re-creates ``<script>`` elements so it runs.

Rotating the payload host on-chain lets the operator swap the drainer without
touching the permanent Arweave content. It carries no ``<script src>`` (so
``external-script-drainer`` misses it), no inputs (credential rules miss it),
and no in-page base64 blob (``obfuscated-loader`` misses it).

Three independent signals, all required (conjunctive):

  1. **cloak shell** — no credential inputs / forms, sparse *visible* body
     (script text excluded), and a loader title or empty root-mount div;
  2. **remote code execution** — a ``fetch()`` paired with a script-injection /
     ``document.write`` / ``eval`` sink that runs fetched markup as code; and
  3. **blockchain / wallet context** — public RPC endpoints, JSON-RPC method
     calls, or wallet-provider interaction.

Fetching code from a runtime-resolved host and executing it is meaningless for
static, self-contained Arweave content; pairing that with a cloak shell and
on-chain RPC calls is unambiguous, so the three together are near-zero false
positive.
"""

from __future__ import annotations

import re

from bs4 import BeautifulSoup

from src.models import RuleResult
from src.rules.base import Rule
from src.rules.utils import has_password_like_input

_LOADER_TITLE_TERMS = (
    "loading",
    "verifying",
    "connecting",
    "please wait",
    "redirecting",
)

# Empty SPA-style mount point (id="root" / "__root" / "app" / "__app" / "mount").
_MOUNT_ID_RE = re.compile(r"id\s*=\s*['\"]_{0,2}(?:root|app|mount)['\"]", re.IGNORECASE)

_FETCH_RE = re.compile(r"\bfetch\s*\(", re.IGNORECASE)

# Sinks that execute fetched markup/code as script (plain innerHTML does not
# run <script>, so it is deliberately excluded).
_EXEC_SINK_RE = re.compile(
    r"createElement\s*\(\s*['\"]script['\"]"
    r"|document\s*\.\s*write\s*\("
    r"|insertAdjacentHTML\s*\("
    r"|\beval\s*\(",
    re.IGNORECASE,
)

# Public blockchain RPC endpoints (host-shaped).
_RPC_HOST_RE = re.compile(
    r"api\.mainnet[.-]?rpc"
    r"|api\.mainnet\.solana|mainnet\.solana\.com"
    r"|\.ankr\.com|drpc\.org|publicnode\.com|omniatech"
    r"|infura\.io|alchemy(?:api)?\.(?:com|io)|quiknode\.pro|blastapi\.io|blockpi",
    re.IGNORECASE,
)

# JSON-RPC method calls / envelope used to talk to a chain.
_RPC_METHOD_RE = re.compile(
    r"getSignaturesForAddress|getTransaction|sendRawTransaction"
    r"|signAndSendTransaction|getAccountInfo|getProgramAccounts"
    r"|eth_(?:call|sendtransaction|getbalance|requestaccounts|sign)"
    r"|['\"]jsonrpc['\"]",
    re.IGNORECASE,
)

# Active wallet-provider interaction.
_WALLET_INTERACTION_RE = re.compile(
    r"window\s*\.\s*(?:solana|ethereum|tron|phantom|solflare)\b"
    r"|eth_requestaccounts|personal_sign"
    r"|wallet_(?:connect|requestpermissions|switchethereumchain)"
    r"|sign(?:all)?transactions?\s*\(",
    re.IGNORECASE,
)


def _visible_text_len(soup: BeautifulSoup) -> int:
    """Length of user-visible text, excluding <script>/<style>/<template>
    contents (which BeautifulSoup's get_text would otherwise include, hiding
    the fact that the body is an empty cloak shell wrapped around a big
    inline bootstrap)."""
    total = 0
    for el in soup.find_all(string=True):
        parent = el.parent.name if el.parent else ""
        if parent in ("script", "style", "template"):
            continue
        total += len(el.strip())
    return total


class DrainerLoaderRule(Rule):
    @property
    def name(self) -> str:
        return "drainer-loader"

    def evaluate(self, html: str, soup: BeautifulSoup) -> RuleResult:
        # S1 — cloak shell
        has_pw, _ = has_password_like_input(soup)
        title = ""
        if soup.title and soup.title.string:
            title = soup.title.string.strip().lower()
        loader_title = any(t in title for t in _LOADER_TITLE_TERMS)
        empty_mount = bool(_MOUNT_ID_RE.search(html))
        cloak_shell = (
            not has_pw
            and soup.find("form") is None
            and soup.find("input") is None
            and _visible_text_len(soup) < 300
            and (loader_title or empty_mount)
        )

        # S2 — fetch() remote payload + a sink that executes it
        remote_exec = bool(_FETCH_RE.search(html)) and bool(_EXEC_SINK_RE.search(html))

        # S3 — blockchain / wallet context
        rpc_ctx = bool(_RPC_HOST_RE.search(html)) or bool(_RPC_METHOD_RE.search(html))
        wallet_ctx = bool(_WALLET_INTERACTION_RE.search(html))
        chain_ctx = rpc_ctx or wallet_ctx

        triggered = cloak_shell and remote_exec and chain_ctx

        return RuleResult(
            rule_name=self.name,
            triggered=triggered,
            signals={
                "cloak_shell": cloak_shell,
                "loader_title": loader_title,
                "empty_mount": empty_mount,
                "remote_exec": remote_exec,
                "rpc_context": rpc_ctx,
                "wallet_interaction": wallet_ctx,
            },
        )
