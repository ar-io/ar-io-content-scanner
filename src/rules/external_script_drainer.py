"""Rule 7: externally-loaded wallet-drainer loaders.

Wallet drainers on Arweave present as a near-empty "Loading…" shell whose real
payload is an executable ``<script src>`` pulled from a throwaway clearnet
domain (a drainer-kit CDN), paired with wallet / chain-RPC references so the
remote script can hijack ``window.solana`` / ``window.ethereum`` and sign a
draining transaction. They carry no password field, so the credential rules
miss them; the malicious code is remote, so ``obfuscated-loader`` (which keys on
*inline* encoding) misses them too — the page itself is nearly empty.

Two independent signals, both required (conjunctive):

  1. an executable ``<script src>`` to an external, non-allowlisted host, and
  2. wallet-interaction or public blockchain-RPC context in the document.

Loading executable JS from an arbitrary clearnet origin is itself anomalous on
*permanent* Arweave content — real dApps bundle their code as Arweave
transactions rather than pulling live code from a clearnet CDN. Pairing that
with active wallet/RPC context makes the intent unambiguous, so the two signals
together are near-zero false positive without needing the cloak shell. Bare
brand mentions ("metamask", "phantom") are deliberately *not* sufficient — an
article discussing wallets must not trip the rule.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from src.models import RuleResult
from src.rules.base import Rule

# Hosts that legitimately serve executable JS for permaweb content: Arweave
# gateways (permanent storage), well-known public CDNs, and ubiquitous
# analytics/tag origins. A <script src> to anything OUTSIDE this set is the
# anomaly we key on. Matched by exact host or dotted suffix.
_ALLOWED_SCRIPT_HOST_SUFFIXES = (
    # Arweave gateways / permaweb
    "arweave.net",
    "arweave.dev",
    "ar.io",
    "ar-io.dev",
    "permagate.io",
    # public code CDNs
    "jsdelivr.net",
    "unpkg.com",
    "cdnjs.cloudflare.com",
    "cloudflare.com",
    "googleapis.com",
    "gstatic.com",
    "jquery.com",
    "bootstrapcdn.com",
    "skypack.dev",
    "esm.sh",
    # analytics / tag managers (common on otherwise-legit pages)
    "google-analytics.com",
    "googletagmanager.com",
)

# Active wallet interaction — the remote drainer, or an inline stub, talking to
# an injected provider. Host-anchored / call-shaped so a prose mention of a
# wallet brand never matches on its own.
_WALLET_INTERACTION_RE = re.compile(
    r"window\s*\.\s*(?:solana|ethereum|tron|phantom|solflare)\b"
    r"|eth_requestaccounts|personal_sign|eth_sendtransaction"
    r"|wallet_(?:connect|requestpermissions|switchethereumchain)"
    r"|sign(?:all)?transactions?\s*\("
    r"|[?&]chain\s*=\s*(?:evm|solana|eth|bsc|polygon)",
    re.IGNORECASE,
)

# Known public blockchain RPC endpoints (host-shaped). Presence of these on an
# otherwise-static page is a strong wallet-drainer tell.
_RPC_HOST_RE = re.compile(
    r"api\.mainnet[.-]?rpc"
    r"|api\.mainnet\.solana|mainnet\.solana\.com"
    r"|\.ankr\.com|drpc\.org|publicnode\.com|omniatech"
    r"|infura\.io|alchemy(?:api)?\.(?:com|io)|quiknode\.pro|blastapi\.io|blockpi",
    re.IGNORECASE,
)

# Cloak shells (informational only — not required to trigger).
_CLOAK_TITLE_TERMS = ("loading", "verifying", "connecting", "please wait")


class ExternalScriptDrainerRule(Rule):
    @property
    def name(self) -> str:
        return "external-script-drainer"

    def evaluate(self, html: str, soup: BeautifulSoup) -> RuleResult:
        external_hosts: list[str] = []
        for tag in soup.find_all("script", src=True):
            host = self._external_host((tag.get("src") or "").strip())
            if host is not None:
                external_hosts.append(host)

        wallet_interaction = bool(_WALLET_INTERACTION_RE.search(html))
        rpc_context = bool(_RPC_HOST_RE.search(html))
        wallet_signal = wallet_interaction or rpc_context

        # Corroborating (not required): near-empty body with a loader title.
        text_len = len(soup.get_text(strip=True))
        title = ""
        if soup.title and soup.title.string:
            title = soup.title.string.strip().lower()
        cloak_shell = text_len < 200 and any(t in title for t in _CLOAK_TITLE_TERMS)

        triggered = bool(external_hosts) and wallet_signal

        return RuleResult(
            rule_name=self.name,
            triggered=triggered,
            signals={
                "external_script_hosts": sorted(set(external_hosts)),
                "wallet_interaction": wallet_interaction,
                "rpc_context": rpc_context,
                "cloak_shell": cloak_shell,
            },
        )

    @staticmethod
    def _external_host(src: str) -> str | None:
        """Host if ``src`` loads JS from an external, non-allowlisted clearnet
        origin; ``None`` for relative, ``data:``/``blob:``/``ar://`` or
        allowlisted (Arweave gateway / known CDN) sources."""
        if not src:
            return None
        low = src.lower()
        if low.startswith(("data:", "blob:", "ar://", "arweave://")):
            return None
        if low.startswith("//"):
            src = "https:" + src
        elif not low.startswith(("http://", "https://")):
            return None  # relative / same-origin — not external
        host = (urlparse(src).hostname or "").lower()
        if not host:
            return None
        for suffix in _ALLOWED_SCRIPT_HOST_SUFFIXES:
            if host == suffix or host.endswith("." + suffix):
                return None
        return host
