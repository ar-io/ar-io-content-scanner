# ar.io Content Scanner

A content moderation sidecar for [ar.io gateways](https://github.com/ar-io/ar-io-node). Detects and auto-blocks phishing content served by the gateway — both Arweave (TX ID) and IPFS (CID) — keeping gateways clean and off blocklists like Netcraft and Google Safe Browsing.

## How It Works

```
    ┌──────────────────────────────────────────────────────────────────┐
    │                          ar-io-node                              │
    │                                                                  │
    │  User request ──> Cache miss ──> Fetch from Arweave              │
    │                        │                                         │
    │                   Cache write ──> Serve content (no delay)       │
    │                        │                                         │
    │                   Webhook events                                  │
    │              (data-cached / tx-indexed /                          │
    │               ans104-data-item-indexed)                           │
    └────────────────────────┼─────────────────────────────────────────┘
                             │
                             ▼
    ┌──────────────────────────────────────────────────────────────────┐
    │                      Content Scanner                             │
    │                                                                  │
    │  POST /scan ──> Check cache ──> Enqueue ──> Worker picks up      │
    │                                                  │               │
    │                                          Fetch content           │
    │                                          GET /raw/:id            │
    │                                                  │               │
    │                                          ┌───────┴────────┐      │
    │                                          │  Route by type  │      │
    │                                          └───┬────────┬───┘      │
    │                                              │        │          │
    │                                   ┌──────────┘        └───────┐  │
    │                                   ▼                           ▼  │
    │                              HTML content              Non-HTML  │
    │                                   │                   (Tier 2)   │
    │                                   ▼                       │      │
    │                          ┌─────────────────┐    Content scanners  │
    │                          │  Static rules   │    (pluggable, async │
    │                          │  4 rules + ML   │     fail-open)      │
    │                          └────────┬────────┘              │      │
    │                                   │                       │      │
    │                          ┌────────┴────────┐              │      │
    │                          │ Defense layers   │              │      │
    │                          │ Iframe scanning  │              │      │
    │                          │ Rendered DOM     │              │      │
    │                          └────────┬────────┘              │      │
    │                                   │                       │      │
    │                                   └───────────┬───────────┘      │
    │                                               ▼                  │
    │                                    ┌─────────────────────┐       │
    │                                    │   Verdict decision   │       │
    │                                    └──────┬──────┬───────┘       │
    │                                           │      │               │
    │                                      malicious   clean           │
    │                                           │      │               │
    │                                    Block content  Cache verdict   │
    │                                    PUT block-data                 │
    │                                           │                      │
    │                                    Future requests ──> 404       │
    └──────────────────────────────────────────────────────────────────┘
```

**On-access scanning** (`data-cached`): The first user to access malicious content sees it. All subsequent requests are blocked.

**Index-time scanning** (`tx-indexed`, `ans104-data-item-indexed`): Content is scanned when indexed by the gateway, before any user accesses it. Requires `WEBHOOK_INDEX_FILTER` on the gateway. Note: for `tx-indexed` events, the content hash is unavailable (only a merkle root), so verdicts are not cached until the content is accessed and a `data-cached` event provides the real hash.

**IPFS content**: When the gateway serves IPFS content (CIDs), it emits the same `data-cached` webhook with a CID in the `id` field. The scanner auto-detects the addressing scheme — Arweave TX IDs are fetched from `GET /raw/{id}` and IPFS CIDs from `GET /ipfs/{id}` — and the same rules, ML model, blocking pipeline, and verdict feed apply. Blocks are issued via `PUT /ar-io/admin/block-data` with the CID in the `id` field; the gateway accepts both ID formats. (Backfill currently scans only Arweave contiguous data; IPFS cache backfill is a future enhancement.)

## Quick Start

### 1. Gateway Configuration

Add to your ar-io-node `.env`:

```bash
WEBHOOK_TARGET_SERVERS=http://content-scanner:3100/scan
WEBHOOK_EMIT_DATA_CACHED_EVENTS=true
```

For index-time scanning (recommended — catches content before first access):

```bash
WEBHOOK_INDEX_FILTER={"always": true}
```

If your gateway has `ENABLE_RATE_LIMITER=true`, allowlist the Docker network:

```bash
RATE_LIMITER_IPS_AND_CIDRS_ALLOWLIST=172.17.0.0/16
```

Requires ar-io-node with webhook event support.

### 2. Run the Scanner

Clone this repo, copy `.env.example` to `.env`, and configure:

```bash
cp .env.example .env
# Edit .env:
#   ADMIN_API_KEY    — must match your gateway's ADMIN_API_KEY
#   SCANNER_ADMIN_KEY — choose a secret key for the admin dashboard
docker compose up -d
```

The included `docker-compose.yml` joins the ar-io-node's `ar-io-network` automatically.

### 3. Observe, Then Enforce

Start with `SCANNER_MODE=dry-run` (the default) to observe detections in logs without blocking. When satisfied with accuracy, set `SCANNER_MODE=enforce` in your `.env` and restart.

## Detection Engine

### Tier 1 Rules (Auto-Block)

Each rule requires 2+ independent signals (conjunctive logic) to ensure near-zero false positives.

| Rule | Signal A | Signal B |
|------|----------|----------|
| **Seed Phrase Harvesting** | 6+ text inputs + seed phrase terminology | External data transmission (form action or JS exfil with external URL) |
| **External Credential Form** | Password input | Form action is absolute URL, or JS exfil patterns with external URL |
| **Wallet Impersonation** | Crypto brand in title/headings/img alt/body text | Password input or key-phrase terminology |
| **Obfuscated Loader** | DOM injection + encoding functions in script | Long base64, hex escapes, or charcode chains |
| **Fake Challenge Page** | Unique fake-Cloudflare/"checking your connection" kit signature | (or) generic cloak phrase + a corroborating phrase |
| **Credential Phishing Kit** | Known webmail/SSO/O365 kit template string | Credential context (password input or the kit's pre-filled error state) |
| **External Script Drainer** | Executable `<script src>` from an external, non-allowlisted host | Wallet-provider interaction or public blockchain-RPC context |
| **Drainer Loader** | Cloak "Loading…" shell (no inputs, sparse body) + `fetch()` into a script-exec sink | Public RPC endpoints, JSON-RPC calls, or wallet interaction |

The last two catch **wallet drainers**: near-empty loader shells that pull their payload from an external clearnet host (External Script Drainer) or from an on-chain dead-drop and inject/execute it in-page (Drainer Loader). Both carry no password field and hide the real logic remotely, so the credential and obfuscated-loader rules miss them.

### ML Model (Advisory)

An XGBoost classifier trained on phishing vs. legitimate HTML provides a secondary signal. The ML model can escalate a CLEAN verdict to SUSPICIOUS (logged for review) but **never triggers auto-blocking on its own**.

```
Rule verdict     ML score       Final verdict
-----------      --------       -------------
MALICIOUS        any            MALICIOUS (auto-block in enforce mode)
CLEAN            >= 0.95        SUSPICIOUS (log only)
CLEAN            < 0.95         CLEAN

Defense-in-depth (automatic, runs after static rules return CLEAN):
Iframe scanning    — extracts + scans data: URI and srcdoc iframes
Rendered DOM scan  — re-renders JS-heavy pages in Playwright, re-runs rules

Post-scan (if SAFE_BROWSING_API_KEY set, optional):
SUSPICIOUS + Google Safe Browsing flags URL → escalated to MALICIOUS
```

### Content Scanners (Tier 2)

The scanner supports a pluggable architecture for non-HTML content types. Content scanners implement the `ContentScanner` ABC and are registered by MIME type pattern (e.g., `image/*`, `application/pdf`). When content arrives that matches a registered scanner, it is routed to that scanner instead of the HTML rule engine.

Content scanners:
- Run asynchronously and can call external APIs
- Are fail-open: scanner errors never block legitimate content
- Multiple scanners matching the same type run concurrently; highest severity verdict wins
- When no content scanners are registered, behavior is identical to before (non-HTML content is skipped)

See `CONTRIBUTING.md` for instructions on adding new content scanners, and `src/scanners/example_image_scanner.py` for a reference implementation.

### Why This Won't Flag Legitimate DApps

Arweave content is static -- there is no server-side backend. A password form posting to an external URL has no legitimate use case. Real Arweave dApps authenticate via wallet signatures (`window.ethereum.request()`), not HTML password forms. The conjunctive rules exploit this Arweave-specific context.

## Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `GATEWAY_URL` | Yes | -- | ar-io-node internal URL (e.g., `http://core:4000`) |
| `ADMIN_API_KEY` | Yes | -- | Must match the gateway's `ADMIN_API_KEY` |
| `SCANNER_ADMIN_KEY` | Yes | -- | Secret key for the admin dashboard (separate from gateway key) |
| `SCANNER_MODE` | No | `dry-run` | `dry-run` (log only) or `enforce` (auto-block) |
| `WEBHOOK_EVENTS` | No | `data-cached,tx-indexed,ans104-data-item-indexed` | Comma-separated webhook events to process |
| `WEBHOOK_INDEX_DELAY` | No | `60` | Seconds to wait before processing indexed events (0 = immediate) |
| `SCANNER_PORT` | No | `3100` | HTTP server port |
| `SCANNER_WORKERS` | No | `2` | Number of concurrent scan workers |
| `ML_MODEL_ENABLED` | No | `true` | Enable XGBoost ML scoring |
| `ML_SUSPICIOUS_THRESHOLD` | No | `0.95` | ML score threshold for SUSPICIOUS escalation (0-1) |
| `LOG_LEVEL` | No | `info` | Logging level (debug, info, warning, error) |
| `LOG_FORMAT` | No | `text` | Log output format: `text` (human-readable) or `json` (for log aggregation) |
| `MAX_SCAN_BYTES` | No | `262144` | Max HTML bytes to scan (256KB) |
| `SCAN_TIMEOUT` | No | `10000` | Gateway fetch timeout in milliseconds |
| `DB_PATH` | No | `/app/data/scanner.db` | SQLite database path |
| `RULE_SEED_PHRASE` | No | `true` | Enable seed phrase harvesting rule |
| `RULE_EXTERNAL_CREDENTIAL_FORM` | No | `true` | Enable external credential form rule |
| `RULE_WALLET_IMPERSONATION` | No | `true` | Enable wallet impersonation rule |
| `RULE_OBFUSCATED_LOADER` | No | `true` | Enable obfuscated loader rule |
| `RULE_FAKE_CHALLENGE` | No | `true` | Enable fake challenge-page (cloak interstitial) rule |
| `RULE_CREDENTIAL_KIT` | No | `true` | Enable known credential-kit template rule |
| `RULE_EXTERNAL_SCRIPT_DRAINER` | No | `true` | Enable external-script wallet-drainer rule |
| `RULE_DRAINER_LOADER` | No | `true` | Enable remote-payload / dead-drop wallet-drainer-loader rule |
| `SCREENSHOT_ENABLED` | No | `true` | Capture screenshots of flagged content for admin review |
| `SCREENSHOT_DIR` | No | `/app/data/screenshots` | Directory to store screenshot files |
| `SCREENSHOT_TIMEOUT_MS` | No | `15000` | Page load + capture timeout in milliseconds |
| `BACKFILL_ENABLED` | No | `false` | Enable proactive filesystem sweep of cached content |
| `BACKFILL_DATA_PATH` | No | -- | Gateway's contiguous data directory (required if backfill enabled) |
| `BACKFILL_GATEWAY_DB_PATH` | No | -- | Gateway's `data.db` path (read-only, for hash→TX ID lookups) |
| `BACKFILL_RATE` | No | `5` | Max files scanned per second during backfill |
| `BACKFILL_INTERVAL_HOURS` | No | `24` | Hours between backfill sweeps (0 = one-shot) |
| `ADMIN_UI_ENABLED` | No | `true` | Enable the admin dashboard at `/admin` |
| `GATEWAY_PUBLIC_URL` | No | -- | Public gateway URL for clickable TX ID links (e.g., `https://vilenarios.com`) |
| `VERDICT_API_KEY` | No | -- | API key for verdict feed (both serving and consuming) |
| `VERDICT_FEED_URLS` | No | -- | Comma-separated peer scanner URLs to poll |
| `VERDICT_FEED_POLL_INTERVAL` | No | `300` | Seconds between polling peers |
| `VERDICT_FEED_TRUST_MODE` | No | `malicious_only` | `malicious_only` or `all` |
| `VERDICT_FEED_ON_DEMAND` | No | `true` | Check peers before scanning locally |
| `VERDICT_FEED_REQUEST_TIMEOUT_MS` | No | `5000` | Timeout for peer API requests |
| `SAFE_BROWSING_API_KEY` | No | -- | Google Safe Browsing API key (optional, enables URL-level checks via Lookup API) |
| `SAFE_BROWSING_CHECK_INTERVAL` | No | `3600` | Seconds between periodic domain + URL monitoring (min 60) |
| `RENDERED_DOM_SCAN_ENABLED` | No | `true` | Two-pass rendered DOM scan for JS-rendered phishing (uses Playwright) |
| `SCANNER_EXAMPLE_IMAGE` | No | `false` | Enable example image scanner (stub, for development/testing) |
| `EDGE_CACHE_REVALIDATION_ENABLED` | No | `false` | Fire one revalidation request per blocked id at the public gateway URL after a `block-data` succeeds, so an HTTP cache (nginx/Varnish/Cloudflare/Fastly) in front of the gateway picks up the new 451 instead of serving its stale 200 until TTL |
| `EDGE_CACHE_REVALIDATION_URL_BASE` | No | falls back to `GATEWAY_PUBLIC_URL` | Public origin to send the revalidation request to (e.g., `https://vilenarios.com`) |
| `EDGE_CACHE_REVALIDATION_HEADERS` | No | `Cache-Control: no-cache, X-Cache-Bypass: 1` | Comma-separated `Header: value` pairs added to revalidation requests |
| `EDGE_CACHE_REVALIDATION_PATHS_ARWEAVE` | No | `/raw/{id},/{id}` | Comma-separated path templates used per Arweave block (`{id}` is substituted) |
| `EDGE_CACHE_REVALIDATION_PATHS_IPFS` | No | `/ipfs/{id}` | Comma-separated path templates used per IPFS block |
| `EDGE_CACHE_REVALIDATION_TIMEOUT_MS` | No | `5000` | Per-request timeout for revalidation calls |

### Edge-cache revalidation

Operators who run an HTTP cache in front of the gateway face a window where a malicious response can be cached at the edge before the scanner blocks it — the gateway will return 451 from then on, but the edge keeps serving the cached 200 until its TTL expires. Setting `EDGE_CACHE_REVALIDATION_ENABLED=true` makes the scanner fire one GET per configured path template after every successful `block-data` (and `unblock-data`) call. The defaults work for nginx setups that honor `X-Cache-Bypass` via `proxy_cache_bypass $http_x_cache_bypass`. Other edges may need different headers — Cloudflare ignores client `Cache-Control` from arbitrary IPs and needs its own purge API; Varnish/Fastly typically honor `Cache-Control: no-cache` from origin-pull contexts. Revalidation failures are logged and counted (`scanner_edge_cache_revalidations_total{result="fail"}`) but never block or retry the underlying `block-data` call. Multi-tier caches (CDN → reverse proxy → origin) are out of scope: the revalidation hit only invalidates whichever edge it reaches.

## Admin Dashboard

Access the admin dashboard at `http://localhost:3100/admin`. Log in with your `SCANNER_ADMIN_KEY`.

The dashboard provides:
- **Dashboard** — real-time stats, system health, backfill status, Google Safe Browsing status, recent detections
- **Review Queue** — confirm or dismiss flagged content with screenshot previews and Safe Browsing indicators
- **Scan History** — searchable, filterable log of all scans with CSV export
- **Manual Block** — block any Arweave transaction by TX ID without waiting for detection
- **Settings** — current configuration, rule status, database stats, training data export

Screenshots of flagged content are captured automatically using a headless Chromium browser (network-isolated to the gateway origin). Screenshots are displayed in the review queue and deleted when an admin confirms or dismisses the item.

Admin actions (confirm/dismiss) create overrides that persist across restarts. Dismissed content is never re-flagged. Confirmed content is always blocked in enforce mode.

### Manual Block

Use the Manual Block tab to immediately block content that the scanner hasn't detected yet — e.g. items reported through external channels or known-bad transactions. You can block by:

- **Arweave TX ID** or **IPFS CID** — one or many (paste up to 100, one per line)
- **Sandbox subdomain** — the base32 hostname Google Safe Browsing / the scanner report content by (e.g. `k7nom5…lfq.arweave.net`) is auto-decoded to its TX ID before blocking
- **ArNS name** — block/unblock name resolution via `POST /api/admin/block-name` (single or up to 100). Name blocks are recorded on the gateway; because they aren't TX-ID-keyed they don't appear in the TX-ID "Manual Blocks" history.

Content (TX ID / CID) manual blocks:

- **Always block the gateway** regardless of scanner mode (dry-run or enforce) — this is an explicit operator action
- Create a MALICIOUS verdict with `source='manual'` and a `confirmed_malicious` admin override
- Appear in Scan History (filterable by "manual" source) and Review Queue (under "confirmed" status)
- Can be reverted from the Review Queue, which restores the previous verdict and unblocks the content
- Are **not exported** via the verdict feed to prevent operator decisions from propagating to peers

## Slack Alerts

When `SLACK_ENABLED=true`, the scanner posts an alert (with a screenshot) to `SLACK_CHANNEL_ID` for each detection at or above `SLACK_NOTIFICATION_THRESHOLD` (`malicious` or `suspicious`). Each alert carries **Confirm / Dismiss / Classify** buttons that block/unblock the content and update the message in place.

Button clicks reach the scanner one of two ways:

- **Socket Mode (recommended)** — set `SLACK_APP_TOKEN` (`xapp-`, scope `connections:write`) and enable Socket Mode + Interactivity in your Slack app. The scanner opens an **outbound** WebSocket to Slack, so **no public callback URL or inbound port is required**.
- **HTTP request URL** — expose `POST /api/slack/actions` (HMAC-verified with `SLACK_SIGNING_SECRET`) publicly over HTTPS and set it as the app's Interactivity Request URL.

The bot needs `chat:write` (post), `files:write` (screenshots), and to be invited to the channel.

## HTTP Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/scan` | POST | Receives gateway webhook events (`data-cached`, `tx-indexed`, `ans104-data-item-indexed`) (returns 202) |
| `/health` | GET | Health check (mode, version) |
| `/metrics` | GET | Scan statistics JSON (verdicts, cache hits, blocks, queue depth) |
| `/metrics/prometheus` | GET | Prometheus-formatted metrics (text/plain) |
| `/admin` | GET | Admin dashboard (browser UI) |
| `/api/admin/stats` | GET | Dashboard data (requires `SCANNER_ADMIN_KEY`) |
| `/api/admin/review` | GET | Review queue with filters |
| `/api/admin/review/:hash/confirm` | POST | Confirm detection as malicious |
| `/api/admin/review/:hash/dismiss` | POST | Dismiss as false positive |
| `/api/admin/review/:hash/revert` | POST | Revert a previous confirm/dismiss |
| `/api/admin/screenshot/:hash` | GET | Screenshot image (JPEG) for flagged content |
| `/api/admin/preview/:txid` | GET | Raw HTML source preview |
| `/api/admin/block` | POST | Manually block a transaction by TX ID |
| `/api/admin/block/export` | GET | Export blocked TX IDs as plain text (for bootstrapping) |
| `/api/admin/history` | GET | Paginated scan history |
| `/api/admin/history/export` | GET | CSV export of scan history |
| `/api/admin/settings` | GET | Current scanner configuration |
| `/api/verdicts/:hash` | GET | Single verdict lookup (requires `VERDICT_API_KEY`) |
| `/api/verdicts` | GET | Paginated verdict feed (requires `VERDICT_API_KEY`) |

## Multi-Gateway Deployment

Each gateway runs its own Content Scanner sidecar. Scanners share detections via the verdict feed — when one scanner detects a phishing page, all peers auto-block it too.

```
Gateway A ──> Scanner A ──┐
                          ├── Verdict Feed (shared API key)
Gateway B ──> Scanner B ──┘
```

Each scanner has its own `GATEWAY_URL`, `ADMIN_API_KEY`, and database. The only shared config is `VERDICT_API_KEY` and `VERDICT_FEED_URLS`. See the [Operator Guide](OPERATOR.md#multi-gateway-deployment) for full setup instructions.

## Verdict Feed

The verdict feed lets multiple content scanners share detection results. One scanner's detection can protect all peers.

### Setup

**Scanner A** (producer only — serves verdicts):
```bash
VERDICT_API_KEY=shared-secret-key
```

**Scanner B** (consumer — polls Scanner A):
```bash
VERDICT_API_KEY=shared-secret-key
VERDICT_FEED_URLS=http://scanner-a:3100
```

**Fleet** (bidirectional — each scanner polls the others):
```bash
# On Scanner A
VERDICT_API_KEY=shared-secret-key
VERDICT_FEED_URLS=http://scanner-b:3100,http://scanner-c:3100

# On Scanner B
VERDICT_API_KEY=shared-secret-key
VERDICT_FEED_URLS=http://scanner-a:3100,http://scanner-c:3100
```

### Trust Modes

- **`malicious_only`** (default) — only import MALICIOUS verdicts from peers. A peer's CLEAN verdict won't prevent local scanning. Safest option.
- **`all`** — import all verdicts. Best for identically-configured scanner fleets.

### How It Works

- **Polling**: A background loop polls each peer every `VERDICT_FEED_POLL_INTERVAL` seconds for new verdicts.
- **On-demand**: When scanning new content, peers are checked first. If a peer already has a verdict, the local scan is skipped.
- **Echo prevention**: Imported verdicts are never re-exported. Scanner A → Scanner B will not echo back to Scanner A.
- **Deduplication**: Local verdicts always take priority. If content was already scanned locally, peer verdicts are ignored.
- **Admin overrides**: Locally dismissed content is never reimported from peers.
- **Blocking**: Imported MALICIOUS verdicts trigger auto-blocking in enforce mode, just like local detections.

## Google Safe Browsing

The scanner automatically monitors your gateway domain against Google Safe Browsing via the Transparency Report — **no API key required**. If your domain is flagged, a warning banner appears on the admin dashboard.

Optionally, you can add a Google Safe Browsing API key to enable URL-level checks via the Lookup API v4, which provides a second independent signal for individual content URLs.

### Domain Monitoring (Automatic)

A background loop checks your gateway domain against Google's Transparency Report every `SAFE_BROWSING_CHECK_INTERVAL` seconds. This detects site-level flags (the same status shown on [Google's Transparency Report](https://transparencyreport.google.com/safe-browsing/search)). Requires `GATEWAY_PUBLIC_URL` to be set.

When `SLACK_ENABLED=true`, a domain flag also fires a **Slack alert** (independent of `SLACK_NOTIFICATION_THRESHOLD`, since a flagged gateway domain is always critical). The alert lists the threat types, a Transparency Report link, and the **recent malicious TX IDs on the domain that are the likely cause** — marked `🔴 Google-flagged` for any that Google's Lookup API independently confirms (requires `SAFE_BROWSING_API_KEY`). Alerts fire only on a flagged↔cleared state change, not every interval, so the channel isn't spammed while the domain stays flagged.

### URL-Level Checks (Optional, requires API key)

To enable per-URL checks via the Lookup API v4:

1. Go to the [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project (or select an existing one)
3. Navigate to **APIs & Services > Library**, search for "Safe Browsing API", and click **Enable**
4. Go to **APIs & Services > Credentials**, click **Create Credentials > API key**
5. (Recommended) Restrict the key to the **Safe Browsing API** only under **API restrictions**
6. Add the key to your `.env`:

```bash
SAFE_BROWSING_API_KEY=your-google-api-key
```

The Safe Browsing API is free for non-commercial use (up to 10,000 requests/day).

When configured, the scanner checks individual flagged content URLs against Google. If a SUSPICIOUS verdict is corroborated by Google, it is escalated to MALICIOUS (two independent signals).

### Fail-Open Design

All Safe Browsing checks (both domain and URL-level) are fail-open. API errors never affect scanning or blocking. If Google is unreachable, verdicts proceed unchanged.

### Dashboard Integration

The admin dashboard shows Safe Browsing status including domain health, threat types, API check counts, flagged URLs, and escalation counts. The review queue shows a "Google Safe Browsing" badge on items flagged by Google.

## Docker Images

Pre-built images are published to GHCR on every push to `main` and on version tags.

```bash
# Pull the latest image
docker pull ghcr.io/ar-io/ar-io-content-scanner:main

# Or pin to a specific version
docker pull ghcr.io/ar-io/ar-io-content-scanner:0.1.0
```

### CI/CD

The GitHub Actions workflow (`.github/workflows/build-and-push.yml`) runs tests then builds and pushes automatically:

| Trigger | Image Tags |
|---------|------------|
| Push to `main` | `:main`, `:sha-<commit>` |
| Tag `v1.0.0` | `:1.0.0`, `:1.0`, `:sha-<commit>` |
| Pull request | Tests only, no image push |

### Creating a Release

```bash
git tag v0.1.0
git push origin v0.1.0
```

This publishes versioned images that operators can pin to.

## Development

```bash
# Install dependencies
pip install -r requirements.txt -r requirements-dev.txt

# Run tests
python3 -m pytest tests/ -v

# Build Docker image locally
docker build -t content-scanner .

# Run locally
GATEWAY_URL=http://localhost:3000 ADMIN_API_KEY=secret SCANNER_ADMIN_KEY=admin python3 -m src.server
```
