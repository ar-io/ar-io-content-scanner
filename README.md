# ar.io Content Scanner

A content moderation sidecar for [ar.io gateways](https://github.com/ar-io/ar-io-node). Detects and auto-blocks phishing HTML content hosted on Arweave, keeping gateways clean and off blocklists like Netcraft and Google Safe Browsing.

## How It Works

```
                    ar-io-node                     Content Scanner
                    ----------                     ---------------

  User request ──> Cache miss ──> Fetch from Arweave
                        |
                   Cache write
                        |
                   DATA_CACHED ──────────────────> POST /scan
                        |                               |
                   Serve content                   Enqueue scan
                   (no delay)                           |
                                                   Worker picks up
                                                        |
                                               GET /raw/:id ──> Fetch HTML
                                                        |
                                                   Parse HTML
                                                   Run 4 rules + ML
                                                        |
                                                ┌── malicious? ──┐
                                                |                |
                                               yes               no
                                                |                |
                                          PUT block-data    Cache clean
                                                |
                                          Future requests ──> 404
```

**Tradeoff:** The first user to access malicious content sees it. All subsequent requests are blocked. This is acceptable because phishing pages need repeat victims, and blocking after first access eliminates the attack surface.

## Quick Start

### 1. Gateway Configuration

Add to your ar-io-node `.env`:

```bash
WEBHOOK_TARGET_SERVERS=http://content-scanner:3100/scan
WEBHOOK_EMIT_DATA_CACHED_EVENTS=true
```

If your gateway has `ENABLE_RATE_LIMITER=true`, allowlist the Docker network:

```bash
RATE_LIMITER_IPS_AND_CIDRS_ALLOWLIST=172.17.0.0/16
```

Requires ar-io-node with the `DATA_CACHED` webhook event support.

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
| **Seed Phrase Harvesting** | 8+ text inputs | Seed phrase terminology in visible text |
| **External Credential Form** | Password input | Form action is absolute URL, or JS exfil patterns with external URL |
| **Wallet Impersonation** | Crypto brand in title/headings/img alt | Password input or key-phrase terminology |
| **Obfuscated Loader** | DOM injection + encoding functions in script | Long base64, hex escapes, or charcode chains |

### ML Model (Advisory)

An XGBoost classifier trained on phishing vs. legitimate HTML provides a secondary signal. The ML model can escalate a CLEAN verdict to SUSPICIOUS (logged for review) but **never triggers auto-blocking on its own**.

```
Rule verdict     ML score       Final verdict
-----------      --------       -------------
MALICIOUS        any            MALICIOUS (auto-block in enforce mode)
CLEAN            >= 0.95        SUSPICIOUS (log only)
CLEAN            < 0.95         CLEAN

Post-scan (if SAFE_BROWSING_API_KEY set):
SUSPICIOUS + Google Safe Browsing flags URL → escalated to MALICIOUS
```

### Why This Won't Flag Legitimate DApps

Arweave content is static -- there is no server-side backend. A password form posting to an external URL has no legitimate use case. Real Arweave dApps authenticate via wallet signatures (`window.ethereum.request()`), not HTML password forms. The conjunctive rules exploit this Arweave-specific context.

## Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `GATEWAY_URL` | Yes | -- | ar-io-node internal URL (e.g., `http://core:4000`) |
| `ADMIN_API_KEY` | Yes | -- | Must match the gateway's `ADMIN_API_KEY` |
| `SCANNER_ADMIN_KEY` | Yes | -- | Secret key for the admin dashboard (separate from gateway key) |
| `SCANNER_MODE` | No | `dry-run` | `dry-run` (log only) or `enforce` (auto-block) |
| `SCANNER_PORT` | No | `3100` | HTTP server port |
| `SCANNER_WORKERS` | No | `2` | Number of concurrent scan workers |
| `ML_MODEL_ENABLED` | No | `true` | Enable XGBoost ML scoring |
| `ML_SUSPICIOUS_THRESHOLD` | No | `0.95` | ML score threshold for SUSPICIOUS escalation (0-1) |
| `LOG_LEVEL` | No | `info` | Logging level (debug, info, warning, error) |
| `MAX_SCAN_BYTES` | No | `262144` | Max HTML bytes to scan (256KB) |
| `SCAN_TIMEOUT` | No | `10000` | Gateway fetch timeout in milliseconds |
| `DB_PATH` | No | `/app/data/scanner.db` | SQLite database path |
| `RULE_SEED_PHRASE` | No | `true` | Enable seed phrase harvesting rule |
| `RULE_EXTERNAL_CREDENTIAL_FORM` | No | `true` | Enable external credential form rule |
| `RULE_WALLET_IMPERSONATION` | No | `true` | Enable wallet impersonation rule |
| `RULE_OBFUSCATED_LOADER` | No | `true` | Enable obfuscated loader rule |
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
| `SAFE_BROWSING_API_KEY` | No | -- | Google Safe Browsing API key (enables SB integration) |
| `SAFE_BROWSING_CHECK_INTERVAL` | No | `300` | Seconds between periodic domain + URL monitoring (min 60) |

## Admin Dashboard

Access the admin dashboard at `http://localhost:3100/admin`. Log in with your `SCANNER_ADMIN_KEY`.

The dashboard provides:
- **Dashboard** — real-time stats, system health, backfill status, Google Safe Browsing status, recent detections
- **Review Queue** — confirm or dismiss flagged content with screenshot previews and Safe Browsing indicators
- **Scan History** — searchable, filterable log of all scans with CSV export
- **Settings** — current configuration, rule status, database stats, training data export

Screenshots of flagged content are captured automatically using a headless Chromium browser (network-isolated to the gateway origin). Screenshots are displayed in the review queue and deleted when an admin confirms or dismisses the item.

Admin actions (confirm/dismiss) create overrides that persist across restarts. Dismissed content is never re-flagged. Confirmed content is always blocked in enforce mode.

## HTTP Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/scan` | POST | Receives `DATA_CACHED` webhook events (returns 202) |
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

Optional integration with Google's Safe Browsing Lookup API v4 provides a second independent signal for threat detection and monitors your gateway domain for blocklist status.

### Getting a Safe Browsing API Key

1. Go to the [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project (or select an existing one)
3. Navigate to **APIs & Services > Library**, search for "Safe Browsing API", and click **Enable**
4. Go to **APIs & Services > Credentials**, click **Create Credentials > API key**
5. (Recommended) Restrict the key to the **Safe Browsing API** only under **API restrictions**
6. Add the key to your `.env`:

```bash
SAFE_BROWSING_API_KEY=your-google-api-key
SAFE_BROWSING_CHECK_INTERVAL=300  # optional, default 5 minutes
```

The Safe Browsing API is free for non-commercial use (up to 10,000 requests/day).

### What It Does

- **On-verdict check**: When a scan produces a MALICIOUS or SUSPICIOUS verdict, the URL is checked against Google Safe Browsing before blocking. If SUSPICIOUS and Google also flags it, the verdict is escalated to MALICIOUS (two independent signals).
- **Periodic monitoring**: A background loop checks your gateway domain + recent malicious/suspicious URLs against Google every `SAFE_BROWSING_CHECK_INTERVAL` seconds. If your gateway domain is flagged, a warning banner appears on the admin dashboard.
- **Fail-open**: API errors never affect scanning or blocking. If Google is unreachable, verdicts proceed unchanged.

### Dashboard Integration

The admin dashboard shows Safe Browsing status including domain health, API check counts, flagged URLs, and escalation counts. The review queue shows a "Google Safe Browsing" badge on items flagged by Google.

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
