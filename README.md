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

Clone this repo, copy `.env.example` to `.env`, and set your `ADMIN_API_KEY`:

```bash
cp .env.example .env
# Edit .env — set ADMIN_API_KEY to match your gateway's key
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
| **Wallet Impersonation** | Crypto brand in title/headings/img alt | Password input |
| **Obfuscated Loader** | DOM injection + encoding functions in script | Long base64, hex escapes, or charcode chains |

### ML Model (Advisory)

An XGBoost classifier trained on phishing vs. legitimate HTML provides a secondary signal. The ML model can escalate a CLEAN verdict to SUSPICIOUS (logged for review) but **never triggers auto-blocking on its own**.

```
Rule verdict     ML score       Final verdict
-----------      --------       -------------
MALICIOUS        any            MALICIOUS (auto-block in enforce mode)
CLEAN            >= 0.95        SUSPICIOUS (log only)
CLEAN            < 0.95         CLEAN
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
| `LOG_LEVEL` | No | `info` | Logging level (debug, info, warning, error) |
| `MAX_SCAN_BYTES` | No | `262144` | Max HTML bytes to scan (256KB) |
| `SCAN_TIMEOUT` | No | `10000` | Gateway fetch timeout in milliseconds |
| `DB_PATH` | No | `/app/data/scanner.db` | SQLite database path |
| `RULE_SEED_PHRASE` | No | `true` | Enable seed phrase harvesting rule |
| `RULE_EXTERNAL_CREDENTIAL_FORM` | No | `true` | Enable external credential form rule |
| `RULE_WALLET_IMPERSONATION` | No | `true` | Enable wallet impersonation rule |
| `RULE_OBFUSCATED_LOADER` | No | `true` | Enable obfuscated loader rule |
| `BACKFILL_ENABLED` | No | `false` | Enable proactive filesystem sweep of cached content |
| `BACKFILL_DATA_PATH` | No | -- | Gateway's contiguous data directory (required if backfill enabled) |
| `BACKFILL_GATEWAY_DB_PATH` | No | -- | Gateway's `data.db` path (read-only, for hash→TX ID lookups) |
| `BACKFILL_RATE` | No | `5` | Max files scanned per second during backfill |
| `BACKFILL_INTERVAL_HOURS` | No | `24` | Hours between backfill sweeps (0 = one-shot) |
| `ADMIN_UI_ENABLED` | No | `true` | Enable the admin dashboard at `/admin` |

## Admin Dashboard

Access the admin dashboard at `http://localhost:3100/admin`. Log in with your `SCANNER_ADMIN_KEY`.

The dashboard provides:
- **Dashboard** — real-time stats, system health, backfill status, recent detections
- **Review Queue** — confirm or dismiss flagged content (MALICIOUS/SUSPICIOUS verdicts)
- **Scan History** — searchable, filterable log of all scans with CSV export
- **Settings** — current configuration, rule status, database stats, training data export

Admin actions (confirm/dismiss) create overrides that persist across restarts. Dismissed content is never re-flagged. Confirmed content is always blocked in enforce mode.

## HTTP Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/scan` | POST | Receives `DATA_CACHED` webhook events (returns 202) |
| `/health` | GET | Health check (mode, version) |
| `/metrics` | GET | Scan statistics (verdicts, cache hits, blocks, queue depth) |

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
GATEWAY_URL=http://localhost:3000 ADMIN_API_KEY=secret python3 -m src.server
```
