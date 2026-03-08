# ar.io Content Scanner — Operator Guide

This guide covers deploying, configuring, and operating Content Scanner alongside your ar.io gateway.

## Prerequisites

- ar-io-node with `DATA_CACHED` webhook event support
- Docker and Docker Compose
- Your gateway's `ADMIN_API_KEY`
- A separate `SCANNER_ADMIN_KEY` for admin dashboard access

## Deployment

### Step 1: Update Gateway Environment

Add these to your ar-io-node `.env`:

```bash
# Point webhooks at Content Scanner
WEBHOOK_TARGET_SERVERS=http://content-scanner:3100/scan

# Enable the DATA_CACHED event (opt-in, default is false)
WEBHOOK_EMIT_DATA_CACHED_EVENTS=true
```

If your gateway has `ENABLE_RATE_LIMITER=true`, allowlist the Docker internal network so Content Scanner can fetch content:

```bash
RATE_LIMITER_IPS_AND_CIDRS_ALLOWLIST=172.17.0.0/16
```

### Step 2: Deploy Content Scanner

Clone the Content Scanner repo, copy `.env.example` to `.env`, and configure:

```bash
git clone https://github.com/ar-io/gateway-content-scanner.git
cd gateway-content-scanner
cp .env.example .env
# Edit .env:
#   ADMIN_API_KEY     — must match your gateway's ADMIN_API_KEY
#   SCANNER_ADMIN_KEY — choose a secret key for the admin dashboard
```

The included `docker-compose.yml` joins the ar-io-node's `ar-io-network` automatically, so both containers can communicate by service name (`core` and `content-scanner`).

### Step 3: Start in Dry-Run Mode

```bash
docker compose up -d
```

In dry-run mode (the default), Content Scanner logs all detections but never blocks content. This lets you verify accuracy before enforcement.

### Step 4: Enable Enforcement

Once you're confident in the detection accuracy (check logs for false positives), set enforce mode in your `.env`:

```bash
SCANNER_MODE=enforce
```

Then restart Content Scanner:

```bash
docker compose restart content-scanner
```

## Admin Dashboard

Access the admin dashboard at `http://localhost:3100/admin`. Log in with your `SCANNER_ADMIN_KEY`.

The dashboard provides:

- **Dashboard** — real-time stats, system health, backfill status, recent detections with 30-second auto-refresh
- **Review Queue** — confirm or dismiss flagged content with screenshot previews of flagged pages
- **Scan History** — searchable, filterable log of all scans with CSV export
- **Settings** — current configuration, rule status, database stats, training data export

Screenshots of flagged content are captured automatically using a headless browser (included in the Docker image). They appear as thumbnails in the review queue, making it easy to identify phishing pages at a glance. Screenshots are deleted when you confirm or dismiss an item.

### Admin Overrides

When you confirm or dismiss a detection, an **admin override** is created:

- **Confirm**: Marks content as malicious. In enforce mode, the content is immediately blocked. The override persists — if the same content is re-encountered (e.g., during backfill), it is blocked without re-scanning.
- **Dismiss**: Marks content as clean. The verdict is updated to CLEAN and the content is never re-flagged, even on subsequent backfill sweeps.

Overrides persist in the database across container restarts.

## Monitoring

### Health Check

```bash
curl http://localhost:3100/health
```

Returns:
```json
{
  "status": "ok",
  "mode": "dry-run",
  "version": "0.1.0"
}
```

### Metrics

```bash
curl http://localhost:3100/metrics
```

Returns:
```json
{
  "scans_total": 1523,
  "scans_by_verdict": {"clean": 1510, "suspicious": 8, "malicious": 5},
  "scans_skipped_not_html": 9843,
  "cache_hits": 320,
  "cache_misses": 1203,
  "blocks_sent": 5,
  "blocks_failed": 0,
  "avg_scan_ms": 35.2,
  "queue_depth": 0,
  "uptime_seconds": 86400,
  "feed_verdicts_imported": 42,
  "feed_verdicts_exported": 156,
  "feed_poll_errors": 0,
  "feed_on_demand_hits": 18,
  "feed_on_demand_misses": 95
}
```

Key metrics to watch:
- **blocks_failed** > 0: Content Scanner can't reach the gateway admin API. Check `ADMIN_API_KEY` and network connectivity.
- **queue_depth** growing: Workers can't keep up. Increase `SCANNER_WORKERS`.
- **scans_by_verdict.suspicious** > 0: ML model flagged content the rules didn't catch. Review logs for these transaction IDs.
- **feed_poll_errors** > 0: Can't reach a peer scanner. Check network and `VERDICT_API_KEY`.
- **feed_on_demand_hits** growing: Peer lookups are saving local scan work.

### Logs

Content Scanner outputs structured JSON logs. Key log events:

```bash
# See all scan results
docker compose logs content-scanner | grep scan_complete

# See blocks
docker compose logs content-scanner | grep block_sent

# See suspicious content (ML-flagged, not blocked)
docker compose logs content-scanner | grep -i suspicious
```

Example log entry for a blocked phishing page:

```json
{
  "timestamp": "2024-01-15T10:30:45",
  "level": "WARNING",
  "logger": "scanner.core",
  "message": "scan_complete",
  "tx_id": "abc123...",
  "verdict": "malicious",
  "rules": ["seed-phrase-harvesting", "wallet-impersonation"],
  "ml_score": 0.97,
  "scan_ms": 42,
  "action": "blocked"
}
```

## Configuration Reference

### Required

| Variable | Description |
|----------|-------------|
| `GATEWAY_URL` | Internal URL of your ar-io-node (e.g., `http://core:4000`) |
| `ADMIN_API_KEY` | Must match the gateway's `ADMIN_API_KEY` (machine-to-machine auth for blocking) |
| `SCANNER_ADMIN_KEY` | Secret key for the admin dashboard (separate from gateway key) |

### Optional

| Variable | Default | Description |
|----------|---------|-------------|
| `SCANNER_MODE` | `dry-run` | `dry-run` logs detections; `enforce` auto-blocks |
| `SCANNER_PORT` | `3100` | HTTP server port |
| `SCANNER_WORKERS` | `2` | Concurrent scan workers |
| `ML_MODEL_ENABLED` | `true` | Enable XGBoost ML scoring |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warning`, `error` |
| `MAX_SCAN_BYTES` | `262144` | Max HTML bytes to scan (256KB) |
| `SCAN_TIMEOUT` | `10000` | Gateway fetch timeout in ms |
| `DB_PATH` | `/app/data/scanner.db` | SQLite database path |
| `ADMIN_UI_ENABLED` | `true` | Enable the admin dashboard at `/admin` |
| `GATEWAY_PUBLIC_URL` | -- | Public gateway URL for clickable TX ID links (e.g., `https://vilenarios.com`) |
| `SCREENSHOT_ENABLED` | `true` | Capture screenshots of flagged content for admin review |
| `SCREENSHOT_DIR` | `/app/data/screenshots` | Directory to store screenshot files |
| `SCREENSHOT_TIMEOUT_MS` | `15000` | Page load + capture timeout in ms |

### Verdict Feed

| Variable | Default | Description |
|----------|---------|-------------|
| `VERDICT_API_KEY` | *(none)* | API key for verdict feed (same key for serving and consuming) |
| `VERDICT_FEED_URLS` | *(none)* | Comma-separated peer scanner URLs to poll |
| `VERDICT_FEED_POLL_INTERVAL` | `300` | Seconds between polling peers |
| `VERDICT_FEED_TRUST_MODE` | `malicious_only` | `malicious_only` or `all` |
| `VERDICT_FEED_ON_DEMAND` | `true` | Check peers before scanning locally |
| `VERDICT_FEED_REQUEST_TIMEOUT_MS` | `5000` | Timeout for peer API requests in ms |

### Rule Toggles

All rules are enabled by default. Disable individual rules if needed:

| Variable | Default | Rule |
|----------|---------|------|
| `RULE_SEED_PHRASE` | `true` | Seed phrase harvesting (8+ inputs + seed terms) |
| `RULE_EXTERNAL_CREDENTIAL_FORM` | `true` | Password + external form action or JS exfil patterns |
| `RULE_WALLET_IMPERSONATION` | `true` | Crypto brand spoofing with password input or key-phrase terminology |
| `RULE_OBFUSCATED_LOADER` | `true` | Encoded/obfuscated DOM injection |

## Troubleshooting

### Content Scanner isn't scanning anything

1. Check that `WEBHOOK_EMIT_DATA_CACHED_EVENTS=true` is set on the gateway
2. Check that `WEBHOOK_TARGET_SERVERS` points to the correct Content Scanner URL
3. Verify Content Scanner is healthy: `curl http://localhost:3100/health`
4. Check gateway logs for webhook delivery errors

### Blocks are failing (blocks_failed > 0)

1. Verify `ADMIN_API_KEY` matches between gateway and Content Scanner
2. Check that `GATEWAY_URL` is reachable from the Content Scanner container
3. Check Content Scanner logs for `block_failed` entries with status codes

### Gateway is rate-limiting Content Scanner

Add the Docker network CIDR to the gateway's rate limiter allowlist:

```bash
RATE_LIMITER_IPS_AND_CIDRS_ALLOWLIST=172.17.0.0/16
```

### Queue depth keeps growing

Increase the number of scan workers:

```bash
SCANNER_WORKERS=4
```

### False positive (legitimate content blocked)

1. Open the admin dashboard at `http://localhost:3100/admin`
2. Go to the **Review Queue** tab and find the flagged content
3. Click **Dismiss** to mark it as a false positive — this updates the verdict to CLEAN and creates an override so the content is never re-flagged
4. If the content was already blocked in enforce mode, you'll also need to unblock it via the gateway's admin API

## Data and Persistence

Content Scanner stores its SQLite database at `DB_PATH` (default: `/app/data/scanner.db`). This contains:

- **Verdict cache** (`scan_verdicts`): Scan results keyed by content hash. Since Arweave content is immutable, these verdicts are permanent.
- **Scan queue** (`scan_queue`): Pending webhook events awaiting processing. Items older than 1 hour are automatically purged.
- **Admin overrides** (`admin_overrides`): Operator confirm/dismiss decisions from the admin dashboard. These persist across restarts and take priority over re-scans.

Screenshots of flagged content are stored at `SCREENSHOT_DIR` (default: `/app/data/screenshots`). These are JPEG files named by content hash, deleted automatically when an admin confirms or dismisses the item. If screenshots are lost, they are not recaptured — this only affects the admin review UI.

The volume should be persisted across container restarts. If the database is lost, Content Scanner will rescan content as it encounters it — there is no data loss, just temporary extra work. However, **admin overrides will be lost**, so dismissed false positives may be re-flagged.

## Backfill: Scanning Existing Cached Content

By default, Content Scanner only scans **newly cached** content via webhooks. To proactively scan content already cached on your gateway, enable the backfill scanner.

### Configuration

Mount the gateway's contiguous data directory and SQLite database (read-only) into the Content Scanner container:

```yaml
content-scanner:
  volumes:
    - scanner-data:/app/data
    - /data/contiguous:/gateway-data/contiguous:ro
    - /path/to/ar-io-node/data/sqlite:/gateway-data/sqlite:ro
  environment:
    BACKFILL_ENABLED: "true"
    BACKFILL_DATA_PATH: "/gateway-data/contiguous"
    BACKFILL_GATEWAY_DB_PATH: "/gateway-data/sqlite/data.db"
    BACKFILL_RATE: "5"              # files per second (default: 5)
    BACKFILL_INTERVAL_HOURS: "24"   # re-sweep interval (0 = one-shot)
```

### How It Works

1. Walks the gateway's contiguous data directory (`data/XX/YY/hash`)
2. Content-sniffs each file — skips non-HTML
3. Scans HTML through the same rule engine + ML pipeline as webhooks
4. Caches verdicts so files are never re-scanned
5. In enforce mode, looks up TX IDs via the gateway's `data.db` and blocks malicious content

### Monitoring Backfill

The admin dashboard's **Dashboard** tab shows backfill status including files scanned, malicious found, sweeps completed, and last sweep time. You can also check via CLI:

```bash
# Check backfill progress in metrics
curl http://localhost:3100/metrics | jq '{backfill_files_scanned, backfill_malicious_found, backfill_sweeps_completed}'

# Watch backfill logs
docker compose logs content-scanner | grep backfill
```

### Notes

- Backfill runs at a rate-limited pace (default 5 files/sec) to avoid I/O contention with the gateway
- First sweep starts 5 seconds after Content Scanner boots
- Subsequent sweeps run every `BACKFILL_INTERVAL_HOURS` hours
- The gateway's `data.db` is opened read-only — Content Scanner never writes to it
- If `BACKFILL_GATEWAY_DB_PATH` is not set in enforce mode, malicious content is detected and logged but cannot be blocked (no TX ID available)

## Verdict Feed: Sharing Detections Across Scanners

The verdict feed lets multiple Content Scanner instances share detection results. When one scanner detects a phishing page, all peers can automatically block it too.

### Producer Only (Serve Verdicts to Peers)

If you just want to share your verdicts for others to consume, set an API key:

```bash
VERDICT_API_KEY=your-shared-secret
```

Your scanner will serve verdicts at `/api/verdicts` and `/api/verdicts/:hash`, protected by this key.

### Consumer (Poll a Peer)

To import verdicts from another scanner:

```bash
VERDICT_API_KEY=shared-secret-key
VERDICT_FEED_URLS=http://scanner-a:3100
```

The API key must match the peer's `VERDICT_API_KEY`.

### Fleet (Bidirectional)

For a fleet of scanners that all share with each other, configure each scanner to poll the others:

```bash
# On Scanner A
VERDICT_API_KEY=shared-secret-key
VERDICT_FEED_URLS=http://scanner-b:3100,http://scanner-c:3100

# On Scanner B
VERDICT_API_KEY=shared-secret-key
VERDICT_FEED_URLS=http://scanner-a:3100,http://scanner-c:3100
```

### Trust Modes

| Mode | Behavior |
|------|----------|
| `malicious_only` (default) | Only import MALICIOUS verdicts. Safest — a peer's CLEAN verdict won't prevent local scanning. |
| `all` | Import all verdicts including CLEAN. Best for identically-configured scanner fleets. |

### On-Demand Lookup

When enabled (default), Content Scanner checks all peers before scanning content locally. If a peer already has a verdict, the local scan is skipped — saving bandwidth and compute. Disable with `VERDICT_FEED_ON_DEMAND=false` if you want every scanner to independently verify content.

### How It Works

- **Polling**: A background loop polls each peer every `VERDICT_FEED_POLL_INTERVAL` seconds (default: 300). Multiple pages of results are fetched automatically if the peer has a backlog.
- **Echo prevention**: Imported verdicts are never re-exported. Scanner A → Scanner B will not echo back to Scanner A.
- **Local priority**: If content was already scanned locally, peer verdicts are ignored.
- **Admin overrides respected**: Locally dismissed content is never reimported from peers.
- **Blocking**: Imported MALICIOUS verdicts trigger auto-blocking in enforce mode, just like local detections.

### Monitoring the Feed

The admin dashboard shows feed status on both the **Dashboard** and **Settings** tabs. You can also check via CLI:

```bash
# Check feed metrics
curl http://localhost:3100/metrics | jq '{feed_verdicts_imported, feed_verdicts_exported, feed_poll_errors, feed_on_demand_hits, feed_on_demand_misses}'

# Watch feed logs
docker compose logs content-scanner | grep feed_
```

Key metrics to watch:
- **feed_poll_errors** > 0: Can't reach a peer. Check network connectivity and API key.
- **feed_on_demand_hits** growing: Peers are saving you local scans.
- **feed_verdicts_imported** growing: Background polling is importing detections.

### Troubleshooting

**Peers returning 401:**
The `VERDICT_API_KEY` must be identical on all scanners in the fleet.

**No verdicts being imported:**
Check trust mode — in `malicious_only` mode (default), CLEAN verdicts from peers are ignored. This is expected behavior.

**Imported verdicts not blocking:**
Imported MALICIOUS verdicts only trigger blocks in `enforce` mode. Check `SCANNER_MODE`.

## Sidecar Downtime

If Content Scanner is down (restart, crash, upgrade), webhook events from the gateway are silently dropped. Content cached during this window will not be scanned. The `restart: unless-stopped` policy keeps downtime brief, and the Docker health check triggers automatic restarts within ~30 seconds.
