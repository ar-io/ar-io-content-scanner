# ar.io Content Scanner — Operator Guide

This guide covers deploying, configuring, and operating Content Scanner alongside your ar.io gateway.

## Prerequisites

- ar-io-node with `DATA_CACHED` webhook event support
- Docker and Docker Compose
- Your gateway's `ADMIN_API_KEY`

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

Content Scanner runs as a separate Docker Compose project, joining the ar-io-node's network so both containers can communicate by service name.

Create a `docker-compose.yml` in the Content Scanner directory:

```yaml
services:
  content-scanner:
    image: ghcr.io/ar-io/gateway-content-scanner:latest
    environment:
      GATEWAY_URL: "http://core:4000"
      ADMIN_API_KEY: "${ADMIN_API_KEY}"
      SCANNER_MODE: "dry-run"
      LOG_LEVEL: "info"
    volumes:
      - scanner-data:/app/data
    restart: unless-stopped
    networks:
      - ar-io-network

volumes:
  scanner-data:

networks:
  ar-io-network:
    external: true
    name: ${DOCKER_NETWORK_NAME:-ar-io-network}
```

This joins the `ar-io-network` created by your ar-io-node compose. The `core` and `content-scanner` hostnames resolve across both projects.

### Step 3: Start in Dry-Run Mode

```bash
docker compose up -d content-scanner
```

In dry-run mode, Content Scanner logs all detections but never blocks content. This lets you verify accuracy before enforcement.

### Step 4: Enable Enforcement

Once you're confident in the detection accuracy (check logs for false positives), switch to enforce mode:

```bash
# In your .env or docker-compose.yml
SCANNER_MODE=enforce
```

Then restart Content Scanner:

```bash
docker compose restart content-scanner
```

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
  "uptime_seconds": 86400
}
```

Key metrics to watch:
- **blocks_failed** > 0: Content Scanner can't reach the gateway admin API. Check `ADMIN_API_KEY` and network connectivity.
- **queue_depth** growing: Workers can't keep up. Increase `SCANNER_WORKERS`.
- **scans_by_verdict.suspicious** > 0: ML model flagged content the rules didn't catch. Review logs for these transaction IDs.

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
| `ADMIN_API_KEY` | Must match the gateway's `ADMIN_API_KEY` |

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

### Rule Toggles

All rules are enabled by default. Disable individual rules if needed:

| Variable | Default | Rule |
|----------|---------|------|
| `RULE_SEED_PHRASE` | `true` | Seed phrase harvesting (8+ inputs + seed terms) |
| `RULE_EXTERNAL_CREDENTIAL_FORM` | `true` | Password + external form action or JS exfil patterns |
| `RULE_WALLET_IMPERSONATION` | `true` | Crypto brand spoofing with credential capture |
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

1. Note the transaction ID from the block log
2. Manually unblock via the gateway's admin API:
   ```bash
   # Use the gateway's admin interface or API to remove the block
   ```
3. Report the false positive so the rules can be improved

## Data and Persistence

Content Scanner stores its SQLite database at `DB_PATH` (default: `/app/data/scanner.db`). This contains:

- **Verdict cache**: Scan results keyed by content hash. Since Arweave content is immutable, these verdicts are permanent.
- **Scan queue**: Pending webhook events awaiting processing. Items older than 1 hour are automatically purged.

The volume should be persisted across container restarts. If the database is lost, Content Scanner will rescan content as it encounters it -- there is no data loss, just temporary extra work.

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

## Sidecar Downtime

If Content Scanner is down (restart, crash, upgrade), webhook events from the gateway are silently dropped. Content cached during this window will not be scanned. The `restart: unless-stopped` policy keeps downtime brief, and the Docker health check triggers automatic restarts within ~30 seconds.
