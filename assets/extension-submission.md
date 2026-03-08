## Extension JSON

**Please fill out the JSON below with your extension information. This will be added to our extensions registry.**

```json
{
  "id": "content-scanner",
  "name": "Content Scanner",
  "description": "Auto-detects and blocks phishing HTML on your gateway using rule-based + ML analysis",
  "longDescription": "Content Scanner is a content moderation sidecar that receives DATA_CACHED webhook events, scans HTML for phishing patterns using 4 conjunctive detection rules and an XGBoost ML model, and auto-blocks malicious content via the gateway admin API. It includes a full admin dashboard for reviewing detections, managing overrides, and exporting training data. Designed for precision over recall — every rule requires 2+ independent signals to avoid false positives.",
  "author": "ar.io",
  "authorUrl": "https://ar.io",
  "url": "https://github.com/ar-io/ar-io-content-scanner",
  "category": "moderation",
  "tags": ["community", "stable"],
  "version": "0.1.0",
  "imageUri": "ghcr.io/ar-io/ar-io-content-scanner:main",
  "lastUpdated": "2026-03-08",
  "minGatewayVersion": "2.0.0",
  "documentation": "https://github.com/ar-io/ar-io-content-scanner/blob/main/README.md",
  "logo": "https://raw.githubusercontent.com/ar-io/ar-io-content-scanner/main/assets/logo.svg",
  "screenshots": []
}
```

### Field Guide:

- **id**: `content-scanner` — unique lowercase identifier
- **name**: `Content Scanner` — display name
- **description**: Short description (93 chars) shown in the extension list
- **longDescription**: Detailed description covering webhook-driven scanning, 4 detection rules, ML model, admin dashboard, and precision-first design
- **author**: `ar.io`
- **authorUrl**: `https://ar.io`
- **url**: GitHub repository URL
- **category**: `moderation` — content moderation is the primary function
- **tags**: `community`, `stable`
- **version**: `0.1.0` — current version from `config.py`
- **imageUri**: GHCR image published by CI on push to main
- **lastUpdated**: Today's date
- **minGatewayVersion**: Requires gateway with `DATA_CACHED` webhook support
- **documentation**: Links to README
- **logo**: SVG logo hosted in the repo's `assets/` directory
- **screenshots**: To be added — capture from running admin dashboard at `/admin`

## Installation & Testing

**Installation Instructions:**

1. Add webhook configuration to your ar-io-node `.env`:
   ```bash
   WEBHOOK_TARGET_SERVERS=http://content-scanner:3100/scan
   WEBHOOK_EMIT_DATA_CACHED_EVENTS=true
   ```

2. Clone the content scanner repo and configure:
   ```bash
   git clone https://github.com/ar-io/ar-io-content-scanner.git
   cd ar-io-content-scanner
   cp .env.example .env
   # Set ADMIN_API_KEY (must match your gateway's key)
   # Set SCANNER_ADMIN_KEY (choose a secret for the admin dashboard)
   ```

3. Start the scanner:
   ```bash
   docker compose up -d
   ```
   The included `docker-compose.yml` automatically joins the ar-io-node's `ar-io-network`.

4. Start in `dry-run` mode (default) to observe detections in logs. When satisfied, switch to `enforce` mode to enable auto-blocking.

**Testing Steps:**

1. Verify the scanner is running: `curl http://localhost:3100/health` — should return JSON with mode, version, and status.
2. Access the admin dashboard at `http://localhost:3100/admin` and log in with your `SCANNER_ADMIN_KEY`.
3. Browse content on your gateway to trigger `DATA_CACHED` webhooks — the scanner will process them and results appear in the dashboard.
4. Check scan metrics: `curl http://localhost:3100/metrics` — shows verdict counts, cache stats, and queue depth.
5. Review detected content in the admin dashboard's Review Queue tab — confirm or dismiss detections.

## Checklist

Please confirm:

- [x] Extension is open source
- [x] Code repository is publicly accessible
- [x] Extension has been tested with AR.IO gateway
- [x] Documentation includes installation instructions
- [x] Extension does not contain malicious code
- [x] Extension respects user privacy and security
- [x] JSON data is complete and valid

## Additional Notes

- **Detection engine**: 4 conjunctive rules (seed phrase harvesting, external credential forms, wallet impersonation, obfuscated loader) plus an XGBoost ML classifier. Rules auto-block; ML can only escalate to SUSPICIOUS (never auto-blocks alone).
- **Why this works on Arweave**: Arweave content is static with no server-side backend. Password forms posting to external URLs have no legitimate use case — real dApps use wallet signatures.
- **Admin dashboard**: Full-featured UI at `/admin` with real-time stats, review queue, scan history with CSV export, and configuration overview.
- **Backfill mode**: Optional proactive filesystem sweep of already-cached content for retroactive scanning.
- **Modes**: `dry-run` (log only, default) and `enforce` (auto-block malicious content).
- **Prometheus metrics**: Available at `/metrics` for monitoring integration.

---

_By submitting this extension, you agree that the extension code can be reviewed and the JSON data above will be added to the AR.IO Gateway Extensions marketplace._
