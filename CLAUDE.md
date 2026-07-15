# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ar.io Content Scanner is a content moderation sidecar for [ar.io gateways](https://github.com/ar-io/ar-io-node). It receives gateway webhook events (`data-cached`, `tx-indexed`, `ans104-data-item-indexed`) to scan content for phishing patterns and auto-block malicious content via the gateway's admin API. Supports both on-access scanning (via `data-cached`) and index-time scanning (via `tx-indexed`/`ans104-data-item-indexed`). Works with both Arweave TX IDs and IPFS CIDs — the scanner auto-detects the addressing scheme from the webhook `id` field and fetches content from the correct gateway path.

Design philosophy: **precision over recall** — incorrectly blocking legitimate content is worse than missing phishing. Every detection rule requires 2+ independent signals (conjunctive logic) before triggering.

## Development Commands

```bash
# Install dependencies
pip install -r requirements.txt -r requirements-dev.txt

# Run all tests
python3 -m pytest tests/ -v

# Run a single test file
python3 -m pytest tests/test_rules.py -v

# Run a single test class or method
python3 -m pytest tests/test_rules.py::TestSeedPhraseRule -v
python3 -m pytest tests/test_scanner.py::TestQueueProcessing::test_process_clean_html -v

# Run the server locally
GATEWAY_URL=http://localhost:3000 ADMIN_API_KEY=secret SCANNER_ADMIN_KEY=admin python3 -m src.server

# Build Docker image
docker build -t content-scanner .
```

## Architecture

### Request Flow

Gateway emits webhook (`data-cached`, `tx-indexed`, or `ans104-data-item-indexed`) → `POST /scan` (FastAPI) → `WebhookPayload.model_validator` normalizes indexed event payloads into `WebhookData` shape → `Scanner.process_webhook()` filters by event type (via `settings.webhook_events`) & content type & checks verdict cache → enqueues to SQLite `scan_queue` (indexed events delayed by `WEBHOOK_INDEX_DELAY` seconds to let the gateway's data indexer save parent bundle relationships) → `WorkerPool` dequeues → optionally queries verdict feed peers (on-demand) → fetches content from gateway via `GET /raw/:id` for Arweave TX IDs or `GET /ipfs/:cid` for IPFS CIDs (path is chosen by `src/ipfs.gateway_fetch_path`; fetch failures are skipped gracefully — `data-cached` handles retry) → routes to appropriate scanning tier:
- **HTML content** → `RuleEngine.evaluate()` runs rules + ML (Tier 1)
- **Non-HTML content** → `ScanDispatcher` → `ContentScannerRegistry` → matching `ContentScanner(s)` run concurrently (Tier 2)
- **No scanner matches** → SKIPPED

After scanning → caches verdict in `scan_verdicts` table → checks Google Safe Browsing if flagged (escalates SUSPICIOUS→MALICIOUS if Google corroborates) → captures screenshot if flagged (HTML only) → blocks via `PUT /ar-io/admin/block-data` if malicious and mode is `enforce` → dispatches a Slack alert via `NotificationRouter` if the verdict meets `SLACK_NOTIFICATION_THRESHOLD`.

### Key Components

- **`server.py`**: FastAPI app with `build_app()` factory. Wires together all components via `lifespan`. Stores shared state on `app.state`.
- **`config.py`**: Frozen `Settings` dataclass + `load_settings()` factory that reads and validates env vars. All settings flow from this single source.
- **`models.py`**: Core types — `WebhookPayload`/`WebhookData` (Pydantic), `Verdict` enum (CLEAN/SUSPICIOUS/MALICIOUS/SKIPPED), `RuleResult`, `ScanResult`, `AdminOverride` dataclass. `WebhookPayload` has a `model_validator(mode='before')` that normalizes indexed event payloads (`tx-indexed`, `ans104-data-item-indexed`) into the `WebhookData` shape (field remapping, base64url tag decoding for content type, string→int coercion).
- **`scanner.py`**: Two code paths — `process_webhook()` (fast filtering + enqueue) and `process_queue_item()` (fetch, parse, evaluate, act). Routes content to HTML rule engine or content scanners via `ScanDispatcher`. For HTML, runs defense-in-depth layers: static rules → iframe extraction (`rules/iframe_scanner.py`) → rendered DOM scan (via `ScreenshotService.render_dom()`). CPU-bound work runs via `run_in_executor()`. On cache miss, optionally queries verdict feed peers before scanning locally.
- **`worker.py`**: `WorkerPool` runs N async worker loops that poll `scan_queue` with 0.5s sleep. Includes a cleanup loop that purges items older than 1 hour. Optionally runs backfill, feed poller, and Safe Browsing monitor loops.
- **`backfill.py`**: `BackfillScanner` walks the gateway's contiguous data filesystem, content-sniffs for HTML, scans through the rule engine + ML, caches verdicts, and blocks malicious content in enforce mode. Uses `GatewayDBReader` for read-only hash→TX ID lookups via the gateway's `data.db`. **IPFS cached content is not covered by backfill** — it lives in a separate `data/ipfs-cache/` directory with a different layout (hash-based subdirs plus `.meta` companion files). IPFS content is still scanned via the on-access (`data-cached`) webhook path; a dedicated IPFS sweep is future work.
- **`db.py`**: Five SQLite tables — `scan_verdicts` (content hash → verdict, with `source` column for local vs peer origin and `safe_browsing_flagged` column), `scan_queue` (pending/processing/failed items), `admin_overrides` (operator confirm/dismiss decisions), `feed_sync_state` (cursor-based sync tracking per peer), `scanner_state` (key-value persistence for dashboard stats across restarts). WAL mode for concurrent reads. `has_verdict()` for efficient backfill cache checks.
- **`rules/engine.py`**: `RuleEngine.evaluate()` runs all enabled rules, then applies the verdict matrix combining rule results with ML score. Shared helpers live in `rules/utils.py` (e.g. `has_password_like_input()` used by multiple rules).
- **`gateway_client.py`**: Async httpx client with streaming fetch (respects `max_bytes` limit) and block API call. `fetch_content()` routes via `src/ipfs.gateway_fetch_path` (`/raw/:id` for Arweave TX IDs, `/ipfs/:cid` for IPFS CIDs); `block_data()` passes the id verbatim — the gateway's `PUT /ar-io/admin/block-data` endpoint accepts both id formats. After a successful `block_data` (or `unblock_data`), if an `EdgeCacheRevalidator` is attached, fires one GET per configured path template to bust HTTP caches in front of the gateway.
- **`edge_cache.py`**: `EdgeCacheRevalidator` — optional best-effort cache busting. Constructed in `server.build_app` from `EDGE_CACHE_REVALIDATION_*` env vars and passed to `GatewayClient`. Disabled by default; when enabled, sends GETs with cache-bypass headers (default `Cache-Control: no-cache` + `X-Cache-Bypass: 1`) to a configured public origin so edges (nginx/Varnish/Cloudflare/Fastly) revalidate against the gateway and pick up the new 451. Failures are logged and counted but never raised — block already succeeded by the time revalidation runs.
- **`ipfs.py`**: CID detection and gateway-path helpers. `is_ipfs_cid()` uses a prefix + length check (CIDv1 base32 starts with `baf` and is longer than 43 chars; CIDv0 starts with `Qm` and is exactly 46 chars). Arweave IDs are always 43-char base64url so the two can't collide. Also mirrored in JS as `isIpfsCid()` in `src/static/admin/app.js` for admin UI link construction.
- **`metrics.py`**: Thread-safe `ScanMetrics` with counters for verdicts, sources, rule triggers, feed import/export stats, and Safe Browsing checks/escalations/errors. Exposes `/metrics/prometheus` endpoint.
- **`safe_browsing.py`**: `SafeBrowsingClient` with two backends: Lookup API v4 (`check_url()`/`check_urls()`, requires `SAFE_BROWSING_API_KEY`) for per-URL checks, and Google Transparency Report (`check_domain()`, no key needed) for site-level domain monitoring. Returns `SafeBrowsingResult` or `DomainStatus`. Fail-open design: API errors never affect scanning. Used on-verdict (in `scanner.py`) and periodically (in `worker.py`'s monitor loop). Domain monitoring requires `GATEWAY_PUBLIC_URL` to be set.
- **`screenshot.py`**: `ScreenshotService` uses Playwright (headless Chromium) to capture screenshots of flagged content and render DOM for two-pass scanning (`render_dom()`). Network-isolated: only gateway-origin requests are allowed. Screenshots stored as `{SCREENSHOT_DIR}/{content_hash}.jpg`, deleted when admin confirms/dismisses.
- **`feed/`**: Peer-to-peer verdict sharing. `client.py` (`FeedClient`) is an async httpx client for fetching verdicts from peers. `poller.py` (`FeedPoller`) periodically syncs new verdicts from configured peer URLs using cursor-based pagination. `routes.py` exposes `GET /api/verdicts` (paginated feed) and `GET /api/verdicts/{hash}` (single lookup) for peers to consume. `auth.py` provides Bearer token auth via `VERDICT_API_KEY`. Only exports `source='local'` verdicts to prevent echo loops.
- **`notifications/`**: Outbound alerting. `router.py` (`NotificationRouter`) dispatches verdict alerts to enabled adapters when the verdict meets `SLACK_NOTIFICATION_THRESHOLD`, and gateway-domain Safe Browsing alerts via `notify_domain_flagged()` (threshold-independent — a flagged gateway domain is always critical; fired by `worker.py`'s monitor loop on a flagged↔clear state change, deduped via the `sb_domain_flagged` key in `scanner_state`). Both fail-open. `slack.py` (`SlackNotifier`) posts Block Kit messages with interactive buttons (Confirm Block / Dismiss / Classify Neutral) and uploads screenshots via Slack's `files.getUploadURLExternal` flow. `slack_socket.py` (`SlackSocketListener`) is an optional Socket Mode transport (outbound WebSocket via `SLACK_APP_TOKEN`) so button callbacks work without exposing a public request URL.
- **`admin/actions.py`**: Shared block/dismiss/reclassify logic used by both the admin API and the Slack action handler. `confirm_block()` enriches the gateway block reason for human-confirmed blocks (e.g. `"Confirmed via Slack (suspicious)"`) so the gateway audit trail distinguishes a human confirm from an auto-block; empty notes fall back to `block_data`'s `"Auto-blocked: <rules>"` default. `classify_neutral()` dismisses as false-positive and exports the HTML to the training-data dir for future ML retraining.
- **`admin/slack_actions.py`**: FastAPI router handling Slack interactivity callbacks. Verifies Slack request signatures (HMAC-SHA256, 5-minute replay window) before routing button presses to the `admin/actions.py` handlers.
- **`scanners/`**: Pluggable content scanner framework (Tier 2). `base.py` defines the `ContentScanner` ABC, `ContentMetadata`, and `ContentScannerResult`. `registry.py` (`ContentScannerRegistry`) matches scanners to MIME types via fnmatch patterns. `dispatcher.py` (`ScanDispatcher`) sits above both tiers, routing HTML to `RuleEngine` and non-HTML to matching content scanners (concurrent via `asyncio.gather`, fail-open). `sniff.py` detects MIME types from magic bytes for backfill. `example_image_scanner.py` is a disabled-by-default stub for `image/*`.
- **`admin/routes.py`**: Admin API router built via `build_admin_router(app_state)`. Uses `_state.db` accessor pattern (reads from `app_state` at request time, not build time) so tests can replace DB after `build_app()`. Includes `POST /api/admin/block` for manual blocking by TX ID (always calls gateway, not mode-gated), plus `POST /api/admin/block-name` / `POST /api/admin/unblock-name` for ArNS-name blocking (single name or array up to 100; names validated against `[a-zA-Z0-9_-]{1,51}` and lowercased). Name blocking goes through `GatewayClient.block_name()`/`unblock_name()` (`PUT /ar-io/admin/block-name` / `/unblock-name`). The Manual Block UI also decodes sandbox subdomains (base32-encoded TX ID → 43-char id) before submitting.
- **`admin/auth.py`**: FastAPI Bearer token dependency factory for `SCANNER_ADMIN_KEY` authentication.

### Verdict Matrix

```
Rule verdict     ML score       Final verdict
-----------      --------       -------------
MALICIOUS        any            MALICIOUS (auto-block in enforce mode)
CLEAN            >= 0.95        SUSPICIOUS (log only, never blocks)
CLEAN            < 0.95         CLEAN

Post-scan Safe Browsing escalation (requires SAFE_BROWSING_API_KEY for URL checks):
SUSPICIOUS + Google flags URL → MALICIOUS (two independent signals)
MALICIOUS + Google flags URL → MALICIOUS (corroborated, no change)
Any verdict + Google error     → no change (fail-open)

Periodic domain monitoring (no API key needed, uses Transparency Report):
Gateway domain flagged → logged as error (critical alert)
GATEWAY_PUBLIC_URL required to enable domain monitoring
```

### Detection Rules (all conjunctive: multiple independent signals required)

| Rule | Signals (all must match) |
|------|--------------------------|
| `seed-phrase-harvesting` | 6+ text inputs AND seed phrase terminology AND external data transmission |
| `external-credential-form` | Password input AND (form action is absolute URL OR JS exfil patterns such as `$.ajax`/`fetch` targeting an external URL) |
| `wallet-impersonation` | Crypto brand in title/headings/img alt/body text AND (password input OR key-phrase terminology) |
| `obfuscated-loader` | DOM injection AND encoding functions in script AND (long base64 OR hex escapes OR charcode chains) |
| `fake-challenge-page` | A near-zero-FP unique kit signature OR (generic cloak phrase AND corroborator). Catches fake Cloudflare/"checking your connection" cloak interstitials that carry no password field and would otherwise land as ML-only SUSPICIOUS and get served |
| `credential-phishing-kit` | A distinctive known-kit template string (webmail portal, Zimbra clone, O365 redirector, etc.) AND a credential context (password-like input OR the kit's own pre-filled error state) |
| `external-script-drainer` | An executable `<script src>` to an external, non-allowlisted host (Arweave dApps bundle their JS) AND wallet-provider interaction or public blockchain-RPC context. Catches wallet drainers whose payload loads from a clearnet drainer CDN |
| `drainer-loader` | The inline/dead-drop sibling: a cloak `Loading…` shell (no inputs, sparse visible body) AND a `fetch()` paired with a script-execution sink (dynamic `<script>`/`document.write`/`eval`) AND blockchain-RPC or wallet context. Catches drainers that resolve their payload host from an on-chain memo and inject+execute it in-page |

### Defense-in-Depth Layers

- **Iframe scanning**: Extracts and scans HTML from `data:` URI and `srcdoc` iframes (static analysis, no Playwright needed). Matched rules prefixed with `iframe:`.
- **Rendered DOM scanning**: Two-pass scan for JS-rendered phishing. When static rules return CLEAN but the page has scripts with DOM manipulation and sparse content, renders in Playwright and re-runs rules on the rendered DOM. Matched rules prefixed with `rendered:`. Toggle: `RENDERED_DOM_SCAN_ENABLED` (default true).

### Admin Frontend

The admin dashboard (`src/templates/admin/`, `src/static/admin/`) uses Alpine.js 3.x with global stores (`$store.auth`, `$store.health`, `$store.toast`). Each tab (dashboard, history, review, block, settings) has its own JS file defining an Alpine component. The frontend authenticates via `SCANNER_ADMIN_KEY` passed as a Bearer token. Key patterns:

- `base.html` handles login, tab routing, and Alpine store initialization.
- Dashboard auto-refreshes every 30 seconds. Detection rows dispatch `search-review` events to cross-link to the review tab.
- History tab supports verdict/source/period filters (including `manual` source), pagination, and CSV export.
- Review tab provides confirm/dismiss actions for flagged content.
- Manual Block tab (`block.html`/`block.js`) lets operators block transactions by TX ID (and ArNS names). Uses `POST /api/admin/block`, always calls the gateway regardless of scanner mode. Creates verdict (`source='manual'`) and override records. Blocks appear in history (filterable by `manual` source) and review queue (as confirmed). Manual blocks are not exported via verdict feed. Also supports ArNS-name blocking via `POST /api/admin/block-name`, and decodes sandbox subdomains (base32 → 43-char TX ID) client-side before submitting.

### Why This Works on Arweave

Arweave content is static with no server-side backend. Password forms posting to external URLs have no legitimate use case. Real dApps authenticate via wallet signatures (`window.ethereum.request()`), not HTML password forms.

## Critical Constraints

- **`from __future__ import annotations`** is required in all source files (project convention, enabled across the entire codebase). Python 3.11+ is required (`pyproject.toml`).
- **Feature vector in `src/ml/features.py`** must remain identical to the trained XGBoost model's expectations. The 17 features, their order, and calculation logic cannot change without retraining. Ported from the original phisherman training pipeline.
- **ML model uses `xgb.Booster`** (not `XGBClassifier`) for cross-version compatibility. The `.pkl` file is a raw xgboost binary model despite the extension.
- **ML never auto-blocks.** The XGBoost classifier can only escalate CLEAN to SUSPICIOUS, never to MALICIOUS.
- **Rules must remain conjunctive.** Every rule requires 2+ independent signals. Single-signal rules risk false positives.
- **Fail-open for external APIs.** External service errors (Safe Browsing, peer feeds, content scanner APIs) must never affect scanning or block legitimate content.
- **Conventional commits.** Commit messages follow the [conventional commits](https://www.conventionalcommits.org/en/v1.0.0/) style (e.g., `feat:`, `fix:`, `docs:`, `refactor:`, `test:`).

## Adding New Detection Rules

1. Create `src/rules/your_rule.py` implementing the `Rule` ABC from `src/rules/base.py`
2. The rule **must** require 2+ independent signals (conjunctive logic)
3. Add a toggle to `Settings` in `src/config.py` (e.g., `rule_your_rule: bool = True`) and read the env var in `load_settings()`
4. Register the rule in `RuleEngine.__init__()` in `src/rules/engine.py`
5. Add test cases in `tests/test_rules.py` with HTML fixtures in `tests/fixtures.py`
6. Add the toggle to `.env.example` and document in `README.md`

## Adding New Content Scanners

1. Create `src/scanners/your_scanner.py` implementing the `ContentScanner` ABC from `src/scanners/base.py`
2. Implement: `name` property, `supported_content_types` property (MIME patterns), `evaluate()` async method
3. Add a toggle to `Settings` in `src/config.py` and read the env var in `load_settings()`
4. Register the scanner in `build_app()` in `src/server.py`, gated by the toggle
5. Add tests in `tests/test_scanners.py` and `tests/test_scanner_content_routing.py`
6. Add the toggle to `.env.example` and document in `README.md`

See `src/scanners/example_image_scanner.py` for a reference implementation.

## Environment Variables

Required: `GATEWAY_URL`, `ADMIN_API_KEY`, `SCANNER_ADMIN_KEY`

Optional: `SCANNER_MODE` (dry-run|enforce, default: dry-run), `WEBHOOK_EVENTS` (comma-separated, default: `data-cached,tx-indexed,ans104-data-item-indexed` — controls which gateway webhook events are processed), `WEBHOOK_INDEX_DELAY` (60 — seconds to wait before processing indexed events, giving the gateway's data indexer time to save parent bundle relationships), `SCANNER_PORT` (3100), `SCANNER_WORKERS` (2), `ML_MODEL_ENABLED` (true), `ML_MODEL_PATH` (./xgboost_model.pkl), `ML_SUSPICIOUS_THRESHOLD` (0.95, range 0–1), `LOG_LEVEL` (info), `LOG_FORMAT` (text|json, default: text — "text" for human-readable Docker logs, "json" for log aggregation), `DB_PATH` (/app/data/scanner.db), `MAX_SCAN_BYTES` (262144), `SCAN_TIMEOUT` (10000ms), `ADMIN_UI_ENABLED` (true), `GATEWAY_PUBLIC_URL` (empty — public gateway URL for clickable TX ID links in admin UI, e.g. `https://vilenarios.com`)

Rule toggles (all default true): `RULE_SEED_PHRASE`, `RULE_EXTERNAL_CREDENTIAL_FORM`, `RULE_WALLET_IMPERSONATION`, `RULE_OBFUSCATED_LOADER`, `RULE_FAKE_CHALLENGE`, `RULE_CREDENTIAL_KIT`, `RULE_EXTERNAL_SCRIPT_DRAINER`, `RULE_DRAINER_LOADER`

Rendered DOM: `RENDERED_DOM_SCAN_ENABLED` (true — two-pass scan with Playwright for JS-rendered phishing)

Content scanners: `SCANNER_EXAMPLE_IMAGE` (false — stub image scanner for development/testing)

Screenshots: `SCREENSHOT_ENABLED` (true), `SCREENSHOT_DIR` (/app/data/screenshots), `SCREENSHOT_TIMEOUT_MS` (15000), `SCREENSHOT_RETENTION_DAYS` (30 — captured screenshots older than this are purged)

Slack notifications: `SLACK_ENABLED` (false), `SLACK_BOT_TOKEN` (required when enabled), `SLACK_CHANNEL_ID` (required when enabled), `SLACK_SIGNING_SECRET` (required when enabled — verifies interactivity callbacks), `SLACK_NOTIFICATION_THRESHOLD` (malicious|suspicious, default: malicious), `SLACK_APP_TOKEN` (optional `xapp-` token — enables Socket Mode so button callbacks work without a public request URL)

Edge cache revalidation: `EDGE_CACHE_REVALIDATION_ENABLED` (false), `EDGE_CACHE_REVALIDATION_URL_BASE` (public origin to hit; falls back to `GATEWAY_PUBLIC_URL`, required when enabled), `EDGE_CACHE_REVALIDATION_HEADERS` (default `Cache-Control: no-cache, X-Cache-Bypass: 1`), `EDGE_CACHE_REVALIDATION_PATHS_ARWEAVE` (default `/raw/{id},/{id}`), `EDGE_CACHE_REVALIDATION_PATHS_IPFS` (default `/ipfs/{id}`), `EDGE_CACHE_REVALIDATION_TIMEOUT_MS` (5000, min 100)

Version: `SCANNER_VERSION` (defaults to the version in `pyproject.toml`)

Verdict feed: `VERDICT_API_KEY` (enables feed feature), `VERDICT_FEED_URLS` (comma-separated peer scanner URLs), `VERDICT_FEED_POLL_INTERVAL` (300s, min 10), `VERDICT_FEED_TRUST_MODE` (malicious_only|all), `VERDICT_FEED_ON_DEMAND` (true — query peers on cache miss), `VERDICT_FEED_REQUEST_TIMEOUT_MS` (5000)

Backfill: `BACKFILL_ENABLED` (false), `BACKFILL_DATA_PATH` (required if enabled), `BACKFILL_GATEWAY_DB_PATH` (optional, for hash→TX ID lookups), `BACKFILL_RATE` (5 files/sec), `BACKFILL_INTERVAL_HOURS` (24)

Safe Browsing: `SAFE_BROWSING_API_KEY` (optional — enables per-URL Lookup API checks; domain monitoring via Transparency Report works without it), `SAFE_BROWSING_CHECK_INTERVAL` (3600s, min 60 — periodic domain + URL monitoring interval)

## Testing Patterns

- Database tests use `tempfile.mkstemp()` for SQLite files; server tests use `db_path=":memory:"`.
- Scanner tests mock `GatewayClient` with `AsyncMock`. Rule and ML tests use HTML fixtures from `tests/fixtures.py`.
- Admin API tests use a pre-initialized DB fixture that replaces `app.state.db` after `build_app()`, since lifespan doesn't run during `TestClient` setup.
- `asyncio_mode = "auto"` in `pyproject.toml` — `@pytest.mark.asyncio` is not required on async test functions.
- Test settings disable ML model (`ml_model_enabled=False`) to avoid needing the `.pkl` file.
- `tests/test_known_bad.py` is a live integration test that fetches from arweave.net — excluded from CI (`--ignore=tests/test_known_bad.py`). Run manually: `python3 -m pytest tests/test_known_bad.py -v -s`.
- No linter or formatter is configured. No pre-commit hooks.

## CI/CD

GitHub Actions (`.github/workflows/build-and-push.yml`) runs `pytest` (excluding `test_known_bad.py`) on pushes to `main`, `v*` tags, and PRs. On non-PR events, builds and pushes Docker images to GHCR with branch/tag/SHA labels.

## Related Docs

- **`OPERATOR.md`** — Production deployment guide (health checks, metrics, troubleshooting, backfill monitoring).
- **`CONTRIBUTING.md`** — PR checklist, branching workflow, and design constraints for contributors.
- **`content-moderation-pipeline.md`** — Architecture overview of the broader AR.IO moderation pipeline (legacy gateway, Phisherman, shepherd-syncer, cross-account IAM). Useful context when integrating this scanner with upstream systems.
- **`training/`** — ML model training pipeline scripts (data collection, feature extraction, XGBoost training). Changes here require retraining and updating `xgboost_model.pkl`.
