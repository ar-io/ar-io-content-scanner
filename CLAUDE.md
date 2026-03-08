# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ar.io Content Scanner is a content moderation sidecar for [ar.io gateways](https://github.com/ar-io/ar-io-node). It receives `DATA_CACHED` webhook events when the gateway caches new Arweave content, scans HTML for phishing patterns, and auto-blocks malicious content via the gateway's admin API.

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

Gateway emits `DATA_CACHED` webhook → `POST /scan` (FastAPI) → `Scanner.process_webhook()` filters by content type & checks verdict cache → enqueues to SQLite `scan_queue` → `WorkerPool` dequeues → optionally queries verdict feed peers (on-demand) → fetches HTML from gateway via `GET /raw/:id` → `RuleEngine.evaluate()` runs rules + ML → caches verdict in `scan_verdicts` table → captures screenshot if flagged → blocks via `PUT /ar-io/admin/block-data` if malicious and mode is `enforce`.

### Key Components

- **`server.py`**: FastAPI app with `build_app()` factory. Wires together all components via `lifespan`. Stores shared state on `app.state`.
- **`config.py`**: Frozen `Settings` dataclass + `load_settings()` factory that reads and validates env vars. All settings flow from this single source.
- **`models.py`**: Core types — `WebhookPayload`/`WebhookData` (Pydantic), `Verdict` enum (CLEAN/SUSPICIOUS/MALICIOUS/SKIPPED), `RuleResult`, `ScanResult`, `AdminOverride` dataclass.
- **`scanner.py`**: Two code paths — `process_webhook()` (fast filtering + enqueue) and `process_queue_item()` (fetch, parse, evaluate, act). CPU-bound work (HTML parsing, rule evaluation) runs via `run_in_executor()`. On cache miss, optionally queries verdict feed peers before scanning locally.
- **`worker.py`**: `WorkerPool` runs N async worker loops that poll `scan_queue` with 0.5s sleep. Includes a cleanup loop that purges items older than 1 hour. Optionally runs backfill and feed poller loops.
- **`backfill.py`**: `BackfillScanner` walks the gateway's contiguous data filesystem, content-sniffs for HTML, scans through the rule engine + ML, caches verdicts, and blocks malicious content in enforce mode. Uses `GatewayDBReader` for read-only hash→TX ID lookups via the gateway's `data.db`.
- **`db.py`**: Five SQLite tables — `scan_verdicts` (content hash → verdict, with `source` column for local vs peer origin), `scan_queue` (pending/processing/failed items), `admin_overrides` (operator confirm/dismiss decisions), `feed_sync_state` (cursor-based sync tracking per peer), `scanner_state` (key-value persistence for dashboard stats across restarts). WAL mode for concurrent reads. `has_verdict()` for efficient backfill cache checks.
- **`rules/engine.py`**: `RuleEngine.evaluate()` runs all enabled rules, then applies the verdict matrix combining rule results with ML score.
- **`gateway_client.py`**: Async httpx client with streaming fetch (respects `max_bytes` limit) and block API call.
- **`metrics.py`**: Thread-safe `ScanMetrics` with counters for verdicts, sources, rule triggers, and feed import/export stats. Exposes `/metrics/prometheus` endpoint.
- **`screenshot.py`**: `ScreenshotService` uses Playwright (headless Chromium) to capture screenshots of flagged content. Network-isolated: only gateway-origin requests are allowed. Screenshots stored as `{SCREENSHOT_DIR}/{content_hash}.jpg`, deleted when admin confirms/dismisses.
- **`feed/`**: Peer-to-peer verdict sharing. `client.py` (`FeedClient`) is an async httpx client for fetching verdicts from peers. `poller.py` (`FeedPoller`) periodically syncs new verdicts from configured peer URLs using cursor-based pagination. `routes.py` exposes `GET /api/verdicts` (paginated feed) and `GET /api/verdicts/{hash}` (single lookup) for peers to consume. `auth.py` provides Bearer token auth via `VERDICT_API_KEY`. Only exports `source='local'` verdicts to prevent echo loops.
- **`admin/routes.py`**: Admin API router built via `build_admin_router(app_state)`. Uses `_state.db` accessor pattern (reads from `app_state` at request time, not build time) so tests can replace DB after `build_app()`.
- **`admin/auth.py`**: FastAPI Bearer token dependency factory for `SCANNER_ADMIN_KEY` authentication.

### Verdict Matrix

```
Rule verdict     ML score       Final verdict
-----------      --------       -------------
MALICIOUS        any            MALICIOUS (auto-block in enforce mode)
CLEAN            >= 0.95        SUSPICIOUS (log only, never blocks)
CLEAN            < 0.95         CLEAN
```

### Detection Rules (all conjunctive: Signal A AND Signal B)

| Rule | Signal A | Signal B |
|------|----------|----------|
| `seed-phrase-harvesting` | 8+ text inputs | Seed phrase terminology in visible text |
| `external-credential-form` | Password input | Form action is absolute URL OR JS exfil patterns ($.ajax, fetch, etc.) with external URL |
| `wallet-impersonation` | Crypto brand in title/headings/img alt | Password input or key-phrase terminology |
| `obfuscated-loader` | DOM injection + encoding functions in script | Long base64, hex escapes, or charcode chains |

### Admin Frontend

The admin dashboard (`src/templates/admin/`, `src/static/admin/`) uses Alpine.js 3.x with global stores (`$store.auth`, `$store.health`, `$store.toast`). Each tab (dashboard, history, review, settings) has its own JS file defining an Alpine component. The frontend authenticates via `SCANNER_ADMIN_KEY` passed as a Bearer token. Key patterns:

- `base.html` handles login, tab routing, and Alpine store initialization.
- Dashboard auto-refreshes every 30 seconds. Detection rows dispatch `search-review` events to cross-link to the review tab.
- History tab supports verdict/source/period filters, pagination, and CSV export.
- Review tab provides confirm/dismiss actions for flagged content.

### Why This Works on Arweave

Arweave content is static with no server-side backend. Password forms posting to external URLs have no legitimate use case. Real dApps authenticate via wallet signatures (`window.ethereum.request()`), not HTML password forms.

## Critical Constraints

- **`from __future__ import annotations`** is required in all source files (project convention, enabled across the entire codebase). Python 3.11+ is required (`pyproject.toml`).
- **Feature vector in `src/ml/features.py`** must remain identical to the trained XGBoost model's expectations. The 17 features, their order, and calculation logic cannot change without retraining. Ported from the original phisherman training pipeline.
- **ML model uses `xgb.Booster`** (not `XGBClassifier`) for cross-version compatibility. The `.pkl` file is a raw xgboost binary model despite the extension.
- **ML never auto-blocks.** The XGBoost classifier can only escalate CLEAN to SUSPICIOUS, never to MALICIOUS.
- **Rules must remain conjunctive.** Every rule requires 2+ independent signals. Single-signal rules risk false positives.

## Environment Variables

Required: `GATEWAY_URL`, `ADMIN_API_KEY`, `SCANNER_ADMIN_KEY`

Optional: `SCANNER_MODE` (dry-run|enforce, default: dry-run), `SCANNER_PORT` (3100), `SCANNER_WORKERS` (2), `ML_MODEL_ENABLED` (true), `ML_MODEL_PATH` (./xgboost_model.pkl), `ML_SUSPICIOUS_THRESHOLD` (0.95, range 0–1), `LOG_LEVEL` (info), `DB_PATH` (/app/data/scanner.db), `MAX_SCAN_BYTES` (262144), `SCAN_TIMEOUT` (10000ms), `ADMIN_UI_ENABLED` (true), `GATEWAY_PUBLIC_URL` (empty — public gateway URL for clickable TX ID links in admin UI, e.g. `https://vilenarios.com`)

Rule toggles (all default true): `RULE_SEED_PHRASE`, `RULE_EXTERNAL_CREDENTIAL_FORM`, `RULE_WALLET_IMPERSONATION`, `RULE_OBFUSCATED_LOADER`

Screenshots: `SCREENSHOT_ENABLED` (true), `SCREENSHOT_DIR` (/app/data/screenshots), `SCREENSHOT_TIMEOUT_MS` (15000)

Verdict feed: `VERDICT_API_KEY` (enables feed feature), `VERDICT_FEED_URLS` (comma-separated peer scanner URLs), `VERDICT_FEED_POLL_INTERVAL` (300s, min 10), `VERDICT_FEED_TRUST_MODE` (malicious_only|all), `VERDICT_FEED_ON_DEMAND` (true — query peers on cache miss), `VERDICT_FEED_REQUEST_TIMEOUT_MS` (5000)

Backfill: `BACKFILL_ENABLED` (false), `BACKFILL_DATA_PATH` (required if enabled), `BACKFILL_GATEWAY_DB_PATH` (optional, for hash→TX ID lookups), `BACKFILL_RATE` (5 files/sec), `BACKFILL_INTERVAL_HOURS` (24)

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
- **`training/`** — ML model training pipeline scripts (data collection, feature extraction, XGBoost training). Changes here require retraining and updating `xgboost_model.pkl`.
