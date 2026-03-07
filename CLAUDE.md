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
GATEWAY_URL=http://localhost:3000 ADMIN_API_KEY=secret python3 -m src.server

# Build Docker image
docker build -t content-scanner .
```

## Architecture

### Request Flow

Gateway emits `DATA_CACHED` webhook → `POST /scan` (FastAPI) → `Scanner.process_webhook()` filters by content type & checks verdict cache → enqueues to SQLite `scan_queue` → `WorkerPool` dequeues → fetches HTML from gateway via `GET /raw/:id` → `RuleEngine.evaluate()` runs rules + ML → caches verdict in `scan_verdicts` table → blocks via `PUT /ar-io/admin/block-data` if malicious and mode is `enforce`.

### Key Components

- **`server.py`**: FastAPI app with `build_app()` factory. Wires together all components via `lifespan`. Stores shared state on `app.state`.
- **`scanner.py`**: Two code paths — `process_webhook()` (fast filtering + enqueue) and `process_queue_item()` (fetch, parse, evaluate, act). CPU-bound work (HTML parsing, rule evaluation) runs via `run_in_executor()`.
- **`worker.py`**: `WorkerPool` runs N async worker loops that poll `scan_queue` with 0.5s sleep. Includes a cleanup loop that purges items older than 1 hour. Optionally runs a backfill loop.
- **`backfill.py`**: `BackfillScanner` walks the gateway's contiguous data filesystem, content-sniffs for HTML, scans through the rule engine + ML, caches verdicts, and blocks malicious content in enforce mode. Uses `GatewayDBReader` for read-only hash→TX ID lookups via the gateway's `data.db`.
- **`db.py`**: Two SQLite tables — `scan_verdicts` (content hash → verdict, permanent cache) and `scan_queue` (pending/processing/failed items). WAL mode for concurrent reads. `has_verdict()` for efficient backfill cache checks.
- **`rules/engine.py`**: `RuleEngine.evaluate()` runs all enabled rules, then applies the verdict matrix combining rule results with ML score.
- **`gateway_client.py`**: Async httpx client with streaming fetch (respects `max_bytes` limit) and block API call.

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
| `wallet-impersonation` | Crypto brand in title/headings/img alt | Password input |
| `obfuscated-loader` | DOM injection + encoding functions in script | Long base64, hex escapes, or charcode chains |

### Why This Works on Arweave

Arweave content is static with no server-side backend. Password forms posting to external URLs have no legitimate use case. Real dApps authenticate via wallet signatures (`window.ethereum.request()`), not HTML password forms.

## Critical Constraints

- **`from __future__ import annotations`** is required in all source files for Python 3.8 compatibility (production target is 3.11).
- **Feature vector in `src/ml/features.py`** must remain identical to the trained XGBoost model's expectations. The 17 features, their order, and calculation logic cannot change without retraining. Ported from the original phisherman training pipeline.
- **ML model uses `xgb.Booster`** (not `XGBClassifier`) for cross-version compatibility. The `.pkl` file is a raw xgboost binary model despite the extension.
- **ML never auto-blocks.** The XGBoost classifier can only escalate CLEAN to SUSPICIOUS, never to MALICIOUS.
- **Rules must remain conjunctive.** Every rule requires 2+ independent signals. Single-signal rules risk false positives.

## Environment Variables

Required: `GATEWAY_URL`, `ADMIN_API_KEY`

Optional: `SCANNER_MODE` (dry-run|enforce, default: dry-run), `SCANNER_PORT` (3100), `SCANNER_WORKERS` (2), `ML_MODEL_ENABLED` (true), `LOG_LEVEL` (info), `DB_PATH` (/app/data/scanner.db), `MAX_SCAN_BYTES` (262144), `SCAN_TIMEOUT` (10000ms)

Rule toggles (all default true): `RULE_SEED_PHRASE`, `RULE_EXTERNAL_CREDENTIAL_FORM`, `RULE_WALLET_IMPERSONATION`, `RULE_OBFUSCATED_LOADER`

Backfill: `BACKFILL_ENABLED` (false), `BACKFILL_DATA_PATH` (required if enabled), `BACKFILL_GATEWAY_DB_PATH` (optional, for hash→TX ID lookups), `BACKFILL_RATE` (5 files/sec), `BACKFILL_INTERVAL_HOURS` (24)

## Testing Patterns

- Database tests use `tempfile.mkstemp()` for SQLite files; server tests use `db_path=":memory:"`.
- Scanner tests mock `GatewayClient` with `AsyncMock`. Rule and ML tests use HTML fixtures from `tests/fixtures.py`.
- Async tests use `@pytest.mark.asyncio` with `pytest-asyncio`.
- Test settings disable ML model (`ml_model_enabled=False`) to avoid needing the `.pkl` file.
