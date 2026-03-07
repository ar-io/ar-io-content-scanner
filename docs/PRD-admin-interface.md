# ar.io Content Scanner — Admin Interface PRD

## 1. Overview

### 1.1 Problem

Gateway operators running Content Scanner have no visibility into what the scanner is doing beyond raw JSON logs and a `/metrics` endpoint. When the scanner detects malicious or suspicious content, operators must SSH into the server, grep logs, and manually curl the gateway admin API to take action. There is no way to:

- Review flagged content before enabling enforcement
- Override false positives or confirm true positives
- See scan history at a glance
- Monitor backfill progress visually
- Build a feedback loop that improves detection over time

### 1.2 Solution

A built-in admin dashboard served from the existing FastAPI application at `/admin`. Modular template architecture using Jinja2 partials (one per tab) with separate static JS files, Alpine.js for reactivity, and Tailwind CSS for styling, following the ar.io brand kit. No build step, no separate frontend project, no npm.

### 1.3 Non-Goals

- Multi-user auth / role-based access control (single admin key is sufficient)
- Public-facing UI (this is an operator tool behind a firewall)
- Real-time WebSocket updates (polling is fine for an ops dashboard)
- Mobile-optimized layout (desktop operator tool)

---

## 2. Architecture

### 2.1 Frontend

A single `index.html` file served at `/admin` containing all HTML, CSS, and JS. External dependencies loaded via CDN:

- **Alpine.js** (v3) — lightweight reactivity (~15KB)
- **Tailwind CSS** (CDN build) — utility-first CSS
- **Google Fonts** — Besley (headlines) + Plus Jakarta Sans (body/UI)

The page is a single-page app with tab-based navigation (no router needed). All data fetched from `/api/admin/*` endpoints via `fetch()`.

### 2.2 Backend

New FastAPI routes under `/api/admin/` prefixed group, protected by `SCANNER_ADMIN_KEY` (a new env var, separate from the gateway's `ADMIN_API_KEY`) via Bearer token in the `Authorization` header. The `/admin` HTML page itself is also protected.

**Key distinction:** `ADMIN_API_KEY` is used by the scanner to authenticate *to the gateway* admin API (for blocking). `SCANNER_ADMIN_KEY` is used by operators to authenticate *to the scanner* admin UI. These are intentionally separate — the gateway key is a machine-to-machine credential, while the scanner admin key is an operator credential.

New file structure:
```
src/
  admin/
    __init__.py
    routes.py             — FastAPI router with all admin API endpoints
    auth.py               — API key dependency for route protection
  templates/
    admin/
      base.html           — layout shell: head, nav bar, login screen, tab container
      dashboard.html      — dashboard tab partial
      review.html         — review queue tab partial
      history.html        — scan history tab partial
      settings.html       — settings tab partial
  static/
    admin/
      app.js              — main Alpine.js app, auth, tab routing, shared utilities
      dashboard.js        — dashboard tab data fetching and display logic
      review.js           — review queue filters, confirm/dismiss actions
      history.js          — search, pagination, CSV export
      settings.js         — settings display, training export
      styles.css          — custom CSS beyond Tailwind (brand colors, component styles)
```

### 2.3 Database Changes

New table `admin_overrides` for operator verdicts:

```sql
CREATE TABLE IF NOT EXISTS admin_overrides (
    content_hash TEXT PRIMARY KEY,
    tx_id TEXT NOT NULL,
    admin_verdict TEXT NOT NULL,      -- 'confirmed_malicious' or 'confirmed_clean'
    original_verdict TEXT NOT NULL,   -- what the scanner said
    original_rules TEXT,              -- JSON array of matched rules
    original_ml_score REAL,
    notes TEXT DEFAULT '',
    created_at INTEGER NOT NULL
);
```

The scanner's `process_queue_item` and backfill `_process_file` check `admin_overrides` before caching verdicts — if an operator has marked a content hash as `confirmed_clean`, it is never re-flagged or blocked.

### 2.4 Authentication

All `/admin` and `/api/admin/*` routes require `SCANNER_ADMIN_KEY`:

- **API calls**: `Authorization: Bearer <SCANNER_ADMIN_KEY>` header
- **Browser session**: on first visit to `/admin`, a simple login form prompts for the admin key. The key is stored in `localStorage` and sent as a Bearer token on all subsequent API requests. A "Logout" button clears it.

No cookies, no sessions, no JWT. The scanner admin key is a standalone credential configured by the operator — it has no relationship to the gateway's `ADMIN_API_KEY`.

---

## 3. UI Design

### 3.1 Brand Kit

| Token | Value | Usage |
|-------|-------|-------|
| Primary | `#5427C8` | CTAs, links, active tab indicators, toggle switches |
| Lavender | `#DFD6F7` | Page background, gradient accents, hover states |
| Black | `#23232D` | Primary text, dark surfaces |
| White | `#FFFFFF` | Card backgrounds, light text on dark surfaces |
| Card Surface | `#F0F0F0` | Card backgrounds, elevated surfaces |
| Headlines | Besley, 800 weight | Page title, section headers, stat numbers |
| Body/UI | Plus Jakarta Sans, variable | All other text, buttons, labels, table content |

### 3.2 Layout

```
+------------------------------------------------------------------+
|  [ar.io logo area]   Content Scanner Admin           [Logout btn] |
+------------------------------------------------------------------+
|  [Dashboard]  [Review Queue]  [Scan History]  [Settings]         |
+------------------------------------------------------------------+
|                                                                    |
|   (active tab content area)                                       |
|                                                                    |
+------------------------------------------------------------------+
```

- Fixed top bar with title and logout
- Tab navigation below the header
- Active tab has Primary color underline
- Content area is a white/card-surface card with rounded corners and subtle shadow
- Page background is Lavender (`#DFD6F7`)

### 3.3 Login Screen

Displayed when no API key is stored in `localStorage` or when the stored key returns 401.

```
+------------------------------------------+
|                                          |
|        ar.io Content Scanner             |
|                                          |
|   +----------------------------------+   |
|   |  API Key                         |   |
|   |  [________________________]      |   |
|   |                                  |   |
|   |         [Sign In]                |   |
|   +----------------------------------+   |
|                                          |
+------------------------------------------+
```

- Centered card on Lavender background
- "ar.io Content Scanner" in Besley 800
- Password input field for the API key
- Primary-colored "Sign In" button
- On submit, calls `GET /api/admin/stats` with the key — if 200, stores key in `localStorage` and loads dashboard; if 401, shows error

---

## 4. Tab Specifications

### 4.1 Dashboard Tab

The landing page. Shows system health and key metrics at a glance.

#### 4.1.1 Status Banner

Full-width banner at the top of the dashboard content area:

| Mode | Display |
|------|---------|
| `dry-run` | Yellow/amber banner: "Scanner Mode: Dry Run — detections are logged but not blocked" |
| `enforce` | Green banner: "Scanner Mode: Enforce — malicious content is auto-blocked" |

#### 4.1.2 Stats Cards Row

Four metric cards in a row:

| Card | Value | Subtitle |
|------|-------|----------|
| Total Scanned | `scans_total` | "HTML pages analyzed" |
| Malicious | `scans_by_verdict.malicious` | "threats detected" — red accent |
| Suspicious | `scans_by_verdict.suspicious` | "flagged for review" — amber accent |
| Blocked | `blocks_sent` | "requests blocked" — green accent if >0 |

Each card: large Besley number, Plus Jakarta Sans subtitle, card-surface background.

#### 4.1.3 System Health Section

Two-column layout:

**Left: Scanner Health**
- Uptime (formatted as "X days, Y hours")
- Scanner version
- Queue depth (with warning color if > 10)
- Workers active
- Avg scan time
- Cache hit rate

**Right: Backfill Status**
- Status: "Complete" / "In Progress" / "Not Configured"
- Files scanned / total
- Malicious found
- Sweeps completed
- Last sweep timestamp

#### 4.1.4 Recent Detections

A compact table showing the 10 most recent MALICIOUS or SUSPICIOUS verdicts:

| Time | TX ID | Verdict | Rules | ML Score | Action |
|------|-------|---------|-------|----------|--------|

- TX ID is a clickable link → opens the content on the gateway in a new tab
- Verdict is a colored badge (red for malicious, amber for suspicious)
- Action shows "blocked", "dry_run", "confirmed_clean", etc.
- "View" link opens the Review detail view

#### 4.1.5 Auto-Refresh

Dashboard polls `GET /api/admin/stats` every 30 seconds. A small "Last updated: X seconds ago" indicator in the top-right of the content area. Refresh can be paused/resumed.

---

### 4.2 Review Queue Tab

The primary workflow page. Shows items that need operator attention.

#### 4.2.1 Queue Filters

Horizontal filter bar at the top:

- **Verdict filter**: All | Malicious | Suspicious (toggle buttons)
- **Status filter**: Pending Review | Confirmed | Dismissed (toggle buttons)
- **Sort**: Newest First | Oldest First | Highest ML Score

Default: "Pending Review" + "All verdicts" + "Newest First"

"Pending review" = items with no entry in `admin_overrides`.

#### 4.2.2 Queue List

Each item is a card:

```
+------------------------------------------------------------------+
|  [MALICIOUS badge]              2026-03-06 23:34:58               |
|                                                                    |
|  TX: G7_Hprn9XUdFf5We4QHHzinI24H4aXhn0q4_bJvrJZU    [View TX ->] |
|  Hash: 5vdUgagxJuM4KWFhEH2N_MYW1afXRsMbVb_iwK40tHM               |
|                                                                    |
|  Rules: obfuscated-loader                                          |
|  ML Score: 0.257  [=====----------] 25.7%                         |
|                                                                    |
|  +---------------------------+  +----------------------------+     |
|  |  Confirm Malicious        |  |  Dismiss (False Positive)  |     |
|  +---------------------------+  +----------------------------+     |
+------------------------------------------------------------------+
```

- Verdict badge: red for MALICIOUS, amber for SUSPICIOUS
- TX ID is a monospace, truncatable link to `{gateway_url}/raw/{tx_id}` (opens new tab)
- Content hash in smaller gray monospace text
- Rules listed as small pill badges
- ML Score shown as number + thin progress bar
- Two action buttons at the bottom of each card

#### 4.2.3 Action Buttons

**Confirm Malicious** (Primary color button):
- Saves `admin_verdict = 'confirmed_malicious'` to `admin_overrides`
- If scanner is in dry-run mode: just records the confirmation
- If scanner is in enforce mode: also triggers `PUT /ar-io/admin/block-data` on the gateway for all TX IDs associated with this content hash
- Button changes to "Confirmed" (disabled, with checkmark) after click
- Optional: text input for notes before confirming

**Dismiss (False Positive)** (outline/secondary button):
- Saves `admin_verdict = 'confirmed_clean'` to `admin_overrides`
- If the content was already blocked (enforce mode): triggers unblock via gateway admin API (if supported) — otherwise logs a warning that manual unblock is needed
- Button changes to "Dismissed" (disabled, with X) after click
- Optional: text input for notes

**Bulk Actions** (appears when multiple items are selected):
- Checkbox on each card for multi-select
- "Confirm Selected" / "Dismiss Selected" buttons in a sticky footer bar

#### 4.2.4 Review Detail Modal

Clicking "View TX" or the TX ID opens a detail modal/panel with:

- Full verdict details (all rule results with signal breakdowns)
- ML feature vector (17 features with names and values)
- Raw HTML source preview (first 2000 chars, syntax highlighted if possible, otherwise `<pre>` with monospace)
- Sandboxed preview: an `<iframe sandbox="allow-same-origin">` loading the content from the gateway (JS disabled via sandbox attribute so phishing pages can't execute)
- Action buttons (same as card)

---

### 4.3 Scan History Tab

Searchable, paginated log of all scan verdicts.

#### 4.3.1 Search and Filters

- **Search box**: search by TX ID or content hash (partial match)
- **Verdict filter**: All | Clean | Suspicious | Malicious | Skipped
- **Source filter**: All | Webhook | Backfill
- **Date range**: Last 24h | Last 7d | Last 30d | All Time
- **Results per page**: 25 | 50 | 100

#### 4.3.2 Results Table

| Scanned At | TX ID | Verdict | Rules | ML Score | Source | Admin Status |
|------------|-------|---------|-------|----------|--------|-------------|

- Scanned At: human-readable timestamp
- TX ID: monospace, clickable link
- Verdict: colored badge
- Rules: comma-separated pill badges (empty for clean)
- ML Score: number with colored indicator (green < 0.5, amber 0.5-0.95, red > 0.95)
- Source: "webhook" or "backfill" (derived from tx_id field — "backfill" if tx_id == "backfill")
- Admin Status: "Confirmed" (green check) / "Dismissed" (gray X) / blank (pending)

#### 4.3.3 Pagination

Simple Previous / Page N of M / Next pagination at the bottom. Server-side pagination via `LIMIT/OFFSET`.

#### 4.3.4 Export

"Export CSV" button that downloads the current filtered results as a CSV file. Useful for:
- Sharing detection reports
- Extracting training data (confirmed verdicts)
- Compliance records

---

### 4.4 Settings Tab

Read-only display of current scanner configuration with a few runtime-adjustable settings.

#### 4.4.1 Current Configuration (Read-Only)

Display the current `Settings` values in a clean two-column layout:

| Setting | Value |
|---------|-------|
| Scanner Mode | dry-run |
| Gateway URL | http://core:4000 |
| Scanner Version | 0.1.0 |
| Workers | 2 |
| ML Model | Enabled |
| Max Scan Bytes | 256 KB |
| Scan Timeout | 10,000 ms |
| Backfill | Enabled (5 files/sec, 24h interval) |

**Rule Status** section showing each rule as a toggle-like indicator (but read-only — rules are configured via env vars):

| Rule | Status |
|------|--------|
| Seed Phrase Harvesting | Enabled |
| External Credential Form | Enabled |
| Wallet Impersonation | Enabled |
| Obfuscated Loader | Enabled |

#### 4.4.2 Training Data Export

A dedicated section for extracting labeled training data:

- **Export Confirmed Verdicts**: downloads a CSV of all items in `admin_overrides` with columns: `content_hash, tx_id, admin_verdict, original_verdict, original_rules, original_ml_score, notes, created_at`
- Stats: "X confirmed malicious, Y dismissed (false positives)"
- This data can be fed back into the ML training pipeline to improve the model

#### 4.4.3 Database Stats

- Total verdicts cached
- Verdicts by type (clean/suspicious/malicious/skipped)
- Queue depth
- Admin overrides count
- Database file size

---

## 5. API Endpoints

All endpoints require `Authorization: Bearer <SCANNER_ADMIN_KEY>`.

### 5.1 Dashboard

#### `GET /api/admin/stats`

Returns aggregated dashboard data in a single call.

```json
{
  "mode": "dry-run",
  "version": "0.1.0",
  "uptime_seconds": 86400,
  "metrics": {
    "scans_total": 2656,
    "scans_by_verdict": {"clean": 2644, "suspicious": 5, "malicious": 7},
    "scans_skipped_not_html": 334,
    "cache_hits": 0,
    "cache_misses": 2,
    "blocks_sent": 0,
    "blocks_failed": 0,
    "avg_scan_ms": 3.8,
    "queue_depth": 0
  },
  "backfill": {
    "enabled": true,
    "files_scanned": 9723,
    "malicious_found": 7,
    "sweeps_completed": 1,
    "last_sweep_at": 1772842027
  },
  "recent_detections": [
    {
      "content_hash": "abc...",
      "tx_id": "G7_...",
      "verdict": "malicious",
      "matched_rules": ["obfuscated-loader"],
      "ml_score": 0.257,
      "scanned_at": 1709768098,
      "admin_status": null
    }
  ]
}
```

### 5.2 Review Queue

#### `GET /api/admin/review`

Returns items needing review (MALICIOUS + SUSPICIOUS verdicts).

Query params:
- `verdict` — filter: `all`, `malicious`, `suspicious` (default: `all`)
- `status` — filter: `pending`, `confirmed`, `dismissed`, `all` (default: `pending`)
- `sort` — `newest`, `oldest`, `ml_score_desc` (default: `newest`)
- `page` — page number (default: 1)
- `per_page` — items per page (default: 25)

```json
{
  "items": [
    {
      "content_hash": "5vdU...",
      "tx_id": "G7_H...",
      "verdict": "malicious",
      "matched_rules": ["obfuscated-loader"],
      "ml_score": 0.257,
      "scanned_at": 1709768098,
      "scanner_version": "0.1.0",
      "admin_override": null
    }
  ],
  "total": 12,
  "page": 1,
  "per_page": 25,
  "pages": 1
}
```

#### `GET /api/admin/review/:content_hash`

Returns detailed information about a specific scan verdict, including full rule signal breakdowns.

```json
{
  "content_hash": "5vdU...",
  "tx_id": "G7_H...",
  "verdict": "malicious",
  "matched_rules": ["obfuscated-loader"],
  "ml_score": 0.257,
  "scanned_at": 1709768098,
  "scanner_version": "0.1.0",
  "admin_override": null,
  "gateway_url": "http://core:4000",
  "content_preview_url": "/api/admin/preview/G7_H..."
}
```

#### `POST /api/admin/review/:content_hash/confirm`

Confirms a detection as truly malicious.

```json
{
  "notes": "Verified phishing page targeting MetaMask users"
}
```

Response: `200 OK`
```json
{
  "status": "confirmed",
  "blocked": true,
  "blocked_tx_ids": ["G7_H..."]
}
```

Side effects:
- Creates/updates `admin_overrides` row
- In enforce mode: calls `PUT /ar-io/admin/block-data` for all TX IDs associated with this content hash

#### `POST /api/admin/review/:content_hash/dismiss`

Dismisses a detection as a false positive.

```json
{
  "notes": "Legitimate AOX DeFi app"
}
```

Response: `200 OK`
```json
{
  "status": "dismissed",
  "unblocked": false
}
```

Side effects:
- Creates/updates `admin_overrides` row with `confirmed_clean`
- Updates `scan_verdicts` to set verdict to `clean` (so future cache hits don't re-flag)

### 5.3 Scan History

#### `GET /api/admin/history`

Paginated scan history with filters.

Query params:
- `q` — search by TX ID or content hash (partial match)
- `verdict` — filter: `all`, `clean`, `suspicious`, `malicious`, `skipped` (default: `all`)
- `source` — filter: `all`, `webhook`, `backfill` (default: `all`)
- `period` — `24h`, `7d`, `30d`, `all` (default: `all`)
- `page` — page number (default: 1)
- `per_page` — items per page (default: 25)

```json
{
  "items": [...],
  "total": 2656,
  "page": 1,
  "per_page": 25,
  "pages": 107
}
```

#### `GET /api/admin/history/export`

Downloads CSV of filtered results. Same query params as `/api/admin/history` but returns `text/csv` with `Content-Disposition: attachment`.

### 5.4 Content Preview

#### `GET /api/admin/preview/:tx_id`

Proxies the content from the gateway (`GET /raw/:tx_id`) and returns it with safe headers:

- `Content-Type: text/plain` (renders as plain text, not executed)
- `Content-Security-Policy: sandbox`
- `X-Content-Type-Options: nosniff`

This allows admins to safely view raw HTML source of flagged content without it executing.

### 5.5 Settings

#### `GET /api/admin/settings`

Returns current scanner configuration (read-only).

```json
{
  "mode": "dry-run",
  "version": "0.1.0",
  "gateway_url": "http://core:4000",
  "workers": 2,
  "ml_model_enabled": true,
  "max_scan_bytes": 262144,
  "scan_timeout_ms": 10000,
  "rules": {
    "seed_phrase": true,
    "external_credential_form": true,
    "wallet_impersonation": true,
    "obfuscated_loader": true
  },
  "backfill": {
    "enabled": true,
    "data_path": "/gateway-data/contiguous",
    "rate": 5,
    "interval_hours": 24
  },
  "db_stats": {
    "total_verdicts": 12379,
    "verdicts_by_type": {"clean": 2644, "suspicious": 5, "malicious": 7, "skipped": 9723},
    "admin_overrides": 3,
    "queue_depth": 0,
    "db_size_bytes": 1048576
  }
}
```

#### `GET /api/admin/training-export`

Downloads CSV of all `admin_overrides` for ML training:

```csv
content_hash,tx_id,admin_verdict,original_verdict,original_rules,original_ml_score,notes,created_at
5vdU...,G7_H...,confirmed_clean,malicious,"[""obfuscated-loader""]",0.257,"Legitimate AOX app",1709768098
```

---

## 6. Scanner Integration

### 6.1 Override Enforcement

When the scanner processes a scan (webhook or backfill), it checks `admin_overrides` before taking action:

1. **Before scanning**: if content hash exists in `admin_overrides` as `confirmed_clean`, skip scanning entirely and return CLEAN
2. **After scanning**: if content hash exists in `admin_overrides` as `confirmed_malicious`, always treat as MALICIOUS regardless of rule results (ensures re-scans after rule changes don't accidentally un-flag confirmed threats)

### 6.2 Metrics Updates

Add to `ScanMetrics`:
- `admin_confirmations`: count of confirmed malicious
- `admin_dismissals`: count of dismissed false positives

### 6.3 New DB Methods

Add to `ScannerDB`:
- `save_override(content_hash, tx_id, admin_verdict, original_verdict, original_rules, original_ml_score, notes)`
- `get_override(content_hash) -> AdminOverride | None`
- `list_review_items(verdict, status, sort, page, per_page) -> (items, total)`
- `list_history(query, verdict, source, period, page, per_page) -> (items, total)`
- `get_db_stats() -> dict`
- `update_verdict(content_hash, new_verdict)` — for dismissals that clear the verdict

---

## 7. Security Considerations

### 7.1 Authentication

- All admin endpoints require Bearer token matching `SCANNER_ADMIN_KEY`
- `SCANNER_ADMIN_KEY` is independent of the gateway's `ADMIN_API_KEY` — compromise of one does not compromise the other
- Failed auth returns 401 with no body detail (no information leakage)
- API key stored in browser `localStorage` (acceptable for single-operator tool; cleared on logout)

### 7.2 Content Preview Safety

- Raw HTML from flagged pages is NEVER rendered as HTML in the admin UI
- Source preview uses `<pre><code>` with HTML entities escaped
- Sandboxed iframe preview (if included) uses `sandbox=""` attribute with no allow flags — scripts, forms, and navigation are all blocked
- Proxy endpoint returns `Content-Type: text/plain` to prevent browser execution

### 7.3 Input Validation

- Content hash and TX ID parameters validated against base64url regex before DB queries
- Notes field limited to 500 characters, HTML-stripped
- Pagination params clamped to reasonable ranges (per_page max 100)

### 7.4 SQL Injection Prevention

- All DB queries use parameterized statements (already the pattern in `ScannerDB`)
- No string interpolation in SQL

---

## 8. Implementation Plan

See `docs/IMPLEMENTATION-admin-interface.md` for the detailed, step-by-step implementation plan with file-level tasks.

---

## 9. Configuration

New environment variables:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SCANNER_ADMIN_KEY` | Yes (if UI enabled) | -- | API key for operator access to the admin dashboard. Independent of the gateway's `ADMIN_API_KEY`. |
| `ADMIN_UI_ENABLED` | No | `true` | Enable the admin dashboard at `/admin` |

---

## 10. File Manifest

```
src/
  admin/
    __init__.py
    auth.py              — FastAPI dependency: validate Bearer token against SCANNER_ADMIN_KEY
    routes.py            — All /api/admin/* endpoints + /admin HTML serving
  templates/
    admin/
      base.html          — layout shell: <head>, nav bar, login screen, tab container
      dashboard.html     — dashboard tab markup (Alpine.js template)
      review.html        — review queue tab markup
      history.html       — scan history tab markup
      settings.html      — settings tab markup
  static/
    admin/
      app.js             — main Alpine.js app: auth, tab routing, shared API helper
      dashboard.js       — dashboard data fetching, stats cards, recent detections
      review.js          — review queue filters, confirm/dismiss actions, detail modal
      history.js         — search, pagination, CSV export
      settings.js        — settings display, training data export
      styles.css         — custom CSS: brand colors, component overrides
  db.py                  — Extended with admin_overrides table + new query methods
  server.py              — Extended to mount admin router + static/template dirs
  config.py              — Add SCANNER_ADMIN_KEY, ADMIN_UI_ENABLED
  scanner.py             — Add override check before scan
  backfill.py            — Add override check before scan
  models.py              — Add AdminOverride dataclass
tests/
  test_admin_api.py      — Tests for all admin API endpoints
  test_admin_overrides.py — Tests for override enforcement in scanner
```
