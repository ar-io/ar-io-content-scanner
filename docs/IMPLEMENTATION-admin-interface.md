# Admin Interface — Implementation Plan

Step-by-step build plan for the admin dashboard. Each step is a committable unit. Reference: `docs/PRD-admin-interface.md`.

---

## Step 1: Configuration + Auth Foundation

**Files: `src/config.py`, `src/admin/__init__.py`, `src/admin/auth.py`**

### 1.1 Add new settings to `config.py`

- `scanner_admin_key: str` — new env var `SCANNER_ADMIN_KEY`, required when `ADMIN_UI_ENABLED=true`
- `admin_ui_enabled: bool` — env var `ADMIN_UI_ENABLED`, default `true`
- Update `load_settings()` to read both
- Validation: if `admin_ui_enabled` and no `scanner_admin_key`, raise with clear error message

### 1.2 Create `src/admin/auth.py`

FastAPI dependency that validates the Bearer token:

```python
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

security = HTTPBearer()

def require_admin_key(settings):
    """Returns a FastAPI dependency that validates SCANNER_ADMIN_KEY."""
    async def verify(creds: HTTPAuthorizationCredentials = Depends(security)):
        if creds.credentials != settings.scanner_admin_key:
            raise HTTPException(status_code=401)
        return creds.credentials
    return verify
```

### 1.3 Create `src/admin/__init__.py`

Empty init file.

### 1.4 Tests

- `test_admin_api.py`: test that endpoints return 401 without key, 401 with wrong key, 200 with correct key

---

## Step 2: Database — Admin Overrides Table + Query Methods

**Files: `src/db.py`, `src/models.py`**

### 2.1 Add `AdminOverride` dataclass to `models.py`

```python
@dataclass
class AdminOverride:
    content_hash: str
    tx_id: str
    admin_verdict: str       # 'confirmed_malicious' or 'confirmed_clean'
    original_verdict: str
    original_rules: str      # JSON
    original_ml_score: float | None
    notes: str
    created_at: int
```

### 2.2 Add `admin_overrides` table to `ScannerDB.initialize()`

```sql
CREATE TABLE IF NOT EXISTS admin_overrides (
    content_hash TEXT PRIMARY KEY,
    tx_id TEXT NOT NULL,
    admin_verdict TEXT NOT NULL,
    original_verdict TEXT NOT NULL,
    original_rules TEXT,
    original_ml_score REAL,
    notes TEXT DEFAULT '',
    created_at INTEGER NOT NULL
);
```

### 2.3 Add new methods to `ScannerDB`

**Override methods:**
- `save_override(content_hash, tx_id, admin_verdict, original_verdict, original_rules, original_ml_score, notes) -> None`
- `get_override(content_hash) -> AdminOverride | None`
- `update_verdict(content_hash, new_verdict) -> None` — updates `scan_verdicts.verdict` for dismissals

**Query methods (for admin API):**
- `list_review_items(verdict_filter, status_filter, sort, page, per_page) -> tuple[list[dict], int]`
  - Joins `scan_verdicts` LEFT JOIN `admin_overrides` ON content_hash
  - Filters: verdict IN (malicious, suspicious), status = pending/confirmed/dismissed
  - Returns (items, total_count) for pagination
- `list_history(query, verdict_filter, source_filter, period, page, per_page) -> tuple[list[dict], int]`
  - Searches `scan_verdicts` with LIKE on tx_id/content_hash
  - Source filter: `tx_id = 'backfill'` vs `tx_id != 'backfill'`
  - Period filter: `scanned_at > cutoff_timestamp`
  - LEFT JOIN `admin_overrides` for admin_status column
- `get_recent_detections(limit=10) -> list[dict]`
  - `SELECT ... FROM scan_verdicts WHERE verdict IN ('malicious','suspicious') ORDER BY scanned_at DESC LIMIT ?`
  - LEFT JOIN admin_overrides
- `get_db_stats() -> dict`
  - Count verdicts by type
  - Count admin overrides by type
  - Queue depth
  - DB file size via `os.path.getsize()`

### 2.4 Tests

- `test_admin_overrides.py`: CRUD on admin_overrides table, list queries with filters, pagination correctness

---

## Step 3: Scanner Integration — Override Enforcement

**Files: `src/scanner.py`, `src/backfill.py`**

### 3.1 Override check in `Scanner.process_queue_item()`

After fetching content and before scanning, check `db.get_override(content_hash)`:

- If `confirmed_clean`: cache as CLEAN, skip scanning, return
- If `confirmed_malicious`: cache as MALICIOUS, block if enforce mode, skip scanning, return
- If no override: proceed with normal scan

### 3.2 Override check in `BackfillScanner._process_file()`

Same logic — after checking `has_verdict` cache but before scanning:

- Check `db.get_override(hash_str)`
- If override exists, honor it and skip scanning

### 3.3 Tests

- `test_admin_overrides.py`: verify that a `confirmed_clean` override prevents blocking, that `confirmed_malicious` forces blocking even if rules wouldn't trigger

---

## Step 4: Admin API — Routes

**Files: `src/admin/routes.py`, `src/server.py`**

### 4.1 Create `src/admin/routes.py`

FastAPI `APIRouter` with prefix `/api/admin`, all routes require `require_admin_key` dependency.

**Endpoints:**

#### `GET /api/admin/stats`
- Reads from `ScanMetrics.to_dict()`, `db.queue_depth()`, `db.get_recent_detections()`
- Includes settings.scanner_mode, settings.scanner_version
- Includes backfill status from metrics

#### `GET /api/admin/review`
- Query params: verdict, status, sort, page, per_page
- Calls `db.list_review_items()`
- Returns paginated JSON

#### `GET /api/admin/review/{content_hash}`
- Calls `db.get_verdict(content_hash)` + `db.get_override(content_hash)`
- Returns detailed verdict info

#### `POST /api/admin/review/{content_hash}/confirm`
- Body: `{ "notes": "..." }`
- Validates content_hash format
- Gets current verdict from DB
- Saves override as `confirmed_malicious`
- If enforce mode: looks up TX IDs and calls `gateway.block_data()` for each
- Returns `{ "status": "confirmed", "blocked": bool, "blocked_tx_ids": [...] }`

#### `POST /api/admin/review/{content_hash}/dismiss`
- Body: `{ "notes": "..." }`
- Saves override as `confirmed_clean`
- Updates `scan_verdicts.verdict` to `clean`
- Returns `{ "status": "dismissed" }`

#### `GET /api/admin/history`
- Query params: q, verdict, source, period, page, per_page
- Calls `db.list_history()`
- Returns paginated JSON

#### `GET /api/admin/history/export`
- Same filters as `/history` but returns CSV with `Content-Disposition: attachment`
- Streams all matching rows (no pagination)

#### `GET /api/admin/preview/{tx_id}`
- Proxies content from gateway via `gateway.fetch_content(tx_id)`
- Returns with `Content-Type: text/plain; charset=utf-8`
- Headers: `Content-Security-Policy: sandbox`, `X-Content-Type-Options: nosniff`

#### `GET /api/admin/settings`
- Returns sanitized settings (excludes `admin_api_key` and `scanner_admin_key`)
- Includes DB stats from `db.get_db_stats()`

#### `GET /api/admin/training-export`
- Queries all rows from `admin_overrides`
- Returns CSV with `Content-Disposition: attachment`

### 4.2 Mount router in `src/server.py`

- Import admin routes
- Conditionally mount if `settings.admin_ui_enabled`
- Pass `settings`, `db`, `metrics`, `gateway` to the router (via `app.state` or dependency injection)
- Mount Jinja2 `TemplateResponse` for `/admin`
- Mount `/static/admin` for static files

### 4.3 Add dependencies to `requirements.txt`

- `jinja2` — for template rendering (FastAPI has built-in support)
- `aiofiles` — for static file serving (FastAPI `StaticFiles` requires it)

### 4.4 Tests

- `test_admin_api.py`: test each endpoint with mock DB data
  - Stats returns correct shape
  - Review list filters work
  - Confirm/dismiss create overrides
  - History pagination + search
  - Preview returns text/plain
  - Settings excludes secrets
  - Export returns CSV content-type

---

## Step 5: Frontend — Base Layout + Login

**Files: `src/templates/admin/base.html`, `src/static/admin/app.js`, `src/static/admin/styles.css`**

### 5.1 `base.html` — Layout Shell

Jinja2 template that renders the full HTML page:

```
<head>
  - Google Fonts: Besley + Plus Jakarta Sans
  - Tailwind CSS CDN
  - Alpine.js CDN (defer)
  - styles.css link
</head>
<body x-data="adminApp()">
  <!-- Login Screen (shown when !authenticated) -->
  <div x-show="!authenticated">
    Login form: API key input + Sign In button
  </div>

  <!-- Main App (shown when authenticated) -->
  <div x-show="authenticated">
    <!-- Header bar -->
    <!-- Tab navigation -->
    <!-- Tab content panels -->
    {% include "admin/dashboard.html" %}
    {% include "admin/review.html" %}
    {% include "admin/history.html" %}
    {% include "admin/settings.html" %}
  </div>

  <!-- JS files -->
  <script src="/static/admin/app.js"></script>
  <script src="/static/admin/dashboard.js"></script>
  <script src="/static/admin/review.js"></script>
  <script src="/static/admin/history.js"></script>
  <script src="/static/admin/settings.js"></script>
</body>
```

### 5.2 `app.js` — Core Application

- `adminApp()` Alpine.js component:
  - `authenticated: false`
  - `apiKey: localStorage.getItem('scanner_admin_key')`
  - `activeTab: 'dashboard'`
  - `login()` — validates key via `GET /api/admin/stats`, stores in localStorage
  - `logout()` — clears localStorage, sets `authenticated = false`
  - `api(path, options)` — wrapper around `fetch()` that adds Bearer header, handles 401 → auto-logout
  - Auto-login on page load if key exists in localStorage

### 5.3 `styles.css` — Brand Overrides

- CSS custom properties for brand colors
- Font family assignments (Besley for `.font-display`, Plus Jakarta Sans for body)
- Tailwind config overrides via `@layer`
- Badge styles (.badge-malicious, .badge-suspicious, .badge-clean)
- Card styles, table styles

### 5.4 Serve route in `routes.py`

```python
@router.get("/admin", response_class=HTMLResponse)
async def admin_page(request: Request):
    return templates.TemplateResponse("admin/base.html", {"request": request})
```

Note: The `/admin` HTML page is served WITHOUT auth — the page itself handles login client-side. Only `/api/admin/*` endpoints require auth.

---

## Step 6: Frontend — Dashboard Tab

**Files: `src/templates/admin/dashboard.html`, `src/static/admin/dashboard.js`**

### 6.1 `dashboard.html` — Markup

Alpine.js template section containing:

- **Mode banner**: `x-show="stats.mode"`, yellow/green based on mode
- **Stats cards row**: 4-card grid
  - Total Scanned (primary accent)
  - Malicious (red accent)
  - Suspicious (amber accent)
  - Blocked (green accent)
  - Each card: large number (Besley 800), subtitle (Plus Jakarta Sans), card-surface bg
- **System health section**: two-column grid
  - Left: uptime, version, queue depth, workers, avg scan time, cache hit rate
  - Right: backfill enabled/disabled, files scanned, malicious found, sweeps, last sweep time
- **Recent detections table**: 10 most recent malicious/suspicious
  - Columns: Time, TX ID (monospace link), Verdict (badge), Rules (pills), ML Score, Admin Status
  - "View in Review Queue" link per row
- **Auto-refresh indicator**: "Updated X seconds ago" + pause/resume button

### 6.2 `dashboard.js` — Logic

- `dashboardData()` Alpine.js component (registered via `Alpine.data()`)
- `loadStats()` — calls `GET /api/admin/stats`, populates reactive data
- `formatUptime(seconds)` — converts to "X days, Y hours"
- `formatTimestamp(unix)` — converts to local datetime string
- Auto-refresh: `setInterval(loadStats, 30000)` with pause/resume toggle
- `init()` — load stats on tab activation

---

## Step 7: Frontend — Review Queue Tab

**Files: `src/templates/admin/review.html`, `src/static/admin/review.js`**

### 7.1 `review.html` — Markup

- **Filter bar**: verdict toggle (All/Malicious/Suspicious), status toggle (Pending/Confirmed/Dismissed), sort dropdown
- **Item cards**: iterated with `x-for="item in items"`
  - Verdict badge, timestamp
  - TX ID (monospace, clickable link to gateway)
  - Content hash (smaller gray monospace)
  - Rules as pill badges
  - ML Score with progress bar
  - Confirm / Dismiss buttons
  - Notes text input (expandable, shown on button click)
- **Empty state**: "No items pending review" with checkmark illustration
- **Pagination**: Previous / Page N of M / Next
- **Detail modal** (hidden by default):
  - Full verdict details
  - Raw HTML source in `<pre><code>` (escaped, monospace, max-height with scroll)
  - Sandboxed iframe preview: `<iframe sandbox="" srcdoc="...">` or src to preview endpoint
  - Confirm/Dismiss buttons

### 7.2 `review.js` — Logic

- `reviewData()` Alpine.js component
- `loadItems()` — calls `GET /api/admin/review` with current filters
- `confirmItem(contentHash)` — calls `POST /api/admin/review/{hash}/confirm`, refreshes list
- `dismissItem(contentHash)` — calls `POST /api/admin/review/{hash}/dismiss`, refreshes list
- `showDetail(contentHash)` — calls `GET /api/admin/review/{hash}`, fetches preview, opens modal
- `setFilter(type, value)` — updates filter state, reloads
- `setPage(n)` — pagination
- Loading/error states for each action

---

## Step 8: Frontend — Scan History Tab

**Files: `src/templates/admin/history.html`, `src/static/admin/history.js`**

### 8.1 `history.html` — Markup

- **Search bar**: text input with search icon, debounced
- **Filter row**: verdict buttons (All/Clean/Suspicious/Malicious/Skipped), source buttons (All/Webhook/Backfill), period dropdown (24h/7d/30d/All)
- **Results table**:
  - Columns: Scanned At, TX ID, Verdict, Rules, ML Score, Source, Admin Status
  - TX ID: monospace link
  - Verdict: colored badge
  - Source: "webhook" or "backfill" text
  - Admin Status: checkmark/X icon or blank
- **Pagination**: Previous / Page N of M / Next / per-page selector
- **Export button**: "Export CSV" in top-right of filter bar

### 8.2 `history.js` — Logic

- `historyData()` Alpine.js component
- `loadHistory()` — calls `GET /api/admin/history` with filters
- `search(query)` — debounced (300ms) search, resets to page 1
- `exportCsv()` — calls `GET /api/admin/history/export` with current filters, triggers download
- `setFilter()`, `setPage()`, `setPerPage()` — filter/pagination state management
- Table sort by clicking column headers (client-side sort within current page)

---

## Step 9: Frontend — Settings Tab

**Files: `src/templates/admin/settings.html`, `src/static/admin/settings.js`**

### 9.1 `settings.html` — Markup

- **Configuration section**: two-column key-value display
  - Scanner Mode, Gateway URL, Version, Workers, ML Model, Max Scan Bytes, Scan Timeout
  - Values formatted for readability (256 KB not 262144, "10s" not 10000)
- **Rules section**: list with enabled/disabled indicator per rule
  - Green dot + "Enabled" or gray dot + "Disabled"
- **Backfill section**: config values if enabled, "Not configured" if disabled
- **Database stats section**: card with verdict counts, override counts, DB file size
- **Training data section**:
  - Stats: "X confirmed malicious, Y dismissed"
  - "Export Training Data (CSV)" button
  - Explanation text: "Download operator-labeled verdicts for ML model retraining"

### 9.2 `settings.js` — Logic

- `settingsData()` Alpine.js component
- `loadSettings()` — calls `GET /api/admin/settings`
- `exportTraining()` — calls `GET /api/admin/training-export`, triggers download
- `formatBytes(n)` — human-readable file size

---

## Step 10: Polish + Edge Cases

### 10.1 Loading States

- Skeleton loaders or spinners on initial data fetch for each tab
- Button loading state (spinner + disabled) during confirm/dismiss
- Error toast/banner on API failures with retry button

### 10.2 Error Handling

- 401 from any API call → auto-logout with "Session expired" message
- 500 from API → red error banner at top of content area, dismissable
- Network errors → "Connection lost" banner with auto-retry

### 10.3 Bulk Actions (Review Queue)

- Checkbox on each review card
- "Select All on Page" checkbox in header
- Sticky footer bar appears when items selected: "N selected — [Confirm All] [Dismiss All]"
- Bulk endpoint: `POST /api/admin/review/bulk` with `{ "content_hashes": [...], "action": "confirm"|"dismiss", "notes": "..." }`

### 10.4 Auto-Refresh

- Dashboard: 30s polling interval
- Review Queue: 60s polling (doesn't refresh if modal is open)
- Visual indicator: "Last updated: Xs ago"
- Pause button to disable auto-refresh

### 10.5 Responsive Considerations

- Min-width: 1024px (operator desktop tool)
- Stats cards: wrap to 2x2 grid below 1200px
- Tables: horizontal scroll on narrow viewports
- Modal: max-width 900px, centered

---

## Step 11: Docker + Documentation

### 11.1 Update `Dockerfile`

- Ensure `src/templates/` and `src/static/` directories are copied into the image
- Add `jinja2` and `aiofiles` to `requirements.txt`

### 11.2 Update `docker-compose.yml`

- Add `SCANNER_ADMIN_KEY` to environment section

### 11.3 Update `.env.example`

- Add `SCANNER_ADMIN_KEY=` with comment explaining it's the operator's admin UI key

### 11.4 Update `README.md`

- Add Admin Dashboard section explaining how to access `/admin`
- Add `SCANNER_ADMIN_KEY` to configuration table
- Screenshot placeholder

### 11.5 Update `OPERATOR.md`

- Add Admin Dashboard subsection under Monitoring
- Explain the review workflow: dry-run → review queue → confirm/dismiss → enable enforce
- Explain training data export for ML improvement

---

## Dependency Summary

| Step | Depends On | Deliverable |
|------|-----------|-------------|
| 1 | — | Config + auth foundation |
| 2 | — | DB schema + query methods |
| 3 | 2 | Scanner override enforcement |
| 4 | 1, 2 | All API endpoints |
| 5 | 4 | Base layout + login |
| 6 | 5 | Dashboard tab |
| 7 | 5 | Review queue tab |
| 8 | 5 | Scan history tab |
| 9 | 5 | Settings tab |
| 10 | 6, 7, 8, 9 | Polish + edge cases |
| 11 | all | Docker + docs |

Steps 1 and 2 can be done in parallel.
Steps 6, 7, 8, 9 can be done in parallel (all depend on 5 only).

---

## Testing Strategy

### Unit Tests (`tests/test_admin_overrides.py`)
- DB: CRUD on admin_overrides, list queries with all filter combinations, pagination edge cases
- Scanner: override enforcement (confirmed_clean skips scan, confirmed_malicious forces block)
- Backfill: override enforcement

### API Tests (`tests/test_admin_api.py`)
- Auth: 401 without key, 401 wrong key, 200 correct key
- Stats: returns correct shape and values
- Review: list/filter/sort, confirm creates override + triggers block, dismiss creates override + clears verdict
- History: search/filter/paginate, export returns CSV
- Preview: returns text/plain, handles missing TX
- Settings: returns config without secrets
- Training export: returns CSV with correct columns

### Manual QA Checklist
- [ ] Login flow: enter key → dashboard loads
- [ ] Login flow: wrong key → error shown
- [ ] Dashboard: stats cards show correct numbers
- [ ] Dashboard: auto-refresh updates values
- [ ] Review: filter by verdict works
- [ ] Review: confirm button → item moves to confirmed
- [ ] Review: dismiss button → item moves to dismissed
- [ ] Review: detail modal shows HTML source safely
- [ ] History: search by TX ID finds results
- [ ] History: CSV export downloads file
- [ ] Settings: all config values displayed
- [ ] Settings: training export downloads CSV
- [ ] Logout: clears session, shows login
