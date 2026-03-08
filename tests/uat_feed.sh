#!/usr/bin/env bash
# =============================================================================
# Verdict Feed — User Acceptance Tests
#
# Runs against a live Content Scanner instance. Requires:
#   - Scanner running with VERDICT_API_KEY set
#   - SCANNER_ADMIN_KEY set (for admin integration tests)
#   - Some verdicts in the DB (e.g. from backfill or webhook scans)
#
# Usage:
#   FEED_KEY=your-feed-key ADMIN_KEY=your-admin-key ./tests/uat_feed.sh
#   FEED_KEY=your-feed-key ADMIN_KEY=your-admin-key BASE=http://host:3100 ./tests/uat_feed.sh
# =============================================================================

set -euo pipefail

BASE="${BASE:-http://localhost:3100}"
FEED_KEY="${FEED_KEY:?Set FEED_KEY to the VERDICT_API_KEY value}"
ADMIN_KEY="${ADMIN_KEY:?Set ADMIN_KEY to the SCANNER_ADMIN_KEY value}"

PASSED=0
FAILED=0
TOTAL=0

pass() { PASSED=$((PASSED + 1)); TOTAL=$((TOTAL + 1)); echo "  PASS"; }
fail() { FAILED=$((FAILED + 1)); TOTAL=$((TOTAL + 1)); echo "  FAIL — $1"; }

http_code() {
    curl -sf -o /dev/null -w "%{http_code}" "$@" 2>/dev/null || true
}

# ---- Auth ----

echo "=== Auth ==="

echo -n "1. No auth → 401: "
CODE=$(http_code "$BASE/api/verdicts")
[ "$CODE" = "401" ] && pass || fail "got $CODE"

echo -n "2. Wrong key → 401: "
CODE=$(http_code -H "Authorization: Bearer wrong-key" "$BASE/api/verdicts")
[ "$CODE" = "401" ] && pass || fail "got $CODE"

echo -n "3. Correct key → 200: "
CODE=$(http_code -H "Authorization: Bearer $FEED_KEY" "$BASE/api/verdicts")
[ "$CODE" = "200" ] && pass || fail "got $CODE"

echo -n "4. Admin key rejected for feed: "
CODE=$(http_code -H "Authorization: Bearer $ADMIN_KEY" "$BASE/api/verdicts")
[ "$CODE" = "401" ] && pass || fail "got $CODE"

# ---- Input Validation ----

echo ""
echo "=== Input Validation ==="

echo -n "5. Invalid hash → 400: "
CODE=$(http_code -H "Authorization: Bearer $FEED_KEY" "$BASE/api/verdicts/!!!invalid!!!")
[ "$CODE" = "400" ] && pass || fail "got $CODE"

echo -n "6. Nonexistent hash → 404: "
CODE=$(http_code -H "Authorization: Bearer $FEED_KEY" "$BASE/api/verdicts/nonexistenthash123")
[ "$CODE" = "404" ] && pass || fail "got $CODE"

# ---- Feed Responses ----

echo ""
echo "=== Feed Responses ==="

echo -n "7. Empty feed (future since) → empty list: "
RESP=$(curl -sf -H "Authorization: Bearer $FEED_KEY" "$BASE/api/verdicts?since=9999999999")
python3 -c "
import sys,json
d = json.loads('$RESP' if len('$RESP') < 2000 else sys.stdin.read())
assert len(d['verdicts']) == 0 and d['has_more'] is False
" <<< "$RESP" 2>/dev/null && pass || fail "unexpected response"

echo -n "8. Feed returns verdicts: "
RESP=$(curl -sf -H "Authorization: Bearer $FEED_KEY" "$BASE/api/verdicts?limit=5")
VCOUNT=$(echo "$RESP" | python3 -c "import sys,json; print(len(json.load(sys.stdin)['verdicts']))")
[ "$VCOUNT" -gt "0" ] && pass || fail "got $VCOUNT verdicts"

echo -n "9. Cursor continuation — no overlap: "
python3 -c "
import requests
h = {'Authorization': 'Bearer $FEED_KEY'}
r1 = requests.get('$BASE/api/verdicts?limit=3', headers=h).json()
if not r1['cursor']:
    print('  SKIP (not enough data)')
    exit(0)
c = r1['cursor']
r2 = requests.get(f'$BASE/api/verdicts?limit=3&since={c[\"scanned_at\"]}&after_hash={c[\"content_hash\"]}', headers=h).json()
h1 = {v['content_hash'] for v in r1['verdicts']}
h2 = {v['content_hash'] for v in r2['verdicts']}
assert h1.isdisjoint(h2), f'overlap: {h1 & h2}'
" 2>/dev/null && pass || fail "pages overlapped"

echo -n "10. Single lookup matches feed data: "
python3 -c "
import requests
h = {'Authorization': 'Bearer $FEED_KEY'}
feed = requests.get('$BASE/api/verdicts?limit=1', headers=h).json()
v = feed['verdicts'][0]
lookup = requests.get(f'$BASE/api/verdicts/{v[\"content_hash\"]}', headers=h).json()
for k in ['content_hash','tx_id','verdict','matched_rules','scanned_at']:
    assert v[k] == lookup[k], f'mismatch on {k}'
" 2>/dev/null && pass || fail "data mismatch"

echo -n "11. SKIPPED verdicts excluded from feed: "
python3 -c "
import requests
h = {'Authorization': 'Bearer $FEED_KEY'}
r = requests.get('$BASE/api/verdicts?limit=1000', headers=h).json()
skipped = [v for v in r['verdicts'] if v['verdict'] == 'skipped']
assert len(skipped) == 0, f'{len(skipped)} skipped verdicts in feed'
" 2>/dev/null && pass || fail "found skipped verdicts"

# ---- Admin Integration ----

echo ""
echo "=== Admin Integration ==="

echo -n "12. Settings shows feed config: "
python3 -c "
import requests
h = {'Authorization': 'Bearer $ADMIN_KEY'}
r = requests.get('$BASE/api/admin/settings', headers=h).json()
vf = r['verdict_feed']
assert vf['enabled'] is True
assert vf['api_key_set'] is True
assert vf['trust_mode'] in ('malicious_only', 'all')
" 2>/dev/null && pass || fail "settings missing feed"

echo -n "13. Stats shows feed section: "
python3 -c "
import requests
h = {'Authorization': 'Bearer $ADMIN_KEY'}
r = requests.get('$BASE/api/admin/stats', headers=h).json()
assert 'verdict_feed' in r
assert 'import_stats' in r['verdict_feed']
" 2>/dev/null && pass || fail "stats missing feed"

echo -n "14. Metrics include feed counters: "
python3 -c "
import requests
r = requests.get('$BASE/metrics').json()
for k in ['feed_verdicts_imported','feed_verdicts_exported','feed_poll_errors','feed_on_demand_hits','feed_on_demand_misses']:
    assert k in r, f'missing {k}'
" 2>/dev/null && pass || fail "missing metrics"

echo -n "15. Prometheus exports feed metrics: "
PROM=$(curl -sf "$BASE/metrics/prometheus")
FEED_LINES=$(echo "$PROM" | grep -c "scanner_feed_")
[ "$FEED_LINES" -ge "5" ] && pass || fail "only $FEED_LINES lines"

# ---- Metrics Accuracy ----

echo ""
echo "=== Metrics Accuracy ==="

echo -n "16. Export counter increments: "
BEFORE=$(curl -sf "$BASE/metrics" | python3 -c "import sys,json; print(json.load(sys.stdin)['feed_verdicts_exported'])")
curl -sf -H "Authorization: Bearer $FEED_KEY" "$BASE/api/verdicts?limit=5" > /dev/null
AFTER=$(curl -sf "$BASE/metrics" | python3 -c "import sys,json; print(json.load(sys.stdin)['feed_verdicts_exported'])")
DELTA=$((AFTER - BEFORE))
[ "$DELTA" -gt "0" ] && pass || fail "delta=$DELTA"

# ---- Schema Validation ----

echo ""
echo "=== Schema Validation ==="

echo -n "17. Feed response schema: "
python3 -c "
import requests
h = {'Authorization': 'Bearer $FEED_KEY'}
r = requests.get('$BASE/api/verdicts?limit=1', headers=h).json()
assert set(r.keys()) == {'verdicts','cursor','has_more'}
if r['verdicts']:
    required = {'content_hash','tx_id','verdict','matched_rules','ml_score','scanned_at','scanner_version','admin_override'}
    assert set(r['verdicts'][0].keys()) == required
    assert set(r['cursor'].keys()) == {'scanned_at','content_hash'}
" 2>/dev/null && pass || fail "schema mismatch"

echo -n "18. No internal fields leaked: "
python3 -c "
import requests
h = {'Authorization': 'Bearer $FEED_KEY'}
r = requests.get('$BASE/api/verdicts?limit=5', headers=h).json()
banned = ['source','_peer_url','id','status','received_at']
for v in r['verdicts']:
    for f in banned:
        assert f not in v, f'{f} leaked'
v0 = r['verdicts'][0]
s = requests.get(f'$BASE/api/verdicts/{v0[\"content_hash\"]}', headers=h).json()
for f in banned:
    assert f not in s, f'{f} leaked in lookup'
" 2>/dev/null && pass || fail "internal fields exposed"

# ---- Full Drain ----

echo ""
echo "=== Full Drain ==="

echo -n "19. Walk all pages to completion: "
python3 -c "
import requests
h = {'Authorization': 'Bearer $FEED_KEY'}
since, after_hash, total, pages = 0, '', 0, 0
while True:
    params = {'limit': 100, 'since': since}
    if after_hash:
        params['after_hash'] = after_hash
    r = requests.get('$BASE/api/verdicts', headers=h, params=params).json()
    total += len(r['verdicts'])
    pages += 1
    if r['cursor']:
        since = r['cursor']['scanned_at']
        after_hash = r['cursor']['content_hash']
    if not r['has_more']:
        break
    assert pages < 200, 'too many pages'
print(f'  {total} verdicts, {pages} pages')
" 2>/dev/null && pass || fail "drain failed"

# ---- Data Integrity ----

echo ""
echo "=== Data Integrity ==="

echo -n "20. Admin dashboard loads: "
CODE=$(http_code "$BASE/admin")
[ "$CODE" = "200" ] && pass || fail "got $CODE"

echo -n "21. List vs lookup consistency (10 items): "
python3 -c "
import requests
h = {'Authorization': 'Bearer $FEED_KEY'}
feed = requests.get('$BASE/api/verdicts?limit=10', headers=h).json()
for v in feed['verdicts']:
    s = requests.get(f'$BASE/api/verdicts/{v[\"content_hash\"]}', headers=h).json()
    for k in ['content_hash','tx_id','verdict','matched_rules','scanned_at','scanner_version']:
        assert v[k] == s[k], f'mismatch: {k}'
" 2>/dev/null && pass || fail "data mismatch"

# ---- Ordering ----

echo ""
echo "=== Ordering ==="

echo -n "22. Feed ordered ASC by scanned_at: "
python3 -c "
import requests
h = {'Authorization': 'Bearer $FEED_KEY'}
r = requests.get('$BASE/api/verdicts?limit=50', headers=h).json()
ts = [v['scanned_at'] for v in r['verdicts']]
assert all(a <= b for a, b in zip(ts, ts[1:])), 'not sorted'
" 2>/dev/null && pass || fail "wrong order"

# ---- Rate Limiting ----

echo ""
echo "=== Rate Limiting ==="

echo -n "23. Rate limiter engages: "
python3 -c "
import requests
h = {'Authorization': 'Bearer $FEED_KEY'}
codes = []
for _ in range(65):
    r = requests.get('$BASE/api/verdicts?limit=1', headers=h)
    codes.append(r.status_code)
ok = codes.count(200)
limited = codes.count(429)
print(f'  {ok} ok, {limited} rate-limited')
assert limited > 0, 'rate limiter never triggered'
" 2>/dev/null && pass || fail "no 429s"

# ---- Summary ----

echo ""
echo "================================================"
echo "  RESULTS: $PASSED passed, $FAILED failed ($TOTAL total)"
echo "================================================"

[ "$FAILED" -eq "0" ] && exit 0 || exit 1
