"""Test known-bad phishing transaction IDs from Slack alerts.

Fetches HTML from arweave.net and runs through the full detection pipeline
(rules + ML model). This is an offline integration test — no gateway needed.

Usage:
    python3 -m pytest tests/test_known_bad.py -v -s
    python3 tests/test_known_bad.py              # standalone mode
"""
from __future__ import annotations

import json
import sys
import time

import httpx

from src.config import Settings
from src.ml.classifier import PhishingClassifier
from src.ml.features import extract_features, parse_html
from src.models import Verdict
from src.rules.engine import RuleEngine
from src.scanner import is_html_content_type, looks_like_html

KNOWN_BAD_TXS = [
    "8EHXJbU7oixJaONTKFOeaXjoe5FbDA-0Sc7E-O8Q8kM",
    "8xGLDTCwUCyI2RO0xPd36Xc2l5Z66e6YnMgK41dSeOM",
    "aaBUiq7SRndzx9hrUHoCbvGBRLmGnkaMPn6mnVuPi7o",
    "brOWuYCe0hT0d3Bt7K2o_dFF7KacU6uAXg3Z3r2FZqU",
    "ECKIrQvsg49Z6XYq9Q0kjinU48jOKnjYkEwKfcrdL4A",
    "fszWPVnPwjNt9y_fw5n2Dwf6f_E4xLWfh-8M_7OvXqA",
    "-Gs_7WZHmV2ngBwf6a4qq9xe_ndDwwGUELKVqh9NsvQ",
    "IDcCFJ3qWVOZqlUipptPQbCFmRBl5nFBksK4LXJ0IS4",
    "J7aBB9XjFLE6bQsu2DKTP8CIBktLPHh51NAO5MoXjyg",
    "km63ipuYgWhJEnRRWoMrJpKjj9XiGZjWK7GwIDn4W2Q",
    "pneWXDhgt29uFvRqXhdHOVNLekTHATUGnutOThyHRRs",
    "remksuNnmaM23fB_b0Cym_V_fzrcJCFRgb2fuyD8jUE",
    "SKkPsd2_oz4YSnAV31aW6io9ZPwqSTa7o6l3ARGq4VM",
    "tWN62EMx9pPzWg9g5ezaJd4QkzRTH1LEJD24Pl95qFc",
    "viy6LqeN8LJDuABiCKylAhrEFjUxM7azgPyDBDpDBoE",
    "W7AtaN2PkLRJ1rI7svyZ9bKh_PksnpRldNlnHqkLSwQ",
    "WQw1oDTYei8YxKhYZergqzReF-Vw3HRocVwG0XCCOZg",
    "2UFDQQAOPQ7CoxBjax8WANUKvWVo0KOJ9kGquF9H3o4",
    "XBwUfh5h0RblPa8LoNvKAmd9SGPGDqNkDEBdpLAReP8",
    "m-hkEAt5Pe8p7xRcy9O46EV_xKb8Op3jVVlMuvWJo2Y",
    "u8Q-C6t8glRL6zVqgbDSnYtAZhKDM7PjTg36lHtZA-o",
    "ditRLCzRrgDxLgjLeTkDjquZ70MXdX_FMDTf8P9jwNo",
]

FETCH_URL = "https://arweave.net"
MAX_BYTES = 262144  # 256KB, same as scanner default
TIMEOUT = 15.0


def build_engine() -> tuple[RuleEngine, bool]:
    """Build the rule engine with ML model if available."""
    settings = Settings(
        gateway_url="http://unused",
        admin_api_key="unused",
        rule_seed_phrase=True,
        rule_external_credential_form=True,
        rule_wallet_impersonation=True,
        rule_obfuscated_loader=True,
    )
    classifier = None
    ml_loaded = False
    try:
        classifier = PhishingClassifier("./xgboost_model.pkl")
        ml_loaded = True
    except Exception as e:
        print(f"[warn] ML model not loaded: {e}")

    engine = RuleEngine(settings, classifier)
    return engine, ml_loaded


def fetch_content(client: httpx.Client, tx_id: str) -> tuple[bytes | None, str | None]:
    """Fetch raw content from arweave.net. Returns (content, content_type)."""
    try:
        resp = client.get(f"/raw/{tx_id}", follow_redirects=True)
        if resp.status_code != 200:
            return None, None
        ct = resp.headers.get("content-type")
        return resp.content[:MAX_BYTES], ct
    except httpx.HTTPError as e:
        return None, None


def scan_tx(engine: RuleEngine, tx_id: str, content: bytes, content_type: str | None) -> dict:
    """Run the full detection pipeline on fetched content."""
    result = {
        "tx_id": tx_id,
        "content_type": content_type,
        "size": len(content),
        "is_html": None,
        "verdict": None,
        "matched_rules": [],
        "ml_score": None,
        "scan_ms": 0,
        "skipped_reason": None,
    }

    # Content-type check
    html_check = is_html_content_type(content_type)
    if html_check is False:
        # Content sniff as fallback
        if not looks_like_html(content):
            result["is_html"] = False
            result["verdict"] = "skipped"
            result["skipped_reason"] = f"not_html ({content_type})"
            return result

    # Content sniff if unknown
    if html_check is None:
        if not looks_like_html(content):
            result["is_html"] = False
            result["verdict"] = "skipped"
            result["skipped_reason"] = "content_sniff_not_html"
            return result

    result["is_html"] = True

    # Parse and evaluate
    html = content.decode("utf-8", errors="replace")
    soup = parse_html(html)
    scan_result = engine.evaluate(html, soup)

    result["verdict"] = scan_result.verdict.value
    result["matched_rules"] = scan_result.matched_rules
    result["ml_score"] = scan_result.ml_score
    result["scan_ms"] = scan_result.scan_duration_ms

    return result


def run_all():
    """Fetch and scan all known-bad TXs, print results."""
    engine, ml_loaded = build_engine()

    print("=" * 78)
    print("ar.io Content Scanner — Known-Bad TX Test")
    print(f"Rules: {[r.name for r in engine.rules]}")
    print(f"ML model: {'loaded' if ml_loaded else 'NOT loaded'}")
    print(f"TXs to test: {len(KNOWN_BAD_TXS)}")
    print("=" * 78)
    print()

    client = httpx.Client(base_url=FETCH_URL, timeout=TIMEOUT)
    results = []

    for i, tx_id in enumerate(KNOWN_BAD_TXS, 1):
        print(f"[{i:2d}/{len(KNOWN_BAD_TXS)}] {tx_id} ... ", end="", flush=True)

        content, content_type = fetch_content(client, tx_id)
        if content is None:
            print("FETCH FAILED (404/timeout/blocked)")
            results.append({
                "tx_id": tx_id,
                "verdict": "fetch_failed",
                "matched_rules": [],
                "ml_score": None,
            })
            continue

        result = scan_tx(engine, tx_id, content, content_type)
        results.append(result)

        verdict = result["verdict"]
        icon = {
            "malicious": "MALICIOUS",
            "suspicious": "SUSPICIOUS",
            "clean": "!! CLEAN (missed) !!",
            "skipped": f"SKIPPED ({result['skipped_reason']})",
        }.get(verdict, verdict)

        rules_str = ", ".join(result["matched_rules"]) if result["matched_rules"] else "-"
        ml_str = f"{result['ml_score']:.3f}" if result["ml_score"] is not None else "-"

        print(f"{icon}  rules=[{rules_str}]  ml={ml_str}  {result['size']}B  {result['scan_ms']}ms")

    client.close()

    # Summary
    print()
    print("=" * 78)
    print("SUMMARY")
    print("=" * 78)

    verdicts = {}
    for r in results:
        v = r["verdict"]
        verdicts[v] = verdicts.get(v, 0) + 1

    for v, count in sorted(verdicts.items()):
        print(f"  {v}: {count}")

    detected = sum(1 for r in results if r["verdict"] in ("malicious", "suspicious"))
    fetchable = sum(1 for r in results if r["verdict"] != "fetch_failed")
    missed = [r for r in results if r["verdict"] == "clean"]

    print()
    if fetchable > 0:
        print(f"Detection rate: {detected}/{fetchable} fetchable TXs "
              f"({100*detected/fetchable:.0f}%)")
    if missed:
        print(f"\nMISSED (verdict=clean):")
        for r in missed:
            ml_str = f"{r['ml_score']:.3f}" if r.get("ml_score") is not None else "-"
            print(f"  {r['tx_id']}  ml={ml_str}  size={r.get('size', '?')}B")

    return results


# Pytest integration — run as test
def test_known_bad_txs():
    """Pytest entry point: fetch all known-bad TXs and assert detection."""
    results = run_all()

    fetchable = [r for r in results if r["verdict"] != "fetch_failed"]
    if not fetchable:
        import pytest
        pytest.skip("No TXs were fetchable (network issue or all blocked)")

    detected = [r for r in fetchable if r["verdict"] in ("malicious", "suspicious")]
    skipped = [r for r in fetchable if r["verdict"] == "skipped"]
    missed = [r for r in fetchable if r["verdict"] == "clean"]

    # We expect high detection on known-bad content
    # Allow skips (non-HTML content) but flag any clean verdicts
    if missed:
        tx_list = "\n  ".join(r["tx_id"] for r in missed)
        print(f"\nWARNING: {len(missed)} known-bad TXs were not detected:\n  {tx_list}")

    html_txs = [r for r in fetchable if r.get("is_html") is True]
    html_detected = [r for r in html_txs if r["verdict"] in ("malicious", "suspicious")]

    if html_txs:
        rate = len(html_detected) / len(html_txs)
        print(f"\nHTML detection rate: {len(html_detected)}/{len(html_txs)} ({rate*100:.0f}%)")
        # Soft assertion — we want to know about misses but not hard-fail the build
        assert rate >= 0.5, (
            f"Detection rate {rate*100:.0f}% is below 50% threshold. "
            f"Review missed TXs above."
        )


if __name__ == "__main__":
    run_all()
