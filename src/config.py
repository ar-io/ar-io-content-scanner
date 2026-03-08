from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    # Gateway connection
    gateway_url: str
    admin_api_key: str

    # Server
    scanner_port: int = 3100
    scanner_workers: int = 2

    # Mode: "dry-run" or "enforce"
    scanner_mode: str = "dry-run"

    # ML model
    ml_model_enabled: bool = True
    ml_model_path: str = "./xgboost_model.pkl"
    ml_suspicious_threshold: float = 0.95

    # Rule toggles
    rule_seed_phrase: bool = True
    rule_external_credential_form: bool = True
    rule_wallet_impersonation: bool = True
    rule_obfuscated_loader: bool = True

    # Content limits
    max_scan_bytes: int = 262144  # 256KB
    scan_timeout_ms: int = 10000

    # DB
    db_path: str = "/app/data/scanner.db"

    # Admin UI
    admin_ui_enabled: bool = True
    scanner_admin_key: str = ""
    gateway_public_url: str = ""  # public-facing gateway URL for TX ID links in admin UI

    # Logging
    log_level: str = "info"

    # Scanner version
    scanner_version: str = "0.1.0"

    # Screenshots
    screenshot_enabled: bool = True
    screenshot_dir: str = "/app/data/screenshots"
    screenshot_timeout_ms: int = 15000

    # Verdict feed: share verdicts with peers
    verdict_api_key: str = ""
    verdict_feed_urls: tuple[str, ...] = ()
    verdict_feed_poll_interval: int = 300  # seconds between polls
    verdict_feed_trust_mode: str = "malicious_only"  # or "all"
    verdict_feed_on_demand: bool = True
    verdict_feed_request_timeout_ms: int = 5000

    # Google Safe Browsing / Web Risk API
    safe_browsing_api_key: str = ""
    safe_browsing_check_interval: int = 300  # seconds between periodic checks

    # Backfill: proactive filesystem sweep
    backfill_enabled: bool = False
    backfill_data_path: str = ""  # gateway's contiguous data directory
    backfill_gateway_db_path: str = ""  # gateway's data.db (read-only, for hash→TX ID)
    backfill_rate: int = 5  # max files scanned per second
    backfill_interval_hours: int = 24  # re-sweep interval (0 = one-shot)


def load_settings() -> Settings:
    gateway_url = os.environ.get("GATEWAY_URL")
    admin_api_key = os.environ.get("ADMIN_API_KEY")

    if not gateway_url:
        raise ValueError("GATEWAY_URL environment variable is required")
    if not admin_api_key:
        raise ValueError("ADMIN_API_KEY environment variable is required")

    mode = os.environ.get("SCANNER_MODE", "dry-run")
    if mode not in ("dry-run", "enforce"):
        raise ValueError(
            f"SCANNER_MODE must be 'dry-run' or 'enforce', got '{mode}'"
        )

    admin_ui_enabled = (
        os.environ.get("ADMIN_UI_ENABLED", "true").lower() == "true"
    )
    scanner_admin_key = os.environ.get("SCANNER_ADMIN_KEY", "")

    if admin_ui_enabled and not scanner_admin_key:
        raise ValueError(
            "SCANNER_ADMIN_KEY is required when ADMIN_UI_ENABLED=true. "
            "Set a secret key for the admin dashboard, or set ADMIN_UI_ENABLED=false."
        )

    backfill_enabled = (
        os.environ.get("BACKFILL_ENABLED", "false").lower() == "true"
    )
    backfill_data_path = os.environ.get("BACKFILL_DATA_PATH", "")

    if backfill_enabled and not backfill_data_path:
        raise ValueError(
            "BACKFILL_DATA_PATH is required when BACKFILL_ENABLED=true"
        )

    scanner_workers = int(os.environ.get("SCANNER_WORKERS", "2"))
    if scanner_workers < 1:
        raise ValueError("SCANNER_WORKERS must be >= 1")

    max_scan_bytes = int(os.environ.get("MAX_SCAN_BYTES", "262144"))
    if max_scan_bytes < 1:
        raise ValueError("MAX_SCAN_BYTES must be >= 1")

    scan_timeout_ms = int(os.environ.get("SCAN_TIMEOUT", "10000"))
    if scan_timeout_ms < 1:
        raise ValueError("SCAN_TIMEOUT must be >= 1")

    backfill_rate = int(os.environ.get("BACKFILL_RATE", "5"))
    if backfill_rate < 1:
        raise ValueError("BACKFILL_RATE must be >= 1")

    ml_suspicious_threshold = float(
        os.environ.get("ML_SUSPICIOUS_THRESHOLD", "0.95")
    )
    if not 0 < ml_suspicious_threshold <= 1:
        raise ValueError("ML_SUSPICIOUS_THRESHOLD must be between 0 and 1")

    # Verdict feed settings
    verdict_api_key = os.environ.get("VERDICT_API_KEY", "")
    verdict_feed_urls_raw = os.environ.get("VERDICT_FEED_URLS", "")
    verdict_feed_urls = tuple(
        u.rstrip("/") for u in verdict_feed_urls_raw.split(",") if u.strip()
    )
    if verdict_feed_urls and not verdict_api_key:
        raise ValueError(
            "VERDICT_API_KEY is required when VERDICT_FEED_URLS is set"
        )

    verdict_feed_poll_interval = int(
        os.environ.get("VERDICT_FEED_POLL_INTERVAL", "300")
    )
    if verdict_feed_poll_interval < 10:
        raise ValueError("VERDICT_FEED_POLL_INTERVAL must be >= 10")

    verdict_feed_trust_mode = os.environ.get(
        "VERDICT_FEED_TRUST_MODE", "malicious_only"
    )
    if verdict_feed_trust_mode not in ("malicious_only", "all"):
        raise ValueError(
            "VERDICT_FEED_TRUST_MODE must be 'malicious_only' or 'all'"
        )

    verdict_feed_on_demand = (
        os.environ.get("VERDICT_FEED_ON_DEMAND", "true").lower() == "true"
    )

    verdict_feed_request_timeout_ms = int(
        os.environ.get("VERDICT_FEED_REQUEST_TIMEOUT_MS", "5000")
    )
    if verdict_feed_request_timeout_ms < 100:
        raise ValueError("VERDICT_FEED_REQUEST_TIMEOUT_MS must be >= 100")

    # Safe Browsing settings
    safe_browsing_api_key = os.environ.get("SAFE_BROWSING_API_KEY", "")
    safe_browsing_check_interval = int(
        os.environ.get("SAFE_BROWSING_CHECK_INTERVAL", "300")
    )
    if safe_browsing_check_interval < 60:
        raise ValueError("SAFE_BROWSING_CHECK_INTERVAL must be >= 60")

    screenshot_enabled = (
        os.environ.get("SCREENSHOT_ENABLED", "true").lower() == "true"
    )
    screenshot_timeout_ms = int(
        os.environ.get("SCREENSHOT_TIMEOUT_MS", "15000")
    )
    if screenshot_timeout_ms < 1000:
        raise ValueError("SCREENSHOT_TIMEOUT_MS must be >= 1000")

    return Settings(
        gateway_url=gateway_url.rstrip("/"),
        admin_api_key=admin_api_key,
        admin_ui_enabled=admin_ui_enabled,
        scanner_admin_key=scanner_admin_key,
        scanner_port=int(os.environ.get("SCANNER_PORT", "3100")),
        scanner_workers=scanner_workers,
        scanner_mode=mode,
        ml_model_enabled=os.environ.get("ML_MODEL_ENABLED", "true").lower()
        == "true",
        ml_model_path=os.environ.get("ML_MODEL_PATH", "./xgboost_model.pkl"),
        ml_suspicious_threshold=ml_suspicious_threshold,
        rule_seed_phrase=os.environ.get("RULE_SEED_PHRASE", "true").lower()
        == "true",
        rule_external_credential_form=os.environ.get(
            "RULE_EXTERNAL_CREDENTIAL_FORM", "true"
        ).lower()
        == "true",
        rule_wallet_impersonation=os.environ.get(
            "RULE_WALLET_IMPERSONATION", "true"
        ).lower()
        == "true",
        rule_obfuscated_loader=os.environ.get(
            "RULE_OBFUSCATED_LOADER", "true"
        ).lower()
        == "true",
        max_scan_bytes=max_scan_bytes,
        scan_timeout_ms=scan_timeout_ms,
        db_path=os.environ.get("DB_PATH", "/app/data/scanner.db"),
        log_level=os.environ.get("LOG_LEVEL", "info"),
        scanner_version=os.environ.get("SCANNER_VERSION", "0.1.0"),
        verdict_api_key=verdict_api_key,
        verdict_feed_urls=verdict_feed_urls,
        verdict_feed_poll_interval=verdict_feed_poll_interval,
        verdict_feed_trust_mode=verdict_feed_trust_mode,
        verdict_feed_on_demand=verdict_feed_on_demand,
        verdict_feed_request_timeout_ms=verdict_feed_request_timeout_ms,
        gateway_public_url=os.environ.get("GATEWAY_PUBLIC_URL", "").rstrip("/"),
        screenshot_enabled=screenshot_enabled,
        screenshot_dir=os.environ.get(
            "SCREENSHOT_DIR", "/app/data/screenshots"
        ),
        screenshot_timeout_ms=screenshot_timeout_ms,
        safe_browsing_api_key=safe_browsing_api_key,
        safe_browsing_check_interval=safe_browsing_check_interval,
        backfill_enabled=backfill_enabled,
        backfill_data_path=backfill_data_path,
        backfill_gateway_db_path=os.environ.get("BACKFILL_GATEWAY_DB_PATH", ""),
        backfill_rate=backfill_rate,
        backfill_interval_hours=int(
            os.environ.get("BACKFILL_INTERVAL_HOURS", "24")
        ),
    )
