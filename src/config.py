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

    # Logging
    log_level: str = "info"

    # Scanner version
    scanner_version: str = "0.1.0"

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
        backfill_enabled=backfill_enabled,
        backfill_data_path=backfill_data_path,
        backfill_gateway_db_path=os.environ.get("BACKFILL_GATEWAY_DB_PATH", ""),
        backfill_rate=backfill_rate,
        backfill_interval_hours=int(
            os.environ.get("BACKFILL_INTERVAL_HOURS", "24")
        ),
    )
