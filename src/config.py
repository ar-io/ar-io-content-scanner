from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:
    import tomli as tomllib  # type: ignore[no-redef]

from src.edge_cache import parse_headers, parse_paths


def _read_pyproject_version() -> str:
    """Read version from pyproject.toml."""
    toml_path = Path(__file__).resolve().parent.parent / "pyproject.toml"
    try:
        with open(toml_path, "rb") as f:
            data = tomllib.load(f)
        return data.get("project", {}).get("version", "0.0.0")
    except (FileNotFoundError, Exception):
        return "0.0.0"


PROJECT_VERSION = _read_pyproject_version()


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

    # Webhook events to process
    webhook_events: frozenset[str] = frozenset({
        "data-cached", "tx-indexed", "ans104-data-item-indexed",
    })

    # Delay (seconds) before enqueueing indexed events, giving the gateway
    # time to finish data indexing so /raw/:id resolution works.
    webhook_index_delay: int = 60

    # ML model
    ml_model_enabled: bool = True
    ml_model_path: str = "./xgboost_model.pkl"
    ml_suspicious_threshold: float = 0.95

    # Rule toggles
    rule_seed_phrase: bool = True
    rule_external_credential_form: bool = True
    rule_wallet_impersonation: bool = True
    rule_obfuscated_loader: bool = True
    rule_fake_challenge: bool = True
    rule_credential_kit: bool = True
    rule_external_script_drainer: bool = True
    rule_drainer_loader: bool = True

    # Content scanner toggles
    scanner_example_image: bool = False

    # Rendered DOM scanning
    rendered_dom_scan_enabled: bool = True

    # Decode SingleFile/SingleFileZ web archives and scan the real page inside
    # (instead of the blank self-extraction wrapper).
    archive_decode_enabled: bool = True

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
    log_format: str = "text"  # "text" (human-readable) or "json"

    # Scanner version
    scanner_version: str = "0.1.0"

    # Screenshots
    screenshot_enabled: bool = True
    screenshot_dir: str = "/app/data/screenshots"
    screenshot_timeout_ms: int = 15000
    screenshot_retention_days: int = 30

    # Verdict feed: share verdicts with peers
    verdict_api_key: str = ""
    verdict_feed_urls: tuple[str, ...] = ()
    verdict_feed_poll_interval: int = 300  # seconds between polls
    verdict_feed_trust_mode: str = "malicious_only"  # or "all"
    verdict_feed_on_demand: bool = True
    verdict_feed_request_timeout_ms: int = 5000

    # Google Safe Browsing / Web Risk API
    safe_browsing_api_key: str = ""
    safe_browsing_check_interval: int = 3600  # seconds between periodic checks

    # Backfill: proactive filesystem sweep
    backfill_enabled: bool = False
    backfill_data_path: str = ""  # gateway's contiguous data directory
    backfill_gateway_db_path: str = ""  # gateway's data.db (read-only, for hash→TX ID)
    backfill_rate: int = 5  # max files scanned per second
    backfill_interval_hours: int = 24  # re-sweep interval (0 = one-shot)

    # Edge-cache revalidation: optional best-effort cache busting after a block.
    # Required for operators who run an HTTP cache (nginx, Varnish, Cloudflare,
    # Fastly, ...) in front of the gateway: blocking via the admin API only
    # affects responses served from origin, so the edge can keep serving the
    # pre-block 200 until its TTL expires. When enabled, the scanner fires one
    # GET per configured path template at the public URL with cache-bypass
    # headers, forcing the edge to revalidate against the gateway and pick up
    # the new 451. Disabled by default since not all gateways have an edge cache.
    edge_cache_revalidation_enabled: bool = False
    edge_cache_revalidation_url_base: str = ""  # falls back to gateway_public_url
    edge_cache_revalidation_headers: tuple[tuple[str, str], ...] = (
        ("Cache-Control", "no-cache"),
        ("X-Cache-Bypass", "1"),
    )
    edge_cache_revalidation_arweave_paths: tuple[str, ...] = (
        "/raw/{id}",
        "/{id}",
    )
    edge_cache_revalidation_ipfs_paths: tuple[str, ...] = ("/ipfs/{id}",)
    edge_cache_revalidation_timeout_ms: int = 5000

    # Slack notifications
    slack_enabled: bool = False
    slack_bot_token: str = ""
    slack_channel_id: str = ""
    slack_signing_secret: str = ""
    slack_app_token: str = ""  # xapp- app token for Socket Mode button handling
    slack_notification_threshold: str = "malicious"  # or "suspicious"
    # Burst rollup: during a flood, coalesce auto-blocked (handled) alerts into
    # a periodic summary instead of one message each. Actionable alerts
    # (suspicious / dry-run / failed block) are always sent individually.
    notification_aggregation_enabled: bool = True
    notification_aggregation_burst_threshold: int = 5  # individual until >N/window
    notification_aggregation_window_s: float = 60.0
    notification_aggregation_flush_interval_s: float = 60.0

    # Email intake (M365)
    # ArNS gateway domains — used by email intake to detect ArNS URLs
    # (e.g., angelferno.ar.io) and resolve them to TX IDs for scanning.
    arns_gateway_domains: tuple[str, ...] = (
        "ar.io",
        "turbo-gateway.com",
        "ardrive.net",
        "ar-io.dev",
    )

    email_intake_enabled: bool = False
    email_intake_tenant_id: str = ""
    email_intake_client_id: str = ""
    email_intake_client_secret: str = ""
    email_intake_mailbox: str = ""  # e.g., abuse@ar.io
    email_intake_poll_interval: int = 60  # seconds


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

    webhook_events_raw = os.environ.get(
        "WEBHOOK_EVENTS",
        "data-cached,tx-indexed,ans104-data-item-indexed",
    )
    webhook_events = frozenset(
        e.strip() for e in webhook_events_raw.split(",") if e.strip()
    )
    known_events = {"data-cached", "tx-indexed", "ans104-data-item-indexed"}
    unknown = webhook_events - known_events
    if unknown:
        raise ValueError(
            f"WEBHOOK_EVENTS contains unknown events: {', '.join(sorted(unknown))}. "
            f"Valid events: {', '.join(sorted(known_events))}"
        )
    if not webhook_events:
        raise ValueError("WEBHOOK_EVENTS must contain at least one event")

    webhook_index_delay = int(os.environ.get("WEBHOOK_INDEX_DELAY", "60"))
    if webhook_index_delay < 0:
        raise ValueError("WEBHOOK_INDEX_DELAY must be >= 0")

    log_format = os.environ.get("LOG_FORMAT", "text").lower()
    if log_format not in ("text", "json"):
        raise ValueError(
            f"LOG_FORMAT must be 'text' or 'json', got '{log_format}'"
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
        os.environ.get("SAFE_BROWSING_CHECK_INTERVAL", "3600")
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

    # Edge-cache revalidation
    edge_cache_revalidation_enabled = (
        os.environ.get("EDGE_CACHE_REVALIDATION_ENABLED", "false").lower()
        == "true"
    )
    # `or DEFAULT` (not `os.environ.get(.., DEFAULT)`) so an explicitly-empty
    # env var (common when docker compose forwards an unset host var as "")
    # falls back to the default rather than disabling the feature silently.
    edge_cache_revalidation_url_base = (
        os.environ.get("EDGE_CACHE_REVALIDATION_URL_BASE") or ""
    ).rstrip("/")
    edge_cache_revalidation_headers = parse_headers(
        os.environ.get("EDGE_CACHE_REVALIDATION_HEADERS")
        or "Cache-Control: no-cache, X-Cache-Bypass: 1"
    )
    edge_cache_revalidation_arweave_paths = parse_paths(
        os.environ.get("EDGE_CACHE_REVALIDATION_PATHS_ARWEAVE")
        or "/raw/{id},/{id}"
    )
    edge_cache_revalidation_ipfs_paths = parse_paths(
        os.environ.get("EDGE_CACHE_REVALIDATION_PATHS_IPFS")
        or "/ipfs/{id}"
    )
    edge_cache_revalidation_timeout_ms = int(
        os.environ.get("EDGE_CACHE_REVALIDATION_TIMEOUT_MS", "5000")
    )
    if edge_cache_revalidation_timeout_ms < 100:
        raise ValueError("EDGE_CACHE_REVALIDATION_TIMEOUT_MS must be >= 100")
    if (
        edge_cache_revalidation_enabled
        and not edge_cache_revalidation_url_base
        and not os.environ.get("GATEWAY_PUBLIC_URL")
    ):
        raise ValueError(
            "EDGE_CACHE_REVALIDATION_URL_BASE (or GATEWAY_PUBLIC_URL fallback) "
            "is required when EDGE_CACHE_REVALIDATION_ENABLED=true"
        )

    # Slack notification settings
    slack_enabled = (
        os.environ.get("SLACK_ENABLED", "false").lower() == "true"
    )
    slack_bot_token = os.environ.get("SLACK_BOT_TOKEN", "")
    slack_channel_id = os.environ.get("SLACK_CHANNEL_ID", "")
    slack_signing_secret = os.environ.get("SLACK_SIGNING_SECRET", "")
    slack_app_token = os.environ.get("SLACK_APP_TOKEN", "")
    notification_aggregation_enabled = (
        os.environ.get("NOTIFICATION_AGGREGATION_ENABLED", "true").lower() == "true"
    )
    notification_aggregation_burst_threshold = int(
        os.environ.get("NOTIFICATION_AGGREGATION_BURST_THRESHOLD", "5")
    )
    if notification_aggregation_burst_threshold < 1:
        raise ValueError("NOTIFICATION_AGGREGATION_BURST_THRESHOLD must be >= 1")
    notification_aggregation_window_s = float(
        os.environ.get("NOTIFICATION_AGGREGATION_WINDOW_S", "60")
    )
    notification_aggregation_flush_interval_s = float(
        os.environ.get("NOTIFICATION_AGGREGATION_FLUSH_INTERVAL_S", "60")
    )
    if notification_aggregation_window_s < 1 or notification_aggregation_flush_interval_s < 1:
        raise ValueError(
            "NOTIFICATION_AGGREGATION_WINDOW_S / _FLUSH_INTERVAL_S must be >= 1"
        )

    slack_notification_threshold = os.environ.get(
        "SLACK_NOTIFICATION_THRESHOLD", "malicious"
    )
    if slack_notification_threshold not in ("malicious", "suspicious"):
        raise ValueError(
            "SLACK_NOTIFICATION_THRESHOLD must be 'malicious' or 'suspicious'"
        )
    if slack_enabled and not slack_bot_token:
        raise ValueError(
            "SLACK_BOT_TOKEN is required when SLACK_ENABLED=true"
        )
    if slack_enabled and not slack_channel_id:
        raise ValueError(
            "SLACK_CHANNEL_ID is required when SLACK_ENABLED=true"
        )
    if slack_enabled and not slack_signing_secret:
        raise ValueError(
            "SLACK_SIGNING_SECRET is required when SLACK_ENABLED=true "
            "(needed to verify Slack button callbacks)"
        )

    # Email intake (M365) settings
    # ArNS gateway domains (configurable for operators with custom domains)
    arns_domains_raw = os.environ.get("ARNS_GATEWAY_DOMAINS", "")
    if arns_domains_raw.strip():
        arns_gateway_domains = tuple(
            d.strip() for d in arns_domains_raw.split(",") if d.strip()
        )
    else:
        arns_gateway_domains = (
            "ar.io", "turbo-gateway.com", "ardrive.net", "ar-io.dev",
        )

    email_intake_enabled = (
        os.environ.get("EMAIL_INTAKE_ENABLED", "false").lower() == "true"
    )
    email_intake_tenant_id = os.environ.get("EMAIL_INTAKE_TENANT_ID", "")
    email_intake_client_id = os.environ.get("EMAIL_INTAKE_CLIENT_ID", "")
    email_intake_client_secret = os.environ.get("EMAIL_INTAKE_CLIENT_SECRET", "")
    email_intake_mailbox = os.environ.get("EMAIL_INTAKE_MAILBOX", "")
    email_intake_poll_interval = int(
        os.environ.get("EMAIL_INTAKE_POLL_INTERVAL", "60")
    )

    if email_intake_enabled:
        if not email_intake_tenant_id:
            raise ValueError(
                "EMAIL_INTAKE_TENANT_ID is required when EMAIL_INTAKE_ENABLED=true"
            )
        if not email_intake_client_id:
            raise ValueError(
                "EMAIL_INTAKE_CLIENT_ID is required when EMAIL_INTAKE_ENABLED=true"
            )
        if not email_intake_client_secret:
            raise ValueError(
                "EMAIL_INTAKE_CLIENT_SECRET is required when EMAIL_INTAKE_ENABLED=true"
            )
        if not email_intake_mailbox:
            raise ValueError(
                "EMAIL_INTAKE_MAILBOX is required when EMAIL_INTAKE_ENABLED=true"
            )
    if email_intake_poll_interval < 10:
        raise ValueError("EMAIL_INTAKE_POLL_INTERVAL must be >= 10")

    return Settings(
        gateway_url=gateway_url.rstrip("/"),
        admin_api_key=admin_api_key,
        admin_ui_enabled=admin_ui_enabled,
        scanner_admin_key=scanner_admin_key,
        scanner_port=int(os.environ.get("SCANNER_PORT", "3100")),
        scanner_workers=scanner_workers,
        scanner_mode=mode,
        webhook_events=webhook_events,
        webhook_index_delay=webhook_index_delay,
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
        rule_fake_challenge=os.environ.get("RULE_FAKE_CHALLENGE", "true").lower()
        == "true",
        rule_credential_kit=os.environ.get("RULE_CREDENTIAL_KIT", "true").lower()
        == "true",
        rule_external_script_drainer=os.environ.get(
            "RULE_EXTERNAL_SCRIPT_DRAINER", "true"
        ).lower()
        == "true",
        rule_drainer_loader=os.environ.get("RULE_DRAINER_LOADER", "true").lower()
        == "true",
        scanner_example_image=os.environ.get(
            "SCANNER_EXAMPLE_IMAGE", "false"
        ).lower()
        == "true",
        rendered_dom_scan_enabled=os.environ.get(
            "RENDERED_DOM_SCAN_ENABLED", "true"
        ).lower()
        == "true",
        archive_decode_enabled=os.environ.get(
            "ARCHIVE_DECODE_ENABLED", "true"
        ).lower()
        == "true",
        max_scan_bytes=max_scan_bytes,
        scan_timeout_ms=scan_timeout_ms,
        db_path=os.environ.get("DB_PATH", "/app/data/scanner.db"),
        log_level=os.environ.get("LOG_LEVEL", "info"),
        log_format=log_format,
        scanner_version=os.environ.get("SCANNER_VERSION", "") or PROJECT_VERSION,
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
        screenshot_retention_days=int(
            os.environ.get("SCREENSHOT_RETENTION_DAYS", "30")
        ),
        safe_browsing_api_key=safe_browsing_api_key,
        safe_browsing_check_interval=safe_browsing_check_interval,
        backfill_enabled=backfill_enabled,
        backfill_data_path=backfill_data_path,
        backfill_gateway_db_path=os.environ.get("BACKFILL_GATEWAY_DB_PATH", ""),
        backfill_rate=backfill_rate,
        backfill_interval_hours=int(
            os.environ.get("BACKFILL_INTERVAL_HOURS", "24")
        ),
        edge_cache_revalidation_enabled=edge_cache_revalidation_enabled,
        edge_cache_revalidation_url_base=edge_cache_revalidation_url_base,
        edge_cache_revalidation_headers=edge_cache_revalidation_headers,
        edge_cache_revalidation_arweave_paths=edge_cache_revalidation_arweave_paths,
        edge_cache_revalidation_ipfs_paths=edge_cache_revalidation_ipfs_paths,
        edge_cache_revalidation_timeout_ms=edge_cache_revalidation_timeout_ms,
        slack_enabled=slack_enabled,
        slack_bot_token=slack_bot_token,
        slack_channel_id=slack_channel_id,
        slack_signing_secret=slack_signing_secret,
        slack_app_token=slack_app_token,
        slack_notification_threshold=slack_notification_threshold,
        notification_aggregation_enabled=notification_aggregation_enabled,
        notification_aggregation_burst_threshold=notification_aggregation_burst_threshold,
        notification_aggregation_window_s=notification_aggregation_window_s,
        notification_aggregation_flush_interval_s=notification_aggregation_flush_interval_s,
        arns_gateway_domains=arns_gateway_domains,
        email_intake_enabled=email_intake_enabled,
        email_intake_tenant_id=email_intake_tenant_id,
        email_intake_client_id=email_intake_client_id,
        email_intake_client_secret=email_intake_client_secret,
        email_intake_mailbox=email_intake_mailbox,
        email_intake_poll_interval=email_intake_poll_interval,
    )
