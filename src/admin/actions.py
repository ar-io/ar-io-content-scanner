from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass

from src.db import ScannerDB
from src.gateway_client import GatewayClient
from src.models import Verdict

logger = logging.getLogger("scanner.admin.actions")


@dataclass
class ActionResult:
    success: bool
    message: str
    blocked: bool = False
    unblocked: bool = False


async def confirm_block(
    content_hash: str,
    db: ScannerDB,
    gateway: GatewayClient,
    scanner_mode: str,
    notes: str = "",
    training_data_dir: str = "/app/data/training",
) -> ActionResult:
    """Confirm content as malicious and block it.

    Shared logic used by both the admin API and Slack action handler.
    Also exports content to the phishing training data directory for
    future ML model retraining.
    """
    verdict = db.get_verdict(content_hash)
    if verdict is None:
        return ActionResult(success=False, message="Not found")

    db.save_override(
        content_hash=content_hash,
        tx_id=verdict.tx_id,
        admin_verdict="confirmed_malicious",
        original_verdict=verdict.verdict.value,
        original_rules=verdict.matched_rules or "[]",
        original_ml_score=verdict.ml_score,
        notes=notes,
    )

    if verdict.verdict != Verdict.MALICIOUS:
        db.update_verdict(content_hash, Verdict.MALICIOUS)

    # An explicit admin confirmation (Slack button or dashboard) always blocks,
    # regardless of SCANNER_MODE. dry-run only suppresses AUTOMATIC blocks from
    # the scan pipeline; a human decision is authoritative and mirrors
    # POST /api/admin/block, which blocks unconditionally. `scanner_mode` is
    # retained for the audit log only.
    rules = json.loads(verdict.matched_rules or "[]")
    # Propagate a meaningful block reason to the gateway. Slack/dashboard
    # confirmations pass `notes` (e.g. "Confirmed via Slack"); enrich it
    # with the triggering rules (or the verdict when no rules matched) so
    # the gateway's audit trail distinguishes a human confirm from an
    # automatic block. Empty notes -> None so block_data keeps its own
    # "Auto-blocked: <rules>" default.
    detail = ", ".join(rules) if rules else verdict.verdict.value
    gw_notes = f"{notes} ({detail})" if notes else None
    blocked = await gateway.block_data(
        verdict.tx_id, content_hash, rules, notes=gw_notes
    )
    if blocked:
        db.mark_blocked(content_hash)

    # Export to phishing training data for ML retraining
    try:
        phishing_dir = os.path.join(training_data_dir, "phishing")
        os.makedirs(phishing_dir, exist_ok=True)
        content = await gateway.fetch_content(verdict.tx_id)
        if content:
            export_path = os.path.join(phishing_dir, f"{content_hash}.html")
            with open(export_path, "wb") as f:
                f.write(content)
            logger.info(
                "training_data_exported",
                extra={
                    "content_hash": content_hash,
                    "label": "phishing",
                    "path": export_path,
                },
            )
    except Exception:
        logger.warning(
            "training_data_export_failed",
            extra={"content_hash": content_hash, "label": "phishing"},
            exc_info=True,
        )

    logger.info(
        "action_confirm",
        extra={
            "content_hash": content_hash,
            "tx_id": verdict.tx_id,
            "blocked": blocked,
            "scanner_mode": scanner_mode,
        },
    )

    return ActionResult(
        success=True,
        message="Confirmed as malicious" + (" and blocked" if blocked else ""),
        blocked=blocked,
    )


async def dismiss_false_positive(
    content_hash: str,
    db: ScannerDB,
    gateway: GatewayClient,
    scanner_mode: str,
    notes: str = "",
) -> ActionResult:
    """Dismiss content as a false positive.

    Shared logic used by both the admin API and Slack action handler.
    """
    verdict = db.get_verdict(content_hash)
    if verdict is None:
        return ActionResult(success=False, message="Not found")

    db.save_override(
        content_hash=content_hash,
        tx_id=verdict.tx_id,
        admin_verdict="confirmed_clean",
        original_verdict=verdict.verdict.value,
        original_rules=verdict.matched_rules or "[]",
        original_ml_score=verdict.ml_score,
        notes=notes,
    )

    db.update_verdict(content_hash, Verdict.CLEAN)
    db.mark_unblocked(content_hash)

    # An explicit admin dismissal always lifts the gateway block, regardless of
    # SCANNER_MODE — content can be blocked in dry-run via the admin API, so a
    # dry-run node must be able to unblock it. Mirrors confirm_block. The
    # gateway unblock is idempotent (no-op if not currently blocked).
    unblocked = await gateway.unblock_data(verdict.tx_id, content_hash)

    logger.info(
        "action_dismiss",
        extra={
            "content_hash": content_hash,
            "tx_id": verdict.tx_id,
            "unblocked": unblocked,
            "scanner_mode": scanner_mode,
        },
    )

    return ActionResult(
        success=True,
        message="Dismissed as false positive" + (" and unblocked" if unblocked else ""),
        unblocked=unblocked,
    )


async def classify_neutral(
    content_hash: str,
    db: ScannerDB,
    gateway: GatewayClient,
    scanner_mode: str,
    training_data_dir: str = "/app/data/training",
    notes: str = "",
) -> ActionResult:
    """Dismiss as false positive and export HTML for ML training data.

    Used by the Slack action handler for the "Classify Neutral" button.
    """
    # First dismiss like a false positive
    result = await dismiss_false_positive(
        content_hash=content_hash,
        db=db,
        gateway=gateway,
        scanner_mode=scanner_mode,
        notes=notes or "Classified as neutral (training data)",
    )
    if not result.success:
        return result

    # Export to neutral training data directory for ML retraining
    try:
        verdict = db.get_verdict(content_hash)
        if verdict and verdict.tx_id:
            neutral_dir = os.path.join(training_data_dir, "neutral")
            os.makedirs(neutral_dir, exist_ok=True)
            content = await gateway.fetch_content(verdict.tx_id)
            if content:
                export_path = os.path.join(neutral_dir, f"{content_hash}.html")
                with open(export_path, "wb") as f:
                    f.write(content)
                logger.info(
                    "training_data_exported",
                    extra={
                        "content_hash": content_hash,
                        "label": "neutral",
                        "path": export_path,
                    },
                )
    except Exception:
        logger.warning(
            "training_data_export_failed",
            extra={"content_hash": content_hash},
            exc_info=True,
        )
        # Fail-open: the dismiss succeeded even if export fails

    return ActionResult(
        success=True,
        message="Classified as neutral and exported for training",
        unblocked=result.unblocked,
    )
