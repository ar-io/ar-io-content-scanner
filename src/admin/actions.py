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
) -> ActionResult:
    """Confirm content as malicious and block it.

    Shared logic used by both the admin API and Slack action handler.
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

    blocked = False
    if scanner_mode == "enforce":
        rules = json.loads(verdict.matched_rules or "[]")
        blocked = await gateway.block_data(
            verdict.tx_id, content_hash, rules
        )
        if blocked:
            db.mark_blocked(content_hash)

    logger.info(
        "action_confirm",
        extra={
            "content_hash": content_hash,
            "tx_id": verdict.tx_id,
            "blocked": blocked,
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

    unblocked = False
    if scanner_mode == "enforce":
        unblocked = await gateway.unblock_data(verdict.tx_id, content_hash)

    logger.info(
        "action_dismiss",
        extra={
            "content_hash": content_hash,
            "tx_id": verdict.tx_id,
            "unblocked": unblocked,
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

    # Export to training data directory
    try:
        verdict = db.get_verdict(content_hash)
        if verdict and verdict.tx_id:
            training_dir = training_data_dir
            os.makedirs(training_dir, exist_ok=True)
            # Fetch content for training export
            content = await gateway.fetch_content(verdict.tx_id)
            if content:
                export_path = os.path.join(training_dir, f"{content_hash}.html")
                with open(export_path, "wb") as f:
                    f.write(content)
                logger.info(
                    "training_data_exported",
                    extra={
                        "content_hash": content_hash,
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
