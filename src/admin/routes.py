from __future__ import annotations

import csv
import io
import json
import logging
import re

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse, StreamingResponse
from fastapi.templating import Jinja2Templates

from src.admin.auth import require_admin_key
from src.ipfs import is_ipfs_cid
from src.models import Verdict

logger = logging.getLogger("scanner.admin")

_BASE64URL_43 = re.compile(r"^[A-Za-z0-9_-]{43}$")
_HASH_PATTERN = re.compile(r"^[A-Za-z0-9_+/=-]{1,64}$")
_MAX_ID_LENGTH = 128
# ArNS names: gateway allows a non-empty string up to 51 chars. Accept base
# names and undernames ([a-z0-9_-]); we normalise to lowercase before sending.
_ARNS_NAME_RE = re.compile(r"^[a-zA-Z0-9_-]{1,51}$")


def _is_valid_content_id(value: object) -> bool:
    """Accept Arweave 43-char base64url or IPFS CID (v0/v1)."""
    if not isinstance(value, str) or len(value) > _MAX_ID_LENGTH:
        return False
    return bool(_BASE64URL_43.match(value)) or is_ipfs_cid(value)


def build_admin_router(app_state) -> APIRouter:
    """Build the admin API router with access to app state.

    Uses accessor functions to read db/metrics/gateway from app_state
    at request time, so tests can replace them after build_app().
    """
    settings = app_state.settings
    _state = app_state  # closure over mutable state object

    router = APIRouter()
    auth = require_admin_key(settings.scanner_admin_key)
    templates = Jinja2Templates(directory="src/templates")

    # --- HTML page (no auth — login is client-side) ---

    @router.get("/admin", response_class=HTMLResponse)
    async def admin_page(request: Request):
        return templates.TemplateResponse(
            request,
            "admin/base.html",
            context={
                "gateway_public_url": settings.gateway_public_url,
            },
        )

    # --- API endpoints (all require auth) ---

    @router.get("/api/admin/stats")
    async def stats(_key: str = Depends(auth)):
        db = _state.db
        data = _state.metrics.to_dict()
        counts = db.get_dashboard_counts()
        data["queue_depth"] = db.queue_depth()
        return {
            "mode": settings.scanner_mode,
            "version": settings.scanner_version,
            "uptime_seconds": data["uptime_seconds"],
            "workers": settings.scanner_workers,
            "counts": counts,
            "metrics": {
                "scans_total": data["scans_total"],
                "scans_by_verdict": data["scans_by_verdict"],
                "scans_skipped_not_html": data["scans_skipped_not_html"],
                "cache_hits": data["cache_hits"],
                "cache_misses": data["cache_misses"],
                "blocks_sent": data["blocks_sent"],
                "blocks_failed": data["blocks_failed"],
                "avg_scan_ms": data["avg_scan_ms"],
                "queue_depth": data["queue_depth"],
            },
            "last_webhook_at": data["last_webhook_at"],
            "backfill": {
                "enabled": settings.backfill_enabled,
                "files_scanned": int(db.get_state("backfill_files_scanned", "0")),
                "malicious_found": int(db.get_state("backfill_malicious_found", "0")),
                "unresolved_found": int(db.get_state("backfill_unresolved_found", "0")),
                "sweeps_completed": int(db.get_state("backfill_sweeps_completed", "0")),
                "last_sweep_at": int(db.get_state("backfill_last_sweep_at", "0")) or None,
                "running": bool(
                    getattr(_state, "backfill", None) is not None
                    and _state.backfill.is_sweeping
                ),
            },
            "verdict_feed": {
                "enabled": bool(settings.verdict_api_key),
                "peers": db.list_feed_sync_states(),
                "import_stats": db.get_feed_import_stats(),
            },
            "safe_browsing": {
                "enabled": True,
                "api_key_set": bool(settings.safe_browsing_api_key),
                "domain_flagged": data.get("safe_browsing_domain_flagged", False),
                "domain_threats": data.get("safe_browsing_domain_threats", []),
                "domain_checks": data.get("safe_browsing_domain_checks", 0),
                "checks": data.get("safe_browsing_checks", 0),
                "flagged": data.get("safe_browsing_flagged", 0),
                "escalations": data.get("safe_browsing_escalations", 0),
                "errors": data.get("safe_browsing_errors", 0),
                "check_interval": settings.safe_browsing_check_interval,
                "stats": db.get_safe_browsing_stats(),
            },
            "recent_detections": db.get_recent_detections(limit=10),
        }

    @router.get("/api/admin/review")
    async def review_list(
        q: str = Query(""),
        verdict: str = Query("all"),
        status: str = Query("pending"),
        sort: str = Query("newest"),
        page: int = Query(1, ge=1),
        per_page: int = Query(25, ge=1, le=100),
        _key: str = Depends(auth),
    ):
        db = _state.db
        items, total = db.list_review_items(
            query=q,
            verdict_filter=verdict,
            status_filter=status,
            sort=sort,
            page=page,
            per_page=per_page,
        )
        pages = max(1, (total + per_page - 1) // per_page)
        return {
            "items": items,
            "total": total,
            "page": page,
            "per_page": per_page,
            "pages": pages,
        }

    @router.get("/api/admin/review/{content_hash}")
    async def review_detail(
        content_hash: str,
        _key: str = Depends(auth),
    ):
        if not _HASH_PATTERN.match(content_hash):
            raise HTTPException(status_code=400, detail="Invalid content hash")

        db = _state.db
        verdict = db.get_verdict(content_hash)
        if verdict is None:
            raise HTTPException(status_code=404, detail="Not found")

        override = db.get_override(content_hash)

        has_screenshot = False
        ss = _state.screenshot
        if ss and ss.get_path(content_hash) is not None:
            has_screenshot = True

        # Look up Safe Browsing and blocked status
        extra_row = db.conn.execute(
            "SELECT safe_browsing_flagged, blocked FROM scan_verdicts WHERE content_hash = ?",
            (content_hash,),
        ).fetchone()
        sb_flagged = extra_row[0] if extra_row and extra_row[0] is not None else None
        blocked = bool(extra_row[1]) if extra_row and extra_row[1] is not None else False

        return {
            "content_hash": verdict.content_hash,
            "tx_id": verdict.tx_id,
            "verdict": verdict.verdict.value,
            "matched_rules": verdict.matched_rules,
            "ml_score": verdict.ml_score,
            "scanned_at": verdict.scanned_at,
            "scanner_version": verdict.scanner_version,
            "admin_override": override.admin_verdict if override else None,
            "admin_notes": override.notes if override else None,
            "content_preview_url": f"/api/admin/preview/{verdict.tx_id}",
            "has_screenshot": has_screenshot,
            "screenshot_url": f"/api/admin/screenshot/{content_hash}" if has_screenshot else None,
            "safe_browsing_flagged": bool(sb_flagged) if sb_flagged is not None else None,
            "blocked": blocked,
        }

    @router.post("/api/admin/review/{content_hash}/confirm")
    async def review_confirm(
        content_hash: str,
        request: Request,
        _key: str = Depends(auth),
    ):
        if not _HASH_PATTERN.match(content_hash):
            raise HTTPException(status_code=400, detail="Invalid content hash")

        body = await request.json() if await request.body() else {}
        notes = str(body.get("notes", ""))[:500]

        from src.admin.actions import confirm_block

        result = await confirm_block(
            content_hash=content_hash,
            db=_state.db,
            gateway=_state.gateway,
            scanner_mode=settings.scanner_mode,
            notes=notes,
        )
        if not result.success:
            raise HTTPException(status_code=404, detail=result.message)

        return {
            "status": "confirmed",
            "blocked": result.blocked,
            "blocked_tx_ids": [_state.db.get_verdict(content_hash).tx_id] if result.blocked else [],
        }

    @router.post("/api/admin/review/{content_hash}/dismiss")
    async def review_dismiss(
        content_hash: str,
        request: Request,
        _key: str = Depends(auth),
    ):
        if not _HASH_PATTERN.match(content_hash):
            raise HTTPException(status_code=400, detail="Invalid content hash")

        body = await request.json() if await request.body() else {}
        notes = str(body.get("notes", ""))[:500]

        from src.admin.actions import dismiss_false_positive

        result = await dismiss_false_positive(
            content_hash=content_hash,
            db=_state.db,
            gateway=_state.gateway,
            scanner_mode=settings.scanner_mode,
            notes=notes,
        )
        if not result.success:
            raise HTTPException(status_code=404, detail=result.message)

        response: dict = {"status": "dismissed"}
        if result.unblocked:
            response["unblocked"] = True
        return response

    @router.post("/api/admin/bulk/confirm")
    async def bulk_confirm(
        request: Request,
        _key: str = Depends(auth),
    ):
        db = _state.db
        body = await request.json()
        hashes = body.get("hashes", [])
        notes = str(body.get("notes", ""))[:500]

        if not isinstance(hashes, list) or len(hashes) == 0:
            raise HTTPException(
                status_code=400, detail="hashes must be a non-empty array"
            )
        if len(hashes) > 100:
            raise HTTPException(
                status_code=400,
                detail="Maximum 100 items per bulk action",
            )

        succeeded = 0
        errors = []
        blocked_tx_ids = []

        for h in hashes:
            if not isinstance(h, str) or not _HASH_PATTERN.match(h):
                errors.append({"hash": str(h)[:64], "error": "Invalid hash"})
                continue

            verdict = db.get_verdict(h)
            if verdict is None:
                errors.append({"hash": h, "error": "Not found"})
                continue

            db.save_override(
                content_hash=h,
                tx_id=verdict.tx_id,
                admin_verdict="confirmed_malicious",
                original_verdict=verdict.verdict.value,
                original_rules=verdict.matched_rules or "[]",
                original_ml_score=verdict.ml_score,
                notes=notes,
            )

            if verdict.verdict != Verdict.MALICIOUS:
                db.update_verdict(h, Verdict.MALICIOUS)

            if settings.scanner_mode == "enforce":
                gateway = _state.gateway
                rules = json.loads(verdict.matched_rules or "[]")
                success = await gateway.block_data(
                    verdict.tx_id, h, rules
                )
                if success:
                    blocked_tx_ids.append(verdict.tx_id)
                    db.mark_blocked(h)

            succeeded += 1

        logger.info(
            "bulk_confirm",
            extra={
                "total": len(hashes),
                "succeeded": succeeded,
                "errors": len(errors),
            },
        )

        return {
            "processed": len(hashes),
            "succeeded": succeeded,
            "failed": len(errors),
            "errors": errors,
            "blocked_tx_ids": blocked_tx_ids,
        }

    @router.post("/api/admin/bulk/dismiss")
    async def bulk_dismiss(
        request: Request,
        _key: str = Depends(auth),
    ):
        db = _state.db
        body = await request.json()
        hashes = body.get("hashes", [])
        notes = str(body.get("notes", ""))[:500]

        if not isinstance(hashes, list) or len(hashes) == 0:
            raise HTTPException(
                status_code=400, detail="hashes must be a non-empty array"
            )
        if len(hashes) > 100:
            raise HTTPException(
                status_code=400,
                detail="Maximum 100 items per bulk action",
            )

        succeeded = 0
        errors = []
        unblocked_tx_ids = []

        for h in hashes:
            if not isinstance(h, str) or not _HASH_PATTERN.match(h):
                errors.append({"hash": str(h)[:64], "error": "Invalid hash"})
                continue

            verdict = db.get_verdict(h)
            if verdict is None:
                errors.append({"hash": h, "error": "Not found"})
                continue

            db.save_override(
                content_hash=h,
                tx_id=verdict.tx_id,
                admin_verdict="confirmed_clean",
                original_verdict=verdict.verdict.value,
                original_rules=verdict.matched_rules or "[]",
                original_ml_score=verdict.ml_score,
                notes=notes,
            )

            db.update_verdict(h, Verdict.CLEAN)
            db.mark_unblocked(h)

            if settings.scanner_mode == "enforce":
                gateway = _state.gateway
                success = await gateway.unblock_data(verdict.tx_id, h)
                if success:
                    unblocked_tx_ids.append(verdict.tx_id)

            succeeded += 1

        logger.info(
            "bulk_dismiss",
            extra={
                "total": len(hashes),
                "succeeded": succeeded,
                "errors": len(errors),
            },
        )

        return {
            "processed": len(hashes),
            "succeeded": succeeded,
            "failed": len(errors),
            "errors": errors,
            "unblocked_tx_ids": unblocked_tx_ids,
        }

    @router.post("/api/admin/review/{content_hash}/revert")
    async def review_revert(
        content_hash: str,
        _key: str = Depends(auth),
    ):
        if not _HASH_PATTERN.match(content_hash):
            raise HTTPException(status_code=400, detail="Invalid content hash")

        db = _state.db
        override = db.get_override(content_hash)
        if override is None:
            raise HTTPException(
                status_code=404, detail="No override found for this content"
            )

        # Restore the original verdict
        original = override.original_verdict
        try:
            original_verdict = Verdict(original)
        except ValueError:
            original_verdict = Verdict.SUSPICIOUS

        db.update_verdict(content_hash, original_verdict)
        db.delete_override(content_hash)

        # In enforce mode, sync gateway block state with the restored verdict
        blocked = None
        unblocked = None
        if settings.scanner_mode == "enforce":
            if (
                override.admin_verdict == "confirmed_clean"
                and original_verdict in (Verdict.MALICIOUS,)
            ):
                # Was blocked originally, then unblocked by dismiss — re-block it
                rules = json.loads(override.original_rules or "[]")
                blocked = await _state.gateway.block_data(
                    override.tx_id, content_hash, rules
                )
                if blocked:
                    db.mark_blocked(content_hash)
            elif (
                override.admin_verdict == "confirmed_malicious"
                and original_verdict not in (Verdict.MALICIOUS,)
            ):
                # Was NOT originally blocked, but was blocked by confirm — unblock it
                unblocked = await _state.gateway.unblock_data(
                    override.tx_id, content_hash
                )
                if unblocked:
                    db.mark_unblocked(content_hash)

        logger.info(
            "admin_revert",
            extra={
                "content_hash": content_hash,
                "tx_id": override.tx_id,
                "reverted_from": override.admin_verdict,
                "restored_verdict": original_verdict.value,
                **({"blocked": blocked} if blocked is not None else {}),
                **({"unblocked": unblocked} if unblocked is not None else {}),
            },
        )

        result: dict = {
            "status": "reverted",
            "restored_verdict": original_verdict.value,
        }
        if blocked is not None:
            result["blocked"] = blocked
        if unblocked is not None:
            result["unblocked"] = unblocked
        return result

    @router.post("/api/admin/block")
    async def manual_block(
        request: Request,
        _key: str = Depends(auth),
    ):
        try:
            body = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid JSON body")
        reason = str(body.get("reason", ""))[:300]

        # Accept either a single tx_id or a list of tx_ids
        tx_ids_raw = body.get("tx_ids", [])
        single_tx_id = body.get("tx_id", "")
        if single_tx_id and not tx_ids_raw:
            tx_ids_raw = [single_tx_id]
        if not isinstance(tx_ids_raw, list) or len(tx_ids_raw) == 0:
            raise HTTPException(status_code=400, detail="tx_id or tx_ids is required")
        if len(tx_ids_raw) > 100:
            raise HTTPException(
                status_code=400, detail="Maximum 100 IDs per request"
            )

        db = _state.db
        gateway = _state.gateway
        notes_text = f"Manual block: {reason}" if reason else "Manual block"

        results = []
        errors = []

        for tx_id in tx_ids_raw:
            if not _is_valid_content_id(tx_id):
                errors.append({
                    "tx_id": str(tx_id)[:64],
                    "error": "Invalid ID (expected Arweave TX ID or IPFS CID)",
                })
                continue

            already_existed = db.has_verdict(tx_id)

            # Store the real original verdict for revert support.
            # If no prior verdict exists, use "skipped" as a sentinel
            # so revert knows to unblock (original was not malicious).
            existing = db.get_verdict(tx_id)
            original_verdict = existing.verdict.value if existing else "skipped"

            db.save_verdict(
                content_hash=tx_id,
                tx_id=tx_id,
                verdict=Verdict.MALICIOUS,
                matched_rules='["manual-block"]',
                ml_score=None,
                scanner_version=settings.scanner_version,
                source="manual",
            )

            db.save_override(
                content_hash=tx_id,
                tx_id=tx_id,
                admin_verdict="confirmed_malicious",
                original_verdict=original_verdict,
                original_rules='["manual-block"]',
                original_ml_score=existing.ml_score if existing else None,
                notes=reason,
            )

            blocked = False
            try:
                blocked = await gateway.block_data(
                    tx_id, tx_id, ["manual-block"], notes=notes_text
                )
            except Exception:
                logger.exception(
                    "manual_block_gateway_error", extra={"tx_id": tx_id}
                )

            if blocked:
                db.mark_blocked(tx_id)

            results.append({
                "tx_id": tx_id,
                "blocked": blocked,
                "already_existed": already_existed,
            })

        logger.info(
            "manual_block",
            extra={
                "count": len(results),
                "reason": reason,
                "blocked": sum(1 for r in results if r["blocked"]),
                "errors": len(errors),
            },
        )

        # Single-TX backward-compatible response
        if single_tx_id and not body.get("tx_ids"):
            if not results:
                raise HTTPException(
                    status_code=400,
                    detail="Invalid ID (expected Arweave TX ID or IPFS CID)",
                )
            r = results[0]
            return {
                "status": "blocked",
                "tx_id": r["tx_id"],
                "blocked": r["blocked"],
                "already_existed": r["already_existed"],
            }

        return {
            "status": "blocked",
            "results": results,
            "succeeded": len(results),
            "failed": len(errors),
            "errors": errors,
        }

    @router.post("/api/admin/backfill/trigger")
    async def backfill_trigger(_key: str = Depends(auth)):
        """Start a backfill sweep on demand, unless one is already running."""
        backfill = getattr(_state, "backfill", None)
        if backfill is None:
            raise HTTPException(
                status_code=400,
                detail="Backfill is not enabled (set BACKFILL_ENABLED=true).",
            )
        status = backfill.trigger()
        if status == "started":
            logger.info("backfill_trigger_manual")
        return {"status": status}
    def _parse_names(body: dict) -> list[str]:
        names_raw = body.get("names", [])
        single = body.get("name", "")
        if single and not names_raw:
            names_raw = [single]
        if not isinstance(names_raw, list) or len(names_raw) == 0:
            raise HTTPException(status_code=400, detail="name or names is required")
        if len(names_raw) > 100:
            raise HTTPException(
                status_code=400, detail="Maximum 100 names per request"
            )
        return names_raw

    @router.post("/api/admin/block-name")
    async def block_name(request: Request, _key: str = Depends(auth)):
        """Block resolution of one or more ArNS names on the gateway."""
        try:
            body = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid JSON body")
        reason = str(body.get("reason", ""))[:300]
        names_raw = _parse_names(body)
        single_name = body.get("name", "")

        gateway = _state.gateway
        notes_text = f"Manual block: {reason}" if reason else "Manual block"
        results, errors = [], []
        for raw in names_raw:
            name = str(raw).strip().lower()
            if not _ARNS_NAME_RE.match(name):
                errors.append({
                    "name": str(raw)[:60],
                    "error": "Invalid ArNS name (1-51 chars, [a-z0-9_-])",
                })
                continue
            blocked = False
            try:
                blocked = await gateway.block_name(name, notes=notes_text)
            except Exception:
                logger.exception("manual_block_name_error", extra={"arns_name": name})
            results.append({"name": name, "blocked": blocked})

        logger.info(
            "manual_block_name",
            extra={
                "count": len(results),
                "reason": reason,
                "blocked": sum(1 for r in results if r["blocked"]),
                "errors": len(errors),
            },
        )

        if single_name and not body.get("names"):
            if not results:
                raise HTTPException(status_code=400, detail="Invalid ArNS name")
            return {
                "status": "blocked",
                "name": results[0]["name"],
                "blocked": results[0]["blocked"],
            }
        return {
            "status": "blocked",
            "results": results,
            "succeeded": len(results),
            "failed": len(errors),
            "errors": errors,
        }

    @router.post("/api/admin/unblock-name")
    async def unblock_name(request: Request, _key: str = Depends(auth)):
        """Unblock resolution of one or more ArNS names on the gateway."""
        try:
            body = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid JSON body")
        names_raw = _parse_names(body)
        single_name = body.get("name", "")

        gateway = _state.gateway
        results, errors = [], []
        for raw in names_raw:
            name = str(raw).strip().lower()
            if not _ARNS_NAME_RE.match(name):
                errors.append({"name": str(raw)[:60], "error": "Invalid ArNS name"})
                continue
            unblocked = False
            try:
                unblocked = await gateway.unblock_name(name)
            except Exception:
                logger.exception("manual_unblock_name_error", extra={"arns_name": name})
            results.append({"name": name, "unblocked": unblocked})

        logger.info(
            "manual_unblock_name",
            extra={
                "count": len(results),
                "unblocked": sum(1 for r in results if r["unblocked"]),
                "errors": len(errors),
            },
        )

        if single_name and not body.get("names"):
            if not results:
                raise HTTPException(status_code=400, detail="Invalid ArNS name")
            return {
                "status": "unblocked",
                "name": results[0]["name"],
                "unblocked": results[0]["unblocked"],
            }
        return {
            "status": "unblocked",
            "results": results,
            "succeeded": len(results),
            "failed": len(errors),
            "errors": errors,
        }

    @router.get("/api/admin/history")
    async def history_list(
        q: str = Query(""),
        verdict: str = Query("all"),
        source: str = Query("all"),
        period: str = Query("all"),
        sort: str = Query("newest"),
        page: int = Query(1, ge=1),
        per_page: int = Query(25, ge=1, le=100),
        _key: str = Depends(auth),
    ):
        db = _state.db
        items, total = db.list_history(
            query=q,
            verdict_filter=verdict,
            source_filter=source,
            period=period,
            sort=sort,
            page=page,
            per_page=per_page,
        )
        pages = max(1, (total + per_page - 1) // per_page)
        return {
            "items": items,
            "total": total,
            "page": page,
            "per_page": per_page,
            "pages": pages,
        }

    @router.get("/api/admin/history/export")
    async def history_export(
        q: str = Query(""),
        verdict: str = Query("all"),
        source: str = Query("all"),
        period: str = Query("all"),
        _key: str = Depends(auth),
    ):
        db = _state.db
        items, _ = db.list_history(
            query=q,
            verdict_filter=verdict,
            source_filter=source,
            period=period,
            page=1,
            per_page=10000,
        )
        output = io.StringIO()
        writer = csv.DictWriter(
            output,
            fieldnames=[
                "content_hash", "tx_id", "verdict", "matched_rules",
                "ml_score", "scanned_at", "scanner_version", "admin_status",
                "source", "admin_notes",
            ],
        )
        writer.writeheader()
        writer.writerows(items)

        return StreamingResponse(
            iter([output.getvalue()]),
            media_type="text/csv",
            headers={
                "Content-Disposition": "attachment; filename=scan_history.csv"
            },
        )

    @router.get("/api/admin/block/export")
    async def block_export(
        source: str = Query("all"),
        _key: str = Depends(auth),
    ):
        """Export blocked TX IDs as plain text (one per line).

        Paste the output directly into the block form on another gateway.
        source=all returns all malicious, source=manual returns only manual blocks.
        """
        db = _state.db
        conditions = ["v.verdict = 'malicious'"]
        if source == "manual":
            conditions.append("v.source = 'manual'")

        where = "WHERE " + " AND ".join(conditions)
        rows = db.conn.execute(
            f"SELECT DISTINCT v.tx_id FROM scan_verdicts v {where} "
            "ORDER BY v.scanned_at DESC",
        ).fetchall()
        tx_ids = [r[0] for r in rows if r[0] != "backfill"]
        text = "\n".join(tx_ids) + "\n" if tx_ids else ""

        return PlainTextResponse(
            content=text,
            headers={
                "Content-Disposition": "attachment; filename=blocked_tx_ids.txt"
            },
        )

    @router.get("/api/admin/preview/{tx_id}")
    async def content_preview(
        tx_id: str,
        _key: str = Depends(auth),
    ):
        if not _BASE64URL_43.match(tx_id):
            raise HTTPException(status_code=400, detail="Invalid TX ID")

        gateway = _state.gateway
        content = await gateway.fetch_content(tx_id)
        if content is None:
            raise HTTPException(status_code=404, detail="Content not found")

        return PlainTextResponse(
            content=content.decode("utf-8", errors="replace"),
            headers={
                "Content-Security-Policy": "sandbox",
                "X-Content-Type-Options": "nosniff",
            },
        )

    @router.get("/api/admin/screenshot/{content_hash}")
    async def screenshot_image(
        content_hash: str,
        _key: str = Depends(auth),
    ):
        if not _HASH_PATTERN.match(content_hash):
            raise HTTPException(status_code=400, detail="Invalid content hash")

        ss = _state.screenshot
        if not ss:
            raise HTTPException(status_code=404, detail="Screenshots not enabled")

        path = ss.get_path(content_hash)
        if path is None:
            raise HTTPException(status_code=404, detail="Screenshot not found")

        return FileResponse(
            path,
            media_type="image/jpeg",
            headers={"Cache-Control": "private, max-age=300"},
        )

    @router.get("/api/admin/settings")
    async def get_settings(_key: str = Depends(auth)):
        db = _state.db
        return {
            "mode": settings.scanner_mode,
            "version": settings.scanner_version,
            "gateway_url": settings.gateway_url,
            "gateway_public_url": settings.gateway_public_url,
            "port": settings.scanner_port,
            "workers": settings.scanner_workers,
            "log_level": settings.log_level,
            "log_format": settings.log_format,
            "db_path": settings.db_path,
            "ml_model_enabled": settings.ml_model_enabled,
            "max_scan_bytes": settings.max_scan_bytes,
            "scan_timeout_ms": settings.scan_timeout_ms,
            "rules": {
                "seed_phrase": settings.rule_seed_phrase,
                "external_credential_form": settings.rule_external_credential_form,
                "wallet_impersonation": settings.rule_wallet_impersonation,
                "obfuscated_loader": settings.rule_obfuscated_loader,
            },
            "backfill": {
                "enabled": settings.backfill_enabled,
                "data_path": settings.backfill_data_path or None,
                "gateway_db_path": settings.backfill_gateway_db_path or None,
                "rate": settings.backfill_rate,
                "interval_hours": settings.backfill_interval_hours,
            },
            "screenshot": {
                "enabled": settings.screenshot_enabled,
                "available": bool(_state.screenshot and _state.screenshot.available),
                "timeout_ms": settings.screenshot_timeout_ms,
            },
            "verdict_feed": {
                "enabled": bool(settings.verdict_api_key),
                "api_key_set": bool(settings.verdict_api_key),
                "peer_urls": list(settings.verdict_feed_urls),
                "poll_interval": settings.verdict_feed_poll_interval,
                "trust_mode": settings.verdict_feed_trust_mode,
                "on_demand": settings.verdict_feed_on_demand,
            },
            "safe_browsing": {
                "enabled": True,
                "api_key_set": bool(settings.safe_browsing_api_key),
                "check_interval": settings.safe_browsing_check_interval,
            },
            "content_scanners": (
                _state.registry.scanner_names
                if hasattr(_state, "registry") and _state.registry
                else []
            ),
            "db_stats": db.get_db_stats(),
        }

    @router.get("/api/admin/training-export")
    async def training_export(_key: str = Depends(auth)):
        db = _state.db
        overrides = db.list_overrides()
        output = io.StringIO()
        writer = csv.DictWriter(
            output,
            fieldnames=[
                "content_hash", "tx_id", "admin_verdict", "original_verdict",
                "original_rules", "original_ml_score", "notes", "created_at",
            ],
        )
        writer.writeheader()
        writer.writerows(overrides)

        return StreamingResponse(
            iter([output.getvalue()]),
            media_type="text/csv",
            headers={
                "Content-Disposition": "attachment; filename=training_data.csv"
            },
        )

    return router
