"""SingleFile / SingleFileZ web-archive decoding.

SingleFileZ saves a whole web page as a single HTML+ZIP *polyglot*: a normal
HTML shell that self-extracts (in a browser with the SingleFileZ extension) the
real page, whose resources are stored in a ZIP appended to the file. Fetched
over plain HTTP the shell renders blank ("Please wait…") and the real content
stays compressed — so the rule engine + ML scan the wrapper, not the page. That
produces ML false positives on benign archives AND lets a *malicious* archived
page hide from detection.

This module detects such archives and extracts the real ``index.html`` so the
scanner can evaluate the actual content. It is defensive: a zip bomb, a corrupt
archive, or anything unexpected returns ``None`` and the caller falls back to
scanning the wrapper (fail-open, i.e. current behaviour).
"""
from __future__ import annotations

import io
import logging
import zipfile

logger = logging.getLogger("scanner.archive")

# ZIP end-of-central-directory signature — appears near the end of any ZIP.
_ZIP_EOCD = b"PK\x05\x06"
# SingleFileZ tags its shell with a data-sfz attribute on <html>.
_SFZ_MARKER = b"data-sfz"

_HTML_STARTS = (b"<!doctype html", b"<html")

# Zip-bomb / resource guards.
ARCHIVE_MAX_ENTRIES = 2000
ARCHIVE_MAX_TOTAL_UNCOMPRESSED = 8 * 1024 * 1024  # 8 MB across all entries
ARCHIVE_MAX_COMPRESSION_RATIO = 200  # per-entry uncompressed/compressed cap


def is_singlefile_archive(content: bytes) -> bool:
    """Cheap structural check: does this look like a SingleFileZ polyglot?

    Requires an HTML start, the SingleFileZ marker in the head, and a ZIP EOCD
    near the tail. All three keep false positives (plain HTML, plain ZIP) out.
    """
    if not content:
        return False
    head = content[:2048].lstrip().lower()
    if not head.startswith(_HTML_STARTS):
        return False
    if _SFZ_MARKER not in content[:2048]:
        return False
    return _ZIP_EOCD in content[-65536:]


def extract_singlefile_html(content: bytes) -> str | None:
    """Return the archive's index.html as text, or None on any problem.

    Guards against zip bombs (entry count, total uncompressed size, per-entry
    compression ratio). Never raises — returns None so the caller falls back to
    the wrapper.
    """
    try:
        zf = zipfile.ZipFile(io.BytesIO(content))
    except (zipfile.BadZipFile, OSError):
        return None

    try:
        infos = zf.infolist()
        if not infos or len(infos) > ARCHIVE_MAX_ENTRIES:
            logger.debug("archive_rejected", extra={"reason": "entry_count",
                                                    "entries": len(infos)})
            return None

        total = sum(i.file_size for i in infos)
        if total > ARCHIVE_MAX_TOTAL_UNCOMPRESSED:
            logger.debug("archive_rejected", extra={"reason": "total_size",
                                                    "total": total})
            return None

        for i in infos:
            if i.compress_size > 0 and (
                i.file_size / i.compress_size > ARCHIVE_MAX_COMPRESSION_RATIO
            ):
                logger.debug("archive_rejected", extra={"reason": "ratio",
                                                        "name": i.filename})
                return None

        # SingleFileZ names the entry point index.html; fall back to the first
        # .html entry if a variant differs.
        names = zf.namelist()
        target = "index.html" if "index.html" in names else next(
            (n for n in names if n.lower().endswith((".html", ".htm"))), None
        )
        if target is None:
            return None

        raw = zf.read(target)
        if len(raw) > ARCHIVE_MAX_TOTAL_UNCOMPRESSED:
            return None
        return raw.decode("utf-8", errors="replace")
    except (zipfile.BadZipFile, OSError, KeyError):
        return None
    finally:
        zf.close()
