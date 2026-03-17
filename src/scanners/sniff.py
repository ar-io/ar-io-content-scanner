from __future__ import annotations


def sniff_content_type(head: bytes) -> str:
    """Detect MIME type from the first bytes of a file.

    Returns the detected type or 'application/octet-stream' as fallback.
    """
    if len(head) < 4:
        return "application/octet-stream"

    # PNG
    if head[:8] == b"\x89PNG\r\n\x1a\n":
        return "image/png"

    # JPEG
    if head[:3] == b"\xff\xd8\xff":
        return "image/jpeg"

    # GIF
    if head[:6] in (b"GIF87a", b"GIF89a"):
        return "image/gif"

    # WebP: RIFF....WEBP
    if head[:4] == b"RIFF" and len(head) >= 12 and head[8:12] == b"WEBP":
        return "image/webp"

    # PDF
    if head[:4] == b"%PDF":
        return "application/pdf"

    # MP4 / QuickTime: ftyp box
    if len(head) >= 8 and head[4:8] == b"ftyp":
        return "video/mp4"

    # WebM / Matroska
    if head[:4] == b"\x1a\x45\xdf\xa3":
        return "video/webm"

    return "application/octet-stream"
