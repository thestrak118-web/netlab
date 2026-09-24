"""Writing out the files that passed through -- Intercepter-NG's Resurrection.

A body that was readable on the path is written to the engagement directory
under a name derived from its URL, with the extension the server said it was
and a numeric suffix rather than an overwrite when the same name comes round
twice.  Nothing is executed and nothing is opened: the bytes are stored and
their type is reported as the *server* described it, which is not necessarily
what they are.
"""

from __future__ import annotations

import hashlib
import os
import re
import time
from pathlib import Path
from urllib.parse import unquote, urlsplit

MAX_FILE = 64 * 1024 * 1024
UNSAFE = re.compile(r"[^A-Za-z0-9._-]+")

EXTENSIONS = {
    "image/jpeg": ".jpg", "image/png": ".png", "image/gif": ".gif",
    "image/webp": ".webp", "image/svg+xml": ".svg", "image/bmp": ".bmp",
    "application/pdf": ".pdf", "application/zip": ".zip",
    "application/gzip": ".gz", "application/json": ".json",
    "application/msword": ".doc", "text/csv": ".csv", "text/plain": ".txt",
    "audio/mpeg": ".mp3", "video/mp4": ".mp4",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ".docx",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": ".xlsx",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": ".pptx",
}


def safe_name(url: str, content_type: str) -> str:
    path = unquote(urlsplit(url).path or "")
    base = os.path.basename(path.rstrip("/")) or "index"
    base = UNSAFE.sub("_", base)[:96].lstrip(".") or "file"
    ctype = (content_type or "").split(";")[0].strip().lower()
    if "." not in base:
        base += EXTENSIONS.get(ctype, ".bin")
    return base


def save_carved(directory, info: dict) -> dict | None:
    """Write one carved body; return its record, or None if it was skipped."""
    data = info.get("data") or b""
    if not data or len(data) > MAX_FILE:
        return None
    directory = Path(directory)
    name = safe_name(info.get("url", ""), info.get("content_type", ""))
    target = directory / name
    stem, dot, ext = name.rpartition(".")
    counter = 1
    while target.exists():
        target = directory / ("%s-%d%s%s" % (stem or name, counter, dot, ext))
        counter += 1
        if counter > 9999:
            return None
    try:
        target.write_bytes(data)
    except OSError:
        return None
    return {
        "path": str(target),
        "name": target.name,
        "url": info.get("url", ""),
        "host": info.get("host", ""),
        "client": info.get("client", ""),
        "content_type": info.get("content_type", ""),
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "source": info.get("source", ""),
        "ts": time.time(),
    }
