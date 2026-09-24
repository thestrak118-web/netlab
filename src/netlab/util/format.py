"""Display formatting helpers. A dash always means "not observed"."""

from __future__ import annotations

from datetime import datetime

DASH = "—"


def dash(value) -> str:
    if value is None or value == "":
        return DASH
    return str(value)


def human_bytes(n: float | int | None) -> str:
    if n is None:
        return DASH
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024.0 or unit == "TB":
            if unit == "B":
                return "%d B" % int(n)
            return "%.1f %s" % (n, unit)
        n /= 1024.0
    return "%.1f TB" % n


def human_rate(n: float | None) -> str:
    if n is None:
        return DASH
    return human_bytes(n) + "/s"


def human_count(n: int | None) -> str:
    if n is None:
        return DASH
    if n >= 1_000_000:
        return "%.2fM" % (n / 1_000_000)
    if n >= 10_000:
        return "%.1fk" % (n / 1000)
    return "{:,}".format(n)


def ts_time(ts: float | None) -> str:
    if not ts:
        return DASH
    try:
        return datetime.fromtimestamp(ts).strftime("%H:%M:%S.%f")[:-3]
    except (OverflowError, OSError, ValueError):
        return DASH


def ts_full(ts: float | None) -> str:
    if not ts:
        return DASH
    try:
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    except (OverflowError, OSError, ValueError):
        return DASH


def duration(seconds: float | None) -> str:
    if seconds is None:
        return DASH
    if seconds < 1:
        return "%d ms" % int(seconds * 1000)
    if seconds < 60:
        return "%.1f s" % seconds
    m, s = divmod(int(seconds), 60)
    if m < 60:
        return "%dm %02ds" % (m, s)
    h, m = divmod(m, 60)
    return "%dh %02dm" % (h, m)


def hexdump(data: bytes, width: int = 16, limit: int = 8192) -> str:
    """Classic offset / hex / ASCII dump."""
    if not data:
        return "(no bytes captured)"
    blob = data[:limit]
    lines = []
    for off in range(0, len(blob), width):
        chunk = blob[off:off + width]
        hexpart = " ".join("%02x" % b for b in chunk)
        if len(chunk) > 8:
            hexpart = hexpart[:23] + " " + hexpart[23:]
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append("%08x  %-*s  |%s|" % (off, width * 3, hexpart, ascii_part))
    if len(data) > limit:
        lines.append("... %d more bytes not shown" % (len(data) - limit))
    return "\n".join(lines)
