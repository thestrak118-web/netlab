"""Cleartext HTTP/1.x metadata extraction.

Scope and honesty notes:

  * This reads *cleartext* HTTP only.  HTTPS is not decrypted anywhere in
    NetLab; TLS-wrapped HTTP never reaches this module.
  * Messages are parsed from *reassembled* TCP streams, so a header block or
    body split across any number of segments is handled.  What is still not
    done is guessing: if the stream has a gap, the parser resynchronises and
    says so rather than parsing across the hole.
  * Credential harvesting is out of scope, so the *values* of Authorization,
    Proxy-Authorization, Cookie and Set-Cookie are never stored - only a
    boolean noting that the header was present.
"""

from __future__ import annotations

from dataclasses import dataclass, field

METHODS = (
    b"GET", b"POST", b"HEAD", b"PUT", b"DELETE", b"OPTIONS", b"PATCH",
    b"TRACE", b"CONNECT", b"PROPFIND", b"PROPPATCH", b"MKCOL", b"COPY",
    b"MOVE", b"LOCK", b"UNLOCK", b"REPORT", b"SEARCH",
)
_METHOD_FIRST_BYTES = {m[0] for m in METHODS}

SENSITIVE_HEADERS = {"authorization", "proxy-authorization", "cookie",
                     "set-cookie"}

# NetLab's passive default records that a credential header was *present* and
# throws the value away.  Intercepter mode needs the value, so the redaction
# is a switch rather than a rule -- but it stays a deliberate, explicit one:
# nothing turns it on except the operator enabling credential harvesting.
RETAIN_SENSITIVE = False


def set_retain_sensitive(enabled: bool) -> None:
    global RETAIN_SENSITIVE
    RETAIN_SENSITIVE = bool(enabled)

MAX_HEADER_BYTES = 16384


@dataclass(slots=True)
class HttpMessage:
    """One parsed request or response start-line plus headers."""

    kind: str                       # "request" | "response"
    version: str
    method: str | None = None
    target: str | None = None
    status: int | None = None
    reason: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    headers_truncated: bool = False
    response_to_method: str | None = None
    has_auth_header: bool = False
    has_cookie_header: bool = False


@dataclass(slots=True)
class HttpTransaction:
    """A request, and the response matched to it on the same TCP flow."""

    ts: float
    flow_key: tuple
    client: str | None
    server: str | None
    client_port: int | None
    server_port: int | None
    method: str | None = None
    host: str | None = None
    path: str | None = None
    version: str | None = None
    user_agent: str | None = None
    referer: str | None = None
    req_content_type: str | None = None
    req_content_length: str | None = None
    req_has_auth: bool = False
    req_has_cookie: bool = False

    status: int | None = None
    reason: str | None = None
    content_type: str | None = None
    content_length: str | None = None
    server_header: str | None = None
    location: str | None = None
    resp_has_set_cookie: bool = False
    resp_ts: float | None = None
    notes: list[str] = field(default_factory=list)
    req_packet_index: int = 0
    resp_packet_index: int | None = None

    # Body framing, observed rather than assumed.
    req_body_bytes: int = 0
    resp_body_bytes: int = 0
    req_transfer: str | None = None       # "length", "chunked", "eof", None
    resp_transfer: str | None = None
    req_chunks: int = 0
    resp_chunks: int = 0
    req_body_complete: bool = False
    resp_body_complete: bool = False
    saw_gap: bool = False

    @property
    def url(self) -> str:
        if self.host and self.path:
            if self.path.startswith("http://") or self.path.startswith("https://"):
                return self.path
            return "http://%s%s" % (self.host, self.path)
        return self.path or ""

    @property
    def duration_ms(self) -> float | None:
        if self.resp_ts is None:
            return None
        return max(0.0, (self.resp_ts - self.ts) * 1000.0)

    @property
    def body_summary(self) -> str:
        """What was actually observed of the response body."""
        if self.status is None:
            return ""
        if self.resp_transfer is None:
            return "no body"
        text = "%d bytes" % self.resp_body_bytes
        if self.resp_transfer == "chunked":
            text += " in %d chunks" % self.resp_chunks
        if not self.resp_body_complete:
            text += " (incomplete)"
        return text


def looks_like_http(payload: bytes) -> bool:
    """Cheap pre-filter run on every TCP payload before full parsing."""
    if len(payload) < 16:
        return False
    first = payload[0]
    if first == 0x48 and payload[:5] == b"HTTP/":         # 'H'
        return True
    if first not in _METHOD_FIRST_BYTES:
        return False
    head = payload[:20]
    for m in METHODS:
        if head.startswith(m) and len(head) > len(m) and head[len(m)] == 0x20:
            return True
    return False


def _split_headers(payload: bytes) -> tuple[list[bytes], bool]:
    """Return (lines, truncated). Lines exclude the terminating blank line."""
    blob = payload[:MAX_HEADER_BYTES]
    end = blob.find(b"\r\n\r\n")
    truncated = False
    if end < 0:
        end = blob.find(b"\n\n")
        if end < 0:
            # Header block is not complete in this segment.
            truncated = True
            end = len(blob)
    block = blob[:end]
    lines = block.replace(b"\r\n", b"\n").split(b"\n")
    return lines, truncated


def _parse_headers(lines: list[bytes]) -> tuple[dict[str, str], bool, bool]:
    headers: dict[str, str] = {}
    has_auth = has_cookie = False
    for line in lines:
        if not line:
            continue
        sep = line.find(b":")
        if sep <= 0:
            continue
        name = line[:sep].decode("ascii", "replace").strip().lower()
        if name in SENSITIVE_HEADERS:
            if name in ("authorization", "proxy-authorization"):
                has_auth = True
            else:
                has_cookie = True
            if not RETAIN_SENSITIVE:
                # Presence only: the value is not retained.
                continue
        value = line[sep + 1:].decode("utf-8", "replace").strip()
        if name not in headers:
            limit = 8192 if name in SENSITIVE_HEADERS else 512
            headers[name] = value[:limit]
    return headers, has_auth, has_cookie


def parse_message(payload: bytes) -> HttpMessage | None:
    """Parse a start line + headers out of one TCP payload."""
    if not looks_like_http(payload):
        return None
    lines, truncated = _split_headers(payload)
    if not lines:
        return None
    start = lines[0]
    try:
        text = start.decode("ascii", "replace")
    except Exception:
        return None
    parts = text.split(" ")

    if text.startswith("HTTP/"):
        if len(parts) < 2 or not parts[1].isdigit():
            return None
        msg = HttpMessage(kind="response", version=parts[0],
                          status=int(parts[1]),
                          reason=" ".join(parts[2:]) or None)
    else:
        if len(parts) < 3 or not parts[2].startswith("HTTP/"):
            return None
        msg = HttpMessage(kind="request", version=parts[2],
                          method=parts[0], target=parts[1])

    msg.headers, msg.has_auth_header, msg.has_cookie_header = _parse_headers(lines[1:])
    msg.headers_truncated = truncated
    return msg


def parse_header_block(block: bytes) -> HttpMessage | None:
    """Parse a complete start line + header block (no trailing blank line)."""
    lines = block.replace(b"\r\n", b"\n").split(b"\n")
    if not lines:
        return None
    text = lines[0].decode("ascii", "replace")
    parts = text.split(" ")
    if text.startswith("HTTP/"):
        if len(parts) < 2 or not parts[1].isdigit():
            return None
        msg = HttpMessage(kind="response", version=parts[0],
                          status=int(parts[1]),
                          reason=" ".join(parts[2:]) or None)
    else:
        if len(parts) < 3 or not parts[2].startswith("HTTP/"):
            return None
        if parts[0].encode() not in METHODS:
            return None
        msg = HttpMessage(kind="request", version=parts[2],
                          method=parts[0], target=parts[1])
    msg.headers, msg.has_auth_header, msg.has_cookie_header = \
        _parse_headers(lines[1:])
    return msg


# Parser states.
S_HEADERS = "headers"
S_BODY_LEN = "body-length"
S_CHUNK_SIZE = "chunk-size"
S_CHUNK_DATA = "chunk-data"
S_CHUNK_CRLF = "chunk-crlf"
S_CHUNK_TRAILER = "chunk-trailer"
S_BODY_EOF = "body-eof"
S_RESYNC = "resync"

_MAX_CHUNK_LINE = 256
_MAX_START_LINE = 8192
_RESYNC_MARKERS = (b"HTTP/1.",) + METHODS
_STATUS_WITHOUT_BODY = {204, 304}


class HttpStreamParser:
    """Incremental HTTP/1.x parser for one direction of a reassembled stream.

    It reports what it observed and nothing more: a body is counted, never
    stored; a gap in the stream puts the parser into resynchronisation rather
    than letting it parse across the hole.
    """

    def __init__(self, header_limit: int = MAX_HEADER_BYTES,
                 on_message=None, on_body_end=None, on_body_data=None) -> None:
        self._buf = bytearray()
        self._state = S_HEADERS
        self._header_limit = int(header_limit)
        self.on_message = on_message
        self.on_body_end = on_body_end
        # Bodies are counted, not kept -- unless a caller explicitly asks for
        # the bytes.  Credential extraction and file carving do; nothing else
        # in NetLab does, so this stays None and no body is ever retained.
        self.on_body_data = on_body_data

        self._current: HttpMessage | None = None
        self._body_remaining = 0
        self._body_bytes = 0
        self._chunks = 0
        self._chunk_remaining = 0
        self._transfer: str | None = None

        self.messages = 0
        self.truncated_headers = 0
        self.resyncs = 0
        self.bytes_seen = 0

    # ------------------------------------------------------------------ feed

    def feed(self, data: bytes) -> None:
        if not data:
            return
        self.bytes_seen += len(data)
        self._buf.extend(data)
        self._pump()

    def on_gap(self, nbytes: int) -> None:
        """A hole in the stream: abandon the current message and resync."""
        if self._current is not None:
            self._end_body(complete=False, gap=True)
        self._buf.clear()
        self._state = S_RESYNC
        self.resyncs += 1

    def on_close(self, reason: str) -> None:
        if self._state == S_BODY_EOF:
            self._end_body(complete=reason == "FIN")
        elif self._current is not None:
            self._end_body(complete=False)
        self._buf.clear()
        self._state = S_HEADERS

    # -------------------------------------------------------------- internals

    def _pump(self) -> None:
        while True:
            if self._state == S_HEADERS:
                if not self._do_headers():
                    return
            elif self._state == S_BODY_LEN:
                if not self._do_body_length():
                    return
            elif self._state == S_BODY_EOF:
                if self.on_body_data and self._buf:
                    self.on_body_data(self._current, bytes(self._buf))
                self._body_bytes += len(self._buf)
                self._buf.clear()
                return
            elif self._state == S_CHUNK_SIZE:
                if not self._do_chunk_size():
                    return
            elif self._state == S_CHUNK_DATA:
                if not self._do_chunk_data():
                    return
            elif self._state == S_CHUNK_CRLF:
                if not self._do_chunk_crlf():
                    return
            elif self._state == S_CHUNK_TRAILER:
                if not self._do_chunk_trailer():
                    return
            elif self._state == S_RESYNC:
                if not self._do_resync():
                    return

    def _do_headers(self) -> bool:
        end = self._buf.find(b"\r\n\r\n")
        skip = 4
        if end < 0:
            end = self._buf.find(b"\n\n")
            skip = 2
        if end < 0:
            if len(self._buf) > self._header_limit:
                # Not a header block we can use; do not guess at it.
                self.truncated_headers += 1
                self._buf.clear()
                self._state = S_RESYNC
                return True
            return False

        block = bytes(self._buf[:end])
        del self._buf[:end + skip]
        msg = parse_header_block(block)
        if msg is None:
            self._state = S_RESYNC
            return True

        self.messages += 1
        self._current = msg
        self._body_bytes = 0
        self._chunks = 0
        if self.on_message:
            self.on_message(msg, self)
        self._start_body(msg)
        return True

    def _start_body(self, msg: HttpMessage) -> None:
        encoding = (msg.headers.get("transfer-encoding") or "").lower()
        length = msg.headers.get("content-length")

        if msg.kind == "response" and (msg.response_to_method == "HEAD"
                or 100 <= (msg.status or 0) < 200
                or msg.status in _STATUS_WITHOUT_BODY):
            self._transfer = None
            self._state = S_HEADERS
            self._end_body(complete=True)
            return
        if "chunked" in encoding:
            self._transfer = "chunked"
            self._state = S_CHUNK_SIZE
            return
        if length is not None:
            try:
                n = int(length.strip())
            except ValueError:
                n = -1
            if n >= 0:
                self._transfer = "length"
                self._body_remaining = n
                self._state = S_BODY_LEN if n else S_HEADERS
                if not n:
                    self._end_body(complete=True)
                return
        if msg.kind == "response":
            status = msg.status or 0
            if 100 <= status < 200 or status in _STATUS_WITHOUT_BODY:
                self._transfer = None
                self._state = S_HEADERS
                self._end_body(complete=True)
                return
            # No framing header: the body runs to end of connection.
            self._transfer = "eof"
            self._state = S_BODY_EOF
            return
        # A request with neither header has no body.
        self._transfer = None
        self._state = S_HEADERS
        self._end_body(complete=True)

    def _do_body_length(self) -> bool:
        if not self._buf:
            return False
        take = min(self._body_remaining, len(self._buf))
        if self.on_body_data and take:
            self.on_body_data(self._current, bytes(self._buf[:take]))
        del self._buf[:take]
        self._body_bytes += take
        self._body_remaining -= take
        if self._body_remaining == 0:
            self._end_body(complete=True)
            self._state = S_HEADERS
            return True
        return False

    def _do_chunk_size(self) -> bool:
        idx = self._buf.find(b"\r\n")
        if idx < 0:
            if len(self._buf) > _MAX_CHUNK_LINE:
                self._state = S_RESYNC
                return True
            return False
        line = bytes(self._buf[:idx]).split(b";")[0].strip()
        del self._buf[:idx + 2]
        try:
            size = int(line, 16)
        except ValueError:
            self._state = S_RESYNC
            return True
        if size == 0:
            self._state = S_CHUNK_TRAILER
            return True
        self._chunks += 1
        self._chunk_remaining = size
        self._state = S_CHUNK_DATA
        return True

    def _do_chunk_data(self) -> bool:
        if not self._buf:
            return False
        take = min(self._chunk_remaining, len(self._buf))
        if self.on_body_data and take:
            self.on_body_data(self._current, bytes(self._buf[:take]))
        del self._buf[:take]
        self._body_bytes += take
        self._chunk_remaining -= take
        if self._chunk_remaining == 0:
            self._state = S_CHUNK_CRLF
            return True
        return False

    def _do_chunk_crlf(self) -> bool:
        if len(self._buf) < 2:
            return False
        del self._buf[:2]
        self._state = S_CHUNK_SIZE
        return True

    def _do_chunk_trailer(self) -> bool:
        end = self._buf.find(b"\r\n")
        if end < 0:
            if len(self._buf) > self._header_limit:
                self._end_body(complete=False)
                self._state = S_RESYNC
                return True
            return False
        if end == 0:
            del self._buf[:2]
            self._end_body(complete=True)
            self._state = S_HEADERS
            return True
        del self._buf[:end + 2]          # a trailer header line
        return True

    def _do_resync(self) -> bool:
        """Find the next plausible start line after a gap or malformed block.

        A marker alone is not enough - "POST" and "HTTP/1." both occur inside
        ordinary payloads - so each candidate is validated as a whole start
        line before the parser commits to it.
        """
        if len(self._buf) < 18:
            return False
        n = len(self._buf)
        start = 0
        while start < n:
            best = -1
            for marker in _RESYNC_MARKERS:
                pos = self._buf.find(marker, start)
                if pos >= 0 and (best < 0 or pos < best):
                    best = pos
            if best < 0:
                break
            verdict = self._plausible_start(best)
            if verdict is None:
                return False           # need more bytes to decide
            if verdict:
                del self._buf[:best]
                self._state = S_HEADERS
                return True
            start = best + 1
        keep = max(0, len(self._buf) - 24)
        del self._buf[:keep]
        return False

    def _plausible_start(self, pos: int) -> bool | None:
        """True/False if decidable, None if more bytes are needed."""
        window = bytes(self._buf[pos:pos + _MAX_START_LINE])
        eol = window.find(b"\r\n")
        if eol < 0:
            eol = window.find(b"\n")
        if eol < 0:
            if len(window) < _MAX_START_LINE:
                return None
            return False
        line = window[:eol]
        if line.startswith(b"HTTP/1."):
            parts = line.split(b" ")
            return len(parts) >= 2 and parts[1].isdigit() and len(parts[1]) == 3
        for method in METHODS:
            if line.startswith(method + b" "):
                return b" HTTP/1." in line
        return False

    def _end_body(self, complete: bool, gap: bool = False) -> None:
        if self._current is not None and self.on_body_end:
            self.on_body_end(self._current, self._body_bytes, self._chunks,
                             self._transfer, complete, gap)
        self._current = None
        self._transfer = None
        self._body_remaining = 0
