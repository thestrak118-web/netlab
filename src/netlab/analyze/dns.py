"""DNS / mDNS / LLMNR message extraction.

Parses the real wire format from observed UDP and TCP payloads.  Anything
that cannot be parsed is discarded rather than guessed at.
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field

DNS_PORTS = {53, 5353, 5355}

QTYPES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT",
    17: "RP", 24: "SIG", 25: "KEY", 28: "AAAA", 29: "LOC", 33: "SRV",
    35: "NAPTR", 39: "DNAME", 41: "OPT", 43: "DS", 46: "RRSIG", 47: "NSEC",
    48: "DNSKEY", 50: "NSEC3", 51: "NSEC3PARAM", 52: "TLSA", 64: "SVCB",
    65: "HTTPS", 99: "SPF", 251: "IXFR", 252: "AXFR", 255: "ANY", 257: "CAA",
}

RCODES = {
    0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP",
    5: "REFUSED", 6: "YXDOMAIN", 7: "YXRRSET", 8: "NXRRSET", 9: "NOTAUTH",
    10: "NOTZONE",
}

_MAX_JUMPS = 32


class DnsParseError(Exception):
    pass


@dataclass(slots=True)
class DnsAnswer:
    name: str
    rtype: str
    value: str
    ttl: int


@dataclass(slots=True)
class DnsEvent:
    ts: float
    src: str | None
    dst: str | None
    sport: int | None
    dport: int | None
    transport: str
    kind: str                       # "query" or "response"
    txid: int
    qname: str | None = None
    qtype: str | None = None
    rcode: str | None = None        # responses only
    answers: list[DnsAnswer] = field(default_factory=list)
    resolved_ips: list[str] = field(default_factory=list)
    protocol: str = "DNS"           # DNS / mDNS / LLMNR
    packet_index: int = 0

    @property
    def answer_summary(self) -> str:
        if self.kind == "query":
            return ""
        if not self.answers:
            return self.rcode or ""
        return ", ".join("%s=%s" % (a.rtype, a.value) for a in self.answers[:6])


def _read_name(buf: bytes, off: int) -> tuple[str, int]:
    """Decode a (possibly compressed) DNS name. Returns (name, next_offset)."""
    labels: list[str] = []
    jumps = 0
    cursor = off
    next_off = -1
    n = len(buf)
    while True:
        if cursor >= n:
            raise DnsParseError("name runs past end of message")
        length = buf[cursor]
        if length == 0:
            cursor += 1
            break
        if length & 0xC0 == 0xC0:
            if cursor + 1 >= n:
                raise DnsParseError("truncated compression pointer")
            ptr = ((length & 0x3F) << 8) | buf[cursor + 1]
            if next_off < 0:
                next_off = cursor + 2
            jumps += 1
            if jumps > _MAX_JUMPS or ptr >= n:
                raise DnsParseError("compression pointer loop")
            cursor = ptr
            continue
        if length > 63 or cursor + 1 + length > n:
            raise DnsParseError("bad label length")
        labels.append(buf[cursor + 1:cursor + 1 + length]
                      .decode("utf-8", "replace"))
        cursor += 1 + length
    if next_off < 0:
        next_off = cursor
    return (".".join(labels) if labels else "."), next_off


def _rdata_to_text(buf: bytes, rtype: int, rdoff: int, rdlen: int) -> str:
    end = rdoff + rdlen
    if end > len(buf):
        raise DnsParseError("rdata past end")
    blob = buf[rdoff:end]
    if rtype == 1 and rdlen == 4:
        return socket.inet_ntop(socket.AF_INET, blob)
    if rtype == 28 and rdlen == 16:
        return socket.inet_ntop(socket.AF_INET6, blob)
    if rtype in (2, 5, 12, 39):
        return _read_name(buf, rdoff)[0]
    if rtype == 15 and rdlen >= 3:
        pref = struct.unpack_from("!H", buf, rdoff)[0]
        return "%d %s" % (pref, _read_name(buf, rdoff + 2)[0])
    if rtype == 33 and rdlen >= 7:
        prio, weight, port = struct.unpack_from("!HHH", buf, rdoff)
        return "%s:%d (prio %d, weight %d)" % (
            _read_name(buf, rdoff + 6)[0], port, prio, weight)
    if rtype == 16:
        out, i = [], 0
        while i < len(blob):
            ln = blob[i]
            out.append(blob[i + 1:i + 1 + ln].decode("utf-8", "replace"))
            i += 1 + ln
        return " ".join(out)
    if rtype == 6:
        mname, off2 = _read_name(buf, rdoff)
        rname, _ = _read_name(buf, off2)
        return "%s %s" % (mname, rname)
    if rtype == 257 and rdlen >= 2:
        taglen = blob[1]
        return "%s %s" % (blob[2:2 + taglen].decode("ascii", "replace"),
                          blob[2 + taglen:].decode("utf-8", "replace").strip('"'))
    return blob[:48].hex()


def parse_dns_message(buf: bytes, ts: float, src, dst, sport, dport,
                      transport: str, packet_index: int = 0) -> DnsEvent | None:
    """Parse one DNS message. Returns None if it is not parseable DNS."""
    if len(buf) < 12:
        return None
    txid, flags, qd, an, ns, ar = struct.unpack_from("!HHHHHH", buf, 0)
    is_response = bool(flags & 0x8000)
    opcode = (flags >> 11) & 0x0F
    if opcode not in (0, 1, 2, 4, 5):
        return None
    if qd > 64 or an > 512 or ns > 512 or ar > 512:
        return None

    proto = "DNS"
    if 5353 in (sport, dport):
        proto = "mDNS"
    elif 5355 in (sport, dport):
        proto = "LLMNR"

    evt = DnsEvent(
        ts=ts, src=src, dst=dst, sport=sport, dport=dport,
        transport=transport, kind="response" if is_response else "query",
        txid=txid, protocol=proto, packet_index=packet_index,
    )
    if is_response:
        evt.rcode = RCODES.get(flags & 0x0F, "RCODE%d" % (flags & 0x0F))

    off = 12
    try:
        for i in range(qd):
            qname, off = _read_name(buf, off)
            if off + 4 > len(buf):
                raise DnsParseError("truncated question")
            qtype, _qclass = struct.unpack_from("!HH", buf, off)
            off += 4
            if i == 0:
                evt.qname = qname
                evt.qtype = QTYPES.get(qtype, "TYPE%d" % qtype)

        for _ in range(an):
            if off >= len(buf):
                break
            name, off = _read_name(buf, off)
            if off + 10 > len(buf):
                raise DnsParseError("truncated RR header")
            rtype, _rclass, ttl, rdlen = struct.unpack_from("!HHIH", buf, off)
            off += 10
            if off + rdlen > len(buf):
                raise DnsParseError("truncated rdata")
            try:
                value = _rdata_to_text(buf, rtype, off, rdlen)
            except DnsParseError:
                value = buf[off:off + min(rdlen, 32)].hex()
            off += rdlen
            evt.answers.append(
                DnsAnswer(name=name, rtype=QTYPES.get(rtype, "TYPE%d" % rtype),
                          value=value, ttl=ttl))
            if rtype in (1, 28):
                evt.resolved_ips.append(value)
    except (DnsParseError, struct.error):
        # Keep whatever we managed to parse; a truncated snaplen is normal.
        if evt.qname is None and not evt.answers:
            return None
    return evt


def extract_from_udp(payload: bytes, ts, src, dst, sport, dport,
                     packet_index=0) -> DnsEvent | None:
    return parse_dns_message(payload, ts, src, dst, sport, dport, "UDP",
                             packet_index)


def extract_from_tcp(payload: bytes, ts, src, dst, sport, dport,
                     packet_index=0) -> DnsEvent | None:
    # DNS over TCP prefixes each message with a 2-byte length.
    if len(payload) < 2:
        return None
    (mlen,) = struct.unpack_from("!H", payload, 0)
    body = payload[2:2 + mlen]
    if len(body) < 12:
        return None
    return parse_dns_message(body, ts, src, dst, sport, dport, "TCP",
                             packet_index)
