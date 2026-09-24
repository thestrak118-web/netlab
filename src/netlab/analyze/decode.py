"""Link-layer through transport-layer decoding.

Every accessor is bounds-checked.  A truncated or malformed frame yields a
`PacketInfo` with `error` set and whatever fields were actually readable --
fields that were not observed stay `None` and are rendered as a dash in the
GUI.  Nothing is ever guessed.
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field

# Link types we can decode (DLT_/LINKTYPE_ values).
DLT_NULL = 0
DLT_EN10MB = 1
DLT_RAW = 101
DLT_LINUX_SLL = 113
DLT_LINUX_SLL2 = 276
DLT_IPV4 = 228
DLT_IPV6 = 229
DLT_LOOP = 108

SUPPORTED_LINKTYPES = {
    DLT_NULL, DLT_EN10MB, DLT_RAW, DLT_LINUX_SLL,
    DLT_LINUX_SLL2, DLT_IPV4, DLT_IPV6, DLT_LOOP,
}

LINKTYPE_NAMES = {
    DLT_NULL: "BSD loopback",
    DLT_EN10MB: "Ethernet",
    DLT_RAW: "Raw IP",
    DLT_LINUX_SLL: "Linux cooked v1",
    DLT_LINUX_SLL2: "Linux cooked v2",
    DLT_IPV4: "Raw IPv4",
    DLT_IPV6: "Raw IPv6",
    DLT_LOOP: "OpenBSD loopback",
}

ETH_IPV4 = 0x0800
ETH_ARP = 0x0806
ETH_IPV6 = 0x86DD
ETH_VLAN = 0x8100
ETH_QINQ = 0x88A8
ETH_QINQ2 = 0x9100

IPPROTO_NAMES = {
    1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 41: "IPv6",
    47: "GRE", 50: "ESP", 51: "AH", 58: "ICMPv6", 89: "OSPF",
    103: "PIM", 112: "VRRP", 132: "SCTP",
}

_IPV6_EXT_HEADERS = {0, 43, 60, 135, 139, 140}   # skippable, have (nh, len)
_TCP_FLAG_BITS = (
    (0x01, "FIN"), (0x02, "SYN"), (0x04, "RST"), (0x08, "PSH"),
    (0x10, "ACK"), (0x20, "URG"), (0x40, "ECE"), (0x80, "CWR"),
)


@dataclass(slots=True)
class PacketInfo:
    """Decoded metadata for one frame. `None` means "not observed"."""

    index: int = 0
    ts: float = 0.0
    wirelen: int = 0
    caplen: int = 0
    linktype: int = DLT_EN10MB

    src_mac: str | None = None
    dst_mac: str | None = None
    arp_sender_mac: str | None = None
    arp_target_mac: str | None = None
    ethertype: int | None = None
    vlan: int | None = None

    ip_version: int | None = None
    src: str | None = None
    dst: str | None = None
    ip_proto: int | None = None
    ttl: int | None = None
    fragmented: bool = False

    proto: str = "?"
    sport: int | None = None
    dport: int | None = None
    tcp_flags: str | None = None
    seq: int | None = None
    ack: int | None = None

    payload: bytes = b""
    info: str = ""
    error: str | None = None
    tags: list[str] = field(default_factory=list)

    @property
    def endpoints(self) -> tuple[str, str] | None:
        if self.src is None or self.dst is None:
            return None
        return (self.src, self.dst)


def _mac(b: bytes) -> str:
    return ":".join("%02x" % x for x in b)


def _ip4(b: bytes) -> str:
    return socket.inet_ntop(socket.AF_INET, b)


def _ip6(b: bytes) -> str:
    return socket.inet_ntop(socket.AF_INET6, b)


def _tcp_flag_str(flags: int) -> str:
    return ",".join(name for bit, name in _TCP_FLAG_BITS if flags & bit) or "-"


def decode(raw_data: bytes, linktype: int, ts: float, wirelen: int,
           index: int = 0) -> PacketInfo:
    """Decode one frame. Never raises: errors are reported in `.error`."""
    pkt = PacketInfo(index=index, ts=ts, wirelen=wirelen,
                     caplen=len(raw_data), linktype=linktype)
    try:
        _decode_link(pkt, raw_data, linktype)
    except (struct.error, IndexError, ValueError, OSError) as exc:
        pkt.error = "malformed frame: %s" % (exc.__class__.__name__,)
        if not pkt.info:
            pkt.info = "Malformed / truncated frame"
        if pkt.proto == "?":
            pkt.proto = "MALFORMED"
    return pkt


# ---------------------------------------------------------------- link layer

def _decode_link(pkt: PacketInfo, data: bytes, linktype: int) -> None:
    if linktype == DLT_EN10MB:
        if len(data) < 14:
            raise ValueError("short ethernet header")
        pkt.dst_mac = _mac(data[0:6])
        pkt.src_mac = _mac(data[6:12])
        etype = struct.unpack_from("!H", data, 12)[0]
        off = 14
        # Walk any number of stacked VLAN tags.
        while etype in (ETH_VLAN, ETH_QINQ, ETH_QINQ2):
            if len(data) < off + 4:
                raise ValueError("short VLAN tag")
            tci, etype = struct.unpack_from("!HH", data, off)
            if pkt.vlan is None:
                pkt.vlan = tci & 0x0FFF
            off += 4
        pkt.ethertype = etype
        if etype <= 1500:
            pkt.proto = "802.3/LLC"
            pkt.info = "IEEE 802.3 length %d" % etype
            return
        _decode_ethertype(pkt, data, off, etype)
        return

    if linktype == DLT_LINUX_SLL:
        if len(data) < 16:
            raise ValueError("short SLL header")
        addrlen = struct.unpack_from("!H", data, 4)[0]
        if addrlen == 6:
            pkt.src_mac = _mac(data[6:12])
        etype = struct.unpack_from("!H", data, 14)[0]
        pkt.ethertype = etype
        _decode_ethertype(pkt, data, 16, etype)
        return

    if linktype == DLT_LINUX_SLL2:
        if len(data) < 20:
            raise ValueError("short SLL2 header")
        etype = struct.unpack_from("!H", data, 0)[0]
        addrlen = data[11]
        if addrlen == 6:
            pkt.src_mac = _mac(data[12:18])
        pkt.ethertype = etype
        _decode_ethertype(pkt, data, 20, etype)
        return

    if linktype in (DLT_NULL, DLT_LOOP):
        if len(data) < 4:
            raise ValueError("short loopback header")
        fmt = "<I" if linktype == DLT_NULL else ">I"
        fam = struct.unpack_from(fmt, data, 0)[0]
        if fam == 2:
            _decode_ipv4(pkt, data, 4)
        elif fam in (24, 28, 30, 10):
            _decode_ipv6(pkt, data, 4)
        else:
            pkt.proto = "LOOPBACK"
            pkt.info = "address family %d" % fam
        return

    if linktype in (DLT_RAW, DLT_IPV4, DLT_IPV6):
        if not data:
            raise ValueError("empty raw frame")
        ver = data[0] >> 4
        if linktype == DLT_IPV4 or ver == 4:
            _decode_ipv4(pkt, data, 0)
        elif linktype == DLT_IPV6 or ver == 6:
            _decode_ipv6(pkt, data, 0)
        else:
            pkt.proto = "RAW"
            pkt.info = "unrecognised raw IP version %d" % ver
        return

    pkt.proto = "UNSUPPORTED-LINK"
    pkt.info = "link type %d (%s) is not decoded" % (
        linktype, LINKTYPE_NAMES.get(linktype, "unknown"))


def _decode_ethertype(pkt: PacketInfo, data: bytes, off: int, etype: int) -> None:
    if etype == ETH_IPV4:
        _decode_ipv4(pkt, data, off)
    elif etype == ETH_IPV6:
        _decode_ipv6(pkt, data, off)
    elif etype == ETH_ARP:
        _decode_arp(pkt, data, off)
    else:
        pkt.proto = "0x%04x" % etype
        pkt.info = "unhandled ethertype 0x%04x" % etype


def _decode_arp(pkt: PacketInfo, data: bytes, off: int) -> None:
    pkt.proto = "ARP"
    if len(data) < off + 8:
        raise ValueError("short ARP header")
    hw, proto_t, hlen, plen, op = struct.unpack_from("!HHBBH", data, off)
    need = off + 8 + 2 * hlen + 2 * plen
    if len(data) < need or hlen != 6 or plen != 4 or proto_t != ETH_IPV4:
        pkt.info = "ARP opcode %d" % op
        return
    p = off + 8
    sha, spa = _mac(data[p:p + 6]), _ip4(data[p + 6:p + 10])
    tha, tpa = _mac(data[p + 10:p + 16]), _ip4(data[p + 16:p + 20])
    pkt.src, pkt.dst = spa, tpa
    pkt.arp_sender_mac = sha
    pkt.arp_target_mac = tha if op == 2 else None
    if op == 1:
        pkt.info = "Who has %s? Tell %s" % (tpa, spa)
    elif op == 2:
        pkt.info = "%s is at %s" % (spa, sha)
    else:
        pkt.info = "ARP opcode %d (%s -> %s)" % (op, sha, tha)


# ------------------------------------------------------------------ network

def _decode_ipv4(pkt: PacketInfo, data: bytes, off: int) -> None:
    if len(data) < off + 20:
        raise ValueError("short IPv4 header")
    vihl = data[off]
    ihl = (vihl & 0x0F) * 4
    if ihl < 20:
        raise ValueError("bad IPv4 IHL")
    total_len, ident, frag = struct.unpack_from("!HHH", data, off + 2)
    pkt.ip_version = 4
    pkt.ttl = data[off + 8]
    proto = data[off + 9]
    pkt.ip_proto = proto
    pkt.src = _ip4(data[off + 12:off + 16])
    pkt.dst = _ip4(data[off + 16:off + 20])
    frag_off = frag & 0x1FFF
    more_frags = bool(frag & 0x2000)
    pkt.fragmented = bool(frag_off or more_frags)

    l4 = off + ihl
    # Trim to the IP total length so trailing ethernet padding is excluded.
    end = off + total_len if total_len >= ihl else len(data)
    end = min(end, len(data))
    if frag_off:
        # Non-first fragment: no transport header present. We do not
        # reassemble in Phase 1, so we report it honestly as a fragment.
        pkt.proto = IPPROTO_NAMES.get(proto, "IPv4/%d" % proto)
        pkt.info = "IPv4 fragment (offset %d) - not reassembled" % (frag_off * 8)
        pkt.tags.append("fragment")
        return
    _decode_transport(pkt, data, l4, end, proto)


def _decode_ipv6(pkt: PacketInfo, data: bytes, off: int) -> None:
    if len(data) < off + 40:
        raise ValueError("short IPv6 header")
    payload_len = struct.unpack_from("!H", data, off + 4)[0]
    nh = data[off + 6]
    pkt.ip_version = 6
    pkt.ttl = data[off + 7]
    pkt.src = _ip6(data[off + 8:off + 24])
    pkt.dst = _ip6(data[off + 24:off + 40])

    cur = off + 40
    end = min(cur + payload_len, len(data)) if payload_len else len(data)
    hops = 0
    while nh in _IPV6_EXT_HEADERS and hops < 8:
        if len(data) < cur + 2:
            raise ValueError("short IPv6 extension header")
        nxt, hdr_len = data[cur], data[cur + 1]
        cur += (hdr_len + 1) * 8
        nh = nxt
        hops += 1
    if nh == 44:                                   # fragment header
        if len(data) < cur + 8:
            raise ValueError("short IPv6 fragment header")
        frag_off = struct.unpack_from("!H", data, cur + 2)[0] >> 3
        nxt = data[cur]
        pkt.fragmented = True
        pkt.tags.append("fragment")
        if frag_off:
            pkt.ip_proto = nxt
            pkt.proto = IPPROTO_NAMES.get(nxt, "IPv6/%d" % nxt)
            pkt.info = "IPv6 fragment (offset %d) - not reassembled" % (frag_off * 8)
            return
        cur += 8
        nh = nxt
    if nh == 51:                                   # AH
        if len(data) < cur + 2:
            raise ValueError("short AH header")
        nxt, ahlen = data[cur], data[cur + 1]
        cur += (ahlen + 2) * 4
        nh = nxt
    pkt.ip_proto = nh
    _decode_transport(pkt, data, cur, end, nh)


# ---------------------------------------------------------------- transport

def _decode_transport(pkt: PacketInfo, data: bytes, off: int, end: int,
                      proto: int) -> None:
    end = min(end, len(data))
    if proto == 6:
        _decode_tcp(pkt, data, off, end)
    elif proto == 17:
        _decode_udp(pkt, data, off, end)
    elif proto == 1:
        _decode_icmp(pkt, data, off, end)
    elif proto == 58:
        _decode_icmpv6(pkt, data, off, end)
    elif proto == 132:
        _decode_sctp(pkt, data, off, end)
    else:
        pkt.proto = IPPROTO_NAMES.get(proto, "IP/%d" % proto)
        pkt.info = "%s payload %d bytes" % (pkt.proto, max(0, end - off))
        if proto == 50:
            pkt.tags.append("encrypted")
            pkt.info = "ESP (encrypted payload, not inspectable)"


def _decode_tcp(pkt: PacketInfo, data: bytes, off: int, end: int) -> None:
    pkt.proto = "TCP"
    if len(data) < off + 20:
        raise ValueError("short TCP header")
    sport, dport, seq, _ack = struct.unpack_from("!HHII", data, off)
    doff = (data[off + 12] >> 4) * 4
    flags = data[off + 13]
    if doff < 20:
        raise ValueError("bad TCP data offset")
    pkt.sport, pkt.dport, pkt.seq = sport, dport, seq
    pkt.ack = _ack
    pkt.tcp_flags = _tcp_flag_str(flags)
    body = off + doff
    if body < end:
        pkt.payload = data[body:end]
    plen = len(pkt.payload)
    pkt.info = "%d -> %d [%s] Seq=%d Len=%d" % (sport, dport, pkt.tcp_flags, seq, plen)


def _decode_udp(pkt: PacketInfo, data: bytes, off: int, end: int) -> None:
    pkt.proto = "UDP"
    if len(data) < off + 8:
        raise ValueError("short UDP header")
    sport, dport, ulen = struct.unpack_from("!HHH", data, off)
    pkt.sport, pkt.dport = sport, dport
    body_end = min(off + max(ulen, 8), end) if ulen >= 8 else end
    if off + 8 < body_end:
        pkt.payload = data[off + 8:body_end]
    pkt.info = "%d -> %d Len=%d" % (sport, dport, len(pkt.payload))


def _decode_icmp(pkt: PacketInfo, data: bytes, off: int, end: int) -> None:
    pkt.proto = "ICMP"
    if len(data) < off + 4:
        raise ValueError("short ICMP header")
    itype, code = data[off], data[off + 1]
    names = {0: "Echo reply", 3: "Destination unreachable", 5: "Redirect",
             8: "Echo request", 11: "Time exceeded", 13: "Timestamp request"}
    pkt.info = "%s (type %d, code %d)" % (names.get(itype, "ICMP"), itype, code)
    if off + 4 < end:
        pkt.payload = data[off + 4:end]


def _decode_icmpv6(pkt: PacketInfo, data: bytes, off: int, end: int) -> None:
    pkt.proto = "ICMPv6"
    if len(data) < off + 4:
        raise ValueError("short ICMPv6 header")
    itype, code = data[off], data[off + 1]
    names = {1: "Destination unreachable", 3: "Time exceeded", 128: "Echo request",
             129: "Echo reply", 133: "Router solicitation", 134: "Router advertisement",
             135: "Neighbor solicitation", 136: "Neighbor advertisement"}
    pkt.info = "%s (type %d, code %d)" % (names.get(itype, "ICMPv6"), itype, code)
    if off + 4 < end:
        pkt.payload = data[off + 4:end]


def _decode_sctp(pkt: PacketInfo, data: bytes, off: int, end: int) -> None:
    pkt.proto = "SCTP"
    if len(data) < off + 12:
        raise ValueError("short SCTP header")
    sport, dport = struct.unpack_from("!HH", data, off)
    pkt.sport, pkt.dport = sport, dport
    pkt.info = "%d -> %d" % (sport, dport)
    if off + 12 < end:
        pkt.payload = data[off + 12:end]
