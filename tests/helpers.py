"""Builders for synthetic capture files and frames.

Tests construct real pcap/pcapng byte streams and real protocol headers so
the parsers are exercised against the actual wire formats rather than
against mocks.
"""

from __future__ import annotations

import struct

ETHERNET = 1


def pcap_file(packets, linktype: int = ETHERNET, endian: str = "<",
              nano: bool = False) -> bytes:
    """Build a classic pcap file. `packets` is [(ts, wirelen, bytes)]."""
    magic = {("<", False): 0xA1B2C3D4, ("<", True): 0xA1B23C4D,
             (">", False): 0xA1B2C3D4, (">", True): 0xA1B23C4D}[(endian, nano)]
    out = bytearray(struct.pack(endian + "IHHiIII", magic, 2, 4, 0, 0,
                                262144, linktype))
    for ts, wirelen, data in packets:
        sec = int(ts)
        frac = int(round((ts - sec) * (1e9 if nano else 1e6)))
        out += struct.pack(endian + "IIII", sec, frac, len(data), wirelen)
        out += data
    return bytes(out)


def _opt(code: int, value: bytes) -> bytes:
    pad = (4 - len(value) % 4) % 4
    return struct.pack("<HH", code, len(value)) + value + b"\x00" * pad


def pcapng_file(packets, linktype: int = ETHERNET, tsresol: int = 6) -> bytes:
    """Build a pcapng file with one interface. `packets` is [(ts, wirelen, bytes)]."""
    shb_body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
    shb = struct.pack("<II", 0x0A0D0D0A, len(shb_body) + 12) + shb_body
    shb += struct.pack("<I", len(shb_body) + 12)

    idb_body = struct.pack("<HHI", linktype, 0, 262144)
    idb_body += _opt(9, bytes([tsresol])) + struct.pack("<HH", 0, 0)
    idb = struct.pack("<II", 1, len(idb_body) + 12) + idb_body
    idb += struct.pack("<I", len(idb_body) + 12)

    out = bytearray(shb + idb)
    divisor = 10 ** tsresol
    for ts, wirelen, data in packets:
        ticks = int(round(ts * divisor))
        pad = (4 - len(data) % 4) % 4
        body = struct.pack("<IIIII", 0, ticks >> 32, ticks & 0xFFFFFFFF,
                           len(data), wirelen) + data + b"\x00" * pad
        total = len(body) + 12
        out += struct.pack("<II", 6, total) + body + struct.pack("<I", total)
    return bytes(out)


# --------------------------------------------------------------- frame parts

def mac(text: str) -> bytes:
    return bytes(int(p, 16) for p in text.split(":"))


def ip4(text: str) -> bytes:
    return bytes(int(p) for p in text.split("."))


def ethernet(src: str, dst: str, ethertype: int, payload: bytes) -> bytes:
    return mac(dst) + mac(src) + struct.pack("!H", ethertype) + payload


def ipv4(src: str, dst: str, proto: int, payload: bytes, ttl: int = 64,
         frag_off: int = 0, more_frags: bool = False) -> bytes:
    total = 20 + len(payload)
    flags = (frag_off & 0x1FFF) | (0x2000 if more_frags else 0)
    header = struct.pack("!BBHHHBBH", 0x45, 0, total, 0x1234, flags, ttl,
                         proto, 0) + ip4(src) + ip4(dst)
    return header + payload


def ipv6(src: bytes, dst: bytes, nh: int, payload: bytes) -> bytes:
    return struct.pack("!IHBB", 0x60000000, len(payload), nh, 64) + src + dst \
        + payload


def tcp(sport: int, dport: int, payload: bytes = b"", flags: int = 0x18,
        seq: int = 1, ack: int = 0) -> bytes:
    return struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 0x50, flags,
                       65535, 0, 0) + payload


def udp(sport: int, dport: int, payload: bytes = b"") -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def eth_ip_tcp(src="10.0.0.1", dst="10.0.0.2", sport=1234, dport=80,
               payload=b"", flags=0x18, smac="aa:bb:cc:dd:ee:01",
               dmac="aa:bb:cc:dd:ee:02", seq=1, ack=0) -> bytes:
    return ethernet(smac, dmac, 0x0800,
                    ipv4(src, dst, 6, tcp(sport, dport, payload, flags, seq, ack)))


def eth_ip_udp(src="10.0.0.1", dst="10.0.0.2", sport=1234, dport=53,
               payload=b"", smac="aa:bb:cc:dd:ee:01",
               dmac="aa:bb:cc:dd:ee:02") -> bytes:
    return ethernet(smac, dmac, 0x0800,
                    ipv4(src, dst, 17, udp(sport, dport, payload)))


def dns_query(name: str, qtype: int = 1, txid: int = 0x1234) -> bytes:
    body = bytearray(struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0))
    for label in name.split("."):
        body.append(len(label))
        body += label.encode()
    body.append(0)
    body += struct.pack("!HH", qtype, 1)
    return bytes(body)


def dns_response(name: str, address: str, txid: int = 0x1234,
                 ttl: int = 300) -> bytes:
    body = bytearray(struct.pack("!HHHHHH", txid, 0x8180, 1, 1, 0, 0))
    for label in name.split("."):
        body.append(len(label))
        body += label.encode()
    body.append(0)
    body += struct.pack("!HH", 1, 1)
    body += b"\xc0\x0c"                       # pointer back to the question
    body += struct.pack("!HHIH", 1, 1, ttl, 4)
    body += ip4(address)
    return bytes(body)


def tls_client_hello(sni: str, alpn=("h2", "http/1.1"),
                     version: int = 0x0303) -> bytes:
    """A ClientHello record carrying SNI and ALPN extensions."""
    sni_bytes = sni.encode()
    sni_ext_body = struct.pack("!HBH", len(sni_bytes) + 3, 0, len(sni_bytes)) \
        + sni_bytes
    exts = struct.pack("!HH", 0, len(sni_ext_body)) + sni_ext_body

    alpn_list = b"".join(bytes([len(p)]) + p.encode() for p in alpn)
    alpn_body = struct.pack("!H", len(alpn_list)) + alpn_list
    exts += struct.pack("!HH", 16, len(alpn_body)) + alpn_body

    body = struct.pack("!H", version) + b"\x00" * 32
    body += b"\x00"                                   # session id length
    body += struct.pack("!H", 4) + struct.pack("!HH", 0x1301, 0xC02F)
    body += b"\x01\x00"                               # compression
    body += struct.pack("!H", len(exts)) + exts

    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def tls_server_hello(cipher: int = 0xC030, version: int = 0x0303) -> bytes:
    body = struct.pack("!H", version) + b"\x00" * 32
    body += b"\x00"
    body += struct.pack("!H", cipher)
    body += b"\x00"
    body += struct.pack("!H", 0)
    handshake = b"\x02" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + struct.pack("!H", len(handshake)) + handshake


HTTP_GET = (b"GET /index.html HTTP/1.1\r\n"
            b"Host: example.test\r\n"
            b"User-Agent: netlab-tests/1.0\r\n"
            b"Referer: http://ref.test/a\r\n"
            b"Cookie: secret=should-not-be-stored\r\n"
            b"Authorization: Bearer do-not-store\r\n"
            b"\r\n")

HTTP_200 = (b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/html; charset=utf-8\r\n"
            b"Content-Length: 42\r\n"
            b"Server: netlab-test-server\r\n"
            b"Set-Cookie: session=should-not-be-stored\r\n"
            b"\r\n")
