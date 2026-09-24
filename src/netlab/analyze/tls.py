"""TLS handshake metadata extraction.

NetLab does not decrypt TLS and does not intercept certificates.  What this
module reads is only what a passive observer can legitimately see on the
wire *before* the handshake completes:

  * ClientHello  -> offered version, SNI, offered ALPN, offered ciphers
  * ServerHello  -> negotiated version, selected cipher, selected ALPN
  * Certificate  -> subject/issuer CN and validity, **TLS 1.2 and below only**

In TLS 1.3 the Certificate message is encrypted, so certificate fields stay
`None` and the session is marked accordingly.  Application data is always
reported as encrypted and is never inspected.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

CT_CHANGE_CIPHER_SPEC = 20
CT_ALERT = 21
CT_HANDSHAKE = 22
CT_APPLICATION_DATA = 23

HS_CLIENT_HELLO = 1
HS_SERVER_HELLO = 2
HS_CERTIFICATE = 11

VERSIONS = {
    0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1",
    0x0303: "TLS 1.2", 0x0304: "TLS 1.3",
}

# Common IANA cipher suites; unknown values are rendered as their hex code.
CIPHER_SUITES = {
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0x1304: "TLS_AES_128_CCM_SHA256",
    0x1305: "TLS_AES_128_CCM_8_SHA256",
    0xC02B: "ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02C: "ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xC02F: "ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC030: "ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xCCA8: "ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0xCCA9: "ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    0xC013: "ECDHE_RSA_WITH_AES_128_CBC_SHA",
    0xC014: "ECDHE_RSA_WITH_AES_256_CBC_SHA",
    0xC009: "ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    0xC00A: "ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    0xC027: "ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    0xC028: "ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    0x009C: "RSA_WITH_AES_128_GCM_SHA256",
    0x009D: "RSA_WITH_AES_256_GCM_SHA384",
    0x002F: "RSA_WITH_AES_128_CBC_SHA",
    0x0035: "RSA_WITH_AES_256_CBC_SHA",
    0x003C: "RSA_WITH_AES_128_CBC_SHA256",
    0x000A: "RSA_WITH_3DES_EDE_CBC_SHA",
    0x0005: "RSA_WITH_RC4_128_SHA",
}

EXT_SERVER_NAME = 0
EXT_ALPN = 16
EXT_SUPPORTED_VERSIONS = 43

# Suites considered weak/legacy, surfaced as a note (observation, not advice).
WEAK_SUITES = {0x000A, 0x0005, 0x002F, 0x0035, 0x003C}


@dataclass(slots=True)
class TlsSession:
    ts: float
    flow_key: tuple
    client: str | None
    server: str | None
    client_port: int | None
    server_port: int | None

    sni: str | None = None
    client_version: str | None = None
    server_version: str | None = None
    negotiated_version: str | None = None
    cipher_suite: str | None = None
    alpn_offered: list[str] = field(default_factory=list)
    alpn_selected: str | None = None
    cipher_count_offered: int | None = None

    cert_subject_cn: str | None = None
    cert_issuer_cn: str | None = None
    cert_not_before: str | None = None
    cert_not_after: str | None = None
    cert_chain_len: int | None = None

    saw_client_hello: bool = False
    saw_server_hello: bool = False
    saw_alert: bool = False
    app_data_bytes: int = 0
    app_data_records: int = 0
    notes: list[str] = field(default_factory=list)
    packet_index: int = 0

    @property
    def encrypted(self) -> bool:
        """Always true. TLS payload is never decrypted by NetLab."""
        return True

    @property
    def cert_availability(self) -> str:
        if self.cert_subject_cn:
            return "observed"
        if (self.negotiated_version or self.server_version) == "TLS 1.3":
            return "encrypted (TLS 1.3)"
        if not self.saw_server_hello:
            return "not observed"
        return "not observed"

    def add_note(self, note: str) -> None:
        if note not in self.notes:
            self.notes.append(note)


COMMON_TLS_PORTS = {443, 465, 563, 636, 853, 989, 990, 992, 993, 994, 995,
                    1443, 2376, 4443, 5061, 5986, 6697, 8443, 8843, 9443, 10443}


def is_handshake_start(payload: bytes) -> bool:
    """True only for a record that actually begins a ClientHello/ServerHello.

    `looks_like_tls` is a 5-byte heuristic and will occasionally match
    arbitrary binary traffic, so session creation is gated on this stricter
    test (or on a well-known TLS port) to avoid mislabelling plain TCP.
    """
    if len(payload) < 6 or payload[0] != CT_HANDSHAKE:
        return False
    ver = (payload[1] << 8) | payload[2]
    if not 0x0300 <= ver <= 0x0304:
        return False
    return payload[5] in (HS_CLIENT_HELLO, HS_SERVER_HELLO)


def looks_like_tls(payload: bytes) -> bool:
    """Cheap pre-filter: a TLS record header with a plausible version."""
    if len(payload) < 5:
        return False
    ctype = payload[0]
    if ctype not in (CT_CHANGE_CIPHER_SPEC, CT_ALERT, CT_HANDSHAKE,
                     CT_APPLICATION_DATA):
        return False
    ver = (payload[1] << 8) | payload[2]
    return 0x0300 <= ver <= 0x0304


def _u24(b: bytes, off: int) -> int:
    return (b[off] << 16) | (b[off + 1] << 8) | b[off + 2]


def iter_records(payload: bytes):
    """Yield (content_type, version, body) for each complete TLS record."""
    off = 0
    n = len(payload)
    while off + 5 <= n:
        ctype = payload[off]
        ver = struct.unpack_from("!H", payload, off + 1)[0]
        rlen = struct.unpack_from("!H", payload, off + 3)[0]
        if rlen > 16640 or ctype not in (20, 21, 22, 23):
            return
        body = payload[off + 5: off + 5 + rlen]
        yield ctype, ver, body
        off += 5 + rlen
        if len(body) < rlen:
            return     # record continues in a segment we did not reassemble


def _parse_extensions(blob: bytes) -> dict:
    out: dict = {}
    off, n = 0, len(blob)
    while off + 4 <= n:
        etype, elen = struct.unpack_from("!HH", blob, off)
        off += 4
        val = blob[off:off + elen]
        off += elen
        if len(val) < elen:
            break
        try:
            if etype == EXT_SERVER_NAME and len(val) >= 5:
                # server_name_list: list_len(2) name_type(1) len(2) name.
                # The name is sent as ASCII/punycode, so decode it as UTF-8;
                # the idna codec raises on perfectly ordinary hostnames.
                name_type = val[2]
                nlen = struct.unpack_from("!H", val, 3)[0]
                raw = val[5:5 + nlen]
                if name_type == 0 and raw:
                    out["sni"] = raw.decode("utf-8", "replace")
            elif etype == EXT_ALPN and len(val) >= 2:
                protos, p = [], 2
                while p < len(val):
                    ln = val[p]
                    protos.append(val[p + 1:p + 1 + ln].decode("ascii", "replace"))
                    p += 1 + ln
                out["alpn"] = [x for x in protos if x]
            elif etype == EXT_SUPPORTED_VERSIONS and val:
                if len(val) == 2:                       # ServerHello form
                    v = struct.unpack_from("!H", val, 0)[0]
                    out["supported_versions"] = [v]
                else:                                   # ClientHello form
                    ln = val[0]
                    vers = [struct.unpack_from("!H", val, 1 + i)[0]
                            for i in range(0, ln, 2)]
                    out["supported_versions"] = vers
        except (struct.error, IndexError, UnicodeError):
            continue
    return out


def parse_client_hello(body: bytes, sess: TlsSession) -> None:
    if len(body) < 38:
        return
    ver = struct.unpack_from("!H", body, 0)[0]
    sess.client_version = VERSIONS.get(ver, "0x%04x" % ver)
    off = 2 + 32
    sid_len = body[off]
    off += 1 + sid_len
    if off + 2 > len(body):
        return
    cs_len = struct.unpack_from("!H", body, off)[0]
    off += 2
    suites = []
    for i in range(0, min(cs_len, len(body) - off), 2):
        suites.append(struct.unpack_from("!H", body, off + i)[0])
    sess.cipher_count_offered = len(suites)
    if any(s in WEAK_SUITES for s in suites):
        sess.add_note("client offered legacy cipher suites")
    off += cs_len
    if off >= len(body):
        return
    comp_len = body[off]
    off += 1 + comp_len
    if off + 2 > len(body):
        return
    ext_len = struct.unpack_from("!H", body, off)[0]
    off += 2
    ext = _parse_extensions(body[off:off + ext_len])
    if "sni" in ext:
        sess.sni = ext["sni"]
    if "alpn" in ext:
        sess.alpn_offered = ext["alpn"]
    sv = ext.get("supported_versions")
    if sv:
        best = max(v for v in sv if v in VERSIONS) if any(v in VERSIONS for v in sv) else None
        if best:
            sess.client_version = VERSIONS.get(best, sess.client_version)
    sess.saw_client_hello = True


def parse_server_hello(body: bytes, sess: TlsSession) -> None:
    if len(body) < 38:
        return
    ver = struct.unpack_from("!H", body, 0)[0]
    legacy = VERSIONS.get(ver, "0x%04x" % ver)
    off = 2 + 32
    sid_len = body[off]
    off += 1 + sid_len
    if off + 3 > len(body):
        return
    cipher = struct.unpack_from("!H", body, off)[0]
    sess.cipher_suite = CIPHER_SUITES.get(cipher, "0x%04x" % cipher)
    if cipher in WEAK_SUITES:
        sess.add_note("negotiated a legacy cipher suite")
    off += 2
    off += 1                                   # compression method
    negotiated = legacy
    if off + 2 <= len(body):
        ext_len = struct.unpack_from("!H", body, off)[0]
        off += 2
        ext = _parse_extensions(body[off:off + ext_len])
        sv = ext.get("supported_versions")
        if sv:
            negotiated = VERSIONS.get(sv[0], "0x%04x" % sv[0])
        if "alpn" in ext and ext["alpn"]:
            sess.alpn_selected = ext["alpn"][0]
    sess.server_version = legacy
    sess.negotiated_version = negotiated
    sess.saw_server_hello = True


# ------------------------------------------------------------- DER / X.509

def _der_tlv(buf: bytes, off: int) -> tuple[int, int, int, int]:
    """Return (tag, content_offset, content_length, next_offset)."""
    if off + 2 > len(buf):
        raise ValueError("short DER")
    tag = buf[off]
    ln = buf[off + 1]
    off += 2
    if ln & 0x80:
        nbytes = ln & 0x7F
        if nbytes == 0 or off + nbytes > len(buf) or nbytes > 4:
            raise ValueError("bad DER length")
        ln = int.from_bytes(buf[off:off + nbytes], "big")
        off += nbytes
    if off + ln > len(buf):
        raise ValueError("DER content past end")
    return tag, off, ln, off + ln


_OID_CN = bytes([0x55, 0x04, 0x03])      # 2.5.4.3 commonName


def _name_cn(buf: bytes, off: int, length: int) -> str | None:
    """Pull the commonName out of an X.501 Name (SEQUENCE OF RDN SET)."""
    end = off + length
    cur = off
    while cur < end:
        try:
            tag, coff, clen, nxt = _der_tlv(buf, cur)
        except ValueError:
            return None
        if tag == 0x31:                  # SET
            inner = coff
            iend = coff + clen
            while inner < iend:
                try:
                    t2, o2, l2, n2 = _der_tlv(buf, inner)
                    if t2 == 0x30:       # SEQUENCE { OID, value }
                        t3, o3, l3, n3 = _der_tlv(buf, o2)
                        if t3 == 0x06 and buf[o3:o3 + l3] == _OID_CN:
                            t4, o4, l4, _ = _der_tlv(buf, n3)
                            return buf[o4:o4 + l4].decode("utf-8", "replace")
                    inner = n2
                except ValueError:
                    break
        cur = nxt
    return None


def _der_time(buf: bytes, off: int, length: int, tag: int) -> str:
    raw = buf[off:off + length].decode("ascii", "replace").rstrip("Z")
    if tag == 0x17 and len(raw) >= 12:              # UTCTime YYMMDDHHMMSS
        yy = int(raw[0:2])
        year = 2000 + yy if yy < 50 else 1900 + yy
        return "%04d-%s-%s %s:%s:%s" % (year, raw[2:4], raw[4:6],
                                        raw[6:8], raw[8:10], raw[10:12])
    if len(raw) >= 14:                              # GeneralizedTime
        return "%s-%s-%s %s:%s:%s" % (raw[0:4], raw[4:6], raw[6:8],
                                      raw[8:10], raw[10:12], raw[12:14])
    return raw


def parse_certificate_message(body: bytes, sess: TlsSession) -> None:
    """Parse the first certificate of an unencrypted Certificate message."""
    if len(body) < 3:
        return
    total = _u24(body, 0)
    off = 3
    certs = 0
    first = None
    end = min(3 + total, len(body))
    while off + 3 <= end:
        clen = _u24(body, off)
        off += 3
        if clen <= 0 or off + clen > len(body):
            break
        if first is None:
            first = body[off:off + clen]
        certs += 1
        off += clen
    sess.cert_chain_len = certs or None
    if not first:
        return
    try:
        _t, coff, clen, _ = _der_tlv(first, 0)          # Certificate
        tag, tboff, tblen, _ = _der_tlv(first, coff)    # tbsCertificate
        cur = tboff
        tag, o, ln, nxt = _der_tlv(first, cur)
        if tag == 0xA0:                                  # [0] version
            cur = nxt
            tag, o, ln, nxt = _der_tlv(first, cur)
        cur = nxt                                        # past serialNumber
        tag, o, ln, nxt = _der_tlv(first, cur)           # signature AlgId
        cur = nxt
        tag, o, ln, nxt = _der_tlv(first, cur)           # issuer
        sess.cert_issuer_cn = _name_cn(first, o, ln)
        cur = nxt
        tag, o, ln, nxt = _der_tlv(first, cur)           # validity
        vt, vo, vl, vnext = _der_tlv(first, o)
        sess.cert_not_before = _der_time(first, vo, vl, vt)
        vt2, vo2, vl2, _ = _der_tlv(first, vnext)
        sess.cert_not_after = _der_time(first, vo2, vl2, vt2)
        cur = nxt
        tag, o, ln, nxt = _der_tlv(first, cur)           # subject
        sess.cert_subject_cn = _name_cn(first, o, ln)
    except (ValueError, IndexError, struct.error):
        sess.add_note("certificate present but not parseable")


def feed_payload(payload: bytes, sess: TlsSession, from_client: bool) -> bool:
    """Feed one TCP payload into a session. Returns True if it was TLS."""
    saw = False
    for ctype, _ver, body in iter_records(payload):
        saw = True
        if ctype == CT_APPLICATION_DATA:
            sess.app_data_records += 1
            sess.app_data_bytes += len(body)
            continue
        if ctype == CT_ALERT:
            sess.saw_alert = True
            continue
        if ctype != CT_HANDSHAKE:
            continue
        off = 0
        while off + 4 <= len(body):
            htype = body[off]
            hlen = _u24(body, off + 1)
            hbody = body[off + 4: off + 4 + hlen]
            if len(hbody) < hlen:
                break                      # spans segments; not reassembled
            try:
                if htype == HS_CLIENT_HELLO:
                    parse_client_hello(hbody, sess)
                elif htype == HS_SERVER_HELLO:
                    parse_server_hello(hbody, sess)
                elif htype == HS_CERTIFICATE:
                    parse_certificate_message(hbody, sess)
            except (struct.error, IndexError, ValueError):
                sess.add_note("malformed handshake message")
            off += 4 + hlen
    return saw


class TlsRecordAssembler:
    """Frames TLS records out of one direction of a reassembled stream.

    Memory is bounded by construction: handshake records are buffered (they
    are small and capped by the protocol), while application-data records are
    counted and skipped without ever being held. Handshake *messages* that
    span several records are reassembled too, which is what makes a split
    ClientHello readable.
    """

    __slots__ = ("_buf", "_hs", "_skip", "limit", "bad_records", "closed")

    def __init__(self, limit: int = 32768) -> None:
        self._buf = bytearray()
        self._hs = bytearray()
        self._skip = 0
        self.limit = int(limit)
        self.bad_records = 0
        self.closed = False

    def reset(self) -> None:
        self._buf.clear()
        self._hs.clear()
        self._skip = 0

    def on_gap(self, nbytes: int) -> None:
        # Record framing is lost after a hole; do not guess where it resumes.
        self.reset()
        self.closed = True

    def feed(self, data: bytes, sess: TlsSession, from_client: bool) -> bool:
        """Returns True if anything TLS-shaped was seen."""
        if self.closed or not data:
            return False
        self._buf.extend(data)
        saw = False
        while True:
            if self._skip > 0:
                take = min(self._skip, len(self._buf))
                del self._buf[:take]
                self._skip -= take
                if self._skip:
                    return saw
            if len(self._buf) < 5:
                return saw
            ctype = self._buf[0]
            version = (self._buf[1] << 8) | self._buf[2]
            rlen = (self._buf[3] << 8) | self._buf[4]
            if ctype not in (CT_CHANGE_CIPHER_SPEC, CT_ALERT, CT_HANDSHAKE,
                             CT_APPLICATION_DATA) \
                    or not (0x0300 <= version <= 0x0304) or rlen > 16640:
                self.bad_records += 1
                self.closed = True
                self._buf.clear()
                return saw
            saw = True

            if ctype == CT_APPLICATION_DATA:
                sess.app_data_records += 1
                sess.app_data_bytes += rlen
                del self._buf[:5]
                self._skip = rlen
                continue

            if len(self._buf) < 5 + rlen:
                if 5 + rlen > self.limit:
                    del self._buf[:5]
                    self._skip = rlen
                    continue
                return saw                      # wait for the rest

            body = bytes(self._buf[5:5 + rlen])
            del self._buf[:5 + rlen]
            if ctype == CT_ALERT:
                sess.saw_alert = True
            elif ctype == CT_HANDSHAKE:
                self._feed_handshake(body, sess)

    def _feed_handshake(self, body: bytes, sess: TlsSession) -> None:
        if len(self._hs) + len(body) > self.limit:
            # A handshake this large is not something we need to hold on to.
            self._hs.clear()
            return
        self._hs.extend(body)
        while len(self._hs) >= 4:
            htype = self._hs[0]
            hlen = (self._hs[1] << 16) | (self._hs[2] << 8) | self._hs[3]
            if len(self._hs) < 4 + hlen:
                if 4 + hlen > self.limit:
                    self._hs.clear()
                return
            hbody = bytes(self._hs[4:4 + hlen])
            del self._hs[:4 + hlen]
            try:
                if htype == HS_CLIENT_HELLO:
                    parse_client_hello(hbody, sess)
                elif htype == HS_SERVER_HELLO:
                    parse_server_hello(hbody, sess)
                elif htype == HS_CERTIFICATE:
                    parse_certificate_message(hbody, sess)
            except (struct.error, IndexError, ValueError):
                sess.add_note("malformed handshake message")
