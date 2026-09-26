"""QUIC Initial SNI extraction.

Instagram, YouTube, Google, Facebook and more now run over HTTP/3 (QUIC, UDP
443), not TCP TLS -- so their ClientHello, and its SNI, never appear on the
port NetLab's TLS parser watches, and those sites show up only as an anonymous
UDP flow.

A QUIC v1 Initial packet carries the TLS ClientHello in the clear-ish: its
payload is encrypted, but with keys derived from the connection's own
Destination Connection ID via a published salt (RFC 9001 s5.2), so anyone on
the path can decrypt an Initial and read the ClientHello -- exactly what we do
here to recover the SNI. Nothing after the handshake is readable; this reads
only the name being requested, like the TLS SNI already does.
"""

from __future__ import annotations

import struct

try:
    from cryptography.hazmat.primitives import hashes, hmac
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    _HAVE_CRYPTO = True
except Exception:                                     # pragma: no cover
    _HAVE_CRYPTO = False

# RFC 9001 s5.2: the salt used to derive QUIC v1 Initial secrets.
_V1_SALT = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
_V1 = 0x00000001
# QUIC v2 (RFC 9369) uses a different salt and labels; support it too.
_V2 = 0x6b3343cf
_V2_SALT = bytes.fromhex("0dede3def700a6db819381be6e269dcbf9bd2ed9")


def is_initial(payload: bytes) -> bool:
    """A QUIC v1/v2 long-header Initial packet (client's first flight)."""
    if not payload or len(payload) < 7:
        return False
    if (payload[0] & 0xC0) != 0xC0:          # long header + fixed bit
        return False
    version = int.from_bytes(payload[1:5], "big")
    if version == _V1:
        return (payload[0] & 0x30) == 0x00   # v1: Initial type = 0
    if version == _V2:
        return (payload[0] & 0x30) == 0x10   # v2: Initial type = 1
    return False


def _read_varint(data: bytes, off: int):
    first = data[off]
    length = 1 << (first >> 6)
    value = first & 0x3F
    for i in range(1, length):
        value = (value << 8) | data[off + i]
    return value, off + length


def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    h = hmac.HMAC(salt, hashes.SHA256())
    h.update(ikm)
    return h.finalize()


def _hkdf_expand_label(secret: bytes, label: bytes, length: int) -> bytes:
    full = b"tls13 " + label
    info = struct.pack("!H", length) + bytes([len(full)]) + full + b"\x00"
    out, prev, counter = b"", b"", 1
    while len(out) < length:
        h = hmac.HMAC(secret, hashes.SHA256())
        h.update(prev + info + bytes([counter]))
        prev = h.finalize()
        out += prev
        counter += 1
    return out[:length]


def sni(payload: bytes) -> str | None:
    """Return the SNI from a single QUIC Initial, or None. Never raises.

    A large ClientHello is split across several Initials, so this only finds
    the SNI when it fits in one packet; the engine uses `initial_crypto` and
    reassembles across packets for the rest.
    """
    got = initial_crypto(payload)
    if not got:
        return None
    dcid, fragments = got
    return client_hello_sni(reassemble(fragments))


def initial_crypto(payload: bytes):
    """Decrypt a QUIC Initial and return `(dcid, [(offset, crypto_bytes)])`,
    or None if it is not a readable Initial. Never raises."""
    if not _HAVE_CRYPTO or not is_initial(payload):
        return None
    try:
        return _extract(payload)
    except Exception:
        return None


def reassemble(fragments) -> bytes:
    """Join offset-tagged CRYPTO fragments into one contiguous buffer."""
    buf = b""
    for off, data in sorted(fragments):
        if off <= len(buf):
            buf = buf[:off] + data
    return buf


class QuicSni:
    """Recovers the SNI from QUIC Initials, reassembling the ClientHello across
    packets (a browser's is usually split over two). Bounded: it forgets old
    connections so a flood of Initials cannot grow it."""

    def __init__(self, max_conns: int = 256) -> None:
        self._buf: dict[bytes, dict[int, bytes]] = {}
        self._done: set[bytes] = set()
        self._max = max_conns

    def observe(self, payload: bytes) -> str | None:
        """Feed one UDP payload; return the SNI if this completes it, else None."""
        got = initial_crypto(payload)
        if not got:
            return None
        dcid, fragments = got
        if dcid in self._done:
            return None
        frags = self._buf.get(dcid)
        if frags is None:
            if len(self._buf) >= self._max:
                self._buf.clear()
            frags = self._buf[dcid] = {}
        for off, data in fragments:
            frags[off] = data
        name = client_hello_sni(reassemble(list(frags.items())))
        if name:
            self._done.add(dcid)
            self._buf.pop(dcid, None)
            if len(self._done) > self._max * 4:
                self._done.clear()
            return name
        return None


def _extract(payload: bytes):
    version = int.from_bytes(payload[1:5], "big")
    salt = _V2_SALT if version == _V2 else _V1_SALT
    off = 5
    dcid_len = payload[off]; off += 1
    dcid = payload[off:off + dcid_len]; off += dcid_len
    scid_len = payload[off]; off += 1
    off += scid_len
    token_len, off = _read_varint(payload, off)
    off += token_len
    length, off = _read_varint(payload, off)
    pn_offset = off

    initial_secret = _hkdf_extract(salt, dcid)
    label_prefix = b"quicv2 " if version == _V2 else b"quic "
    client_secret = _hkdf_expand_label(initial_secret, b"client in", 32)
    key = _hkdf_expand_label(client_secret, label_prefix + b"key", 16)
    iv = _hkdf_expand_label(client_secret, label_prefix + b"iv", 12)
    hp = _hkdf_expand_label(client_secret, label_prefix + b"hp", 16)

    # Remove header protection using a 16-byte sample past the packet number.
    sample = payload[pn_offset + 4:pn_offset + 20]
    enc = Cipher(algorithms.AES(hp), modes.ECB()).encryptor()
    mask = enc.update(sample) + enc.finalize()
    first_byte = payload[0] ^ (mask[0] & 0x0F)
    pn_len = (first_byte & 0x03) + 1
    pn_bytes = bytes(payload[pn_offset + i] ^ mask[1 + i] for i in range(pn_len))

    nonce = bytes(iv[i] ^ pn_bytes.rjust(12, b"\x00")[i] for i in range(12))
    header = bytes([first_byte]) + payload[1:pn_offset] + pn_bytes
    ciphertext = payload[pn_offset + pn_len: pn_offset + length]
    plaintext = AESGCM(key).decrypt(nonce, ciphertext, header)

    return dcid, _crypto_fragments(plaintext)


def _crypto_fragments(plaintext: bytes):
    """Every CRYPTO frame's (offset, data) from a decrypted Initial payload."""
    frames = []
    off, n = 0, len(plaintext)
    while off < n:
        ftype, off = _read_varint(plaintext, off)
        if ftype in (0x00, 0x01):                       # PADDING, PING
            continue
        if ftype in (0x02, 0x03):                       # ACK
            _largest, off = _read_varint(plaintext, off)
            _delay, off = _read_varint(plaintext, off)
            count, off = _read_varint(plaintext, off)
            _first, off = _read_varint(plaintext, off)
            for _ in range(count):
                _gap, off = _read_varint(plaintext, off)
                _rng, off = _read_varint(plaintext, off)
            if ftype == 0x03:                           # ECN counts
                for _ in range(3):
                    _v, off = _read_varint(plaintext, off)
            continue
        if ftype == 0x06:                               # CRYPTO
            c_off, off = _read_varint(plaintext, off)
            c_len, off = _read_varint(plaintext, off)
            frames.append((c_off, plaintext[off:off + c_len]))
            off += c_len
            continue
        break                                           # anything else: stop
    return frames


def client_hello_sni(handshake: bytes) -> str | None:
    # handshake: type(1)=0x01 ClientHello, length(3), body.
    if len(handshake) < 4 or handshake[0] != 0x01:
        return None
    body_len = int.from_bytes(handshake[1:4], "big")
    body = handshake[4:4 + body_len]
    # Reuse the TLS ClientHello extension parser.
    from netlab.analyze.tls import _parse_extensions
    if len(body) < 38:
        return None
    off = 2 + 32                                        # version + random
    sid_len = body[off]; off += 1 + sid_len
    if off + 2 > len(body):
        return None
    cs_len = struct.unpack_from("!H", body, off)[0]; off += 2 + cs_len
    if off >= len(body):
        return None
    comp_len = body[off]; off += 1 + comp_len
    if off + 2 > len(body):
        return None
    ext_len = struct.unpack_from("!H", body, off)[0]; off += 2
    ext = _parse_extensions(body[off:off + ext_len])
    return ext.get("sni")
