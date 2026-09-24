"""Incremental pcap / pcapng reader.

One parser serves two callers:

  * the live capture engine, which feeds it chunks tailed from the file
    dumpcap is still writing to, and
  * the PCAP import path, which feeds it a whole file in chunks.

Because it is incremental it never assumes a read ends on a record
boundary; a partial trailing record is retained until the rest arrives.
No third-party dependency is used here on purpose: this is the hot path.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

# Sentinel meaning "not enough bytes buffered yet, come back later".
NEED_MORE = object()

MAX_BLOCK_BYTES = 64 * 1024 * 1024
MAX_PACKET_BYTES = 16 * 1024 * 1024

_PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", False),   # microsecond, little endian
    b"\xa1\xb2\xc3\xd4": (">", False),   # microsecond, big endian
    b"\x4d\x3c\xb2\xa1": ("<", True),    # nanosecond, little endian
    b"\xa1\xb2\x3c\x4d": (">", True),    # nanosecond, big endian
}
_PCAPNG_SHB = b"\x0a\x0d\x0d\x0a"
_BT_SHB = 0x0A0D0D0A
_BT_IDB = 0x00000001
_BT_PB = 0x00000002      # obsolete Packet Block
_BT_SPB = 0x00000003     # Simple Packet Block
_BT_EPB = 0x00000006     # Enhanced Packet Block


class CaptureFormatError(Exception):
    """Raised when a byte stream is not a usable pcap/pcapng capture."""


@dataclass(slots=True)
class RawPacket:
    ts: float
    caplen: int
    wirelen: int
    linktype: int
    data: bytes
    offset: int = 0          # byte offset of this record within the stream


@dataclass(slots=True)
class _Iface:
    linktype: int = 1
    divisor: float = 1e6
    tsoffset: float = 0.0
    snaplen: int = 262144
    name: str = ""


class StreamingCaptureParser:
    """Feed bytes in, get `RawPacket`s out. Format is auto-detected."""

    def __init__(self) -> None:
        self._buf = bytearray()
        self._fmt: str | None = None
        self._endian = "<"
        self._nano = False
        self._linktype = 1
        self._snaplen = 0
        self._ifaces: list[_Iface] = []
        self._ng_endian_known = False
        self._pos = 0                 # bytes consumed from the stream so far
        self.malformed_blocks = 0

    # ---- public -------------------------------------------------------

    @property
    def fmt(self) -> str | None:
        return self._fmt

    @property
    def position(self) -> int:
        """Absolute offset of the next unconsumed byte in the stream."""
        return self._pos

    def _consume(self, n: int) -> None:
        del self._buf[:n]
        self._pos += n

    @property
    def linktype(self) -> int:
        if self._fmt == "pcapng" and self._ifaces:
            return self._ifaces[0].linktype
        return self._linktype

    def feed(self, data: bytes) -> list[RawPacket]:
        if data:
            self._buf.extend(data)
        out: list[RawPacket] = []
        while True:
            item = self._step()
            if item is NEED_MORE:
                break
            if item is not None:
                out.append(item)
        return out

    def pending_bytes(self) -> int:
        return len(self._buf)

    # ---- internals ----------------------------------------------------

    def _step(self):
        if self._fmt is None:
            return self._detect()
        if self._fmt == "pcap":
            return self._step_pcap()
        return self._step_pcapng()

    def _detect(self):
        if len(self._buf) < 4:
            return NEED_MORE
        head = bytes(self._buf[:4])
        if head == _PCAPNG_SHB:
            self._fmt = "pcapng"
            return None
        if head in _PCAP_MAGICS:
            if len(self._buf) < 24:
                return NEED_MORE
            self._endian, self._nano = _PCAP_MAGICS[head]
            fields = struct.unpack(self._endian + "IHHiIII", bytes(self._buf[:24]))
            self._snaplen = fields[5]
            self._linktype = fields[6] & 0xFFFF
            self._consume(24)
            self._fmt = "pcap"
            return None
        raise CaptureFormatError(
            "not a pcap or pcapng file (bad magic %s)" % head.hex()
        )

    def _step_pcap(self):
        if len(self._buf) < 16:
            return NEED_MORE
        ts_sec, ts_frac, caplen, wirelen = struct.unpack_from(
            self._endian + "IIII", self._buf, 0
        )
        if caplen > MAX_PACKET_BYTES:
            raise CaptureFormatError(
                "corrupt pcap record: capture length %d exceeds sane limit" % caplen
            )
        if len(self._buf) < 16 + caplen:
            return NEED_MORE
        data = bytes(self._buf[16 : 16 + caplen])
        offset = self._pos
        self._consume(16 + caplen)
        ts = ts_sec + ts_frac / (1e9 if self._nano else 1e6)
        return RawPacket(ts, caplen, wirelen or caplen, self._linktype, data,
                         offset)

    def _step_pcapng(self):
        if not self._ng_endian_known:
            if len(self._buf) < 12:
                return NEED_MORE
            bom = bytes(self._buf[8:12])
            if bom == b"\x4d\x3c\x2b\x1a":
                self._endian = "<"
            elif bom == b"\x1a\x2b\x3c\x4d":
                self._endian = ">"
            else:
                raise CaptureFormatError(
                    "pcapng section header has bad byte-order magic %s" % bom.hex()
                )
            self._ng_endian_known = True

        if len(self._buf) < 12:
            return NEED_MORE
        btype, blen = struct.unpack_from(self._endian + "II", self._buf, 0)
        if blen < 12 or blen % 4 or blen > MAX_BLOCK_BYTES:
            raise CaptureFormatError("corrupt pcapng block length %d" % blen)
        if len(self._buf) < blen:
            return NEED_MORE
        body = bytes(self._buf[8 : blen - 4])
        block_offset = self._pos
        self._consume(blen)

        try:
            if btype == _BT_SHB:
                # A new section resets interface numbering and byte order.
                bom = body[0:4]
                if bom == b"\x4d\x3c\x2b\x1a":
                    self._endian = "<"
                elif bom == b"\x1a\x2b\x3c\x4d":
                    self._endian = ">"
                self._ifaces = []
                return None
            if btype == _BT_IDB:
                self._ifaces.append(self._parse_idb(body))
                return None
            if btype == _BT_EPB:
                return self._parse_epb(body, block_offset)
            if btype == _BT_SPB:
                return self._parse_spb(body, block_offset)
            if btype == _BT_PB:
                return self._parse_obsolete_pb(body, block_offset)
        except (struct.error, IndexError, ValueError):
            # A single unreadable block must not abort the whole capture.
            self.malformed_blocks += 1
            return None
        return None

    def _parse_idb(self, body: bytes) -> _Iface:
        linktype, _res, snaplen = struct.unpack_from(self._endian + "HHI", body, 0)
        iface = _Iface(linktype=linktype, snaplen=snaplen or 262144)
        for code, value in self._options(body[8:]):
            if code == 9 and len(value) >= 1:          # if_tsresol
                raw = value[0]
                iface.divisor = float(
                    2 ** (raw & 0x7F) if raw & 0x80 else 10 ** raw
                )
            elif code == 14 and len(value) >= 8:       # if_tsoffset
                iface.tsoffset = float(
                    struct.unpack(self._endian + "q", value[:8])[0]
                )
            elif code == 2:                            # if_name
                iface.name = value.decode("utf-8", "replace")
        return iface

    def _options(self, blob: bytes):
        off = 0
        n = len(blob)
        while off + 4 <= n:
            code, length = struct.unpack_from(self._endian + "HH", blob, off)
            off += 4
            if code == 0:
                return
            value = blob[off : off + length]
            off += length + ((4 - length % 4) % 4)
            yield code, value

    def _iface(self, idx: int) -> _Iface:
        if 0 <= idx < len(self._ifaces):
            return self._ifaces[idx]
        if self._ifaces:
            return self._ifaces[0]
        return _Iface()

    def _parse_epb(self, body: bytes, offset: int = 0) -> RawPacket | None:
        iface_id, ts_hi, ts_lo, caplen, wirelen = struct.unpack_from(
            self._endian + "IIIII", body, 0
        )
        if caplen > MAX_PACKET_BYTES or 20 + caplen > len(body):
            self.malformed_blocks += 1
            return None
        iface = self._iface(iface_id)
        ts = ((ts_hi << 32) | ts_lo) / iface.divisor + iface.tsoffset
        return RawPacket(ts, caplen, wirelen or caplen, iface.linktype,
                         body[20 : 20 + caplen], offset)

    def _parse_spb(self, body: bytes, offset: int = 0) -> RawPacket | None:
        (wirelen,) = struct.unpack_from(self._endian + "I", body, 0)
        iface = self._iface(0)
        caplen = min(wirelen, len(body) - 4, iface.snaplen)
        if caplen < 0:
            self.malformed_blocks += 1
            return None
        # Simple Packet Blocks carry no timestamp at all.
        return RawPacket(0.0, caplen, wirelen, iface.linktype,
                         body[4 : 4 + caplen], offset)

    def _parse_obsolete_pb(self, body: bytes, offset: int = 0) -> RawPacket | None:
        iface_id, _drops, ts_hi, ts_lo, caplen, wirelen = struct.unpack_from(
            self._endian + "HHIIII", body, 0
        )
        if caplen > MAX_PACKET_BYTES or 20 + caplen > len(body):
            self.malformed_blocks += 1
            return None
        iface = self._iface(iface_id)
        ts = ((ts_hi << 32) | ts_lo) / iface.divisor + iface.tsoffset
        return RawPacket(ts, caplen, wirelen or caplen, iface.linktype,
                         body[20 : 20 + caplen], offset)


def iter_capture_file(path: str | Path, chunk: int = 1 << 20) -> Iterator[RawPacket]:
    """Yield every packet in a pcap/pcapng file on disk."""
    parser = StreamingCaptureParser()
    with open(path, "rb") as fh:
        while True:
            blob = fh.read(chunk)
            if not blob:
                break
            yield from parser.feed(blob)


def read_capture_file(path: str | Path, chunk: int = 1 << 20):
    """Read a whole file, returning ``(packets, truncated)``.

    ``truncated`` is True when the file ends in the middle of a record: bytes
    are left over that never completed a block. For a live capture that would
    just mean "more is coming", but a file on disk has no more coming, so it
    is a genuinely cut-short capture -- the complete packets before the cut are
    still returned.
    """
    parser = StreamingCaptureParser()
    packets: list[RawPacket] = []
    with open(path, "rb") as fh:
        while True:
            blob = fh.read(chunk)
            if not blob:
                break
            packets.extend(parser.feed(blob))
    return packets, parser.pending_bytes() > 0


def probe_capture_file(path: str | Path) -> dict:
    """Cheap header probe: format + link type, without reading all packets."""
    parser = StreamingCaptureParser()
    with open(path, "rb") as fh:
        parser.feed(fh.read(65536))
    return {
        "format": parser.fmt or "unknown",
        "linktype": parser.linktype,
        "size": Path(path).stat().st_size,
    }


class RandomAccessCapture:
    """Read a single packet record back out of a capture file by offset.

    The GUI keeps only lightweight rows in memory and stores each packet's
    byte offset; the detail/hex pane seeks the record back out of the file
    on demand.  That keeps memory flat regardless of capture size.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._fmt: str | None = None
        self._endian = "<"
        self._nano = False
        self._linktype = 1
        self._ifaces: list[_Iface] = []
        self._prime()

    def _prime(self) -> None:
        """Read the file header (and pcapng IDBs) so records can be decoded."""
        with open(self.path, "rb") as fh:
            head = fh.read(4)
            if head == _PCAPNG_SHB:
                self._fmt = "pcapng"
                fh.seek(0)
                parser = StreamingCaptureParser()
                # IDBs live at the top of the section; a small read is enough
                # to pick up the interface table for typical captures.
                parser.feed(fh.read(1 << 20))
                self._ifaces = parser._ifaces or [_Iface()]
                self._endian = parser._endian
            elif head in _PCAP_MAGICS:
                self._fmt = "pcap"
                self._endian, self._nano = _PCAP_MAGICS[head]
                fh.seek(0)
                fields = struct.unpack(self._endian + "IHHiIII", fh.read(24))
                self._linktype = fields[6] & 0xFFFF
            else:
                raise CaptureFormatError("unsupported capture file header")

    @property
    def linktype(self) -> int:
        if self._fmt == "pcapng" and self._ifaces:
            return self._ifaces[0].linktype
        return self._linktype

    def read_at(self, offset: int) -> RawPacket | None:
        try:
            with open(self.path, "rb") as fh:
                fh.seek(offset)
                if self._fmt == "pcap":
                    hdr = fh.read(16)
                    if len(hdr) < 16:
                        return None
                    ts_sec, ts_frac, caplen, wirelen = struct.unpack(
                        self._endian + "IIII", hdr)
                    if caplen > MAX_PACKET_BYTES:
                        return None
                    data = fh.read(caplen)
                    ts = ts_sec + ts_frac / (1e9 if self._nano else 1e6)
                    return RawPacket(ts, len(data), wirelen or caplen,
                                     self._linktype, data, offset)
                hdr = fh.read(8)
                if len(hdr) < 8:
                    return None
                btype, blen = struct.unpack(self._endian + "II", hdr)
                if blen < 12 or blen > MAX_BLOCK_BYTES:
                    return None
                body = fh.read(blen - 12)
                if btype != _BT_EPB or len(body) < 20:
                    return None
                iface_id, ts_hi, ts_lo, caplen, wirelen = struct.unpack_from(
                    self._endian + "IIIII", body, 0)
                iface = self._ifaces[iface_id] if iface_id < len(self._ifaces) \
                    else (self._ifaces[0] if self._ifaces else _Iface())
                ts = ((ts_hi << 32) | ts_lo) / iface.divisor + iface.tsoffset
                return RawPacket(ts, caplen, wirelen or caplen, iface.linktype,
                                 body[20:20 + caplen], offset)
        except (OSError, struct.error, ValueError):
            return None
