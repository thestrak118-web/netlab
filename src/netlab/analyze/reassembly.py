"""Bounded bidirectional TCP stream reassembly.

Design rules, in order of priority:

1. **Never invent bytes.** A hole in the sequence space is reported as a gap
   of a known size; it is never zero-filled and never silently closed over.
   Consumers are told about gaps so they can resynchronise instead of
   parsing across a hole and producing confident nonsense.
2. **Bounded memory.** Only *out-of-order* segments are held. In-order bytes
   are handed straight to the consumer and forgotten, so a well-behaved
   stream of any length costs nothing. Per-direction, per-stream and global
   caps all apply; hitting one forces a gap rather than growing.
3. **Stable direction.** Direction is derived from the canonical flow key,
   not from which side we currently believe is the client, so a late SYN
   that re-labels client/server can never swap the two half-streams.

Sequence numbers are compared with wrap-safe signed arithmetic throughout.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from netlab.util.bounded import BoundedLRUDict

SEQ_MOD = 1 << 32
SEQ_HALF = 1 << 31


def seq_diff(a: int, b: int) -> int:
    """Signed distance a - b, correct across the 32-bit wrap."""
    d = (a - b) % SEQ_MOD
    return d - SEQ_MOD if d >= SEQ_HALF else d


def seq_add(a: int, n: int) -> int:
    return (a + n) % SEQ_MOD


# Event kinds handed back from a direction push.
EV_DATA = "data"
EV_GAP = "gap"
EV_CLOSE = "close"


@dataclass(slots=True)
class DirectionStats:
    segments: int = 0
    bytes_delivered: int = 0
    retransmissions: int = 0
    out_of_order: int = 0
    overlaps: int = 0
    gaps: int = 0
    gap_bytes: int = 0
    forced_flushes: int = 0


class TcpDirection:
    """One half of a TCP conversation."""

    __slots__ = ("isn", "next_seq", "buffer", "buffered_bytes", "stats",
                 "syn_seen", "fin_seen", "rst_seen", "mid_stream", "closed",
                 "max_buffer_bytes", "max_segments", "last_ts", "last_ack", "fin_seq")

    def __init__(self, max_buffer_bytes: int, max_segments: int) -> None:
        self.isn: int | None = None
        self.next_seq: int | None = None
        self.buffer: dict[int, bytes] = {}
        self.buffered_bytes = 0
        self.stats = DirectionStats()
        self.syn_seen = False
        self.fin_seen = False
        self.rst_seen = False
        self.mid_stream = False
        self.closed = False
        self.max_buffer_bytes = max_buffer_bytes
        self.max_segments = max_segments
        self.last_ts = 0.0
        self.last_ack = None
        self.fin_seq = None

    # ------------------------------------------------------------------ push

    def push(self, seq: int, data: bytes, syn: bool, fin: bool, rst: bool,
             ts: float) -> list[tuple]:
        """Feed one segment. Returns a list of (kind, payload) events."""
        events: list[tuple] = []
        self.last_ts = ts

        if rst:
            self.rst_seen = True
            if not self.closed:
                events.extend(self._flush("RST"))
                self.closed = True
            return events

        if syn:
            self.syn_seen = True
            if self.isn is None:
                self.isn = seq
                # The SYN itself consumes one sequence number.
                self.next_seq = seq_add(seq, 1)
            seq = seq_add(seq, 1)
            if not data and not fin:
                return events

        if self.next_seq is None:
            # Capture started mid-conversation: anchor here and say so, rather
            # than pretending we have the stream from the beginning.
            self.next_seq = seq
            self.mid_stream = True

        if fin:
            self.fin_seen = True
            self.fin_seq = seq_add(seq, len(data))
        if not data:
            return self._finish_if_ready()

        self.stats.segments += 1
        delta = seq_diff(seq, self.next_seq)

        if delta == 0:
            events.append((EV_DATA, data))
            self.stats.bytes_delivered += len(data)
            self.next_seq = seq_add(seq, len(data))
            events.extend(self._drain())
        elif delta < 0:
            overlap = -delta
            if overlap >= len(data):
                # Everything here has already been delivered.
                self.stats.retransmissions += 1
            else:
                fresh = data[overlap:]
                self.stats.overlaps += 1
                events.append((EV_DATA, fresh))
                self.stats.bytes_delivered += len(fresh)
                self.next_seq = seq_add(seq, len(data))
                events.extend(self._drain())
        else:
            events.extend(self._buffer(seq, data))

        events.extend(self._finish_if_ready())
        return events

    def _finish_if_ready(self):
        if (not self.closed and self.fin_seq is not None
                and seq_diff(self.next_seq, self.fin_seq) >= 0):
            self.next_seq = seq_add(self.fin_seq, 1)
            self.closed = True
            return [(EV_CLOSE, "FIN")]
        return []

    # -------------------------------------------------------------- internals

    def _buffer(self, seq: int, data: bytes) -> list[tuple]:
        existing = self.buffer.get(seq)
        if existing is not None:
            if len(existing) >= len(data):
                self.stats.retransmissions += 1
                return []
            self.buffered_bytes -= len(existing)
        else:
            self.stats.out_of_order += 1
        self.buffer[seq] = data
        self.buffered_bytes += len(data)

        events: list[tuple] = []
        # A hole that never fills must not be allowed to pin memory forever.
        while (self.buffered_bytes > self.max_buffer_bytes
               or len(self.buffer) > self.max_segments):
            forced = self._force_gap()
            if forced is None:
                break
            self.stats.forced_flushes += 1
            events.extend(forced)
        return events

    def _drain(self) -> list[tuple]:
        """Deliver any buffered segments that are now contiguous."""
        events: list[tuple] = []
        while self.buffer:
            # Fully covered out-of-order segments must not pin memory or
            # prevent a later positive gap from being flushed.
            stale = [start for start, blob in self.buffer.items()
                     if seq_diff(seq_add(start, len(blob)), self.next_seq) <= 0]
            for start in stale:
                self.buffered_bytes -= len(self.buffer.pop(start))
                self.stats.retransmissions += 1
            seg = self.buffer.pop(self.next_seq, None)
            if seg is not None:
                self.buffered_bytes -= len(seg)
                events.append((EV_DATA, seg))
                self.stats.bytes_delivered += len(seg)
                self.next_seq = seq_add(self.next_seq, len(seg))
                continue

            # No exact match: look for a buffered segment that starts at or
            # before next_seq but still carries unseen bytes.
            found = None
            for start, blob in self.buffer.items():
                if seq_diff(start, self.next_seq) <= 0 and \
                        seq_diff(seq_add(start, len(blob)), self.next_seq) > 0:
                    found = start
                    break
            if found is None:
                break
            blob = self.buffer.pop(found)
            self.buffered_bytes -= len(blob)
            offset = -seq_diff(found, self.next_seq)
            fresh = blob[offset:]
            self.stats.overlaps += 1
            events.append((EV_DATA, fresh))
            self.stats.bytes_delivered += len(fresh)
            self.next_seq = seq_add(found, len(blob))
        return events

    def _force_gap(self) -> list[tuple] | None:
        """Skip forward to the earliest buffered segment, reporting the hole."""
        if not self.buffer or self.next_seq is None:
            return None
        lowest = min(self.buffer, key=lambda s: seq_diff(s, self.next_seq))
        missing = seq_diff(lowest, self.next_seq)
        if missing <= 0:
            return None
        self.stats.gaps += 1
        self.stats.gap_bytes += missing
        self.next_seq = lowest
        events: list[tuple] = [(EV_GAP, missing)]
        events.extend(self._drain())
        return events

    def _flush(self, reason: str, end_seq: int | None = None) -> list[tuple]:
        """Release whatever is still buffered when the stream ends."""
        events: list[tuple] = []
        while self.buffer:
            forced = self._force_gap()
            if forced is None:
                break
            events.extend(forced)
        if self.buffer:
            self.buffered_bytes = 0
            self.buffer.clear()
        if end_seq is not None and self.next_seq is not None:
            missing = seq_diff(end_seq, self.next_seq)
            if missing > 0:
                self.stats.gaps += 1
                self.stats.gap_bytes += missing
                self.next_seq = end_seq
                events.append((EV_GAP, missing))
        events.append((EV_CLOSE, reason))
        return events

    def discard(self) -> int:
        freed = self.buffered_bytes
        self.buffer.clear()
        self.buffered_bytes = 0
        return freed

    @property
    def state_flags(self) -> str:
        bits = []
        if self.syn_seen:
            bits.append("SYN")
        if self.fin_seen:
            bits.append("FIN")
        if self.rst_seen:
            bits.append("RST")
        if self.mid_stream:
            bits.append("MIDSTREAM")
        return ",".join(bits) or "-"


@dataclass(slots=True)
class DirectionSummary:
    """A retired direction's facts, kept after its buffers are released."""
    endpoint: tuple = ()
    segments: int = 0
    bytes_delivered: int = 0
    retransmissions: int = 0
    out_of_order: int = 0
    overlaps: int = 0
    gaps: int = 0
    gap_bytes: int = 0
    flags: str = "-"
    buffered: int = 0
    last_ack: int | None = None


@dataclass(slots=True)
class StreamSummary:
    directions: tuple = ()
    live: bool = True


@dataclass
class ReassemblyStats:
    streams: int = 0
    streams_created: int = 0
    streams_expired: int = 0
    streams_evicted: int = 0
    segments: int = 0
    bytes_reassembled: int = 0
    retransmissions: int = 0
    out_of_order: int = 0
    overlaps: int = 0
    gaps: int = 0
    gap_bytes: int = 0
    forced_flushes: int = 0
    buffered_bytes: int = 0
    peak_buffered_bytes: int = 0


class TcpStream:
    """Both halves of one TCP conversation, plus per-direction consumer state."""

    __slots__ = ("key", "a_endpoint", "directions", "created_ts", "last_ts",
                 "app_state")

    def __init__(self, key, max_buffer_bytes: int, max_segments: int,
                 ts: float) -> None:
        self.key = key
        # key is canonical: (proto, ip_a, port_a, ip_b, port_b)
        self.a_endpoint = (key[1], key[2])
        self.directions = (TcpDirection(max_buffer_bytes, max_segments),
                           TcpDirection(max_buffer_bytes, max_segments))
        self.created_ts = ts
        self.last_ts = ts
        self.app_state: dict = {}

    def direction_index(self, src: str, sport) -> int:
        return 0 if (src, sport) == self.a_endpoint else 1

    def endpoint(self, index: int) -> tuple:
        return self.a_endpoint if index == 0 else (self.key[3], self.key[4])

    @property
    def buffered_bytes(self) -> int:
        return sum(d.buffered_bytes for d in self.directions)

    @property
    def closed(self) -> bool:
        return all(d.closed for d in self.directions)

    def summary(self, live: bool = True) -> StreamSummary:
        """Snapshot the per-direction facts. Cheap: a handful of integers.

        This is what lets a finished connection still show its reassembly
        statistics after its buffers have been released.
        """
        out = []
        for index, direction in enumerate(self.directions):
            st = direction.stats
            out.append(DirectionSummary(
                endpoint=self.endpoint(index),
                segments=st.segments,
                bytes_delivered=st.bytes_delivered,
                retransmissions=st.retransmissions,
                out_of_order=st.out_of_order,
                overlaps=st.overlaps,
                gaps=st.gaps,
                gap_bytes=st.gap_bytes,
                flags=direction.state_flags,
                buffered=direction.buffered_bytes,
                last_ack=direction.last_ack,
            ))
        return StreamSummary(directions=tuple(out), live=live)

    def discard(self) -> int:
        return sum(d.discard() for d in self.directions)


class TcpReassembler:
    """Owns every tracked stream and enforces the global memory ceiling."""

    def __init__(self, config, on_data=None, on_gap=None, on_close=None,
                 on_retire=None) -> None:
        self._cfg = config
        self.on_data = on_data
        self.on_gap = on_gap
        self.on_close = on_close
        # Called just before a stream's buffers are released, so a consumer
        # can keep its statistics somewhere that outlives the stream.
        self.on_retire = on_retire

        self.max_streams = max(1, int(config.get("max_streams")))
        self.dir_buffer_bytes = int(config.get("reasm_dir_buffer_kb")) * 1024
        self.max_segments = int(config.get("reasm_max_segments"))
        self.total_buffer_bytes = int(config.get("reasm_total_buffer_mb")) * 1024 * 1024
        self.idle_timeout = float(config.get("flow_idle_timeout"))

        self.streams = BoundedLRUDict(self.max_streams)
        self._buffered = 0
        self._peak_buffered = 0
        self._totals = DirectionStats()
        self._streams_created = 0
        self._streams_expired = 0
        self._streams_evicted = 0
        self._retired = DirectionStats()
        self._last_expiry = time.monotonic()

    # --------------------------------------------------------------- ingest

    def push(self, pkt, flow) -> None:
        """Feed one decoded TCP packet."""
        if flow is None or pkt.proto != "TCP" or pkt.seq is None or pkt.error:
            return
        flags = pkt.tcp_flags or ""
        syn = "SYN" in flags
        fin = "FIN" in flags
        rst = "RST" in flags
        data = pkt.payload

        key = flow.key
        if self.streams.get(key) is None and len(self.streams) >= self.max_streams:
            old_key, old_stream = self.streams.items()[0]
            self._retire(old_key, old_stream)
            self._streams_evicted += 1
        stream, created = self.streams.get_or_create(
            key, lambda: TcpStream(key, self.dir_buffer_bytes,
                                   self.max_segments, pkt.ts))
        if created:
            self._streams_created += 1
        stream.last_ts = pkt.ts

        index = stream.direction_index(pkt.src, pkt.sport)
        direction = stream.directions[index]
        if "ACK" in flags:
            direction.last_ack = pkt.ack
        before = direction.buffered_bytes

        events = direction.push(pkt.seq, data, syn, fin, rst, pkt.ts)

        self._buffered += direction.buffered_bytes - before
        if self._buffered > self._peak_buffered:
            self._peak_buffered = self._buffered

        self._dispatch(stream, index, events, pkt, flow)

        if rst:
            other = stream.directions[1 - index]
            before = other.buffered_bytes
            events = other.push(0, b"", False, False, True, pkt.ts)
            self._buffered += other.buffered_bytes - before
            self._dispatch(stream, 1 - index, events, pkt, flow)
        if self._buffered > self.total_buffer_bytes:
            self._relieve_pressure(pkt, flow)

    def _dispatch(self, stream, index, events, pkt, flow) -> None:
        for kind, payload in events:
            if kind == EV_DATA:
                self._totals.bytes_delivered += len(payload)
                if self.on_data:
                    self.on_data(stream, index, payload, pkt, flow)
            elif kind == EV_GAP:
                self._totals.gaps += 1
                self._totals.gap_bytes += payload
                if self.on_gap:
                    self.on_gap(stream, index, payload, flow)
            elif kind == EV_CLOSE:
                if self.on_close:
                    self.on_close(stream, index, payload, flow)

    def _relieve_pressure(self, pkt, flow) -> None:
        """Global ceiling hit: drop the oldest buffers, reporting each gap."""
        for stream in self.streams.values():
            if self._buffered <= self.total_buffer_bytes:
                break
            if stream.buffered_bytes <= 0:
                continue
            for index, direction in enumerate(stream.directions):
                if direction.buffered_bytes <= 0:
                    continue
                missing = max(seq_diff(seq_add(start, len(blob)), direction.next_seq)
                              for start, blob in direction.buffer.items())
                missing = max(0, missing)
                direction.next_seq = seq_add(direction.next_seq, missing)
                freed = direction.discard()
                self._buffered -= freed
                direction.stats.forced_flushes += 1
                direction.stats.gaps += 1
                direction.stats.gap_bytes += missing
                self._totals.gaps += 1
                self._totals.gap_bytes += missing
                if self.on_gap:
                    self.on_gap(stream, index, missing, flow)

    # --------------------------------------------------------------- expiry

    def expire(self, now: float | None = None, force: bool = False) -> int:
        """Retire streams idle beyond the timeout. Returns how many went."""
        now_mono = time.monotonic()
        if not force and now_mono - self._last_expiry < 5.0:
            return 0
        self._last_expiry = now_mono
        cutoff = (now if now is not None else time.time()) - self.idle_timeout

        expired = []
        for key, stream in self.streams.items():
            if stream.last_ts and stream.last_ts < cutoff:
                expired.append((key, stream))
            elif stream.closed and not stream.buffered_bytes:
                expired.append((key, stream))

        for key, stream in expired:
            self._retire(key, stream)
            self._streams_expired += 1
        return len(expired)

    def _retire(self, key, stream):
        # Buffered data beyond a hole is explicitly abandoned on eviction.
        for index, direction in enumerate(stream.directions):
            if direction.buffered_bytes or (direction.fin_seq is not None and not direction.closed):
                ends = [seq_diff(seq_add(start, len(blob)), direction.next_seq)
                        for start, blob in direction.buffer.items()]
                if direction.fin_seq is not None:
                    ends.append(seq_diff(direction.fin_seq, direction.next_seq))
                missing = max([0] + ends)
                direction.stats.gaps += 1
                direction.stats.gap_bytes += missing
                self._totals.gaps += 1
                self._totals.gap_bytes += missing
                if self.on_gap:
                    self.on_gap(stream, index, missing, None)
            if self.on_close:
                self.on_close(stream, index, "EXPIRED", None)
            for name in ("segments", "retransmissions", "out_of_order",
                         "overlaps", "forced_flushes"):
                setattr(self._retired, name, getattr(self._retired, name)
                        + getattr(direction.stats, name))
        self._buffered -= stream.discard()
        if self.on_retire:
            self.on_retire(stream)
        stream.app_state.clear()
        self.streams.pop(key)

    # ---------------------------------------------------------------- stats

    def stats(self) -> ReassemblyStats:
        st = ReassemblyStats()
        st.streams = len(self.streams)
        st.streams_created = self._streams_created
        st.streams_expired = self._streams_expired
        st.streams_evicted = self._streams_evicted
        st.buffered_bytes = max(0, self._buffered)
        st.peak_buffered_bytes = self._peak_buffered
        st.bytes_reassembled = self._totals.bytes_delivered
        st.gaps = self._totals.gaps
        st.gap_bytes = self._totals.gap_bytes
        for name in ("segments", "retransmissions", "out_of_order",
                     "overlaps", "forced_flushes"):
            setattr(st, name, getattr(self._retired, name))
        for stream in self.streams.values():
            for direction in stream.directions:
                d = direction.stats
                st.segments += d.segments
                st.retransmissions += d.retransmissions
                st.out_of_order += d.out_of_order
                st.overlaps += d.overlaps
                st.forced_flushes += d.forced_flushes
        return st

    def get(self, key):
        return self.streams.get(key)

    def reset(self) -> None:
        self.streams.clear()
        self._buffered = 0
        self._peak_buffered = 0
        self._totals = DirectionStats()
        self._streams_created = 0
        self._streams_expired = 0
        self._streams_evicted = 0
        self._retired = DirectionStats()
