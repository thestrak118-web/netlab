"""TCP reassembly: ordering, loss, duplication and memory bounds."""

import unittest

from netlab.analyze.decode import decode
from netlab.analyze.flows import FlowTable
from netlab.analyze.reassembly import (EV_CLOSE, EV_DATA, EV_GAP, SEQ_MOD,
                                       TcpDirection, TcpReassembler, seq_diff)
from netlab.config import Config
from tests.helpers import eth_ip_tcp

FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10


def new_direction(buffer_bytes=1024, segments=8):
    return TcpDirection(buffer_bytes, segments)


def data_of(events):
    return b"".join(p for k, p in events if k == EV_DATA)


def kinds(events):
    return [k for k, _ in events]


class TestSequenceArithmetic(unittest.TestCase):
    def test_wraps_correctly(self):
        self.assertEqual(seq_diff(5, 3), 2)
        self.assertEqual(seq_diff(3, 5), -2)
        # Across the 32-bit boundary.
        self.assertEqual(seq_diff(2, SEQ_MOD - 2), 4)
        self.assertEqual(seq_diff(SEQ_MOD - 2, 2), -4)

    def test_reassembly_across_the_wrap(self):
        d = new_direction()
        start = SEQ_MOD - 4
        d.push(start, b"", True, False, False, 1.0)     # SYN at 0xFFFFFFFC
        base = (start + 1) % SEQ_MOD
        e1 = d.push(base, b"AAAA", False, False, False, 1.0)
        e2 = d.push((base + 4) % SEQ_MOD, b"BBBB", False, False, False, 1.0)
        self.assertEqual(data_of(e1) + data_of(e2), b"AAAABBBB")


class TestInOrder(unittest.TestCase):
    def test_simple_in_order_stream(self):
        d = new_direction()
        d.push(1000, b"", True, False, False, 1.0)
        out = b""
        for i, chunk in enumerate([b"one", b"two", b"three"]):
            out += data_of(d.push(1001 + sum(len(c) for c in
                                             [b"one", b"two", b"three"][:i]),
                                  chunk, False, False, False, 1.0))
        self.assertEqual(out, b"onetwothree")
        self.assertEqual(d.stats.out_of_order, 0)
        self.assertEqual(d.stats.gaps, 0)
        self.assertEqual(d.stats.bytes_delivered, 11)

    def test_midstream_capture_is_flagged(self):
        """No SYN seen: anchor where we start and say so, do not pretend."""
        d = new_direction()
        events = d.push(5000, b"hello", False, False, False, 1.0)
        self.assertEqual(data_of(events), b"hello")
        self.assertTrue(d.mid_stream)
        self.assertIn("MIDSTREAM", d.state_flags)


class TestOutOfOrder(unittest.TestCase):
    def test_out_of_order_is_buffered_then_delivered(self):
        d = new_direction()
        d.push(100, b"", True, False, False, 1.0)
        # Segment 2 arrives before segment 1.
        e2 = d.push(106, b"WORLD", False, False, False, 1.0)
        self.assertEqual(data_of(e2), b"")           # nothing deliverable yet
        self.assertEqual(d.stats.out_of_order, 1)
        self.assertGreater(d.buffered_bytes, 0)

        e1 = d.push(101, b"HELLO", False, False, False, 1.0)
        self.assertEqual(data_of(e1), b"HELLOWORLD")
        self.assertEqual(d.buffered_bytes, 0)
        self.assertEqual(d.stats.gaps, 0)

    def test_three_segments_fully_reversed(self):
        d = new_direction()
        d.push(0, b"", True, False, False, 1.0)
        got = b""
        got += data_of(d.push(11, b"CCC", False, False, False, 1.0))
        got += data_of(d.push(7, b"BBBB", False, False, False, 1.0))
        got += data_of(d.push(1, b"AAAAAA", False, False, False, 1.0))
        self.assertEqual(got, b"AAAAAABBBBCCC")
        self.assertEqual(d.buffered_bytes, 0)


class TestRetransmission(unittest.TestCase):
    def test_pure_retransmission_delivers_nothing_twice(self):
        d = new_direction()
        d.push(100, b"", True, False, False, 1.0)
        first = d.push(101, b"PAYLOAD", False, False, False, 1.0)
        again = d.push(101, b"PAYLOAD", False, False, False, 1.0)
        self.assertEqual(data_of(first), b"PAYLOAD")
        self.assertEqual(data_of(again), b"")
        self.assertEqual(d.stats.retransmissions, 1)
        self.assertEqual(d.stats.bytes_delivered, 7)

    def test_partial_overlap_delivers_only_the_new_tail(self):
        d = new_direction()
        d.push(0, b"", True, False, False, 1.0)
        d.push(1, b"ABCDE", False, False, False, 1.0)
        # Retransmit from 3 with extra data: only "FG" is new.
        events = d.push(3, b"CDEFG", False, False, False, 1.0)
        self.assertEqual(data_of(events), b"FG")
        self.assertEqual(d.stats.overlaps, 1)

    def test_duplicate_buffered_segment_counted_once(self):
        d = new_direction()
        d.push(0, b"", True, False, False, 1.0)
        d.push(11, b"XYZ", False, False, False, 1.0)
        d.push(11, b"XYZ", False, False, False, 1.0)
        self.assertEqual(d.stats.retransmissions, 1)
        self.assertEqual(d.stats.out_of_order, 1)


class TestMissingSegments(unittest.TestCase):
    def test_gap_is_reported_with_its_size_and_never_filled(self):
        d = new_direction(buffer_bytes=16, segments=4)
        d.push(0, b"", True, False, False, 1.0)
        d.push(1, b"AAAA", False, False, False, 1.0)
        # Bytes 5..100 never arrive; a far-future segment forces the issue.
        events = []
        for i in range(6):
            events += d.push(101 + i * 4, b"Z" * 4, False, False, False, 1.0)
        self.assertIn(EV_GAP, kinds(events))
        gap = next(p for k, p in events if k == EV_GAP)
        self.assertEqual(gap, 96)                 # 101 - 5
        self.assertNotIn(b"\x00", data_of(events))
        self.assertGreater(d.stats.gaps, 0)
        self.assertEqual(d.stats.gap_bytes, gap)

    def test_fin_waits_for_out_of_order_data(self):
        d = new_direction()
        d.push(0, b"", True, False, False, 1.0)
        d.push(5, b"TAIL", False, False, False, 1.0)
        events = d.push(9, b"", False, True, False, 1.0)
        self.assertEqual(events, [])
        self.assertFalse(d.closed)
        events = d.push(1, b"HEAD", False, False, False, 2.0)
        self.assertEqual(data_of(events), b"HEADTAIL")
        self.assertIn(EV_CLOSE, kinds(events))
        self.assertNotIn(EV_GAP, kinds(events))
        self.assertTrue(d.closed)


class TestCloseSemantics(unittest.TestCase):
    def test_fin_closes(self):
        d = new_direction()
        d.push(0, b"", True, False, False, 1.0)
        events = d.push(1, b"", False, True, False, 1.0)
        self.assertTrue(d.fin_seen)
        self.assertTrue(d.closed)
        self.assertIn("FIN", d.state_flags)

    def test_rst_closes_and_discards(self):
        d = new_direction()
        d.push(0, b"", True, False, False, 1.0)
        d.push(20, b"ORPHAN", False, False, False, 1.0)     # out of order
        events = d.push(1, b"", False, False, True, 1.0)    # RST
        self.assertIn(EV_CLOSE, kinds(events))
        self.assertEqual(next(p for k, p in events if k == EV_CLOSE), "RST")
        self.assertTrue(d.rst_seen)
        self.assertEqual(d.buffered_bytes, 0)

    def test_data_after_close_is_not_lost_silently(self):
        d = new_direction()
        d.push(0, b"", True, False, False, 1.0)
        d.push(1, b"HI", False, True, False, 1.0)
        self.assertTrue(d.closed)


class TestMemoryLimits(unittest.TestCase):
    def test_per_direction_byte_cap_forces_a_gap(self):
        d = new_direction(buffer_bytes=64, segments=1000)
        d.push(0, b"", True, False, False, 1.0)
        for i in range(40):
            d.push(1000 + i * 16, b"X" * 16, False, False, False, 1.0)
        self.assertLessEqual(d.buffered_bytes, 64 + 16)
        self.assertGreater(d.stats.forced_flushes, 0)

    def test_per_direction_segment_cap_forces_a_gap(self):
        d = new_direction(buffer_bytes=1 << 20, segments=4)
        d.push(0, b"", True, False, False, 1.0)
        for i in range(20):
            d.push(1000 + i * 4, b"Y" * 4, False, False, False, 1.0)
        self.assertLessEqual(len(d.buffer), 5)
        self.assertGreater(d.stats.forced_flushes, 0)


class TestMalformed(unittest.TestCase):
    def test_zero_length_and_flag_only_segments(self):
        d = new_direction()
        self.assertEqual(d.push(10, b"", False, False, False, 1.0), [])
        self.assertEqual(d.push(10, b"", False, False, False, 1.0), [])

    def test_reassembler_ignores_non_tcp_and_missing_flow(self):
        r = TcpReassembler(Config())
        frame = eth_ip_tcp(payload=b"x")
        pkt = decode(frame, 1, 1.0, len(frame))
        r.push(pkt, None)                       # no flow
        self.assertEqual(len(r.streams), 0)
        pkt.proto = "UDP"
        r.push(pkt, object())
        self.assertEqual(len(r.streams), 0)

    def test_truncated_tcp_header_never_reaches_reassembly(self):
        frame = eth_ip_tcp()[:30]
        pkt = decode(frame, 1, 1.0, 60)
        self.assertIsNotNone(pkt.error)
        r = TcpReassembler(Config())
        r.push(pkt, None)
        self.assertEqual(len(r.streams), 0)


class TestBidirectional(unittest.TestCase):
    def setUp(self):
        self.cfg = Config()
        self.delivered = []
        self.gaps = []
        self.closes = []
        self.r = TcpReassembler(
            self.cfg,
            on_data=lambda st, i, d, p, f: self.delivered.append((i, d)),
            on_gap=lambda st, i, n, f: self.gaps.append((i, n)),
            on_close=lambda st, i, why, f: self.closes.append((i, why)))
        self.flows = FlowTable(100)

    def feed(self, ts=1.0, **kw):
        frame = eth_ip_tcp(**kw)
        pkt = decode(frame, 1, ts, len(frame))
        flow = self.flows.update(pkt)
        self.r.push(pkt, flow)
        return pkt

    def test_two_directions_stay_separate(self):
        c = dict(src="10.0.0.1", dst="10.0.0.2", sport=1234, dport=80)
        s = dict(src="10.0.0.2", dst="10.0.0.1", sport=80, dport=1234)
        # Real sequence numbers: the SYN itself consumes one.
        self.feed(**c, flags=SYN, payload=b"", seq=1000)
        self.feed(**s, flags=SYN | ACK, payload=b"", seq=5000)
        self.feed(**c, flags=PSH | ACK, payload=b"REQUEST", seq=1001)
        self.feed(**s, flags=PSH | ACK, payload=b"RESPONSE", seq=5001)

        by_dir = {}
        for index, blob in self.delivered:
            by_dir.setdefault(index, b"")
            by_dir[index] += blob
        self.assertEqual(len(by_dir), 2)
        self.assertEqual(sorted(by_dir.values()), [b"REQUEST", b"RESPONSE"])

    def test_direction_survives_a_late_syn_relabelling_the_client(self):
        """A late SYN can flip flow.client; the half-streams must not swap."""
        s = dict(src="10.0.0.2", dst="10.0.0.1", sport=80, dport=1234)
        c = dict(src="10.0.0.1", dst="10.0.0.2", sport=1234, dport=80)
        self.feed(**s, flags=PSH | ACK, payload=b"SERVER-FIRST", seq=5000)
        self.feed(**c, flags=SYN, payload=b"", seq=1000)
        self.feed(**s, flags=PSH | ACK, payload=b"-MORE", seq=5012)
        server_index = self.delivered[0][0]
        for index, blob in self.delivered:
            if blob.startswith(b"-MORE"):
                self.assertEqual(index, server_index)

    def test_stats_are_exposed(self):
        c = dict(src="10.0.0.1", dst="10.0.0.2", sport=1234, dport=80)
        self.feed(**c, flags=SYN, payload=b"", seq=1000)
        self.feed(**c, flags=PSH | ACK, payload=b"HELLO", seq=1001)
        self.feed(**c, flags=PSH | ACK, payload=b"HELLO", seq=1001)  # retransmit
        st = self.r.stats()
        self.assertEqual(st.streams, 1)
        self.assertEqual(st.streams_created, 1)
        self.assertEqual(st.bytes_reassembled, 5)
        self.assertEqual(st.retransmissions, 1)

    def test_flow_expiration_frees_memory(self):
        c = dict(src="10.0.0.1", dst="10.0.0.2", sport=1234, dport=80)
        self.feed(**c, flags=SYN, payload=b"", seq=1000)
        self.feed(**c, flags=PSH | ACK, payload=b"DATA", seq=1001)
        self.assertEqual(len(self.r.streams), 1)
        # Everything is far older than the idle timeout.
        gone = self.r.expire(now=1.0 + self.r.idle_timeout + 10, force=True)
        self.assertEqual(gone, 1)
        self.assertEqual(len(self.r.streams), 0)
        self.assertEqual(self.r.stats().streams_expired, 1)

    def test_stream_cap_evicts_oldest(self):
        cfg = Config()
        cfg.set("max_streams", 3)
        r = TcpReassembler(cfg)
        flows = FlowTable(100)
        for i in range(10):
            frame = eth_ip_tcp(sport=2000 + i, payload=b"x", flags=PSH | ACK)
            pkt = decode(frame, 1, 1.0, len(frame))
            r.push(pkt, flows.update(pkt))
        self.assertEqual(len(r.streams), 3)
        self.assertEqual(r.stats().streams_evicted, 7)

    def test_global_buffer_ceiling_is_enforced(self):
        cfg = Config()
        cfg.set("reasm_total_buffer_mb", 0)      # ceiling of zero bytes
        cfg.set("reasm_dir_buffer_kb", 1024)
        gaps = []
        r = TcpReassembler(cfg, on_gap=lambda st, i, n, f: gaps.append(n))
        flows = FlowTable(100)
        for i in range(6):
            frame = eth_ip_tcp(sport=3000, payload=b"Z" * 100,
                               flags=PSH | ACK)
            pkt = decode(frame, 1, 1.0, len(frame))
            pkt.seq = 5000 + i * 200             # always out of order
            r.push(pkt, flows.update(pkt))
        self.assertLessEqual(r.stats().buffered_bytes, 0)
        self.assertTrue(gaps, "exceeding the global ceiling must report gaps")


if __name__ == "__main__":
    unittest.main()


class TestRetiredStreamStatistics(unittest.TestCase):
    """A finished connection must keep its reassembly facts after its
    buffers are released - the acceptance run showed they were being lost."""

    def test_summary_survives_expiry(self):
        from netlab.analyze.engine import AnalysisEngine
        from netlab.util.bounded import DropCountingQueue
        from netlab.capture.pcapio import iter_capture_file
        from pathlib import Path

        fixture = Path(__file__).parent / "fixtures" / "http_fragmented.pcapng"
        if not fixture.is_file():
            self.skipTest("fixture missing")

        engine = AnalysisEngine(DropCountingQueue(50000), Config())
        engine.ingest_batch(list(iter_capture_file(fixture)))
        flow = engine.flows.ordered()[0]

        live = engine.stream_summary_for_flow(flow)
        self.assertIsNotNone(live)
        self.assertTrue(live.live)
        live_bytes = sum(d.bytes_delivered for d in live.directions)
        self.assertGreater(live_bytes, 0)

        # Retire every stream, as the idle sweep eventually does.
        engine.reassembler.expire(now=1e12, force=True)
        self.assertEqual(len(engine.reassembler.streams), 0)

        retired = engine.stream_summary_for_flow(flow)
        self.assertIsNotNone(retired, "statistics were lost when the stream "
                                      "was retired")
        self.assertFalse(retired.live)
        self.assertEqual(sum(d.bytes_delivered for d in retired.directions),
                         live_bytes)
        self.assertEqual(engine.relations_for_flow(flow)["summary"], retired)

    def test_closed_streams_are_retired_by_the_idle_sweep(self):
        from netlab.analyze.engine import AnalysisEngine
        from netlab.util.bounded import DropCountingQueue
        from netlab.capture.pcapio import iter_capture_file
        from pathlib import Path

        fixture = Path(__file__).parent / "fixtures" / "http_fragmented.pcapng"
        if not fixture.is_file():
            self.skipTest("fixture missing")
        engine = AnalysisEngine(DropCountingQueue(50000), Config())
        engine.ingest_batch(list(iter_capture_file(fixture)))
        # The fixture's connection closes with FIN on both sides.
        removed = engine.reassembler.expire(force=True)
        self.assertEqual(removed, 1)
        self.assertEqual(engine.stats().streams_expired, 1)
        self.assertIsNotNone(engine.flows.ordered()[0].reasm)
