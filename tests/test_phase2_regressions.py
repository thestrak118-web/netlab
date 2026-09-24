"""End-to-end regressions for boundary conditions found in Phase 2 review."""
import unittest
from netlab.analyze.reassembly import TcpDirection, TcpReassembler, EV_DATA, EV_CLOSE, EV_GAP
from netlab.analyze.engine import AnalysisEngine
from netlab.analyze.decode import decode
from netlab.analyze.flows import FlowTable
from netlab.config import Config
from netlab.capture.pcapio import StreamingCaptureParser
from netlab.util.bounded import DropCountingQueue
from tests.helpers import eth_ip_tcp, pcapng_file


class TestPhase2Regressions(unittest.TestCase):
    def test_fin_without_payload_waits_for_missing_tail(self):
        d = TcpDirection(1024, 8)
        d.push(100, b'', True, False, False, 1)
        events = d.push(111, b'', False, True, False, 2)
        self.assertEqual(events, [])
        self.assertFalse(d.closed)
        events = d.push(101, b'0123456789', False, False, False, 3)
        self.assertIn((EV_CLOSE, 'FIN'), events)
        self.assertEqual(d.next_seq, 112)

    def test_syn_payload_is_not_lost(self):
        d = TcpDirection(1024, 8)
        self.assertIn((EV_DATA, b'hello'), d.push(100, b'hello', True, False, False, 1))
        self.assertEqual(d.next_seq, 106)

    def test_covered_buffer_does_not_pin_memory(self):
        d = TcpDirection(1024, 8)
        d.push(0, b'', True, False, False, 1)
        d.push(3, b'cd', False, False, False, 1)
        d.push(10, b'j', False, False, False, 1)
        d.push(1, b'abcdef', False, False, False, 1)
        d.push(11, b'', False, True, False, 2)
        events = d._flush('EXPIRED')
        self.assertIn((EV_GAP, 3), events)
        self.assertIn((EV_DATA, b'j'), events)
        self.assertEqual(d.buffered_bytes, 0)

    def test_eviction_accounting_and_retired_counters(self):
        cfg = Config(); cfg.set('max_streams', 1)
        retired = []
        r = TcpReassembler(cfg, on_retire=lambda st: retired.append(st.summary(False)))
        flows = FlowTable(10)
        for port, seq, payload, flags in [(1000, 0, b'', 2), (1000, 5, b'gap', 24),
                                          (1001, 0, b'', 2)]:
            frame = eth_ip_tcp(sport=port, seq=seq, payload=payload, flags=flags)
            pkt = decode(frame, 1, 1, len(frame))
            r.push(pkt, flows.update(pkt))
        self.assertEqual(r.stats().buffered_bytes, 0)
        self.assertEqual(r.stats().streams_evicted, 1)
        self.assertEqual(r.stats().out_of_order, 1)
        self.assertEqual(r.stats().segments, 1)
        self.assertEqual(len(retired), 1)
        self.assertGreater(r.stats().gaps, 0)

    def test_ack_tracked_and_rst_closes_both_directions(self):
        r = TcpReassembler(Config()); flows = FlowTable(10)
        for flags in (2, 16, 4):
            frame = eth_ip_tcp(flags=flags, seq=1, ack=987, payload=b'')
            pkt = decode(frame, 1, 1, len(frame)); flow = flows.update(pkt)
            r.push(pkt, flow)
        stream = r.get(flow.key)
        self.assertTrue(stream.closed)
        self.assertEqual(stream.directions[0].last_ack, 987)

    def test_one_byte_http_signature_and_empty_body(self):
        request = b'GET / HTTP/1.1\r\nHost: split.test\r\n\r\n'
        response = b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n'
        frames = []
        c = dict(src='10.0.0.1', dst='10.0.0.2', sport=1234, dport=80)
        s = dict(src='10.0.0.2', dst='10.0.0.1', sport=80, dport=1234)
        def add(**kwargs):
            frame = eth_ip_tcp(**kwargs)
            frames.append((1 + len(frames) * .001, len(frame), frame))
        add(**c, seq=0, flags=2, payload=b'')
        add(**s, seq=0, flags=18, payload=b'')
        for endpoint, blob in ((c, request), (s, response)):
            for i, byte in enumerate(blob, 1):
                add(**endpoint, seq=i, flags=24, payload=bytes([byte]))
        engine = AnalysisEngine(DropCountingQueue(100), Config())
        engine.ingest_batch(StreamingCaptureParser().feed(pcapng_file(frames)))
        txns = engine.http_txns.snapshot()
        self.assertEqual(len(txns), 1)
        self.assertEqual(txns[0].host, 'split.test')
        self.assertEqual(txns[0].status, 200)
        self.assertTrue(txns[0].req_body_complete)
        self.assertTrue(txns[0].resp_body_complete)

    def test_interim_response_and_head_keep_pipeline_alignment(self):
        request = (b'HEAD /one HTTP/1.1\r\nHost: test\r\n\r\n'
                   b'GET /two HTTP/1.1\r\nHost: test\r\n\r\n')
        response = (b'HTTP/1.1 100 Continue\r\n\r\n'
                    b'HTTP/1.1 200 OK\r\nContent-Length: 500\r\n\r\n'
                    b'HTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\nok')
        frames = []
        for kwargs in [dict(seq=1, payload=request),
                       dict(src='10.0.0.2', dst='10.0.0.1', sport=80,
                            dport=1234, seq=1, payload=response)]:
            frame = eth_ip_tcp(**kwargs)
            frames.append((1 + len(frames), len(frame), frame))
        engine = AnalysisEngine(DropCountingQueue(100), Config())
        engine.ingest_batch(StreamingCaptureParser().feed(pcapng_file(frames)))
        txns = engine.http_txns.snapshot()
        self.assertEqual([(t.method, t.status) for t in txns], [('HEAD', 200), ('GET', 201)])
        self.assertEqual([t.resp_body_bytes for t in txns], [0, 2])
        self.assertTrue(all(t.resp_body_complete for t in txns))

    def test_real_wlan0_fin_before_response_segments(self):
        from pathlib import Path
        from netlab.capture.pcapio import iter_capture_file
        fixture = Path(__file__).parent / 'fixtures/http_fin_out_of_order.pcapng'
        engine = AnalysisEngine(DropCountingQueue(1000), Config())
        engine.ingest_batch(iter_capture_file(fixture))
        txns = engine.http_txns.snapshot()
        self.assertEqual(len(txns), 2)
        self.assertTrue(all(t.status == 200 and t.resp_body_complete for t in txns))
        self.assertEqual([t.resp_body_bytes for t in txns], [11513, 11513])
        self.assertEqual(engine.stats().stream_gaps, 0)
        self.assertGreater(engine.stats().out_of_order, 0)
        self.assertGreater(engine.stats().retransmissions, 0)
