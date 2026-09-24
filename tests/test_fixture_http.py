"""Integration test against a real capture with heavily fragmented HTTP.

`tests/fixtures/http_fragmented.pcapng` was produced by dumpcap on a real
loopback TCP connection where both peers wrote in many small pieces with
TCP_NODELAY set. The header block, the header terminator (the CRLF is split
across two segments) and the chunked body all straddle segment boundaries,
so nothing here can be parsed without real reassembly.
"""

import unittest
from pathlib import Path

from netlab.analyze.engine import AnalysisEngine
from netlab.capture.pcapio import iter_capture_file, probe_capture_file
from netlab.config import Config
from netlab.util.bounded import DropCountingQueue

FIXTURE = Path(__file__).parent / "fixtures" / "http_fragmented.pcapng"


@unittest.skipUnless(FIXTURE.is_file(), "fixture missing")
class TestFragmentedHttpFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = AnalysisEngine(DropCountingQueue(50000), Config())
        cls.packets = list(iter_capture_file(FIXTURE))
        cls.engine.ingest_batch(cls.packets)
        cls.stats = cls.engine.stats()

    def test_fixture_is_a_real_capture(self):
        info = probe_capture_file(FIXTURE)
        self.assertEqual(info["format"], "pcapng")
        self.assertEqual(info["linktype"], 1)
        self.assertGreater(len(self.packets), 20)

    def test_the_payload_really_is_fragmented(self):
        """Guard the premise: if this stops being fragmented the test is void."""
        sizes = [len(p.data) for p in self.packets]
        self.assertGreater(len(sizes), 20)
        payload_segments = [
            row for row in self.engine.live.snapshot()
            if row.proto == "TCP" and "Len=" in row.info
            and not row.info.endswith("Len=0")
        ]
        self.assertGreaterEqual(len(payload_segments), 15)
        # At least one segment carrying a single byte.
        self.assertTrue(any("Len=1" in r.info for r in payload_segments),
                        "expected a 1-byte segment in the fixture")

    def test_everything_parsed_cleanly(self):
        self.assertEqual(self.stats.malformed, 0)
        self.assertEqual(self.stats.queue_dropped, 0)
        self.assertEqual(self.stats.stream_gaps, 0)
        self.assertGreater(self.stats.reassembled_bytes, 0)
        self.assertEqual(self.stats.streams, 1)

    def test_request_reassembled_across_segments(self):
        txns = self.engine.http_txns.snapshot()
        self.assertEqual(len(txns), 1)
        txn = txns[0]
        self.assertEqual(txn.method, "POST")
        self.assertEqual(txn.path, "/upload")
        # The Host header value was itself split across segments.
        self.assertEqual(txn.host, "fragment.test")
        self.assertEqual(txn.user_agent, "netlab-frag/1.0")
        # "Content-Len" / "gth: 26" arrived as two segments.
        self.assertEqual(txn.req_content_length, "26")
        self.assertEqual(txn.req_body_bytes, 26)
        self.assertTrue(txn.req_body_complete)

    def test_response_and_chunked_body_metadata(self):
        txn = self.engine.http_txns.snapshot()[0]
        self.assertEqual(txn.status, 200)
        self.assertEqual(txn.reason, "OK")
        self.assertEqual(txn.content_type, "application/json")
        self.assertEqual(txn.server_header, "netlab-frag-server")
        self.assertEqual(txn.resp_transfer, "chunked")
        self.assertEqual(txn.resp_chunks, 3)
        self.assertEqual(txn.resp_body_bytes, 15)   # hello + " world" + !!!!
        self.assertTrue(txn.resp_body_complete)

    def test_request_and_response_are_correlated(self):
        txn = self.engine.http_txns.snapshot()[0]
        self.assertIsNotNone(txn.duration_ms)
        self.assertGreater(txn.duration_ms, 0)
        self.assertEqual(txn.client_port and txn.server_port and 1, 1)
        self.assertEqual(txn.server_port, 18099)

    def test_credentials_in_the_real_capture_are_not_retained(self):
        txn = self.engine.http_txns.snapshot()[0]
        self.assertTrue(txn.req_has_cookie)
        self.assertTrue(txn.resp_has_set_cookie)
        blob = repr(txn)
        self.assertNotIn("should-not-be-stored", blob)

    def test_cookie_and_body_are_not_retained_even_when_harvesting(self):
        """The fixture's request Cookie, response Set-Cookie and both bodies
        are all the sentinel "should-not-be-stored". Turning harvesting on must
        still not keep them: the request Cookie is not a session token and the
        text/plain body is not a form, so nothing here is a credential."""
        from netlab.analyze import http as httpmod
        cfg = Config()
        cfg.set("harvest_credentials", True)
        try:
            engine = AnalysisEngine(DropCountingQueue(50000), cfg)
            engine.ingest_batch(list(iter_capture_file(FIXTURE)))
            creds = engine.credentials.snapshot()
            self.assertEqual(creds, [],
                             "nothing in this capture is a real credential")
            txn = engine.http_txns.snapshot()[0]
            # Presence is still reported...
            self.assertTrue(txn.req_has_cookie)
            self.assertTrue(txn.resp_has_set_cookie)
            # ...but the sentinel value appears nowhere it was harvested to.
            self.assertNotIn("should-not-be-stored", repr(txn) + repr(creds))
        finally:
            httpmod.set_retain_sensitive(False)     # reset the module global

    def test_flow_and_host_correlation(self):
        flows = self.engine.flows.ordered()
        self.assertEqual(len(flows), 1)
        flow = flows[0]
        self.assertEqual(flow.app_proto, "HTTP")
        self.assertEqual(flow.server_port, 18099)
        # The capture covers the whole connection, so it ends closed.
        self.assertTrue(flow.saw_syn, "SYN should have been observed")
        self.assertTrue(flow.saw_synack, "SYN/ACK should have been observed")
        self.assertTrue(flow.saw_fin, "the connection closes in this capture")
        self.assertFalse(flow.saw_rst)
        self.assertEqual(flow.state, "CLOSING")
        self.assertGreater(flow.pkts_c2s, 0)
        self.assertGreater(flow.pkts_s2c, 0)
        self.assertEqual(flow.service, "fragment.test")

        host = self.engine.hosts.get("127.0.0.1")
        self.assertIsNotNone(host)
        self.assertIn("fragment.test", host.http_names)
        self.assertNotIn("fragment.test", host.dns_names)

    def test_reassembly_statistics_are_reported(self):
        st = self.stats
        self.assertGreater(st.reassembly_segments, 15)
        self.assertGreaterEqual(st.http_messages, 2)
        self.assertEqual(st.http_resyncs, 0)
        self.assertEqual(st.out_of_order, 0)

    def test_without_reassembly_the_same_capture_cannot_be_parsed(self):
        """Shows the fixture genuinely requires reassembly."""
        cfg = Config()
        cfg.set("tcp_reassembly", False)
        engine = AnalysisEngine(DropCountingQueue(50000), cfg)
        engine.ingest_batch(list(iter_capture_file(FIXTURE)))
        txns = engine.http_txns.snapshot()
        complete = [t for t in txns
                    if t.host == "fragment.test" and t.status == 200]
        self.assertEqual(
            complete, [],
            "per-packet parsing should not be able to recover this request")


if __name__ == "__main__":
    unittest.main()
