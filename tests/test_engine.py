"""End-to-end: a synthetic capture file through the whole analysis engine."""

import tempfile
import unittest
from pathlib import Path

from netlab.analyze.engine import AnalysisEngine
from netlab.capture.pcapio import iter_capture_file
from netlab.config import Config
from netlab.util.bounded import DropCountingQueue
from tests.helpers import (HTTP_200, HTTP_GET, dns_query, dns_response,
                           eth_ip_tcp, eth_ip_udp, pcapng_file,
                           tls_client_hello, tls_server_hello)

CLIENT, SERVER, RESOLVER = "10.0.0.10", "93.184.216.34", "10.0.0.53"


def build_capture() -> list:
    """A capture containing DNS, cleartext HTTP and a TLS handshake.

    Sequence numbers are realistic: each SYN consumes one, and each side
    advances by the bytes it sent. Reassembly depends on this, so the fixture
    has to behave like a real endpoint rather than reusing seq=1 everywhere.
    """
    t = 1_700_000_000.0

    # HTTP conversation on port 80.
    http_c, http_s = 1000, 5000
    # TLS conversation on port 443.
    tls_c, tls_s = 2000, 6000

    frames = [
        # DNS lookup
        (t + 0.00, eth_ip_udp(src=CLIENT, dst=RESOLVER, sport=40000, dport=53,
                              payload=dns_query("example.test"))),
        (t + 0.01, eth_ip_udp(src=RESOLVER, dst=CLIENT, sport=53, dport=40000,
                              payload=dns_response("example.test", SERVER))),
        # TCP handshake (SYN consumes one sequence number each way)
        (t + 0.02, eth_ip_tcp(src=CLIENT, dst=SERVER, sport=51000, dport=80,
                              flags=0x02, seq=http_c)),
        (t + 0.03, eth_ip_tcp(src=SERVER, dst=CLIENT, sport=80, dport=51000,
                              flags=0x12, seq=http_s)),
        # Cleartext HTTP request/response
        (t + 0.04, eth_ip_tcp(src=CLIENT, dst=SERVER, sport=51000, dport=80,
                              payload=HTTP_GET, seq=http_c + 1)),
        (t + 0.09, eth_ip_tcp(src=SERVER, dst=CLIENT, sport=80, dport=51000,
                              payload=HTTP_200, seq=http_s + 1)),
        # TLS handshake on a separate flow
        (t + 0.10, eth_ip_tcp(src=CLIENT, dst=SERVER, sport=51001, dport=443,
                              flags=0x02, seq=tls_c)),
        (t + 0.11, eth_ip_tcp(src=SERVER, dst=CLIENT, sport=443, dport=51001,
                              flags=0x12, seq=tls_s)),
        (t + 0.12, eth_ip_tcp(src=CLIENT, dst=SERVER, sport=51001, dport=443,
                              payload=tls_client_hello("example.test"),
                              seq=tls_c + 1)),
        (t + 0.13, eth_ip_tcp(src=SERVER, dst=CLIENT, sport=443, dport=51001,
                              payload=tls_server_hello(), seq=tls_s + 1)),
    ]
    return [(ts, len(data), data) for ts, data in frames]


class TestEngineIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.NamedTemporaryFile(suffix=".pcapng", delete=False)
        cls.tmp.write(pcapng_file(build_capture()))
        cls.tmp.close()
        cls.path = Path(cls.tmp.name)

        cls.engine = AnalysisEngine(DropCountingQueue(10000), Config())
        cls.engine.ingest_batch(list(iter_capture_file(cls.path)))
        cls.stats = cls.engine.stats()

    @classmethod
    def tearDownClass(cls):
        cls.path.unlink(missing_ok=True)

    def test_every_packet_was_analysed(self):
        self.assertEqual(self.stats.total_packets, 10)
        self.assertEqual(self.stats.malformed, 0)
        self.assertEqual(self.stats.queue_dropped, 0)

    def test_flows_were_correlated(self):
        # DNS/UDP, HTTP/TCP and TLS/TCP
        self.assertEqual(self.stats.flows, 3)
        apps = sorted(f.app_proto for f in self.engine.flows.ordered()
                      if f.app_proto)
        self.assertEqual(apps, ["DNS", "HTTP", "TLS"])

    def test_hosts_were_discovered(self):
        self.assertEqual(self.stats.hosts, 3)
        server = self.engine.hosts.get(SERVER)
        self.assertIsNotNone(server)
        self.assertIn("example.test", server.hostnames)
        self.assertEqual(server.tcp_ports_served, {80, 443})

    def test_dns_events(self):
        self.assertEqual(self.stats.dns_events, 2)
        events = self.engine.dns_events.snapshot()
        self.assertEqual(events[0].kind, "query")
        self.assertEqual(events[1].resolved_ips, [SERVER])

    def test_http_transaction_was_correlated(self):
        self.assertEqual(self.stats.http_transactions, 1)
        txn = self.engine.http_txns.snapshot()[0]
        self.assertEqual(txn.method, "GET")
        self.assertEqual(txn.host, "example.test")
        self.assertEqual(txn.path, "/index.html")
        self.assertEqual(txn.status, 200)
        self.assertEqual(txn.content_type, "text/html; charset=utf-8")
        self.assertIsNotNone(txn.duration_ms)
        self.assertGreater(txn.duration_ms, 0)

    def test_http_credentials_are_not_retained_anywhere(self):
        txn = self.engine.http_txns.snapshot()[0]
        self.assertTrue(txn.req_has_auth)
        self.assertTrue(txn.req_has_cookie)
        self.assertTrue(txn.resp_has_set_cookie)
        blob = repr(txn)
        self.assertNotIn("do-not-store", blob)
        self.assertNotIn("should-not-be-stored", blob)

    def test_tls_metadata_without_decryption(self):
        self.assertEqual(self.stats.tls_sessions, 1)
        sess = self.engine.tls_order.snapshot()[0]
        self.assertEqual(sess.sni, "example.test")
        self.assertEqual(sess.cipher_suite,
                         "ECDHE_RSA_WITH_AES_256_GCM_SHA384")
        self.assertEqual(sess.negotiated_version, "TLS 1.2")
        self.assertEqual(sess.alpn_offered, ["h2", "http/1.1"])
        self.assertTrue(sess.encrypted)
        # No certificate was sent in this capture, so it must stay absent.
        self.assertIsNone(sess.cert_subject_cn)
        self.assertEqual(sess.cert_availability, "not observed")

    def test_live_rows_carry_offsets_that_resolve(self):
        from netlab.capture.pcapio import RandomAccessCapture
        reader = RandomAccessCapture(self.path)
        rows = self.engine.live.snapshot()
        self.assertEqual(len(rows), 10)
        for row in rows:
            self.assertIsNotNone(reader.read_at(row.offset))

    def test_reset_clears_everything(self):
        engine = AnalysisEngine(DropCountingQueue(1000), Config())
        engine.ingest_batch(list(iter_capture_file(self.path)))
        self.assertGreater(engine.stats().total_packets, 0)
        engine.reset()
        stats = engine.stats()
        self.assertEqual(stats.total_packets, 0)
        self.assertEqual(stats.flows, 0)
        self.assertEqual(stats.hosts, 0)
        self.assertEqual(stats.dns_events, 0)
        self.assertEqual(len(engine.live), 0)


if __name__ == "__main__":
    unittest.main()
