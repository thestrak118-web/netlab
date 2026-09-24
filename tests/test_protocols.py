"""DNS, HTTP and TLS extraction."""

import unittest

from netlab.analyze import http as httpmod
from netlab.analyze import tls as tlsmod
from netlab.analyze.dns import extract_from_tcp, extract_from_udp
from tests.helpers import (HTTP_200, HTTP_GET, dns_query, dns_response,
                           tls_client_hello, tls_server_hello)


class TestDns(unittest.TestCase):
    def test_query(self):
        evt = extract_from_udp(dns_query("example.com"), 1.0, "10.0.0.1",
                               "10.0.0.53", 40000, 53)
        self.assertIsNotNone(evt)
        self.assertEqual(evt.kind, "query")
        self.assertEqual(evt.qname, "example.com")
        self.assertEqual(evt.qtype, "A")
        self.assertIsNone(evt.rcode)

    def test_response_with_compression_pointer(self):
        evt = extract_from_udp(dns_response("example.com", "93.184.216.34"),
                               1.0, "10.0.0.53", "10.0.0.1", 53, 40000)
        self.assertEqual(evt.kind, "response")
        self.assertEqual(evt.rcode, "NOERROR")
        self.assertEqual(evt.resolved_ips, ["93.184.216.34"])
        self.assertEqual(evt.answers[0].name, "example.com")
        self.assertEqual(evt.answers[0].rtype, "A")
        self.assertEqual(evt.answers[0].ttl, 300)

    def test_aaaa_type_name(self):
        evt = extract_from_udp(dns_query("example.com", qtype=28), 1.0,
                               "10.0.0.1", "10.0.0.53", 40000, 53)
        self.assertEqual(evt.qtype, "AAAA")

    def test_mdns_is_labelled(self):
        evt = extract_from_udp(dns_query("printer.local"), 1.0, "10.0.0.1",
                               "224.0.0.251", 5353, 5353)
        self.assertEqual(evt.protocol, "mDNS")

    def test_dns_over_tcp_length_prefix(self):
        body = dns_query("example.com")
        payload = len(body).to_bytes(2, "big") + body
        evt = extract_from_tcp(payload, 1.0, "10.0.0.1", "10.0.0.53", 40000, 53)
        self.assertEqual(evt.qname, "example.com")
        self.assertEqual(evt.transport, "TCP")

    def test_garbage_is_rejected(self):
        self.assertIsNone(extract_from_udp(b"\x00" * 4, 1.0, "a", "b", 1, 53))
        self.assertIsNone(extract_from_udp(b"", 1.0, "a", "b", 1, 53))

    def test_compression_loop_does_not_hang(self):
        # A pointer that points at itself must be rejected, not looped on.
        evil = bytearray(dns_query("a.b"))
        evil[12] = 0xC0
        evil[13] = 12
        evt = extract_from_udp(bytes(evil), 1.0, "a", "b", 1, 53)
        self.assertTrue(evt is None or evt.qname is None)


class TestHttp(unittest.TestCase):
    def test_request_parsing(self):
        msg = httpmod.parse_message(HTTP_GET)
        self.assertEqual(msg.kind, "request")
        self.assertEqual(msg.method, "GET")
        self.assertEqual(msg.target, "/index.html")
        self.assertEqual(msg.headers["host"], "example.test")
        self.assertEqual(msg.headers["user-agent"], "netlab-tests/1.0")
        self.assertFalse(msg.headers_truncated)

    def test_credential_headers_are_flagged_but_never_stored(self):
        msg = httpmod.parse_message(HTTP_GET)
        self.assertTrue(msg.has_auth_header)
        self.assertTrue(msg.has_cookie_header)
        self.assertNotIn("authorization", msg.headers)
        self.assertNotIn("cookie", msg.headers)
        blob = repr(msg)
        self.assertNotIn("do-not-store", blob)
        self.assertNotIn("should-not-be-stored", blob)

    def test_response_parsing(self):
        msg = httpmod.parse_message(HTTP_200)
        self.assertEqual(msg.kind, "response")
        self.assertEqual(msg.status, 200)
        self.assertEqual(msg.reason, "OK")
        self.assertEqual(msg.headers["content-length"], "42")
        self.assertTrue(msg.has_cookie_header)
        self.assertNotIn("set-cookie", msg.headers)

    def test_truncated_headers_are_flagged(self):
        msg = httpmod.parse_message(HTTP_GET[:40])
        self.assertIsNotNone(msg)
        self.assertTrue(msg.headers_truncated)

    def test_non_http_is_rejected(self):
        self.assertFalse(httpmod.looks_like_http(b"\x16\x03\x01\x00\x50abcdefghij"))
        self.assertIsNone(httpmod.parse_message(b"GETTING started here now"))
        self.assertIsNone(httpmod.parse_message(b"\x00" * 64))


class TestTls(unittest.TestCase):
    def test_client_hello_sni_and_alpn(self):
        sess = tlsmod.TlsSession(ts=1.0, flow_key=(), client="c", server="s",
                                 client_port=1, server_port=443)
        self.assertTrue(tlsmod.feed_payload(tls_client_hello("example.test"),
                                            sess, True))
        self.assertEqual(sess.sni, "example.test")
        self.assertEqual(sess.alpn_offered, ["h2", "http/1.1"])
        self.assertEqual(sess.client_version, "TLS 1.2")
        self.assertEqual(sess.cipher_count_offered, 2)
        self.assertTrue(sess.saw_client_hello)

    def test_server_hello_cipher_name(self):
        sess = tlsmod.TlsSession(ts=1.0, flow_key=(), client="c", server="s",
                                 client_port=1, server_port=443)
        tlsmod.feed_payload(tls_server_hello(cipher=0xC030), sess, False)
        self.assertEqual(sess.cipher_suite, "ECDHE_RSA_WITH_AES_256_GCM_SHA384")
        self.assertEqual(sess.negotiated_version, "TLS 1.2")
        self.assertTrue(sess.saw_server_hello)

    def test_unobserved_fields_stay_none(self):
        """Nothing may be invented for a session we only partly saw."""
        sess = tlsmod.TlsSession(ts=1.0, flow_key=(), client="c", server="s",
                                 client_port=1, server_port=443)
        tlsmod.feed_payload(tls_client_hello("example.test"), sess, True)
        self.assertIsNone(sess.cipher_suite)
        self.assertIsNone(sess.cert_subject_cn)
        self.assertIsNone(sess.negotiated_version)
        self.assertEqual(sess.cert_availability, "not observed")

    def test_tls13_certificate_reported_as_encrypted(self):
        sess = tlsmod.TlsSession(ts=1.0, flow_key=(), client="c", server="s",
                                 client_port=1, server_port=443)
        tlsmod.feed_payload(tls_server_hello(), sess, False)
        sess.negotiated_version = "TLS 1.3"
        self.assertEqual(sess.cert_availability, "encrypted (TLS 1.3)")
        self.assertIsNone(sess.cert_subject_cn)

    def test_application_data_is_counted_never_read(self):
        sess = tlsmod.TlsSession(ts=1.0, flow_key=(), client="c", server="s",
                                 client_port=1, server_port=443)
        record = b"\x17\x03\x03" + (32).to_bytes(2, "big") + b"S" * 32
        tlsmod.feed_payload(record, sess, True)
        self.assertEqual(sess.app_data_records, 1)
        self.assertEqual(sess.app_data_bytes, 32)
        self.assertTrue(sess.encrypted)

    def test_handshake_gate_rejects_random_binary(self):
        self.assertFalse(tlsmod.is_handshake_start(b"\x16\x03\x01\x00\x50\x63"))
        self.assertTrue(tlsmod.is_handshake_start(tls_client_hello("a.test")))
        self.assertTrue(tlsmod.is_handshake_start(tls_server_hello()))

    def test_malformed_handshake_does_not_raise(self):
        sess = tlsmod.TlsSession(ts=1.0, flow_key=(), client="c", server="s",
                                 client_port=1, server_port=443)
        tlsmod.feed_payload(b"\x16\x03\x01\x00\x08\x01\x00\xff\xff\x00\x00\x00\x00",
                            sess, True)
        self.assertIsNone(sess.sni)


if __name__ == "__main__":
    unittest.main()
