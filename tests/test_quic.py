"""QUIC Initial SNI extraction.

Modern sites (Instagram, YouTube, Google) run over HTTP/3 (QUIC, UDP 443), so
their SNI never crosses TCP TLS. These tests cover the key derivation against
the RFC 9001 vector, the ClientHello parse, and the across-packet reassembly
that a browser's split ClientHello needs.
"""

import struct
import unittest

from netlab.analyze import quic


def _client_hello(sni: str) -> bytes:
    """A minimal ClientHello handshake message carrying `sni`."""
    name = sni.encode()
    server_name = (struct.pack("!H", 3 + len(name)) + b"\x00"
                   + struct.pack("!H", len(name)) + name)
    ext = struct.pack("!HH", 0x0000, len(server_name)) + server_name
    body = (b"\x03\x03" + b"\x00" * 32          # version + random
            + b"\x00"                            # session id length 0
            + struct.pack("!H", 2) + b"\x13\x01"  # one cipher suite
            + b"\x01\x00"                        # compression: len 1, method 0
            + struct.pack("!H", len(ext)) + ext)  # extensions
    return b"\x01" + struct.pack("!I", len(body))[1:] + body


class TestQuic(unittest.TestCase):
    def test_v1_key_derivation_matches_rfc9001(self):
        dcid = bytes.fromhex("8394c8f03e515708")
        sec = quic._hkdf_extract(quic._V1_SALT, dcid)
        cs = quic._hkdf_expand_label(sec, b"client in", 32)
        self.assertEqual(
            quic._hkdf_expand_label(cs, b"quic key", 16).hex(),
            "1f369613dd76d5467730efcbe3b1a22d")
        self.assertEqual(
            quic._hkdf_expand_label(cs, b"quic iv", 12).hex(),
            "fa044b2f42a3fd3b46fb255c")
        self.assertEqual(
            quic._hkdf_expand_label(cs, b"quic hp", 16).hex(),
            "9f50449e04a0e810283a1e9933adedd2")

    def test_is_initial(self):
        # long header + fixed bit + v1 + Initial type 0
        self.assertTrue(quic.is_initial(b"\xc0\x00\x00\x00\x01\x00\x00"))
        # short header
        self.assertFalse(quic.is_initial(b"\x40\x00\x00\x00\x01\x00\x00"))
        # v1 Handshake type (0x20), not Initial
        self.assertFalse(quic.is_initial(b"\xe0\x00\x00\x00\x01\x00\x00"))
        self.assertFalse(quic.is_initial(b""))

    def test_client_hello_sni(self):
        self.assertEqual(
            quic.client_hello_sni(_client_hello("www.instagram.com")),
            "www.instagram.com")
        self.assertIsNone(quic.client_hello_sni(b"not a handshake"))

    def test_reassemble_orders_fragments(self):
        ch = _client_hello("split.example.com")
        # split it across two CRYPTO fragments, delivered out of order
        mid = 40
        fragments = [(mid, ch[mid:]), (0, ch[:mid])]
        buf = quic.reassemble(fragments)
        self.assertEqual(buf, ch)
        self.assertEqual(quic.client_hello_sni(buf), "split.example.com")

    def test_quicsni_reassembles_across_packets(self):
        """The reassembler completes a ClientHello split over two Initials."""
        ch = _client_hello("youtube.com")
        mid = 50
        dcid = b"\x01\x02\x03\x04"
        q = quic.QuicSni()
        # Feed the reassembler through its own machinery by monkeypatching the
        # per-packet decrypt to return our fragments.
        packets = [(dcid, [(0, ch[:mid])]), (dcid, [(mid, ch[mid:])])]
        idx = [0]

        def fake_initial(_payload):
            r = packets[idx[0]]
            idx[0] += 1
            return r

        orig = quic.initial_crypto
        quic.initial_crypto = fake_initial
        try:
            self.assertIsNone(q.observe(b"pkt1"))     # partial
            self.assertEqual(q.observe(b"pkt2"), "youtube.com")  # completes
        finally:
            quic.initial_crypto = orig


if __name__ == "__main__":
    unittest.main()
