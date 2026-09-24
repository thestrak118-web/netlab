"""Link, network and transport decoding."""

import unittest

from netlab.analyze.decode import decode
from tests.helpers import (eth_ip_tcp, eth_ip_udp, ethernet, ip4, ipv4, ipv6,
                           mac, tcp, udp)


class TestDecode(unittest.TestCase):
    def test_ethernet_ipv4_tcp(self):
        frame = eth_ip_tcp(src="192.168.1.10", dst="192.168.1.20",
                           sport=51000, dport=443, payload=b"hello",
                           flags=0x18)
        pkt = decode(frame, 1, 1.0, len(frame))
        self.assertIsNone(pkt.error)
        self.assertEqual(pkt.src, "192.168.1.10")
        self.assertEqual(pkt.dst, "192.168.1.20")
        self.assertEqual(pkt.proto, "TCP")
        self.assertEqual(pkt.sport, 51000)
        self.assertEqual(pkt.dport, 443)
        self.assertEqual(pkt.payload, b"hello")
        self.assertIn("PSH", pkt.tcp_flags)
        self.assertIn("ACK", pkt.tcp_flags)
        self.assertEqual(pkt.src_mac, "aa:bb:cc:dd:ee:01")
        self.assertEqual(pkt.ip_version, 4)

    def test_udp(self):
        frame = eth_ip_udp(sport=5353, dport=5353, payload=b"abc")
        pkt = decode(frame, 1, 1.0, len(frame))
        self.assertEqual(pkt.proto, "UDP")
        self.assertEqual(pkt.payload, b"abc")

    def test_tcp_flag_names(self):
        frame = eth_ip_tcp(flags=0x02)
        self.assertEqual(decode(frame, 1, 1.0, len(frame)).tcp_flags, "SYN")
        frame = eth_ip_tcp(flags=0x12)
        self.assertEqual(decode(frame, 1, 1.0, len(frame)).tcp_flags, "SYN,ACK")
        frame = eth_ip_tcp(flags=0x04)
        self.assertEqual(decode(frame, 1, 1.0, len(frame)).tcp_flags, "RST")

    def test_vlan_tag_is_walked(self):
        inner = ipv4("10.1.1.1", "10.1.1.2", 6, tcp(1, 2))
        frame = (mac("aa:bb:cc:dd:ee:02") + mac("aa:bb:cc:dd:ee:01")
                 + b"\x81\x00" + b"\x00\x64" + b"\x08\x00" + inner)
        pkt = decode(frame, 1, 1.0, len(frame))
        self.assertEqual(pkt.vlan, 100)
        self.assertEqual(pkt.src, "10.1.1.1")
        self.assertEqual(pkt.proto, "TCP")

    def test_ipv6_tcp(self):
        src = bytes.fromhex("20010db8" + "00" * 11 + "01")
        dst = bytes.fromhex("20010db8" + "00" * 11 + "02")
        frame = ethernet("aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02", 0x86DD,
                         ipv6(src, dst, 6, tcp(443, 51000)))
        pkt = decode(frame, 1, 1.0, len(frame))
        self.assertEqual(pkt.ip_version, 6)
        self.assertEqual(pkt.src, "2001:db8::1")
        self.assertEqual(pkt.proto, "TCP")
        self.assertEqual(pkt.sport, 443)

    def test_arp(self):
        body = (b"\x00\x01\x08\x00\x06\x04\x00\x01"
                + mac("aa:bb:cc:dd:ee:01") + ip4("10.0.0.1")
                + mac("00:00:00:00:00:00") + ip4("10.0.0.5"))
        frame = ethernet("aa:bb:cc:dd:ee:01", "ff:ff:ff:ff:ff:ff", 0x0806, body)
        pkt = decode(frame, 1, 1.0, len(frame))
        self.assertEqual(pkt.proto, "ARP")
        self.assertEqual(pkt.src, "10.0.0.1")
        self.assertIn("Who has 10.0.0.5", pkt.info)

    def test_icmp(self):
        frame = ethernet("aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02", 0x0800,
                         ipv4("10.0.0.1", "10.0.0.2", 1, b"\x08\x00\x00\x00abc"))
        pkt = decode(frame, 1, 1.0, len(frame))
        self.assertEqual(pkt.proto, "ICMP")
        self.assertIn("Echo request", pkt.info)

    def test_ipv4_fragment_is_flagged_not_guessed(self):
        frag = ipv4("10.0.0.1", "10.0.0.2", 6, b"\x00" * 16, frag_off=185)
        frame = ethernet("aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02", 0x0800, frag)
        pkt = decode(frame, 1, 1.0, len(frame))
        self.assertTrue(pkt.fragmented)
        self.assertIsNone(pkt.sport)          # no transport header present
        self.assertIn("not reassembled", pkt.info)

    def test_truncated_frame_is_reported_not_raised(self):
        frame = eth_ip_tcp()[:18]
        pkt = decode(frame, 1, 1.0, 74)
        self.assertIsNotNone(pkt.error)
        self.assertEqual(pkt.proto, "MALFORMED")

    def test_empty_frame_does_not_raise(self):
        pkt = decode(b"", 1, 1.0, 0)
        self.assertIsNotNone(pkt.error)

    def test_unknown_linktype_is_reported(self):
        pkt = decode(b"\x00" * 40, 999, 1.0, 40)
        self.assertEqual(pkt.proto, "UNSUPPORTED-LINK")

    def test_raw_ip_linktype(self):
        pkt = decode(ipv4("10.0.0.1", "10.0.0.2", 17, udp(53, 53)), 101, 1.0, 40)
        self.assertEqual(pkt.src, "10.0.0.1")
        self.assertEqual(pkt.proto, "UDP")

    def test_ethernet_padding_is_not_counted_as_payload(self):
        """A short TCP segment padded to the 60-byte Ethernet minimum must
        not report the padding as transport payload."""
        frame = eth_ip_tcp(payload=b"hi")
        frame = frame + b"\x00" * (60 - len(frame))
        pkt = decode(frame, 1, 1.0, 60)
        self.assertEqual(pkt.payload, b"hi")


if __name__ == "__main__":
    unittest.main()
