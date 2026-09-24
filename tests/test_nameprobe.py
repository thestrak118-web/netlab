"""Native name resolution: NBNS parsing, reverse DNS and the concurrent pass.

No real network is touched -- the socket calls are stubbed, so these pin down
the parsing and orchestration, not connectivity.
"""

import socket
import struct
import unittest
from unittest.mock import patch

from netlab.analyze import nameprobe


def _nbstat_response(names):
    """Build a NBSTAT reply carrying `names` = [(name, suffix, group)]."""
    hdr = struct.pack(">HHHHHH", 0x4E45, 0x8400, 0, 1, 0, 0)
    q = b"\x20" + (b"CK" + b"AA" * 15) + b"\x00" + struct.pack(">HH", 0x21, 1)
    body = bytes([len(names)])
    for name, suffix, group in names:
        flags = 0x8000 if group else 0x0400
        body += name.encode().ljust(15, b" ") + bytes([suffix]) + \
            struct.pack(">H", flags)
    ans = b"\x20" + (b"CK" + b"AA" * 15) + b"\x00" + \
        struct.pack(">HHIH", 0x21, 1, 0, len(body)) + body
    return hdr + q + ans


class TestNbnsParsing(unittest.TestCase):
    def test_unique_workstation_name_is_taken(self):
        resp = _nbstat_response([("WORKGROUP", 0x00, True),
                                 ("MYPC", 0x00, False),
                                 ("MYPC", 0x20, False)])
        self.assertEqual(nameprobe._parse_nbstat(resp), "MYPC")

    def test_group_only_falls_back_but_not_to_a_group_unique(self):
        resp = _nbstat_response([("WORKGROUP", 0x00, True)])
        # Only a group name -- nothing unique to report.
        self.assertIsNone(nameprobe._parse_nbstat(resp))

    def test_garbage_is_rejected(self):
        self.assertIsNone(nameprobe._parse_nbstat(b"not a real packet"))
        self.assertIsNone(nameprobe._parse_nbstat(b""))


class TestReverseDns(unittest.TestCase):
    def test_returns_the_ptr_name(self):
        with patch("socket.gethostbyaddr", return_value=("host.lan", [], [])):
            self.assertEqual(nameprobe.reverse_dns("10.0.0.5"), "host.lan")

    def test_failure_is_none(self):
        with patch("socket.gethostbyaddr", side_effect=socket.herror()):
            self.assertIsNone(nameprobe.reverse_dns("10.0.0.5"))

    def test_an_in_addr_arpa_echo_is_not_a_name(self):
        with patch("socket.gethostbyaddr",
                   return_value=("5.0.0.10.in-addr.arpa", [], [])):
            self.assertIsNone(nameprobe.reverse_dns("10.0.0.5"))

    def test_multicast_is_never_queried(self):
        with patch("socket.gethostbyaddr") as g:
            self.assertIsNone(nameprobe.reverse_dns("224.0.0.251"))
            g.assert_not_called()


class TestResolveNames(unittest.TestCase):
    def test_reverse_dns_wins_and_nbns_is_the_fallback(self):
        def fake_reverse(ip, timeout=1.0):
            return "router" if ip == "10.0.0.1" else None

        def fake_nbns(ip, timeout=1.0):
            return "DESKTOP" if ip == "10.0.0.5" else None

        hits = []
        with patch.object(nameprobe, "reverse_dns", fake_reverse), \
                patch.object(nameprobe, "nbns_query", fake_nbns):
            out = nameprobe.resolve_names(
                ["10.0.0.1", "10.0.0.5", "10.0.0.9"],
                on_name=lambda ip, n, s: hits.append((ip, n, s)))

        self.assertEqual(out["10.0.0.1"], ("router", "reverse DNS"))
        self.assertEqual(out["10.0.0.5"], ("DESKTOP", "NBNS"))
        self.assertNotIn("10.0.0.9", out)          # silent host, no invention
        self.assertEqual(len(hits), 2)

    def test_duplicates_and_multicast_are_dropped(self):
        with patch.object(nameprobe, "reverse_dns", lambda ip, timeout=1.0: "x"), \
                patch.object(nameprobe, "nbns_query", lambda ip, timeout=1.0: None):
            out = nameprobe.resolve_names(["10.0.0.5", "10.0.0.5",
                                           "224.0.0.251"])
        self.assertEqual(set(out), {"10.0.0.5"})


class TestUpnpAndMdnsParsing(unittest.TestCase):
    def test_server_product_token(self):
        self.assertEqual(
            nameprobe._server_product("Linux/3.4 UPnP/1.0 R8000/1.0"), "R8000")
        self.assertIsNone(nameprobe._server_product("Linux/3.4 UPnP/1.0"))

    def test_http_header_extraction(self):
        text = "HTTP/1.1 200 OK\r\nLOCATION: http://10.0.0.1/d.xml\r\nSERVER: x\r\n"
        self.assertEqual(nameprobe._http_header(text, "LOCATION"),
                         "http://10.0.0.1/d.xml")
        self.assertEqual(nameprobe._http_header(text, "MISSING"), "")

    def test_upnp_friendly_name_prefers_friendly_over_model(self):
        xml = (b"<root><device><friendlyName>Living Room TV</friendlyName>"
               b"<modelName>QN55</modelName></device></root>")

        class FakeResp:
            def read(self, n=0):
                return xml

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        with patch("urllib.request.urlopen", return_value=FakeResp()):
            self.assertEqual(
                nameprobe.upnp_friendly_name("http://10.0.0.1/d.xml"),
                "Living Room TV")

    def test_upnp_rejects_non_http(self):
        self.assertIsNone(nameprobe.upnp_friendly_name("ftp://10.0.0.1/d.xml"))

    def test_mdns_hostname_picks_the_device_label(self):
        # A literal 'MacBook-Pro' label with service/protocol tokens around it.
        data = struct.pack(">HHHHHH", 0, 0x8400, 0, 1, 0, 0)
        data += bytes([11]) + b"MacBook-Pro" + bytes([5]) + b"local" + b"\x00"
        self.assertEqual(nameprobe._mdns_hostname(data), "MacBook-Pro")

    def test_mdns_hostname_none_when_only_service_tokens(self):
        data = bytes([9]) + b"_services" + bytes([4]) + b"_tcp" + \
            bytes([5]) + b"local" + b"\x00"
        self.assertIsNone(nameprobe._mdns_hostname(data))


if __name__ == "__main__":
    unittest.main()
