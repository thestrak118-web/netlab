"""Passive device-name extraction from DHCP and NetBIOS."""

from __future__ import annotations

import struct

from netlab.analyze import names
from netlab.analyze.engine import AnalysisEngine
from netlab.config import Config
from netlab.util.bounded import DropCountingQueue


def _dhcp(mac_hex: str, hostname: str, msg_type: int = 1,
          extra_opts: bytes = b"") -> bytes:
    mac = bytes.fromhex(mac_hex.replace(":", ""))
    pkt = bytearray(240)
    pkt[0] = 1                      # op = BOOTREQUEST
    pkt[1] = 1                      # htype = Ethernet
    pkt[2] = 6                      # hlen
    pkt[28:34] = mac                # chaddr
    pkt[236:240] = names.DHCP_MAGIC
    opts = bytes([53, 1, msg_type])
    if hostname:
        h = hostname.encode()
        opts += bytes([12, len(h)]) + h
    opts += extra_opts + bytes([255])
    return bytes(pkt) + opts


def _nbns(name: str, suffix: int = 0x00) -> bytes:
    padded = (name.upper()[:15].ljust(15))[:15].encode("ascii") + bytes([suffix])
    encoded = bytearray()
    for b in padded:
        encoded.append((b >> 4) + 0x41)
        encoded.append((b & 0x0F) + 0x41)
    header = struct.pack(">HHHHHH", 0x1234, 0x2910, 1, 0, 0, 0)  # registration
    return header + bytes([0x20]) + bytes(encoded) + b"\x00" + b"\x00\x20\x00\x01"


# ------------------------------------------------------------------- DHCP

def test_dhcp_hostname_from_discover():
    pkt = _dhcp("aa:bb:cc:dd:ee:ff", "Erwins-iPhone")
    info = names.dhcp_hostname(pkt)
    assert info == ("aa:bb:cc:dd:ee:ff", "Erwins-iPhone")


def test_dhcp_without_hostname_is_none():
    assert names.dhcp_hostname(_dhcp("aa:bb:cc:dd:ee:ff", "")) is None


def test_dhcp_rejects_non_dhcp():
    assert names.dhcp_hostname(b"\x00" * 300) is None
    assert names.dhcp_hostname(b"short") is None


def test_dhcp_fqdn_option_81_plain():
    opt81 = bytes([81, 3 + len("laptop")]) + b"\x00\x00\x00" + b"laptop"
    info = names.dhcp_hostname(_dhcp("11:22:33:44:55:66", "", extra_opts=opt81))
    assert info == ("11:22:33:44:55:66", "laptop")


# ------------------------------------------------------------------ NetBIOS

def test_nbns_name_decode():
    assert names.nbns_name(_nbns("DESKTOP-7F3A")) == "DESKTOP-7F3A"


def test_nbns_rejects_junk():
    assert names.nbns_name(b"\x00" * 8) is None
    assert names.nbns_name(b"\x12\x34\x29\x10" + b"\x00" * 20) is None


# ---------------------------------------------------- engine integration

class Raw:
    def __init__(self, data, ts=1.0):
        self.data, self.ts, self.linktype, self.wirelen = data, ts, 1, len(data)
        self.offset = 0


def _eth_ip_udp(src_mac, dst_mac, src_ip, dst_ip, sport, dport, payload):
    eth = bytes.fromhex(dst_mac.replace(":", "")) + \
        bytes.fromhex(src_mac.replace(":", "")) + b"\x08\x00"
    udp = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload
    ihl_total = 20 + len(udp)
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, ihl_total, 0, 0, 64, 17, 0,
                     bytes(int(x) for x in src_ip.split(".")),
                     bytes(int(x) for x in dst_ip.split(".")))
    return eth + ip + udp


def _local_context(interface="wlan0", ip="10.0.0.28", prefix=24):
    from netlab.analyze.devices import NetworkContext
    return NetworkContext.from_json(
        interface,
        [{"ifname": interface, "address": "00:11:22:33:44:55",
          "addr_info": [{"local": ip, "prefixlen": prefix}]}],
        [], (), "tester", 0)


def test_engine_learns_dhcp_hostname_by_mac_then_binds_to_ip():
    engine = AnalysisEngine(DropCountingQueue(1000), Config())
    # A real capture has an interface context, so LAN peers are on-link and
    # their frame MACs are observed; mirror that here.
    engine.hosts.apply_context(_local_context())
    mac = "de:ad:be:ef:00:11"
    # 1. DHCP DISCOVER from 0.0.0.0 — name learned, bound to the MAC.
    dhcp = _eth_ip_udp(mac, "ff:ff:ff:ff:ff:ff", "0.0.0.0", "255.255.255.255",
                       68, 67, _dhcp(mac, "Galaxy-S21"))
    # 2. Later traffic from that MAC at a real IP binds the name to the IP.
    later = _eth_ip_udp(mac, "00:11:22:33:44:55", "10.0.0.42", "10.0.0.1",
                        50000, 443, b"\x17\x03\x03\x00\x10payloadpayload!!")
    engine.ingest_batch([Raw(dhcp), Raw(later)])
    host = engine.hosts.get("10.0.0.42")
    assert host is not None
    names_seen = {e.value for e in host.evidence.values()
                  if e.field == "Hostname"}
    assert "Galaxy-S21" in names_seen


def test_engine_learns_nbns_name_from_source_ip():
    engine = AnalysisEngine(DropCountingQueue(1000), Config())
    nb = _eth_ip_udp("aa:aa:aa:bb:bb:bb", "ff:ff:ff:ff:ff:ff",
                     "10.0.0.7", "10.0.0.255", 137, 137, _nbns("OFFICE-PC"))
    engine.ingest_batch([Raw(nb)])
    host = engine.hosts.get("10.0.0.7")
    assert host is not None
    assert "OFFICE-PC" in {e.value for e in host.evidence.values()
                           if e.field == "Hostname"}


# --------------------------------------------------------------- OS hints

def test_dhcp_os_from_vendor_class():
    opt60 = bytes([60, len(b"MSFT 5.0")]) + b"MSFT 5.0"
    assert names.dhcp_os(_dhcp("aa:bb:cc:dd:ee:ff", "", extra_opts=opt60)) == "Windows"
    a = bytes([60, len(b"android-dhcp-13")]) + b"android-dhcp-13"
    assert names.dhcp_os(_dhcp("aa:bb:cc:dd:ee:ff", "", extra_opts=a)) == "Android"


def test_os_from_user_agent():
    assert names.os_from_user_agent("Mozilla/5.0 (Windows NT 10.0; Win64)") == "Windows"
    assert names.os_from_user_agent("Dalvik/2.1 (Linux; U; Android 13; Pixel)") == "Android"
    assert names.os_from_user_agent("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0)") == "iOS"
    assert names.os_from_user_agent("curl/8.0") == ""


def test_os_from_hostname():
    assert names.os_from_hostname("DESKTOP-7F3A") == "Windows"
    assert names.os_from_hostname("android-9a8b") == "Android"
    assert names.os_from_hostname("Erwins-iPhone") == "iOS"


def test_engine_learns_os_from_dhcp_vendor_class():
    engine = AnalysisEngine(DropCountingQueue(1000), Config())
    engine.hosts.apply_context(_local_context())
    mac = "de:ad:be:ef:22:33"
    opt60 = bytes([60, len(b"MSFT 5.0")]) + b"MSFT 5.0"
    dhcp = _eth_ip_udp(mac, "ff:ff:ff:ff:ff:ff", "0.0.0.0", "255.255.255.255",
                       68, 67, _dhcp(mac, "DESKTOP-ABC", extra_opts=opt60))
    later = _eth_ip_udp(mac, "00:11:22:33:44:55", "10.0.0.51", "10.0.0.1",
                        50000, 443, b"\x17\x03\x03\x00\x10xxxxxxxxxxxxxxxx")
    engine.ingest_batch([Raw(dhcp), Raw(later)])
    host = engine.hosts.get("10.0.0.51")
    assert host is not None
    assert "Windows" in {e.value for e in host.evidence.values() if e.field == "OS"}


def test_os_from_ttl():
    assert names.os_from_ttl(64) == "Unix"
    assert names.os_from_ttl(61) == "Unix"      # a few hops away
    assert names.os_from_ttl(128) == "Windows"
    assert names.os_from_ttl(120) == "Windows"
    assert names.os_from_ttl(255) == "Network device"
    assert names.os_from_ttl(0) == "" and names.os_from_ttl(None) == ""
