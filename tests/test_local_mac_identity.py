"""Locally generated ARP must not become another device's hardware identity."""
from ipaddress import ip_address

import pytest

from netlab.analyze.devices import NetworkContext, Confidence, Evidence
from netlab.analyze.flows import HostTable
from netlab.analyze.decode import decode
from netlab.analyze.engine import AnalysisEngine
from netlab.config import Config
from netlab.util.bounded import DropCountingQueue
from netlab.capture.pcapio import StreamingCaptureParser
from netlab.intercept.arp import build_arp, mac_bytes, ip_bytes
from netlab.integrations.discovery import DiscoveredHost
from tests.helpers import pcapng_file, ethernet, ipv6, udp

OWN, OWN_MAC = '192.168.1.13', 'f4:7b:09:70:46:26'
GW, GW_MAC = '192.168.1.1', 'e0:d3:62:c7:0c:50'
PEER, PEER_MAC = '192.168.1.5', 'a4:c7:88:03:04:10'
V6 = 'fe80::b974:9f24:2a38:f320'


def context():
    return NetworkContext(interface='wlan0', addresses=(
        (OWN, OWN_MAC, 24), ('fe80::13', OWN_MAC, 64)), gateways=((OWN, GW),),
        neighbors=((GW, GW_MAC), (PEER, PEER_MAC), (V6, PEER_MAC)), ts=1)


def arp(src, smac, dst, dmac):
    return build_arp(2, mac_bytes(smac), ip_bytes(src), mac_bytes(dmac), ip_bytes(dst))


@pytest.mark.parametrize('context_first', [True, False])
def test_own_arp_does_not_split_dual_stack_client(context_first):
    engine = AnalysisEngine(DropCountingQueue(100), Config())
    if context_first:
        engine.hosts.apply_context(context())
    # Genuine binding followed by both locally forged halves of the exchange.
    frames = [arp(PEER, PEER_MAC, OWN, OWN_MAC),
              arp(PEER, OWN_MAC, GW, GW_MAC), arp(GW, OWN_MAC, PEER, PEER_MAC)]
    packets = list(StreamingCaptureParser().feed(pcapng_file(
        [(1.0, len(frame), frame) for frame in frames])))
    engine.ingest_batch(packets)
    if not context_first:
        engine.hosts.apply_context(context())
    client = engine.resolve_device(PEER)
    assert engine.resolve_device(V6).identity == client.identity
    assert client.ipv4_addresses == (PEER,)
    assert client.mac_addresses == (PEER_MAC,)
    assert engine.resolve_device(GW).mac_addresses == (GW_MAC,)
    assert engine.resolve_device(OWN).mac_addresses == (OWN_MAC,)
    assert engine.stats().total_packets == 3  # Claims remain visible as traffic.
    assert len(engine.device_view()[0]) == 3


def test_refresh_removes_only_local_mac_and_its_vendor():
    hosts = HostTable(20)
    hosts.oui.vendors = {'F47B09': 'Intel', 'A4C788': 'Xiaomi'}
    for frame in (arp(PEER, PEER_MAC, OWN, OWN_MAC), arp(PEER, OWN_MAC, GW, GW_MAC)):
        hosts.update(decode(frame, 1, 1, len(frame)), None)
    assert hosts.get(PEER).macs == {PEER_MAC, OWN_MAC}
    hosts.apply_context(context())
    host = hosts.get(PEER)
    assert host.macs == {PEER_MAC} and host.manufacturer == 'Xiaomi'
    assert {e.value for e in host.evidence.values() if e.field == 'Manufacturer'} == {'Xiaomi'}
    # A real conflict with another remote MAC must still prevent forced merging.
    other_mac = '00:33:44:55:66:77'
    frame = arp(PEER, other_mac, GW, GW_MAC)
    hosts.update(decode(frame, 1, 2, len(frame)), None)
    hosts.apply_context(context())
    assert hosts.get(PEER).macs == {PEER_MAC, other_mac}


def test_local_forwarding_mac_is_rejected_for_link_local_ipv6():
    hosts = HostTable(20)
    hosts.apply_context(context())
    frame = ethernet(OWN_MAC, GW_MAC, 0x86dd,
                     ipv6(ip_address(V6).packed, ip_address('fe80::1').packed,
                          17, udp(1234, 5678)))
    hosts.update(decode(frame, 1, 1, len(frame)), None)
    assert hosts.get(V6).macs == {PEER_MAC}


def test_discovery_mac_evidence_cannot_reintroduce_local_forwarder():
    hosts = HostTable(20)
    c = context()
    hosts.apply_context(c)
    record = DiscoveredHost(PEER, OWN_MAC, (
        Evidence('MAC', OWN_MAC, 'Active discovery: neighbour table', Confidence.OBSERVED, 2),), 2)
    hosts.apply_discovery(c, (record,))
    host = hosts.get(PEER)
    assert host.macs == {PEER_MAC}
    assert {e.value for e in host.evidence.values() if e.field == 'MAC'} == {PEER_MAC}
