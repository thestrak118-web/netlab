"""Flow keying, direction inference and host correlation."""

import unittest

from netlab.analyze.devices import NetworkContext
from netlab.analyze.decode import decode
from netlab.analyze.flows import FlowTable, HostTable, make_flow_key
from tests.helpers import eth_ip_tcp, eth_ip_udp


def pkt(**kw):
    frame = eth_ip_tcp(**kw)
    return decode(frame, 1, 1.0, len(frame))


class TestFlowKey(unittest.TestCase):
    def test_both_directions_share_one_key(self):
        a, _ = make_flow_key("TCP", "10.0.0.1", 1234, "10.0.0.2", 80)
        b, _ = make_flow_key("TCP", "10.0.0.2", 80, "10.0.0.1", 1234)
        self.assertEqual(a, b)

    def test_different_ports_are_different_flows(self):
        a, _ = make_flow_key("TCP", "10.0.0.1", 1234, "10.0.0.2", 80)
        b, _ = make_flow_key("TCP", "10.0.0.1", 1235, "10.0.0.2", 80)
        self.assertNotEqual(a, b)


class TestFlowTable(unittest.TestCase):
    def test_syn_decides_the_client_side(self):
        table = FlowTable(100)
        # First packet observed is from the server, mid-conversation.
        table.update(pkt(src="10.0.0.2", dst="10.0.0.1", sport=80,
                         dport=1234, flags=0x10))
        # Then the real SYN arrives and must correct the direction.
        flow = table.update(pkt(src="10.0.0.1", dst="10.0.0.2", sport=1234,
                                dport=80, flags=0x02))
        self.assertEqual(flow.client, "10.0.0.1")
        self.assertEqual(flow.server, "10.0.0.2")
        self.assertEqual(flow.server_port, 80)

    def test_synack_decides_the_server_side(self):
        table = FlowTable(100)
        table.update(pkt(src="10.0.0.2", dst="10.0.0.1", sport=80,
                         dport=1234, flags=0x12))
        flow = table.get(make_flow_key("TCP", "10.0.0.1", 1234,
                                       "10.0.0.2", 80)[0])
        self.assertEqual(flow.server, "10.0.0.2")
        self.assertEqual(flow.state, "ESTABLISHED")

    def test_counters_are_directional(self):
        table = FlowTable(100)
        table.update(pkt(src="10.0.0.1", dst="10.0.0.2", sport=1234,
                         dport=80, flags=0x02))
        table.update(pkt(src="10.0.0.2", dst="10.0.0.1", sport=80,
                         dport=1234, flags=0x12))
        flow = table.get(make_flow_key("TCP", "10.0.0.1", 1234,
                                       "10.0.0.2", 80)[0])
        self.assertEqual(flow.pkts_c2s, 1)
        self.assertEqual(flow.pkts_s2c, 1)
        self.assertEqual(flow.packets, 2)
        self.assertGreater(flow.bytes, 0)

    def test_states(self):
        table = FlowTable(100)
        flow = table.update(pkt(flags=0x02))
        self.assertEqual(flow.state, "SYN_SENT")
        table.update(pkt(src="10.0.0.2", dst="10.0.0.1", sport=80,
                         dport=1234, flags=0x04))
        self.assertEqual(flow.state, "RESET")

    def test_eviction_is_bounded_and_counted(self):
        table = FlowTable(5)
        for i in range(20):
            table.update(pkt(sport=1000 + i))
        self.assertEqual(len(table), 5)
        self.assertEqual(table.evicted, 15)

    def test_ordered_is_creation_order(self):
        table = FlowTable(100)
        for i in range(5):
            table.update(pkt(sport=2000 + i))
        # Touch the first flow again; display order must not change.
        table.update(pkt(sport=2000))
        ordered = table.ordered()
        self.assertEqual([f.client_port for f in ordered],
                         [2000, 2001, 2002, 2003, 2004])


class TestHostTable(unittest.TestCase):
    def test_counts_and_macs(self):
        flows = FlowTable(10)
        hosts = HostTable(10)
        # Ethernet alone identifies a next hop, not an arbitrary IP endpoint.
        # This fixture asserts same-segment attribution, so supply its prefix.
        hosts.apply_context(NetworkContext(addresses=(("10.0.0.99", None, 24),)))
        p = pkt(src="10.0.0.1", dst="10.0.0.2", flags=0x02)
        hosts.update(p, flows.update(p))
        src = hosts.get("10.0.0.1")
        dst = hosts.get("10.0.0.2")
        self.assertEqual(src.pkts_sent, 1)
        self.assertEqual(dst.pkts_recv, 1)
        self.assertEqual(src.mac, "aa:bb:cc:dd:ee:01")
        self.assertTrue(src.local)

    def test_ethernet_without_on_link_evidence_does_not_identify_host(self):
        hosts = HostTable(10)
        hosts.update(pkt(), None)
        self.assertIsNone(hosts.get("10.0.0.1").mac)

    def test_remote_ip_does_not_inherit_gateway_mac(self):
        hosts = HostTable(10)
        hosts.apply_context(NetworkContext(addresses=(("10.0.0.1", None, 24),)))
        hosts.update(pkt(src="8.8.8.8", dst="10.0.0.1"), None)
        self.assertIsNone(hosts.get("8.8.8.8").mac)
        self.assertIsNotNone(hosts.get("10.0.0.1").mac)

    def test_broadcast_mac_is_not_attributed_to_a_host(self):
        flows = FlowTable(10)
        hosts = HostTable(10)
        frame = eth_ip_udp(dmac="ff:ff:ff:ff:ff:ff", dport=67)
        p = decode(frame, 1, 1.0, len(frame))
        hosts.update(p, flows.update(p))
        self.assertIsNone(hosts.get("10.0.0.2").mac)

    def test_listening_port_needs_a_synack(self):
        flows = FlowTable(10)
        hosts = HostTable(10)
        # A bare SYN to a port proves nothing about it being open.
        p = pkt(src="10.0.0.1", dst="10.0.0.2", sport=1234, dport=8080,
                flags=0x02)
        hosts.update(p, flows.update(p))
        self.assertEqual(hosts.get("10.0.0.2").tcp_ports_served, set())
        # The SYN/ACK does.
        p2 = pkt(src="10.0.0.2", dst="10.0.0.1", sport=8080, dport=1234,
                 flags=0x12)
        hosts.update(p2, flows.update(p2))
        self.assertEqual(hosts.get("10.0.0.2").tcp_ports_served, {8080})

    def test_hostnames_are_bounded(self):
        hosts = HostTable(10)
        for i in range(50):
            hosts.add_hostname("10.0.0.9", "name%d.test" % i, 1.0)
        self.assertLessEqual(len(hosts.get("10.0.0.9").hostnames), 16)


if __name__ == "__main__":
    unittest.main()
