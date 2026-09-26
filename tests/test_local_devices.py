"""Local device identities are projections, never every observed endpoint."""
from dataclasses import replace
import pytest
from netlab.analyze.devices import NetworkContext, Confidence, DeviceSnapshot, EndpointSnapshot
from netlab.analyze.monitor import snapshot_for_device
from netlab.gui.pages.devices import DeviceModel
from netlab.gui.pages.topology import TopologyPage
from netlab.gui.pages.monitor import MonitorPage
from netlab.capture.export import export_device_pcap
from netlab.capture.pcapio import iter_capture_file
from netlab.gui.filters import compile_filter
from tests.test_phase3 import app, engine, context
from tests.test_engine import CLIENT, SERVER, build_capture
from tests.test_flows import pkt
from tests.helpers import pcapng_file

OWN_MAC='00:11:22:33:44:55'
PEER_MAC='00:33:44:55:66:77'
V6='fe80::1234'


def configured(engine):
    c=replace(context(),addresses=((CLIENT,OWN_MAC,24),(V6,OWN_MAC,64)))
    engine.hosts.apply_context(c)
    return c


def test_remote_observation_and_dns_answer_are_endpoints_only(engine):
    configured(engine)
    endpoints,_=engine.endpoint_view()
    remote=next(e for e in endpoints if e.ip==SERVER)
    assert isinstance(remote,EndpointSnapshot) and not isinstance(remote,DeviceSnapshot)
    assert remote.packets and remote.hostname=='example.test'
    assert engine.resolve_device(SERVER) is None
    assert all(SERVER not in d.addresses for d in engine.device_view()[0])
    assert engine.relations_for_device(SERVER)['connections']
    assert engine.relations_for_device(SERVER)['dns']


def test_local_prefix_gateway_and_interface_evidence(engine):
    configured(engine)
    devices=engine.device_view()[0]
    own=[d for d in devices if d.device_type=='This Device']
    assert len(own)==1
    assert set(own[0].addresses)=={CLIENT,V6}
    assert own[0].ipv4_addresses==(CLIENT,) and own[0].ipv6_addresses==(V6,)
    assert own[0].identity=='interface:wlan0'
    assert own[0].packets==10
    gateway=[d for d in devices if d.device_type=='Gateway']
    assert len(gateway)==1 and gateway[0].ip=='10.0.0.1'
    assert any(e.source=='Routing table' and e.confidence==Confidence.CONFIRMED for e in gateway[0].evidence)
    unknown=engine.resolve_device('10.0.0.53')
    assert unknown.device_type=='Unknown' and unknown.monitor_eligible
    assert 'on-link prefix' in ' '.join(unknown.local_evidence)


def test_arp_binding_proves_local_without_system_context(engine):
    p=replace(pkt(src='192.168.7.8',dst='192.168.7.1'),proto='ARP',arp_sender_mac=PEER_MAC)
    engine.hosts.update(p,None)
    d=engine.resolve_device('192.168.7.8')
    assert d and d.mac==PEER_MAC and 'Observed ARP address binding' in d.local_evidence
    assert engine.resolve_device('192.168.7.1') is None


def test_ipv6_remote_and_public_onlink_are_evidence_not_ip_range_rules(engine):
    c=configured(engine)
    remote='2001:4860:4860::8888'
    engine.hosts.update(replace(pkt(),src=remote,dst=V6),None)
    assert engine.resolve_device(remote) is None
    assert any(e.ip==remote for e in engine.endpoint_view()[0])
    engine.hosts.apply_context(replace(c,addresses=c.addresses+(('198.51.100.2',OWN_MAC,24),)))
    engine.hosts.update(pkt(src='198.51.100.8',dst=CLIENT),None)
    assert engine.resolve_device('198.51.100.8').monitor_eligible


def test_stable_neighbor_mac_merges_multiple_addresses(engine):
    c=configured(engine)
    peers=('10.0.0.21','10.0.0.22','fe80::21')
    engine.hosts.apply_context(replace(c,neighbors=c.neighbors+tuple((ip,PEER_MAC) for ip in peers)))
    device=engine.resolve_device(peers[0])
    assert set(device.addresses)==set(peers)
    assert all(engine.resolve_device(ip).identity==device.identity for ip in peers)
    assert device.mac_addresses==(PEER_MAC,)
    assert len([d for d in engine.device_view()[0] if d.mac==PEER_MAC])==1


def test_shared_gateway_mac_and_conflicting_bindings_never_merge_peers(engine):
    c=configured(engine)
    gateway_mac=c.neighbors[0][1]
    engine.hosts.apply_context(replace(c,neighbors=c.neighbors+(('10.0.0.2',gateway_mac),('10.0.0.21',PEER_MAC),('10.0.0.22',PEER_MAC))))
    assert engine.resolve_device('10.0.0.2').identity!=engine.resolve_device('10.0.0.1').identity
    engine.hosts.update(pkt(src='10.0.0.21',dst=CLIENT,smac='00:33:44:55:66:88'),None)
    a,b=engine.resolve_device('10.0.0.21'),engine.resolve_device('10.0.0.22')
    assert a.identity!=b.identity
    assert len(a.mac_addresses)==2
    assert a.manufacturer=='Unknown'
    assert engine.resolve_device('10.0.0.2').manufacturer=='Unknown'


def test_hostname_alone_does_not_merge_or_promote(engine):
    configured(engine)
    for ip in ('10.0.0.30','10.0.0.31',SERVER):
        engine.hosts.add_hostname(ip,'same-name.test',1700000001)
    assert engine.resolve_device('10.0.0.30') is None
    for ip in ('10.0.0.30','10.0.0.31'):
        engine.hosts.update(pkt(src=ip,dst=CLIENT,smac='ff:ff:ff:ff:ff:ff'),None)
    assert engine.resolve_device('10.0.0.30').identity!=engine.resolve_device('10.0.0.31').identity
    assert engine.resolve_device(SERVER) is None


def test_monitor_accepts_group_rejects_remote_backend_and_widget(app,engine):
    configured(engine)
    from netlab.analyze.engine import PacketRow
    engine.live.append(PacketRow(100,1700000001,V6,'2001:db8::99','TCP',1000,443,60,'',0,1))
    a=snapshot_for_device(engine,CLIENT)
    b=snapshot_for_device(engine,V6)
    assert a.identity==b.identity and a.activity==b.activity
    assert any(r.src==V6 and r.direction=='OUT' for r in a.activity)
    page=MonitorPage(engine,lambda:None,lambda:True)
    with pytest.raises(ValueError):page.select_device(SERVER)
    with pytest.raises(ValueError):snapshot_for_device(engine,SERVER)
    assert not page.registry.subscriptions
    page.close()


def test_devices_model_enforces_local_filters_and_all_addresses(app,engine):
    configured(engine)
    devices,_=engine.device_view()
    model=DeviceModel();model.replace_items([*devices,*engine.endpoint_view()[0]])
    assert model.rowCount()==len(devices)
    assert all(model.object_at(i).monitor_eligible for i in range(model.rowCount()))
    model.category='Gateway';model.replace_items(devices)
    assert model.rowCount()==1 and model.object_at(0).device_type=='Gateway'
    model.category='Unknown';model.replace_items(devices)
    assert model.rowCount() and all(model.object_at(i).device_type=='Unknown' for i in range(model.rowCount()))
    model.category='All Local';model.replace_items(devices)
    own=engine.resolve_device(CLIENT)
    assert compile_filter('device:'+V6).matches(model.fields(own), '')
    model.category='High Traffic';model.replace_items(devices)
    values=[model.object_at(i).bytes for i in range(model.rowCount())]
    assert values==sorted(values,reverse=True)


def test_topology_separates_remote_nodes_and_never_draws_physical_remote_edges(app,engine):
    configured(engine)
    graph=engine.network_view(1700000001)
    assert SERVER in {e.ip for e in graph.endpoints}
    assert SERVER not in {a for d in graph.devices for a in d.addresses}
    assert sum(d.device_type=='This Device' for d in graph.devices)==1
    assert any(e.kind=='traffic' and SERVER in (e.source,e.destination) for e in graph.edges)
    page=TopologyPage();page.update_snapshot(graph)
    assert page.nodes[SERVER][0].pos().x()>=760
    assert page.nodes[CLIENT][0].pos().x()<760
    assert page.edges and all(key[2]=='route' for key in page.edges)
    assert all(SERVER not in key[:2] for key in page.edges)
    page._remote_selected(SERVER)
    assert set(page.remote_buttons)=={'Traffic','Connections'}
    assert all(b.isEnabled() for b in page.remote_buttons.values())
    page.close()


def test_multi_address_export_preserves_source_packets(engine,tmp_path):
    source=tmp_path/'source.pcapng';target=tmp_path/'selected.pcapng'
    from ipaddress import ip_address
    from tests.helpers import ethernet, ipv6, udp, eth_ip_tcp
    frame=ethernet(OWN_MAC,PEER_MAC,0x86dd,ipv6(ip_address(V6).packed,ip_address('fe80::99').packed,17,udp(1234,9000)))
    unrelated=eth_ip_tcp(src='10.0.0.99',dst=SERVER)
    packets=build_capture()+[(1700000001,len(frame),frame),(1700000002,len(unrelated),unrelated)]
    source.write_bytes(pcapng_file(packets))
    export_device_pcap(source,target,(CLIENT,V6))
    assert [p.data for p in iter_capture_file(target)]==[p[2] for p in packets[:-1]]
    configured(engine)
    engine.ingest_batch(list(iter_capture_file(source))[-2:])
    selected=snapshot_for_device(engine,V6,1700000002)
    assert selected.device.packets==11
    assert len(selected.activity)==11
    assert selected.activity[-1].src==V6
    assert all('10.0.0.99' not in (r.src,r.dst) for r in selected.activity)


def test_gateway_ipv4_and_its_link_local_merge(engine):
    """A router's IPv4 and its own fe80:: (same MAC) are one device, not two.

    Regression: the link-local carried the gateway's MAC, and both the MAC
    observer and the identity grouping used to treat that MAC as a shared
    next-hop and refuse it, so the fe80:: became a separate 'Unknown' device.
    """
    from ipaddress import ip_address
    from netlab.analyze.devices import NetworkContext
    from netlab.capture.pcapio import iter_capture_file
    from tests.helpers import ethernet, ipv6, udp, eth_ip_tcp
    import tempfile, os
    GW, GW_MAC, GW_V6 = '10.0.0.1', '00:aa:bb:cc:dd:ee', 'fe80::abcd'
    OWN, OWN_MAC, OWN_V6 = '10.0.0.50', '00:11:22:33:44:55', 'fe80::50'
    c = NetworkContext(interface='wlan0',
                       addresses=((OWN, OWN_MAC, 24), (OWN_V6, OWN_MAC, 64)),
                       gateways=((OWN, GW),), neighbors=((GW, GW_MAC),), ts=0)
    engine.hosts.apply_context(c)
    f1 = eth_ip_tcp(src=GW, dst=OWN, smac=GW_MAC, dmac=OWN_MAC)
    f2 = ethernet(GW_MAC, OWN_MAC, 0x86dd,
                  ipv6(ip_address(GW_V6).packed, ip_address(OWN_V6).packed,
                       17, udp(546, 547)))
    with tempfile.NamedTemporaryFile(suffix='.pcapng', delete=False) as fh:
        fh.write(pcapng_file([(1.0, len(f1), f1), (1.0, len(f2), f2)]))
        path = fh.name
    try:
        engine.ingest_batch(list(iter_capture_file(path)))
    finally:
        os.unlink(path)
    a = engine.resolve_device(GW)
    b = engine.resolve_device(GW_V6)
    assert a is not None and b is not None
    assert a.identity == b.identity            # merged
    assert a.device_type == 'Gateway'
    assert set(a.addresses) >= {GW, GW_V6}
