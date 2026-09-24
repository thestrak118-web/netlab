"""Discovery identity is scoped, evidenced and independent of passive counts."""
from dataclasses import replace
import pytest
from netlab.analyze.devices import Confidence, Evidence
from netlab.integrations.discovery import parse_discovery, discovery_targets, DiscoveredHost, clean
from netlab.gui.pages.devices import DevicesPage
from netlab.gui.device_icons import icon_name
from tests.test_phase3 import app, engine, context
from tests.test_local_devices import configured
from tests.test_flows import pkt
from tests.test_engine import CLIENT


XML = '''<nmaprun><host><status state="up" reason="arp-response"/>
<address addr="10.0.0.21" addrtype="ipv4"/><address addr="02:11:22:33:44:55" addrtype="mac"/>
<ports><port protocol="udp" portid="5353"><script id="dns-service-discovery" output="&#10;7000/tcp airplay:&#10; name: MacBook Pro&#10; hostname: MacBook-Pro.local&#10; model=Mac15,6&#10;"/></port></ports>
<os><osmatch name="Apple macOS or iOS" accuracy="98"/></os></host></nmaprun>'''


def test_advertised_identity_not_vendor_guess(engine, app):
    c=configured(engine)
    records=parse_discovery(XML,c,1700000001)
    assert len(records)==1
    engine.hosts.apply_discovery(c,records)
    d=engine.resolve_device('10.0.0.21',1700000002)
    assert d.model=='Mac15,6' and d.display_name=='MacBook Pro'
    assert d.hostname=='MacBook-Pro.local' and d.device_type=='Laptop'
    assert d.os=='Unknown' and '98%' in d.attribute('OS estimate')
    assert d.packets==0 and d.bytes==0 and d.status=='Discovered'
    assert d.manufacturer=='Unknown' and d.monitor_eligible
    assert icon_name(d.device_type)=='laptop'
    assert any(e.confidence==Confidence.INFERRED for e in d.evidence)
    page=DevicesPage();page.engine=engine;page.refresh(engine.device_view(1700000002)[0])
    assert page.select_device(d.ip)
    assert 'Mac15,6' in page.detail.text.toPlainText()
    assert 'Active discovery: mDNS' in page.detail.text.toPlainText()
    assert 'MacBook Pro' in page.model.cell(d,0)
    assert not page.model.data(page.model.index(0,0)) is None
    page.close()


def test_scan_never_promotes_remote_or_off_interface(engine):
    c=configured(engine)
    assert not parse_discovery(XML.replace('10.0.0.21','104.18.32.47'),c)
    record=parse_discovery(XML,c,1700000001)[0]
    engine.hosts.apply_discovery(replace(c,interface='eth9'),(record,))
    assert engine.resolve_device(record.ip) is None
    engine.hosts.apply_discovery(c,(replace(record,ip='104.18.32.47'),))
    assert engine.resolve_device('104.18.32.47') is None


def test_name_does_not_merge_distinct_macs(engine):
    c=configured(engine);a=parse_discovery(XML,c,1700000001)[0]
    b=replace(a,ip='10.0.0.22',mac='02:11:22:33:44:66',evidence=tuple(replace(e,value='10.0.0.22') if e.field=='IP' else replace(e,value='02:11:22:33:44:66') if e.field=='MAC' else e for e in a.evidence))
    engine.hosts.apply_discovery(c,(a,b))
    assert engine.resolve_device(a.ip).identity != engine.resolve_device(b.ip).identity


def test_changed_mac_does_not_inherit_model(engine):
    c=configured(engine);record=parse_discovery(XML,c,1700000001)[0]
    engine.hosts.apply_discovery(c,(record,))
    engine.hosts.update(pkt(src=record.ip,dst=CLIENT,smac='02:aa:bb:cc:dd:ee'),None)
    d=engine.resolve_device(record.ip)
    assert d.model=='Unknown' and d.device_type=='Unknown'


def test_discovery_age_and_counts(engine):
    c=configured(engine);before=engine.stats().total_packets
    engine.hosts.apply_discovery(c,parse_discovery(XML,c,1700000001))
    assert engine.stats().total_packets==before
    assert engine.resolve_device('10.0.0.21',1700000032).status=='Inactive'
    assert engine.resolve_device('10.0.0.21',1700000032).packets==0
    engine.hosts.apply_context(replace(c,ts=1700000010))
    assert engine.resolve_device('10.0.0.21').model=='Mac15,6'
    engine.hosts.clear()
    assert engine.resolve_device('10.0.0.21') is None


def test_gateway_role_preserved_and_model_observed(engine):
    c=configured(engine)
    xml='''<nmaprun><host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/>
    <ports><port><script id="upnp-info" output="friendlyName: R8000 (Gateway)&#10;manufacturer: NETGEAR, Inc.&#10;modelName: R8000&#10;server: Linux/2.6.12&#10;deviceType: urn:schemas-upnp-org:device:InternetGatewayDevice:1"/></port></ports></host></nmaprun>'''
    engine.hosts.apply_discovery(c,parse_discovery(xml,c,1700000001))
    d=engine.resolve_device('10.0.0.1')
    assert d.device_type=='Gateway' and d.model=='R8000'
    assert d.manufacturer=='NETGEAR, Inc.' and d.os=='Linux/2.6.12'


def test_limits_unknown_and_untrusted_text():
    assert discovery_targets(context())==['10.0.0.0/24']
    with pytest.raises(ValueError):discovery_targets(replace(context(),addresses=(('10.0.0.28',None,8),)))
    with pytest.raises(ValueError):discovery_targets(replace(context(),addresses=()))
    with pytest.raises(Exception):parse_discovery('<broken',context())
    assert clean(r'MacBook\xC2\xA0Pro')=='MacBook Pro'
    assert '\x1b' not in clean('\x1bname') and len(clean('x'*1000))==200
    assert not parse_discovery(XML.replace('state="up"','state="down"'),context())
    unknown=XML.replace('dns-service-discovery','untrusted-script')
    records=parse_discovery(unknown,context())
    assert not any(e.field=='Hostname' for e in records[0].evidence)


def test_discovery_ui_is_explicit_and_cancel_state(app):
    page=DevicesPage();requests=[]
    page.discovery_requested.connect(lambda:requests.append(True))
    assert requests==[]
    page.discover_button.click();assert requests==[True]
    page.set_discovery_status('Finding devices',True)
    assert not page.discover_button.isEnabled() and not page.cancel_discovery.isHidden()
    page.set_discovery_status('Finished',False)
    assert page.discover_button.isEnabled() and page.cancel_discovery.isHidden()
    page.close()


def test_arp_sweep_targets_do_not_become_devices(engine):
    c=configured(engine)
    before={d.ip for d in engine.device_view()[0]}
    for i in range(100,150):
        query=replace(pkt(src=CLIENT,dst=f'10.0.0.{i}',smac='00:11:22:33:44:55'),
                      proto='ARP',arp_sender_mac='00:11:22:33:44:55',arp_target_mac='00:00:00:00:00:00')
        engine.hosts.update(query,None)
    assert {d.ip for d in engine.device_view()[0]}==before
    assert not any(e.ip.startswith('10.0.0.1') and int(e.ip.split('.')[-1]) >= 100 for e in engine.network_view().endpoints)
    response=replace(pkt(src='10.0.0.123',dst=CLIENT,smac='02:11:22:33:44:99'),
                     proto='ARP',arp_sender_mac='02:11:22:33:44:99',arp_target_mac='00:11:22:33:44:55')
    engine.hosts.update(response,None)
    assert engine.resolve_device('10.0.0.123').mac=='02:11:22:33:44:99'


def test_next_hop_mac_does_not_replace_discovered_peer_identity(engine):
    c=configured(engine)
    record=parse_discovery(XML,c,1700000001)[0]
    engine.hosts.apply_discovery(c,(record,))
    gateway_mac=next(mac for ip,mac in c.neighbors if ip=='10.0.0.1')
    engine.hosts.update(pkt(src=record.ip,dst=CLIENT,smac=gateway_mac),None)
    d=engine.resolve_device(record.ip)
    assert d.mac==record.mac and d.model=='Mac15,6'


def test_context_discovery_retains_neighbor_interface(monkeypatch):
    import json
    from types import SimpleNamespace
    from netlab.analyze.devices import NetworkContext
    def run(argv, **kw):
        if 'address' in argv:
            data=[{'ifname':'wlan0','address':'00:11:22:33:44:55','addr_info':[{'local':'10.0.0.28','prefixlen':24}]}]
        elif 'neighbor' in argv:
            assert 'dev' not in argv, 'ip omits dev from filtered neighbor JSON'
            data=[{'dev':'wlan0','dst':'10.0.0.1','lladdr':'00:22:33:44:55:66','state':['REACHABLE']},
                  {'dev':'eth0','dst':'192.168.1.5','lladdr':'00:22:33:44:55:77','state':['REACHABLE']}]
        else:data=[]
        return SimpleNamespace(stdout=json.dumps(data))
    monkeypatch.setattr('netlab.analyze.devices.subprocess.run',run)
    c=NetworkContext.discover('wlan0')
    assert c.neighbors==(('10.0.0.1','00:22:33:44:55:66'),)
