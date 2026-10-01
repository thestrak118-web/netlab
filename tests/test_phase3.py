"""Phase 3 evidence, graphical rendering, and real analyzer/navigation regressions."""
import dataclasses
import time
from pathlib import Path
from unittest.mock import patch
import pytest
from PySide6.QtCore import Qt
from PySide6.QtSvg import QSvgRenderer
from PySide6.QtGui import QIcon
from netlab.analyze.devices import NetworkContext, Confidence, OuiDatabase, valid_mac, topology_snapshot
from netlab.analyze.flows import HostTable
from netlab.analyze.engine import AnalysisEngine
from netlab.config import Config
from netlab.util.bounded import DropCountingQueue
from netlab.capture.pcapio import iter_capture_file
from netlab.capture.export import export_device_pcap
from netlab.gui.device_icons import ICON_DIR, ICON_NAMES, device_icon, icon_name
from netlab.gui.pages.devices import DeviceModel
from netlab.gui.pages.topology import TopologyPage
from netlab.gui.main_window import MainWindow
from netlab.gui.filters import compile_filter
from tests.qtapp import get_app
from tests.test_engine import build_capture, CLIENT, SERVER
from tests.test_flows import pkt
from tests.helpers import pcapng_file


@pytest.fixture
def app():
    return get_app()


@pytest.fixture
def engine(tmp_path):
    path = tmp_path / 'fixture.pcapng'
    path.write_bytes(pcapng_file(build_capture()))
    e = AnalysisEngine(DropCountingQueue(100), Config())
    e.ingest_batch(list(iter_capture_file(path)))
    return e


def context():
    return NetworkContext.from_json('wlan0',
        [dict(ifname='wlan0', address='00:11:22:33:44:55', addr_info=[dict(local=CLIENT, prefixlen=24)])],
        [dict(dev='wlan0', dst='default', gateway='10.0.0.1'),
         dict(dev='eth0', dst='default', gateway='192.168.1.1')],
        [dict(dev='wlan0', dst='10.0.0.1', lladdr='00:22:33:44:55:66', state=['REACHABLE'])],
        hostname='test-machine', ts=1700000000)


def test_gateway_evidence_and_interface_scope():
    c = context()
    assert c.gateways == ((CLIENT, '10.0.0.1'),)
    h = HostTable(20)
    h.apply_context(c)
    devices = {d.ip: d for d in h.device_snapshots(c.ts)}
    assert devices[CLIENT].device_type == 'This Device'
    assert devices[CLIENT].hostname == 'test-machine'
    assert devices['10.0.0.1'].device_type == 'Gateway'
    assert any(e.source == 'Routing table' and e.confidence == Confidence.CONFIRMED for e in devices['10.0.0.1'].evidence)
    h.apply_context(dataclasses.replace(c, gateways=(), ts=c.ts+10))
    assert h.get('10.0.0.1').device_type == 'Unknown'
    assert not any(e.source == 'Routing table' for e in h.get('10.0.0.1').evidence.values())
    assert h.get(CLIENT).last_ts == c.ts


def test_vendor_lookup_and_randomized_mac(tmp_path):
    registry = tmp_path / 'oui'
    registry.write_text('001122 Example Vendor\nAABBCC Not valid for randomized identity\n')
    oui = OuiDatabase(registry)
    assert oui.lookup('00:11:22:33:44:55') == 'Example Vendor'
    assert oui.lookup('aa:bb:cc:dd:ee:01') == 'Unknown'
    assert valid_mac('aa:bb:cc:dd:ee:01') is not None
    assert valid_mac('ff:ff:ff:ff:ff:ff') is None
    h = HostTable(10); h.oui = oui; h.apply_context(context())
    d = next(d for d in h.device_snapshots(1700000000) if d.ip == CLIENT)
    assert d.manufacturer == 'Example Vendor'
    assert any(e.field == 'Manufacturer' and e.confidence == Confidence.OBSERVED for e in d.evidence)


def test_unknown_device_and_observed_evidence(engine):
    # Remote records remain endpoint observations, never local Device identities.
    devices, _ = engine.endpoint_view(1700000001)
    d = next(d for d in devices if d.ip == SERVER)
    assert d.device_type == d.os == d.mac == d.manufacturer == 'Unknown'
    assert d.hostname == 'example.test'
    assert any(e.field == 'IP' and e.confidence == Confidence.OBSERVED for e in d.evidence)
    assert any(e.source == 'DNS answer' and e.confidence == Confidence.OBSERVED for e in d.evidence)
    assert engine.hosts.context == NetworkContext()


@pytest.mark.parametrize('name', ICON_NAMES)
def test_svg_asset_renders(app, name):
    path = ICON_DIR / (name + '.svg')
    assert QSvgRenderer(str(path)).isValid()
    pixmap = QIcon(str(path)).pixmap(32, 32)
    assert not pixmap.isNull()
    img = pixmap.toImage()
    assert any(img.pixelColor(x, y).alpha() for x in range(32) for y in range(32))


def test_icons_do_not_guess_models():
    assert icon_name('This Device') == 'computer'
    assert icon_name('Gateway') == 'router'
    assert icon_name('Unknown') == 'unknown'
    assert icon_name('Apple') == 'unknown'


def test_devices_model_updates_immutable_rows(app, engine):
    engine.hosts.apply_context(context())
    model = DeviceModel()
    devices, _ = engine.device_view(1700000001)
    model.replace_items(devices)
    for row in range(model.rowCount()):
        assert not model.data(model.index(row, 0), Qt.ItemDataRole.DecorationRole).isNull()
        for col in range(model.columnCount()):
            assert isinstance(model.data(model.index(row, col)), str)
    model.set_filter('device:' + CLIENT)
    assert model.rowCount() == 1
    d = model.object_at(0)
    model.replace_items([dataclasses.replace(x, packets=999) if x.ip == CLIENT else x for x in devices])
    assert model.object_at(0).packets == 999
    assert model.cell(model.object_at(0), 6) == '999'


def test_topology_edges_and_bounds(engine):
    engine.hosts.apply_context(context())
    snap = engine.network_view(1700000001)
    route = next(e for e in snap.edges if e.kind == 'route')
    assert (route.source, route.destination) == (CLIENT, '10.0.0.1')
    assert route.evidence == 'Routing table: default gateway'
    traffic = [e for e in snap.edges if e.kind == 'traffic']
    assert traffic and all(e.packets > 0 and e.bytes > 0 for e in traffic)
    assert not any(e.source == '10.0.0.1' and e.destination == SERVER for e in snap.edges)
    devices, flows = engine.device_view(1700000001)
    bounded = topology_snapshot(devices, flows, context(), 1700000001, node_limit=2, edge_limit=1)
    assert len(bounded.devices) <= 2 and len(bounded.edges) <= 1
    expired = engine.network_view(1700000200)
    assert all(e.kind == 'route' for e in expired.edges)


def test_topology_updates_reuse_items(app, engine):
    engine.hosts.apply_context(context())
    page = TopologyPage()
    first = engine.network_view(1700000001)
    page.update_snapshot(first)
    node = page.nodes[CLIENT][0]
    key = next(iter(page.edges))
    line = page.edges[key][0]
    changed = dataclasses.replace(first, edges=tuple(dataclasses.replace(e, bytes=e.bytes+500) for e in first.edges))
    page.update_snapshot(changed)
    assert page.nodes[CLIENT][0] is node
    assert page.edges[key][0] is line
    assert page.communications.rowCount() == len([e for e in changed.edges if e.kind == 'traffic'])
    from netlab.util.format import human_bytes
    assert page.communications.item(0,4).text() == human_bytes(next(e for e in changed.edges if e.kind=='traffic').bytes)
    assert page.revisions == 2
    page.update_snapshot(dataclasses.replace(first, devices=(), endpoints=(), edges=()))
    assert not page.nodes and not page.edges


def test_exact_device_filter_excludes_prefix_collision():
    f = compile_filter('device:10.0.0.1')
    assert f.matches({'src': '10.0.0.1', 'dst': '8.8.8.8'}, '')
    assert not f.matches({'src': '10.0.0.10'}, '')


@pytest.fixture
def window(app, engine, tmp_path):
    from netlab.config import CONFIG
    CONFIG.set('capture_dir', str(tmp_path))
    w = MainWindow()
    w.analysis.stop()
    w.timer.stop()
    engine.hosts.apply_context(context())
    w.analysis = engine
    w.devices_page.engine = engine
    w.live_page.set_engine(engine)
    w.connections_page.set_engine(engine)
    w._tick()
    yield w
    # A test may leave interception "armed"; closeEvent would then pop a modal
    # confirmation that blocks forever under offscreen Qt. Clear it so teardown
    # never hangs.
    w._armed = False
    with patch.object(w.config, 'save'):
        w.close()


@pytest.mark.parametrize('action', ['Traffic', 'Connections', 'DNS', 'HTTP', 'TLS'])
def test_device_navigation_uses_existing_pages(window, action):
    window._open_device(CLIENT)
    assert window.devices_page.detail.ip == CLIENT
    detail = window.devices_page.detail.text.toPlainText()
    assert 'Identity' in detail and 'OBSERVED' in detail and 'Exact device model' in detail
    window.devices_page.detail.buttons[action].click()
    page = {'Traffic': window.live_page, 'Connections': window.connections_page,
            'DNS': window.dns_page, 'HTTP': window.http_page, 'TLS': window.tls_page}[action]
    assert window.stack.currentWidget() is page
    assert page.model.filter_text == 'device:' + CLIENT
    assert page.model.rowCount() > 0
    assert all(page.model._passes(x) for x in page.model._rows)
    if action == 'DNS':
        assert CLIENT in (page.model.object_at(0).src, page.model.object_at(0).dst)
        # A remote answer IP still correlates on the existing DNS page.
        window._device_action('DNS', SERVER)
        assert SERVER in page.model.object_at(0).resolved_ips


def test_hosts_open_device_details(window):
    # Hosts and Devices are one list now; it opens a host's detail evidence.
    window._show_page('devices')
    assert window.devices_page.select_device(CLIENT)
    assert window.devices_page.detail.ip == CLIENT
    window.devices_page.detail.buttons['Connections'].click()
    assert window.stack.currentWidget() is window.connections_page


def test_double_click_drills_into_selected_device(window):
    # The host-centric flow: activating a host row opens its Selected Device
    # tabs (the drill-down), and the back button returns to the host list.
    window.monitor_page.engine = window.analysis
    window._show_page('devices')
    assert window.devices_page.select_device(CLIENT)
    model = window.devices_page.model
    device = next(model.object_at(r) for r in range(model.rowCount())
                  if getattr(model.object_at(r), 'ip', '') == CLIENT)
    window.devices_page._activated(device)
    assert window.stack.currentWidget() is window.monitor_page
    window.monitor_page.back_requested.emit()
    assert window.stack.currentWidget() is window.devices_page


def test_context_lifecycle_rejects_stale_or_offline_results(window):
    window._mode = 'live'
    window._apply_network_context(window._context_generation, context())
    assert window.analysis.hosts.context.gateways
    old = window._context_generation
    window._clear_analysis()
    window._mode = 'offline'
    window._apply_network_context(old, context())
    window._apply_network_context(window._context_generation, context())
    assert window.analysis.hosts.context == NetworkContext()


def test_live_traffic_device_direction_domain(window):
    window.analysis.hosts.apply_context(context())
    row = next(r for r in window.analysis.live.snapshot() if r.src == CLIENT and r.dport == 80)
    model = window.live_page.model
    assert 'This Device' in model.cell(row, 0)
    assert model.cell(row, 1) == 'Upload'
    assert model.cell(row, 5) == 'example.test'


def test_device_pcap_export_preserves_packets(window, tmp_path):
    source = tmp_path / 'source.pcapng'
    target = tmp_path / 'device.pcapng'
    source.write_bytes(pcapng_file(build_capture()))
    window._set_source(source)
    window._open_device(CLIENT)
    window.devices_page.detail.buttons['PCAP'].click()
    assert window.stack.currentWidget() is window.pcap_page
    assert window.pcap_page.device_ip == (CLIENT,)
    with patch('netlab.gui.pages.pcapviewer.QFileDialog.getSaveFileName', return_value=(str(target), '')), patch('netlab.gui.pages.pcapviewer.QMessageBox.information'):
        window.pcap_page.export_btn.click()
    from netlab.analyze.decode import decode
    expected = [p for p in iter_capture_file(source) if CLIENT in (decode(p.data,p.linktype,p.ts,p.wirelen).src, decode(p.data,p.linktype,p.ts,p.wirelen).dst)]
    actual = list(iter_capture_file(target))
    assert actual and [p.data for p in actual] == [p.data for p in expected]
    with pytest.raises(ValueError):
        export_device_pcap(source, source, CLIENT)


def test_arp_binding_identifies_sender_without_system_context():
    from tests.helpers import mac, ip4, ethernet
    from netlab.analyze.decode import decode
    body = (b'\x00\x01\x08\x00\x06\x04\x00\x01' + mac('aa:bb:cc:dd:ee:01') + ip4('10.0.0.1')
            + mac('00:00:00:00:00:00') + ip4('10.0.0.5'))
    frame = ethernet('aa:bb:cc:dd:ee:01', 'ff:ff:ff:ff:ff:ff', 0x0806, body)
    h = HostTable(10)
    h.update(decode(frame, 1, 1, len(frame)), None)
    assert h.get('10.0.0.1').mac == 'aa:bb:cc:dd:ee:01'
    assert h.get('10.0.0.5').mac is None
    assert any(e.source == 'ARP address binding' for e in h.get('10.0.0.1').evidence.values())


def test_timer_driven_topology_receives_new_analysis(window, app):
    window._mode = 'offline'
    window._network_next = 0
    window.timer.start(250)
    old = window.topology_page.revisions
    before = sum(d.packets for d in window.topology_page.snapshot.devices)
    # The existing ingestion path updates hosts and flows; only timer batches reach GUI.
    row = pkt(src='10.0.0.99', dst=SERVER)
    row.ts = 1700000001
    window.analysis.hosts.update(row, window.analysis.flows.update(row))
    end = time.monotonic()+2
    while time.monotonic() < end and window.topology_page.revisions == old:
        app.processEvents()
        time.sleep(.01)
    window.timer.stop()
    assert window.topology_page.revisions > old
    assert '10.0.0.99' in window.topology_page.nodes
    assert sum(d.packets for d in window.topology_page.snapshot.devices) > before


def test_device_refresh_keeps_order_and_detail_scroll(window, app):
    window._open_device(CLIENT)
    page = window.devices_page
    order = [d.ip for d in page.model._rows]
    page.detail.text.resize(400, 90)
    page.detail.text.show()
    app.processEvents()
    page.detail.text.verticalScrollBar().setValue(5)
    scroll = page.detail.text.verticalScrollBar().value()
    devices, _ = window.analysis.device_view()
    page.refresh(tuple(reversed(devices)))
    assert [d.ip for d in page.model._rows] == order
    assert page.detail.text.verticalScrollBar().value() == scroll


# --- one-click Kuzat (no confirm) and auto-watch target switching ------------

def test_watch_arms_without_confirm_by_default(window, monkeypatch):
    """Kuzat / auto-watch arm the selected device directly -- confirm=False --
    and switching to a new target disarms the current one first so a second
    arm never races the helper (v2.16 session lock)."""
    from types import SimpleNamespace
    w = window
    monkeypatch.setattr(w, "_ensure_helper", lambda: True)
    monkeypatch.setattr(w, "_host_reachable", lambda ip: True)
    monkeypatch.setattr(w.monitor_page, "select_device", lambda ip: None)
    watched, disarms = [], []
    monkeypatch.setattr(w.mitm_page, "watch",
                        lambda ip, confirm=True: watched.append((ip, confirm)))
    w.mitm_page.disarm_requested.connect(lambda: disarms.append(True))
    devs = {"10.0.0.50": SimpleNamespace(device_type="Smartphone", ipv4_addresses=("10.0.0.50",)),
            "10.0.0.51": SimpleNamespace(device_type="Smartphone", ipv4_addresses=("10.0.0.51",))}
    monkeypatch.setattr(w.analysis, "resolve_device", lambda ip: devs.get(ip))
    w._watch_target = None
    w._armed = False

    w._watch_device("10.0.0.50")                    # not armed -> arm A directly
    assert watched == [("10.0.0.50", False)]
    assert w._watch_target == "10.0.0.50"

    w._armed = True                                 # helper confirmed armed
    w._watch_device("10.0.0.51")                    # armed on A -> disarm, queue B
    assert disarms == [True]
    assert w._pending_watch_ip == "10.0.0.51"
    assert watched == [("10.0.0.50", False)]        # B not armed yet

    w._helper_event("disarmed", {})                 # helper down -> arm queued B
    assert watched[-1] == ("10.0.0.51", False)
    assert w._watch_target == "10.0.0.51"
    assert w._pending_watch_ip is None


def test_watch_confirm_setting_forces_the_dialog(window, monkeypatch):
    from types import SimpleNamespace
    w = window
    monkeypatch.setattr(w, "_ensure_helper", lambda: True)
    monkeypatch.setattr(w, "_host_reachable", lambda ip: True)
    monkeypatch.setattr(w.monitor_page, "select_device", lambda ip: None)
    calls = []
    monkeypatch.setattr(w.mitm_page, "watch",
                        lambda ip, confirm=True: calls.append(confirm))
    monkeypatch.setattr(w.analysis, "resolve_device",
                        lambda ip: SimpleNamespace(device_type="Smartphone", ipv4_addresses=("10.0.0.60",)))
    w._armed = False
    w._watch_target = None
    w.config.set("watch_confirm", True)
    w._watch_device("10.0.0.60")
    assert calls == [True]


def test_arm_confirm_false_skips_the_dialog_and_arms(window, monkeypatch):
    import netlab.gui.pages.mitmpage as M
    mp = window.mitm_page
    # This test checks the dialog/signal contract, not the privileged helper.
    # A real arm request leaves a queued error dialog for the next Qt test.
    mp.arm_requested.disconnect(window._arm_interception)
    monkeypatch.setattr(mp, "engagement_dict", lambda: {"targets": ["10.0.0.50"]})
    monkeypatch.setattr(mp, "modules_dict", lambda: {"arp_poison": True})
    monkeypatch.setattr(mp, "save_config", lambda: None)

    def _boom(*a, **k):
        raise AssertionError("ArmDialog must not be built when confirm=False")
    monkeypatch.setattr(M, "ArmDialog", _boom)
    emitted = []
    mp.arm_requested.connect(lambda eng, mods: emitted.append((eng, mods)))
    mp._arm(confirm=False)
    assert len(emitted) == 1
    eng, _mods = emitted[0]
    assert eng["authorised"] is True and "Kuzat" in eng["authorisation_text"]


def test_arm_confirm_true_still_gates_on_the_dialog(window, monkeypatch):
    from PySide6.QtWidgets import QDialog
    import netlab.gui.pages.mitmpage as M
    mp = window.mitm_page
    monkeypatch.setattr(mp, "engagement_dict", lambda: {"targets": ["10.0.0.50"]})
    monkeypatch.setattr(mp, "modules_dict", lambda: {"arp_poison": True})
    monkeypatch.setattr(mp, "save_config", lambda: None)

    class Rejected:
        def __init__(self, *a, **k): pass
        def exec(self): return QDialog.DialogCode.Rejected
    monkeypatch.setattr(M, "ArmDialog", Rejected)
    emitted = []
    mp.arm_requested.connect(lambda *a: emitted.append(a))
    mp._arm(confirm=True)
    assert emitted == []                            # cancelled -> nothing armed


def test_watch_on_unreachable_target_does_not_arm(window, monkeypatch):
    """A dozing target is caught before the helper: no arm, a friendly nudge."""
    from types import SimpleNamespace
    w = window
    monkeypatch.setattr(w, "_ensure_helper", lambda: True)
    monkeypatch.setattr(w, "_host_reachable", lambda ip: False)   # asleep
    monkeypatch.setattr(w.monitor_page, "select_device", lambda ip: None)
    watched, statuses = [], []
    monkeypatch.setattr(w.mitm_page, "watch",
                        lambda ip, confirm=True: watched.append(ip))
    monkeypatch.setattr(w, "_discovery_status",
                        lambda text, running=False: statuses.append(text))
    monkeypatch.setattr(w.analysis, "resolve_device",
                        lambda ip: SimpleNamespace(device_type="Smartphone",
                                                   ipv4_addresses=("10.0.0.70",),
                                                   addresses=("10.0.0.70",)) if ip == "10.0.0.70" else None)
    w._armed = False
    w._watch_target = None
    w._watch_device("10.0.0.70")
    assert watched == []                       # nothing was armed
    assert w._watch_target is None
    assert any("javob bermayapti" in s for s in statuses)


def test_watch_arm_success_lands_on_the_device_not_the_mitm_page(window, monkeypatch):
    w = window
    opened, navs = [], []
    monkeypatch.setattr(w, "_open_monitor", lambda ip: opened.append(ip))
    monkeypatch.setattr(w, "_nav_to", lambda key: navs.append(key))
    monkeypatch.setattr(w.mitm_page, "set_armed", lambda *a, **k: None)
    w._watch_target = "10.0.0.80"
    w._helper_requests[999] = "arm"
    w._helper_replied(999, True, {"targets": ["10.0.0.80"]})
    assert opened == ["10.0.0.80"]             # the device's own live view
    assert "mitm" not in navs                  # not the MITM config page


def test_arm_arp_failure_is_a_friendly_nudge_not_a_refusal(window, monkeypatch):
    import netlab.gui.main_window as MW
    w = window
    boxes, statuses = [], []
    monkeypatch.setattr(MW.QMessageBox, "warning", lambda *a, **k: boxes.append(a))
    monkeypatch.setattr(w, "_discovery_status",
                        lambda text, running=False: statuses.append(text))
    w._watch_target = "10.0.0.81"
    w._helper_requests[7] = "arm"
    w._helper_replied(7, False,
                      "no target in the engagement answered ARP; nothing to poison")
    assert boxes == []                         # no scary "Helper refused" modal
    assert any("javob bermayapti" in s for s in statuses)
    assert w._watch_target is None
