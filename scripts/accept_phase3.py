#!/usr/bin/python3
"""Real installed GUI + wlan0 acceptance. Generates ordinary DNS/HTTP/TLS traffic.
Only save-file/message dialogs are automated; capture, buttons, filters, graph,
export and import all execute the installed production code.
"""
import argparse
import csv
import dataclasses
import json
import os
import subprocess
import threading
import time
from pathlib import Path
from unittest.mock import patch
import netlab
from PySide6.QtCore import QTimer, Qt
from PySide6.QtWidgets import QApplication
from netlab.config import CONFIG
from netlab.gui.main_window import MainWindow
from netlab.gui import theme
from netlab.capture.pcapio import iter_capture_file

parser = argparse.ArgumentParser()
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
args.output.mkdir(parents=True, exist_ok=True)
assert str(netlab.__file__).startswith('/usr/lib/python3/dist-packages/'), netlab.__file__
assert netlab.__version__ == '1.2.0'
CONFIG.set('capture_dir', str(args.output))
CONFIG.set('bpf_filter', '')
app = QApplication([])
app.setStyleSheet(theme.STYLESHEET)
w = MainWindow()
w.show()
errors = []
w.capture.failed.connect(errors.append)
result = dict(version=netlab.__version__, module=netlab.__file__, interface='wlan0',
              platform=app.platformName(), started=time.time(), checks={})
heartbeats = []
heartbeat = QTimer()
heartbeat.timeout.connect(lambda: heartbeats.append(time.monotonic()))
heartbeat.start(50)


def pump(seconds):
    end = time.monotonic()+seconds
    while time.monotonic() < end:
        app.processEvents()
        time.sleep(.01)


def wait_for(predicate, timeout=30):
    end = time.monotonic()+timeout
    while time.monotonic() < end:
        pump(.05)
        if errors:
            raise RuntimeError(errors)
        if predicate():
            return
    raise TimeoutError('acceptance condition timed out')


def shot(name):
    pump(.25)
    assert w.grab().save(str(args.output / (name+'.png')))


def independent(path):
    count = sum(1 for _ in iter_capture_file(path))
    text = subprocess.check_output(['capinfos','-Tm','-c',str(path)],text=True)
    capinfos = int(list(csv.reader(text.splitlines()))[-1][-1])
    tshark = subprocess.check_output(['tshark','-r',str(path),'-T','fields','-e','frame.number'],text=True)
    assert count == capinfos == len(tshark.splitlines())
    return dict(netlab=count, capinfos=capinfos, tshark=len(tshark.splitlines()))


try:
    pump(.5)
    idx = w.iface_combo.findData('wlan0')
    assert idx >= 0
    w.iface_combo.setCurrentIndex(idx)
    w.bpf_edit.setText('arp or port 53 or tcp port 80 or tcp port 443 or icmp')
    w.start_btn.click()
    wait_for(lambda: w.capture.is_running and w._source_path.exists() and bool(w.analysis.hosts.context.addresses))
    context = w.analysis.hosts.context
    own = next(a[0] for a in context.addresses if ':' not in a[0])
    assert context.gateways, 'No verified route available for gateway acceptance'
    result['context'] = dataclasses.asdict(context)
    w._goto('Topology')
    wait_for(lambda: own in w.topology_page.nodes)
    initial_node = w.topology_page.nodes[own][0]
    initial_revision = w.topology_page.revisions
    initial_packets = w.analysis.stats().total_packets
    traffic_results = []
    def traffic():
        commands = [
            ['dig', '-b', own, 'httpforever.com', 'A', '+tries=1', '+time=5'],
            ['curl', '--interface', 'wlan0', '--noproxy', '*', '--max-time', '20', '-sS', '-o', '/dev/null', '-w', '%{http_code}', 'http://httpforever.com/'],
            ['curl', '--interface', 'wlan0', '--noproxy', '*', '--max-time', '20', '-sS', '-o', '/dev/null', '-w', '%{http_code}', 'https://www.google.com/'],
        ]
        for command in commands:
            proc = subprocess.run(command,capture_output=True,text=True,timeout=25)
            traffic_results.append(dict(command=command, returncode=proc.returncode, stdout=proc.stdout, stderr=proc.stderr))
    worker = threading.Thread(target=traffic,daemon=True)
    worker.start()
    wait_for(lambda: not worker.is_alive(),75)
    result['traffic_commands'] = traffic_results
    assert all(r['returncode'] == 0 for r in traffic_results), traffic_results
    wait_for(lambda: w.analysis.stats().dns_events > 0 and w.analysis.stats().http_transactions > 0 and w.analysis.stats().tls_sessions > 0)
    wait_for(lambda: w.topology_page.revisions > initial_revision and w.analysis.stats().total_packets > initial_packets)
    assert w.capture.is_running
    assert w.topology_page.nodes[own][0] is initial_node
    graph = w.topology_page.snapshot
    assert any(e.kind == 'route' for e in graph.edges)
    assert any(e.kind == 'traffic' and e.packets > 0 for e in graph.edges)
    assert any(d.scope == 'Remote' and d.packets > 0 for d in graph.devices)
    result['live_graph'] = dataclasses.asdict(graph)
    result['checks']['live_topology'] = dict(initial_revision=initial_revision, final_revision=w.topology_page.revisions,
        initial_packets=initial_packets, final_packets=w.analysis.stats().total_packets, node_item_reused=True, capture_running=True)
    shot('topology-live')
    w._goto('Devices')
    wait_for(lambda: w.devices_page.model.rowCount() > 0)
    assert w.devices_page.select_device(own)
    detail = w.devices_page.detail.text.toPlainText()
    assert 'This Device' in detail and 'CONFIRMED' in detail
    devices, _ = w.analysis.device_view()
    local = next(d for d in devices if d.ip == own)
    assert local.mac != 'Unknown' and local.packets > 0 and local.bytes > 0
    result['local_device'] = dataclasses.asdict(local)
    shot('devices-detail')
    w._goto('Hosts')
    assert w.hosts_page.select_device(own)
    shot('hosts')
    for name, page in [('Traffic',w.live_page), ('Connections',w.connections_page),
                       ('DNS',w.dns_page), ('HTTP',w.http_page), ('TLS',w.tls_page)]:
        w._open_device(own)
        w.devices_page.detail.buttons[name].click()
        pump(.3)
        assert w.stack.currentWidget() is page
        assert page.model.rowCount() > 0, name
        assert page.model.filter_text == 'device:'+own
        assert all(page.model._passes(row) for row in page.model._rows)
        result['checks'][name] = dict(rows=page.model.rowCount(), filter=page.model.filter_text)
        shot('device-'+name.lower())
    # The existing packet-to-connection drill-down remains part of the chain.
    row = next(r for r in w.analysis.live.snapshot() if r.proto == 'TCP' and r.dport == 80)
    flow = w.analysis.flow_for_packet(row)
    assert flow and w.analysis.relations_for_flow(flow)['http']
    w.live_page.row_activated.emit(row)
    assert w.stack.currentWidget() is w.connections_page
    result['checks']['packet_to_http_connection'] = True
    w._open_device(own)
    w.devices_page.detail.buttons['PCAP'].click()
    assert w.stack.currentWidget() is w.pcap_page and w.pcap_page.device_ip == own
    w.pcap_page.packets_btn.click()
    assert w.stack.currentWidget() is w.live_page
    assert w.live_page.model.filter_text == 'device:'+own
    w.stop_btn.click()
    wait_for(lambda: not w.capture.is_running)
    pump(1)
    source = w._source_path
    result['source_pcap'] = str(source)
    result['source_counts'] = independent(source)
    wait_for(lambda: w.analysis.stats().total_packets == result['source_counts']['netlab'])
    result['stats'] = dataclasses.asdict(w.analysis.stats())
    assert result['stats']['queue_dropped'] == 0
    exported = args.output / 'exported-full.pcapng'
    with patch('netlab.gui.main_window.QFileDialog.getSaveFileName', return_value=(str(exported),'')), patch('netlab.gui.main_window.QMessageBox.information'):
        w._export_current()
    assert exported.read_bytes() == source.read_bytes()
    result['exported_counts'] = independent(exported)
    w._device_action('PCAP',own)
    device_export = args.output / 'exported-device.pcapng'
    with patch('netlab.gui.pages.pcapviewer.QFileDialog.getSaveFileName', return_value=(str(device_export),'')), patch('netlab.gui.pages.pcapviewer.QMessageBox.information'):
        w.pcap_page.export_btn.click()
    result['device_export_counts'] = independent(device_export)
    assert result['device_export_counts']['netlab'] > 0
    from netlab.analyze.decode import decode
    for raw in iter_capture_file(device_export):
        packet = decode(raw.data,raw.linktype,raw.ts,raw.wirelen)
        assert own in (packet.src,packet.dst)
    w.open_capture_file(str(exported))
    wait_for(lambda: w.analysis.stats().total_packets == result['source_counts']['netlab'])
    pump(.8)
    assert not w.analysis.hosts.context.addresses and not w.analysis.hosts.context.gateways
    result['reopened_packets'] = w.analysis.stats().total_packets
    result['checks']['offline_no_system_identity'] = True
    shot('reopened-pcap')
    result['gui_heartbeat'] = dict(samples=len(heartbeats), max_gap_seconds=max(b-a for a,b in zip(heartbeats,heartbeats[1:])))
    result['completed'] = time.time()
    result['passed'] = True
finally:
    (args.output/'acceptance.json').write_text(json.dumps(result,indent=2)+'\n')
    if w.capture.is_running:
        w.stop_capture()
    w.close()
print(json.dumps({k:v for k,v in result.items() if k not in ('live_graph','context','local_device')},indent=2))
