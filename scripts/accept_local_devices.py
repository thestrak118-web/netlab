#!/usr/bin/python3
"""Installed 1.4.0 GUI acceptance: fresh wlan0 traffic, no synthetic injection."""
import argparse
import csv
import dataclasses
import json
import subprocess
import threading
import time
from pathlib import Path
from unittest.mock import patch
import netlab
from PySide6.QtWidgets import QApplication
from netlab.config import CONFIG
from netlab.gui.main_window import MainWindow
from netlab.gui import theme
from netlab.capture.pcapio import iter_capture_file
from netlab.analyze.decode import decode

parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path,required=True)
args=parser.parse_args();args.output.mkdir(parents=True,exist_ok=True)
assert netlab.__version__=='1.4.0'
assert netlab.__file__.startswith('/usr/lib/python3/dist-packages/'),netlab.__file__
CONFIG.set('capture_dir',str(args.output));CONFIG.set('bpf_filter','')
app=QApplication([]);app.setStyleSheet(theme.STYLESHEET)
w=MainWindow();w.resize(1720,1000);w.show()
errors=[];w.capture.failed.connect(errors.append)
result=dict(version=netlab.__version__,module=netlab.__file__,platform=app.platformName(),started=time.time())
traffic_results=[]


def pump(seconds):
    end=time.monotonic()+seconds
    while time.monotonic()<end:app.processEvents();time.sleep(.01)


def wait(predicate,timeout=30):
    end=time.monotonic()+timeout
    while time.monotonic()<end:
        pump(.05)
        if errors:raise RuntimeError(errors)
        if predicate():return
    raise TimeoutError('acceptance condition timed out')


def shot(name):
    pump(.25);assert w.grab().save(str(args.output/(name+'.png')))


def traffic():
    commands=[['dig','-b',own,'httpforever.com','A','+tries=1','+time=5'],
              ['curl','--interface','wlan0','--noproxy','*','--max-time','20','-sS','-o','/dev/null','-w','%{http_code}','http://httpforever.com/'],
              ['curl','--interface','wlan0','--noproxy','*','--max-time','20','-sS','-o','/dev/null','-w','%{http_code}','https://www.google.com/']]
    for command in commands:
        p=subprocess.run(command,capture_output=True,text=True,timeout=25)
        traffic_results.append(dict(command=command,returncode=p.returncode,stdout=p.stdout,stderr=p.stderr))


try:
    pump(.4)
    idx=w.iface_combo.findData('wlan0');assert idx>=0
    w.iface_combo.setCurrentIndex(idx);w.bpf_edit.setText('')
    w.start_btn.click()
    wait(lambda:w.capture.is_running and bool(w.analysis.hosts.context.addresses))
    context=w.analysis.hosts.context
    own=next(a[0] for a in context.addresses if ':' not in a[0])
    own_addresses={a[0] for a in context.addresses}
    result['network_context']=dataclasses.asdict(context)
    w._goto('Devices');wait(lambda:w.devices_page.model.rowCount()>0)
    initial=w.analysis.resolve_device(own).packets
    revisions=w.topology_page.revisions
    worker=threading.Thread(target=traffic,daemon=True);worker.start()
    wait(lambda:not worker.is_alive(),75)
    assert all(p['returncode']==0 for p in traffic_results),traffic_results
    wait(lambda:w.analysis.resolve_device(own).packets>initial)
    wait(lambda:w.analysis.http_txns.snapshot() and w.analysis.tls_order.snapshot())
    pump(1)
    devices=w.analysis.device_view()[0]
    this=[d for d in devices if d.device_type=='This Device']
    assert len(this)==1 and set(this[0].addresses)==own_addresses
    assert this[0].ipv4_addresses and this[0].ipv6_addresses
    gateways=[d for d in devices if d.device_type=='Gateway']
    assert len(gateways)==1
    assert set(gateways[0].addresses).intersection(g for _,g in context.gateways)
    locals_={ip for d in devices for ip in d.addresses}
    remote={e.ip for e in w.analysis.endpoint_view()[0] if e.ip not in locals_ and e.packets>0}
    assert remote
    model=w.devices_page.model
    assert model.rowCount()==len(devices)
    assert all(model.object_at(i).monitor_eligible for i in range(model.rowCount()))
    assert not remote.intersection(a for i in range(model.rowCount()) for a in model.object_at(i).addresses)
    assert all(model.cell(model.object_at(i),12)=='Monitor' for i in range(model.rowCount()))
    assert w.devices_page.select_device(own)
    assert all(a in w.devices_page.detail.text.toPlainText() for a in own_addresses)
    shot('devices-corrected')
    result['devices']=[dataclasses.asdict(d) for d in devices]
    result['remote_excluded']=sorted(remote)
    result['gui_rows']=model.rowCount()
    result['ipv4_ipv6_merged']=True
    result['live_counter']={'before':initial,'after':this[0].packets}
    remote_ip=next(iter(remote))
    w._monitor_device(remote_ip)
    assert not w.monitor_page.registry.subscriptions
    assert w.stack.currentWidget() is w.devices_page
    result['remote_monitor_rejected']=True
    w._device_action('Traffic',own)
    wait(lambda:w.live_page.model.rowCount()>0)
    assert any(r.src in remote or r.dst in remote for r in w.live_page.model._rows)
    assert all(own_addresses.intersection((r.src,r.dst)) for r in w.live_page.model._rows)
    shot('traffic-remote-destinations')
    w._device_action('Connections',own);pump(.4)
    assert w.connections_page.model.rowCount()>0
    assert any(f.client in remote or f.server in remote for f in w.connections_page.model._rows)
    shot('connections-remote-destinations')
    w._goto('Topology');pump(.5)
    topology=w.topology_page
    assert topology.revisions>revisions
    assert remote.intersection(e.ip for e in topology.snapshot.endpoints)
    assert all(key[2]=='route' for key in topology.edges)
    assert not remote.intersection(a for key in topology.edges for a in key[:2])
    topology.view.resetTransform()
    topology.view.horizontalScrollBar().setValue(topology.view.horizontalScrollBar().minimum())
    topology.view.verticalScrollBar().setValue(topology.view.verticalScrollBar().minimum())
    shot('topology-separated')
    result['topology']=dict(local_devices=len(topology.snapshot.devices),remote_endpoints=len(topology.snapshot.endpoints),
        revisions_before=revisions,revisions_after=topology.revisions,drawn_edges=[list(k) for k in topology.edges],
        communication_rows=topology.communications.rowCount())
    w._goto('Devices');pump(.4);assert w.devices_page.select_device(own)
    w.devices_page.monitor_button.click();m=w.monitor_page
    wait(lambda:m.snapshot is not None)
    s=m.snapshot
    assert set(s.addresses)==own_addresses
    assert all(own_addresses.intersection((r.src,r.dst)) for r in s.activity)
    assert s.counts['dns'] and s.counts['http'] and s.counts['tls']
    result['monitor']=dict(identity=s.identity,addresses=s.addresses,counts=s.counts,activity_rows=len(s.activity))
    shot('monitor-local-device')
    target=args.output/'selected-device.pcapng'
    with patch('netlab.gui.pages.monitor.QFileDialog.getSaveFileName',return_value=(str(target),'')):
        m.buttons['Export Device Traffic'].click()
    wait(lambda:target.exists() and not m._export_busy)
    exported=list(iter_capture_file(target));assert exported
    assert all(own_addresses.intersection((p.src,p.dst)) for raw in exported for p in [decode(raw.data,raw.linktype,raw.ts,raw.wirelen)])
    independent=subprocess.check_output(['tshark','-r',str(target),'-T','fields','-e','frame.number'],text=True)
    infos=subprocess.check_output(['capinfos','-Tm','-c',str(target)],text=True)
    count=int(list(csv.reader(infos.splitlines()))[-1][-1])
    assert len(exported)==len(independent.splitlines())==count
    result['export']=dict(path=str(target),netlab=len(exported),tshark=count,capinfos=count)
    before=w.analysis.stats().total_packets
    m.buttons['Stop Monitoring'].click()
    assert not m.registry.subscriptions and w.capture.is_running
    worker=threading.Thread(target=traffic,daemon=True);worker.start()
    wait(lambda:not worker.is_alive(),75)
    wait(lambda:w.analysis.stats().total_packets>before)
    result['stop_monitoring']=dict(before=before,after=w.analysis.stats().total_packets,capture_running=w.capture.is_running)
    w._goto('Devices');pump(.5);w.devices_page.select_device(own);shot('devices-corrected-final')
    w.stop_btn.click();wait(lambda:not w.capture.is_running);pump(.5)
    source=w._source_path
    original=[]
    for raw in iter_capture_file(source):
        p=decode(raw.data,raw.linktype,raw.ts,raw.wirelen)
        if own_addresses.intersection((p.src,p.dst)):original.append(raw.data)
    assert [p.data for p in exported]==original[:len(exported)]
    result['export']['original_bytes_preserved']=True
    result['source_pcap']=str(source)
    result['traffic_commands']=traffic_results
    assert all(p['returncode']==0 for p in traffic_results)
    result['passed']=True
finally:
    result['completed']=time.time()
    (args.output/'acceptance.json').write_text(json.dumps(result,indent=2)+'\n')
    if w.capture.is_running:w.stop_capture()
    w.close()
print(json.dumps({k:v for k,v in result.items() if k!='devices'},indent=2))
