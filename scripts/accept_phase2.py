#!/usr/bin/python3
"""Opt-in real GUI acceptance; run against the installed package (no PYTHONPATH).
Captures only HTTP test traffic. Use isolated XDG config/data directories.
"""
import argparse
import csv
import dataclasses
import json
import socket
import subprocess
import threading
import time
from pathlib import Path
import netlab
from PySide6.QtWidgets import QApplication
from netlab.config import CONFIG
from netlab.gui.main_window import MainWindow
from netlab.capture.pcapio import iter_capture_file, RandomAccessCapture

parser = argparse.ArgumentParser()
parser.add_argument('--interface', choices=['wlan0', 'lo'], required=True)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
args.output.mkdir(parents=True, exist_ok=True)
CONFIG.set('capture_dir', str(args.output))
CONFIG.set('bpf_filter', '')
app = QApplication([])
from netlab.gui import theme
app.setStyleSheet(theme.STYLESHEET)
window = MainWindow()
window.show()
errors = []
window.capture.failed.connect(errors.append)

def pump(seconds):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        app.processEvents()
        time.sleep(.02)

def wait_for(predicate, timeout=20):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        pump(.05)
        if errors:
            raise RuntimeError(errors)
        if predicate():
            return
    raise TimeoutError('acceptance condition timed out')

responses = []
traffic_errors = []
listener = None
port = 80 if args.interface == 'wlan0' else 18099
if args.interface == 'lo':
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(('127.0.0.1', port)); listener.listen(2)
    listener.settimeout(15)
    def serve():
        try:
            for _ in range(2):
                conn, _ = listener.accept()
                with conn:
                    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    request = b''
                    while b'\r\n\r\n' not in request:
                        request += conn.recv(4096)
                    chunks = [b'HT', b'TP/1.1 200 OK\r\nContent-Ty',
                              b'pe: text/plain\r\nTransfer-Encoding: chunked\r\n',
                              b'Connection: close\r\n\r', b'\n', b'5\r\nhe',
                              b'llo\r\n', b'6\r\n world\r\n', b'0\r\n\r\n']
                    for chunk in chunks:
                        conn.sendall(chunk); time.sleep(.03)
        except Exception as exc:
            traffic_errors.append(repr(exc))
        finally:
            listener.close()
    threading.Thread(target=serve, daemon=True).start()

def traffic():
    try:
        host = 'httpforever.com' if args.interface == 'wlan0' else '127.0.0.1'
        address = socket.gethostbyname(host)
        source = None
        if args.interface == 'wlan0':
            info = json.loads(subprocess.check_output(['ip', '-j', '-4', 'addr', 'show', 'wlan0']))
            source = next(a['local'] for a in info[0]['addr_info'] if a['family'] == 'inet')
        for _ in range(2):
            with socket.socket() as client:
                client.settimeout(12)
                client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                if source:
                    client.bind((source, 0))
                client.connect((address, port))
                for part in [b'G', b'E', b'T / HTTP/1.1\r\nHo',
                             b'st: ' + host.encode() + b'\r\n', b'Connection: close\r\n\r', b'\n']:
                    client.sendall(part); time.sleep(.03)
                payload = b''
                while True:
                    chunk = client.recv(65536)
                    if not chunk:
                        break
                    payload += chunk
                assert payload.startswith(b'HTTP/1.1 200'), payload[:100]
                responses.append(len(payload))
    except Exception as exc:
        traffic_errors.append(repr(exc))

try:
    pump(.5)
    index = window.iface_combo.findData(args.interface)
    assert index >= 0, 'interface unavailable'
    window.iface_combo.setCurrentIndex(index)
    window.bpf_edit.setText('tcp port %d' % port)
    window.start_capture()
    wait_for(lambda: window.capture.is_running and window._source_path.exists())
    pump(.5)
    worker = threading.Thread(target=traffic, daemon=True); worker.start()
    wait_for(lambda: not worker.is_alive(), 35)
    assert not traffic_errors, traffic_errors
    wait_for(lambda: len([t for t in window.analysis.http_txns.snapshot() if t.status == 200]) >= 2)
    pump(1)
    window.stop_capture(); pump(1)
    path = window._source_path
    count = sum(1 for _ in iter_capture_file(path))
    wait_for(lambda: window.analysis.stats().total_packets == count)
    window._tick()
    assert window.live_page.model.rowCount() > 0
    live = dataclasses.asdict(window.analysis.stats())
    assert live['queue_dropped'] == live['malformed'] == 0
    txns = window.analysis.http_txns.snapshot()
    successful = [t for t in txns if t.status == 200]
    assert len(successful) == 2
    assert all(t.resp_body_complete for t in successful)
    flow = window.analysis.flows.get(successful[0].flow_key)
    relations = window.analysis.relations_for_flow(flow)
    assert relations['http'] and relations['summary']
    row = relations['packets'][0]
    assert window.analysis.flow_for_packet(row).key == flow.key
    reader = RandomAccessCapture(path)
    raw = reader.read_at(row.offset)
    assert raw and raw.data
    window.live_page.detail.show_packet(row)
    window._goto('Live Traffic'); pump(.2)
    window.grab().save(str(args.output / 'packets.png'))
    window.live_page.row_activated.emit(row); pump(.2)
    window.grab().save(str(args.output / 'connection.png'))
    capinfos = subprocess.check_output(['capinfos', '-Tm', '-c', str(path)], text=True)
    independent_count = int(list(csv.reader(capinfos.splitlines()))[-1][-1])
    tshark = subprocess.check_output(['tshark', '-r', str(path), '-T', 'fields', '-e', 'frame.number'], text=True)
    assert count == independent_count == len(tshark.splitlines())
    window.open_capture_file(str(path))
    wait_for(lambda: window.analysis.stats().total_packets == count)
    pump(.6)
    assert len([t for t in window.analysis.http_txns.snapshot() if t.status == 200]) == 2
    result = dict(version=netlab.__version__, module=netlab.__file__, interface=args.interface,
                  gui_platform=app.platformName(), pcap=str(path), packets=count,
                  capinfos_count=independent_count, tshark_count=len(tshark.splitlines()),
                  reopened_packets=window.analysis.stats().total_packets,
                  traffic_response_bytes=responses, stats=live,
                  http=[dict(method=t.method, status=t.status, body_bytes=t.resp_body_bytes,
                             body_complete=t.resp_body_complete, transfer=t.resp_transfer) for t in successful],
                  packet_flow_correlation=True, file_offset_seek=True)
    (args.output / 'acceptance.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2), flush=True)
finally:
    if window.capture.is_running:
        window.stop_capture()
    window.analysis.stop()
    window.close()
