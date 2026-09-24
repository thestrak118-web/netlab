"""One-device passive live monitor with off-thread bounded snapshot collection."""
import threading
import queue
from PySide6.QtCore import Signal, Qt, QTimer
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
                               QTabWidget, QFileDialog, QMessageBox)
from netlab.analyze.monitor import MonitorRegistry, MonitorState, snapshot_for_device
from netlab.capture.export import export_device_pcap
from netlab.gui.device_icons import device_icon
from netlab.gui.models import (NetLabTableModel, DnsModel, HttpModel,
                               CredentialModel, LEFT, RIGHT)
from netlab.gui.widgets import make_table
from netlab.util.format import ts_full, ts_time, human_bytes


class ActivityModel(NetLabTableModel):
    COLUMNS = [('Time',100,LEFT), ('Direction',85,LEFT), ('Destination / peer',180,LEFT),
               ('Domain',230,LEFT), ('Protocol',90,LEFT), ('Bytes',90,RIGHT)]

    def cell(self, r, col):
        return (ts_time(r.ts), r.direction, r.destination, r.domain, r.protocol, human_bytes(r.bytes))[col]

    def identity(self, r): return r.index


class MonitorConnectionModel(NetLabTableModel):
    ip = None
    addresses = ()
    COLUMNS = [('Destination / peer',180,LEFT), ('Port',65,RIGHT), ('Protocol',90,LEFT),
               ('Bytes',90,RIGHT), ('Packets',80,RIGHT), ('First seen',180,LEFT),
               ('Last seen',180,LEFT), ('State',100,LEFT)]

    def cell(self, f, col):
        peer, port = (f.server, f.server_port) if f.client in self.addresses else (f.client, f.client_port)
        return (peer, str(port) if port is not None else 'Unknown', f.app_proto or f.proto,
                human_bytes(f.bytes), str(f.packets), ts_full(f.first_ts), ts_full(f.last_ts), f.state)[col]

    def identity(self, f): return f.key


class MonitorTlsModel(NetLabTableModel):
    flow_data = {}
    COLUMNS = [('SNI',210,LEFT), ('TLS version',110,LEFT), ('ALPN',190,LEFT),
               ('Cipher',240,LEFT), ('First seen',180,LEFT), ('Last seen',180,LEFT),
               ('Flow bytes',100,RIGHT), ('Visibility',220,LEFT)]

    def cell(self, t, col):
        size, first, last = self.flow_data.get(t.flow_key, (None,t.ts,t.ts))
        alpn = t.alpn_selected or (', '.join(t.alpn_offered)+' (offered)' if t.alpn_offered else 'Unknown')
        return (t.sni or 'Unknown', t.negotiated_version or t.server_version or 'Unknown',
                alpn, t.cipher_suite or 'Unknown', ts_full(first), ts_full(last),
                human_bytes(size) if size is not None else 'Unknown', 'Encrypted — metadata only')[col]

    def identity(self, t): return t.flow_key


import collections
Site = collections.namedtuple('Site', 'domain kind visits first last')


class MonitorSitesModel(NetLabTableModel):
    """Which sites this device visited — domains, not IPs, not packet counts."""
    COLUMNS = [('Sayt (domain)', 320, LEFT), ('Turi', 90, LEFT),
               ('Tashrif', 80, RIGHT), ('Birinchi', 150, LEFT),
               ('Oxirgi', 150, LEFT)]

    def cell(self, s, col):
        return (s.domain, s.kind, str(s.visits), ts_full(s.first),
                ts_full(s.last))[col]

    def identity(self, s):
        return s.domain

    def colour(self, s, col):
        from netlab.gui import theme
        if col == 1:
            return {'HTTP': theme.AMBER, 'HTTPS': theme.GREEN,
                    'DNS': theme.PURPLE}.get(s.kind)
        return None


def aggregate_sites(snapshot):
    """Fold a device's TLS/HTTP/DNS records into one list of visited sites."""
    rank = {'HTTP': 3, 'HTTPS': 2, 'DNS': 1}
    agg = {}

    def add(domain, kind, ts):
        if not domain:
            return
        domain = domain.split(':')[0].rstrip('.').lower()
        if not domain or domain.endswith('.arpa'):
            return
        cur = agg.get(domain)
        if cur is None:
            agg[domain] = [kind, 1, ts, ts]
        else:
            cur[1] += 1
            cur[2] = min(cur[2], ts)
            cur[3] = max(cur[3], ts)
            if rank.get(kind, 0) > rank.get(cur[0], 0):
                cur[0] = kind

    for t in snapshot.tls:
        if t.sni:
            add(t.sni, 'HTTPS', t.ts)
    for h in snapshot.http:
        if h.host:
            add(h.host, 'HTTP', h.ts)
    for e in snapshot.dns:
        if e.qname:
            add(e.qname, 'DNS', e.ts)
    return [Site(d, v[0], v[1], v[2], v[3])
            for d, v in sorted(agg.items(), key=lambda kv: -kv[1][3])]


class MonitorPage(QWidget):
    indicator_changed = Signal(str, str)
    open_connection = Signal(object)
    back_requested = Signal()

    def __init__(self, engine, source_provider, capture_running,
                 creds_provider=None):
        super().__init__()
        self.engine = engine
        self.source_provider = source_provider
        self.capture_running = capture_running
        # Returns every credential (passive + active) so this page can show the
        # ones that belong to the selected device. None => passive only.
        self.creds_provider = creds_provider
        self.registry = MonitorRegistry()
        self.selected_ip = None
        self.selected_id = None
        self._last_device = None
        self.snapshot = None
        self._busy = False
        self._export_busy = False
        self._results = queue.SimpleQueue()
        self.revisions = 0
        layout = QVBoxLayout(self)
        header = QHBoxLayout()
        # Drill-down view: a way back to the host list it was opened from.
        self.back_button = QPushButton('← Hostlar')
        self.back_button.setObjectName('BackButton')
        self.back_button.clicked.connect(self.back_requested.emit)
        header.addWidget(self.back_button)
        self.icon = QLabel()
        header.addWidget(self.icon)
        self.title = QLabel('Selected Device')
        self.title.setObjectName('PageTitle')
        header.addWidget(self.title, 1)
        self.status = QLabel('Stopped')
        header.addWidget(self.status)
        layout.addLayout(header)
        self.identity = QLabel('Hostlar → hostga ikki marta bosing')
        self.identity.setWordWrap(True)
        self.identity.setTextFormat(Qt.TextFormat.PlainText)
        layout.addWidget(self.identity)
        self.notice = QLabel('Passive observations only. HTTPS/TLS payload contents are encrypted and are not visible.')
        self.notice.setWordWrap(True)
        layout.addWidget(self.notice)
        buttons = QHBoxLayout()
        self.buttons = {}
        for label, callback in [('Monitor',self.start), ('Pause',self.pause), ('Resume',self.resume),
                                ('Stop Monitoring',self.stop), ('Export Device Traffic',self.export)]:
            button = QPushButton(label)
            button.clicked.connect(callback)
            buttons.addWidget(button)
            self.buttons[label] = button
        buttons.addStretch()
        layout.addLayout(buttons)
        # Packet/byte/rate counters are noise for this view; the tabs below
        # carry the content. Kept for callers but hidden.
        self.statistics = QLabel('No selected device')
        self.statistics.setWordWrap(True)
        self.statistics.setVisible(False)
        layout.addWidget(self.statistics)
        self.tabs = QTabWidget()
        self.models = dict(Sites=MonitorSitesModel(), Activity=ActivityModel(),
                           Connections=MonitorConnectionModel(),
                           DNS=DnsModel(), HTTP=HttpModel(), TLS=MonitorTlsModel(),
                           Passwords=CredentialModel())
        self.tables = {}
        _tab_titles = {'Sites': 'Saytlar', 'Activity': 'Live Activity',
                       'Connections': 'Active Connections', 'Passwords': 'Passwords'}
        for name, model in self.models.items():
            table = make_table(model)
            self.tables[name] = table
            self.tabs.addTab(table, _tab_titles.get(name, name))
        self.tables['Connections'].clicked.connect(self._connection_clicked)
        self.tables['Activity'].doubleClicked.connect(self._activity_clicked)
        layout.addWidget(self.tabs, 1)
        self.footnote = QLabel('')
        self.footnote.setWordWrap(True)
        self.footnote.setVisible(False)
        layout.addWidget(self.footnote)
        # Workers hold only engine/path/queue references, never this QWidget.
        # Qt widgets and model mutation stay entirely on the GUI thread.
        self._delivery_timer = QTimer(self)
        self._delivery_timer.timeout.connect(self._poll_results)
        self._delivery_timer.start(50)
        self._controls()

    @property
    def subscription(self):
        return self.registry.subscriptions.get(self.selected_id)

    @property
    def state(self):
        return self.subscription.state if self.subscription else MonitorState.STOPPED

    def select_device(self, ip):
        device = self.engine.resolve_device(ip)
        if device is None:
            raise ValueError('Remote destinations cannot be monitored as devices')
        sub = self.registry.select_one(device.identity)
        self.selected_id = sub.ip
        self.selected_ip = device.ip
        self._last_device = device
        self.snapshot = None
        self._clear_rows()
        self.title.setText('Selected Device — '+device.ip)
        self.identity.setText('Loading observed identity…')
        self._controls()
        self.refresh()

    def start(self):
        if self.selected_ip:
            self.registry.select_one(self.selected_id)
            self._controls()
            self.refresh()

    def pause(self):
        if self.state == MonitorState.MONITORING:
            self.registry.transition(self.selected_id, MonitorState.PAUSED)
            self._controls()

    def resume(self):
        if self.state == MonitorState.PAUSED:
            self.registry.transition(self.selected_id, MonitorState.MONITORING)
            self._controls()
            self.refresh()

    def stop(self):
        self.registry.clear()
        self.snapshot = None
        self._clear_rows()
        self._controls()

    def reset(self):
        self.stop()
        self.selected_ip = None
        self.selected_id = None
        self._last_device = None
        self.title.setText('Selected Device')
        self.identity.setText('Devices → select a device → Monitor')
        self.icon.clear()
        self._controls()

    def _clear_rows(self):
        for model in self.models.values(): model.clear()
        self.statistics.setText('No active monitoring subscription')

    def _controls(self):
        active = self.state == MonitorState.MONITORING
        paused = self.state == MonitorState.PAUSED
        self.status.setText('● Monitoring' if active else '○ Paused — frozen view' if paused else 'Stopped')
        self.buttons['Monitor'].setEnabled(bool(self.selected_ip) and not active and not paused)
        self.buttons['Pause'].setEnabled(active)
        self.buttons['Resume'].setEnabled(paused)
        self.buttons['Stop Monitoring'].setEnabled(active or paused)
        self.buttons['Export Device Traffic'].setEnabled(bool(self.selected_ip) and not self._export_busy)
        self.indicator_changed.emit(self.selected_ip or '', self.state.value)

    def refresh(self):
        if self.state != MonitorState.MONITORING or self._busy:
            return
        self._busy = True
        generation = self.subscription.generation
        ip = self.selected_id
        previous = self._last_device
        engine, results = self.engine, self._results
        def run():
            try:
                snapshot = snapshot_for_device(engine, ip, previous=previous)
                results.put(('snapshot', generation, snapshot, ''))
            except Exception as exc:
                results.put(('snapshot', generation, None, str(exc)))
        threading.Thread(target=run, daemon=True, name='netlab-monitor-snapshot').start()

    def _poll_results(self):
        while True:
            try:
                kind, *values = self._results.get_nowait()
            except queue.Empty:
                break
            if kind == 'snapshot': self._received(*values)
            else: self._export_finished(*values)

    def shutdown(self):
        self.stop()
        self._delivery_timer.stop()

    def closeEvent(self, event):
        self.shutdown()
        super().closeEvent(event)

    def _received(self, generation, snapshot, error):
        self._busy = False
        if not self.subscription or generation != self.subscription.generation or self.state != MonitorState.MONITORING:
            return
        if error:
            self.notice.setText('Could not refresh monitor: '+error)
            return
        self.apply_snapshot(snapshot)

    def apply_snapshot(self, snapshot):
        if snapshot.identity != self.selected_id:
            return
        self.snapshot = snapshot
        self.revisions += 1
        d = snapshot.device
        if d:
            self._last_device = d
            self.selected_ip = d.ip
            self.icon.setPixmap(device_icon(d.device_type).pixmap(36,36))
            status = '● Active' if d.status == 'Active' else '○ Inactive'
            # Plain identity line; the per-field evidence/confidence detail
            # moves to the tooltip so the page stays readable.
            self.identity.setText(f'{", ".join(d.addresses)}   |   MAC: {d.mac}   |   '
                                  f'{d.hostname}   |   Vendor: {d.manufacturer}   |   {status}')
            self.identity.setToolTip('\n'.join(f'{e.field}: {e.value} — {e.confidence}: {e.source}' for e in d.evidence))
            traffic = f'{d.packets:,} packets · {human_bytes(d.bytes)} · {d.packets_sec:.1f} packets/sec · {human_bytes(d.bytes_sec)}/sec'
        else:
            self.icon.setPixmap(device_icon('Unknown').pixmap(36,36))
            self.identity.setText(f'{snapshot.ip} · ○ Inactive · No longer retained in the host table\nMAC / hostname / vendor / evidence: Unknown')
            traffic = 'Packets / bytes / rates: Unknown'
        counts = snapshot.counts
        self.statistics.setText(f'{traffic}\n{counts["active_connections"]} active connections · {counts["dns"]} DNS events · '
                                f'{counts["http"]} HTTP sessions · {counts["tls"]} TLS sessions')
        self.models['Connections'].ip = snapshot.ip
        self.models['Connections'].addresses = snapshot.addresses
        self.models['TLS'].flow_data = snapshot.tls_bytes
        for name, rows in [('Activity',snapshot.activity),('Connections',snapshot.connections),
                           ('DNS',snapshot.dns),('HTTP',snapshot.http),('TLS',snapshot.tls)]:
            self.models[name].replace_items(rows)
        # Credentials this device gave away (login/password read from its
        # cleartext HTTP, and hashes) — the content, not packet counts.
        creds = []
        if self.creds_provider:
            addresses = set(snapshot.addresses)
            creds = [c for c in self.creds_provider()
                     if c.client in addresses or c.server in addresses]
        self.models['Passwords'].replace_items(creds)
        # Which sites this device visited (domains, not IPs).
        self.models['Sites'].replace_items(aggregate_sites(snapshot))
        self.notice.setText('Passive monitoring. HTTPS/TLS payload contents are encrypted and are not visible. '
                            + ('Global capture running.' if self.capture_running() else 'Global capture stopped; showing retained observations.'))
        self.footnote.setText('Counters cover current capture/retained analysis. Activity is per observed packet; IN shows the sending peer. '
                             f'Each table retains up to 1,000 rows; omitted: {sum(snapshot.omitted.values())}. '
                             'Active means traffic within 30 seconds. Pause freezes the view; resume catches up retained data.')

    def _connection_clicked(self, index):
        flow = self.models['Connections'].object_at(index.row())
        if flow is not None:
            original = self.engine.flows.get(flow.key)
            if original is not None: self.open_connection.emit(original)

    def _activity_clicked(self, index):
        row = self.models['Activity'].object_at(index.row())
        flow = self.engine.flows.get(row.flow_key) if row else None
        if flow is not None: self.open_connection.emit(flow)

    def export(self):
        source = self.source_provider()
        if not self.selected_ip or not source or not source.exists():
            QMessageBox.information(self, 'No capture', 'No capture file is available.')
            return
        target, _ = QFileDialog.getSaveFileName(self, 'Export Device Traffic', 'device-traffic.pcapng', 'PCAPNG (*.pcapng)')
        if not target: return
        self._export_busy = True
        self._controls()
        ip = self._last_device.addresses if self._last_device else ()
        results = self._results
        def run():
            try:
                count = export_device_pcap(source, target, ip)
                results.put(('export', target, count, ''))
            except Exception as exc:
                results.put(('export', target, 0, str(exc)))
        threading.Thread(target=run, daemon=True, name='netlab-monitor-export').start()

    def _export_finished(self, path, count, error):
        self._export_busy = False
        self._controls()
        self.notice.setText('Export failed: '+error if error else f'Exported {count} original packets to {path}')
