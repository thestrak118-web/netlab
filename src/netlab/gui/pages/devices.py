"""Device projections of HostTable, with navigation to the existing analyzers."""
import time
from PySide6.QtCore import Qt, Signal, QSize, QEvent
from PySide6.QtGui import QColor
from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QComboBox, QStyledItemDelegate, QStyleOptionButton, QStyle, QApplication
from netlab.gui.models import NetLabTableModel, LEFT, RIGHT
from netlab.gui.device_icons import device_icon, os_icon
from netlab.gui.pages.detail import DetailPane, kv
from netlab.gui.widgets import TablePage
from netlab.util.format import human_bytes, ts_full


class DeviceModel(NetLabTableModel):
    category = 'All Local'

    def _passes(self, d):
        if not getattr(d, 'monitor_eligible', False): return False
        if self.category == 'Gateway' and d.device_type != 'Gateway': return False
        if self.category == 'Active' and d.status != 'Active': return False
        if self.category == 'Unknown' and d.device_type != 'Unknown': return False
        return super()._passes(d)

    def replace_items(self, items):
        items = [d for d in items if getattr(d, 'monitor_eligible', False)]
        if self.category == 'High Traffic': items.sort(key=lambda d:d.bytes, reverse=True)
        super().replace_items(items)

    COLUMNS = [(title, width, align) for title, width, align in (
        ('Device / addresses', 285, LEFT), ('Hostname / OS / MAC / Vendor', 245, LEFT), ('MAC', 160, LEFT),
        ('Vendor', 165, LEFT), ('Type', 110, LEFT), ('Scope', 90, LEFT),
        ('Packets', 75, RIGHT), ('Bytes', 90, RIGHT), ('Connections', 105, RIGHT),
        ('Activity', 105, LEFT), ('First seen', 190, LEFT), ('Last seen', 190, LEFT), ('Monitor', 95, LEFT), ('pkt/s', 70, RIGHT), ('Bytes/s', 90, RIGHT))]

    def cell(self, d, col):
        if col == 12: return "Monitor"
        if col == 13: return f'{d.packets_sec:.1f}'
        if col == 14: return human_bytes(d.bytes_sec)
        if col == 1:
            os = d.os if getattr(d, 'os', 'Unknown') not in ('', 'Unknown') else ''
            vendor = d.manufacturer if d.manufacturer != 'Unknown' else ''
            line3 = ' · '.join(x for x in (os, vendor) if x) or 'Unknown'
            return f'{d.hostname}\n{d.mac}\n{line3}'
        label = d.device_type if d.device_type in ('This Device', 'Gateway') else d.display_name
        address = '\n'.join(d.addresses[:2]) + (f' (+{len(d.addresses)-2} more)' if len(d.addresses)>2 else '')
        return (label + '\n' + address, d.hostname, d.mac, d.manufacturer, d.device_type, d.scope,
                str(d.packets), human_bytes(d.bytes), str(d.active_connections),
                d.status, ts_full(d.first_seen) if d.first_seen else 'Unknown',
                ts_full(d.last_seen) if d.last_seen else 'Unknown')[col]

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if index.isValid() and index.column() == 0 and role == Qt.ItemDataRole.DecorationRole:
            d = self._rows[index.row()]
            # OS icon (penguin / Windows / Android / Apple) when the OS is
            # known, like Intercepter-NG; otherwise the device-type icon.
            return (os_icon(d.os) if getattr(d, 'os', 'Unknown') not in ('', 'Unknown')
                    else None) or device_icon(d.device_type)
        return super().data(index, role)

    def tooltip(self, d, col):
        return ('Addresses: ' + ', '.join(d.addresses) + '\nMAC: ' + d.mac +
                '\nHostname: ' + d.hostname + '\nVendor: ' + d.manufacturer +
                '\nType: ' + d.device_type + '\nLocal evidence: ' + '; '.join(d.local_evidence) +
                ('\nNo verified device type: phone/laptop icons require identity evidence.' if d.device_type == 'Unknown' else ''))

    def fields(self, d):
        return dict(device=d.addresses, src=d.ip, dst=d.ip, hostname=d.hostname, mac=d.mac,
                    type=d.device_type, state=d.status, vendor=d.manufacturer)

    def identity(self, d):
        return d.identity


class DeviceDetails(QWidget):
    navigate = Signal(str, str)

    def __init__(self):
        super().__init__()
        self.ip = None
        layout = QVBoxLayout(self)
        bar = QHBoxLayout()
        self.icon = QLabel()
        bar.addWidget(self.icon)
        self.buttons = {}
        for name in ('Traffic', 'Connections', 'DNS', 'HTTP', 'TLS', 'PCAP'):
            button = QPushButton('View ' + name)
            button.setEnabled(False)
            button.clicked.connect(lambda checked=False, n=name: self.navigate.emit(n, self.ip))
            self.buttons[name] = button
            bar.addWidget(button)
        layout.addLayout(bar)
        self.text = DetailPane('Select a device to inspect its evidence and traffic.')
        layout.addWidget(self.text)

    def clear_detail(self):
        self.ip = None
        self.icon.clear()
        self.text.clear_detail()
        for button in self.buttons.values():
            button.setEnabled(False)

    def show_device(self, d, relations):
        self.ip = d.ip
        self.icon.setPixmap(device_icon(d.device_type).pixmap(32, 32))
        for button in self.buttons.values():
            button.setEnabled(True)
        lines = ['Identity', kv('Device ID', d.identity),
                 kv('IPv4 addresses', ', '.join(d.ipv4_addresses) or 'Unknown'),
                 kv('IPv6 addresses', ', '.join(d.ipv6_addresses) or 'Unknown'),
                 kv('Local evidence', '; '.join(d.local_evidence)), '']
        attributes = [('IP', d.ip), ('MAC', d.mac), ('Hostname', d.hostname),
                      ('Manufacturer', d.manufacturer), ('Device type', d.device_type),
                      ('OS', d.os), ('Exact device model', d.model), ('Friendly name', d.attribute('Friendly name')),
                      ('OS estimate', d.attribute('OS estimate'))]
        for field, value in attributes:
            lines.append(kv(field, value))
            evidence = [e for e in d.evidence if e.field == field]
            if not evidence:
                lines.append('    Evidence: UNKNOWN')
            for e in evidence:
                lines.append(f'    {e.confidence}: {e.value} — {e.source}')
        if d.device_type == 'Unknown':
            lines += ['    Icon: Unknown — no verified phone/computer/printer identity.',
                      '    A MAC or OUI vendor alone does not establish device type.']
        lines += ['', 'Traffic', kv('Scope', d.scope), kv('Activity', d.status),
                  kv('Packets', d.packets), kv('Bytes', human_bytes(d.bytes)),
                  kv('Upload', human_bytes(d.upload)), kv('Download', human_bytes(d.download)),
                  kv('Packets/sec (5s)', f'{d.packets_sec:.1f}'),
                  kv('Bytes/sec (5s)', f'{d.bytes_sec:.1f}'),
                  kv('Active connections', d.active_connections)]
        lines += ['', f'Connections ({len(relations["connections"])})']
        lines += [f'  {f.proto} {f.client}:{f.client_port} → {f.server}:{f.server_port}  {f.state}'
                  for f in relations['connections'][:12]] or ['  None observed']
        lines += ['', f'DNS ({len(relations["dns"])})']
        lines += [f'  {e.qname or "Unknown"}  {e.answer_summary}' for e in relations['dns'][-12:]] or ['  None observed']
        lines += ['', f'HTTP ({len(relations["http"])})']
        lines += [f'  {t.method or "Unknown"} {t.host or "Unknown"}{t.path or ""} → {t.status or "Unknown"}' for t in relations['http'][-12:]] or ['  None observed']
        lines += ['', f'TLS ({len(relations["tls"])})']
        lines += [f'  {t.sni or "Unknown"}  {t.negotiated_version or t.server_version or "Unknown"}' for t in relations['tls'][-12:]] or ['  None observed']
        lines += ['', 'Timeline', kv('First seen', ts_full(d.first_seen) if d.first_seen else 'Unknown'),
                  kv('Last seen', ts_full(d.last_seen) if d.last_seen else 'Unknown'),
                  '', 'Protocol names are observations, not proof of device model.']
        # Counters refresh while the operator may be reading lower sections.
        vertical = self.text.verticalScrollBar().value()
        horizontal = self.text.horizontalScrollBar().value()
        if self.text.toPlainText() != '\n'.join(lines):
            self.text.show_lines(lines)
            self.text.verticalScrollBar().setValue(vertical)
            self.text.horizontalScrollBar().setValue(horizontal)


class MonitorButtonDelegate(QStyledItemDelegate):
    monitor_requested = Signal(str)

    def paint(self, painter, option, index):
        painter.save()
        painter.setPen(QColor('#485160'))
        painter.setBrush(QColor('#252a32'))
        painter.drawRoundedRect(option.rect.adjusted(6, 12, -6, -12), 4, 4)
        painter.setPen(QColor('#e1e6ee'))
        painter.drawText(option.rect, Qt.AlignmentFlag.AlignCenter, 'Monitor')
        painter.restore()

    def editorEvent(self, event, model, option, index):
        if event.type() == QEvent.Type.MouseButtonRelease and event.button() == Qt.MouseButton.LeftButton and option.rect.contains(event.position().toPoint()):
            self.monitor_requested.emit(model.object_at(index.row()).identity)
            return True
        return False


class DevicesPage(TablePage):
    monitor_requested = Signal(str)
    intercept_requested = Signal(list)
    discovery_requested = Signal()
    discovery_cancelled = Signal()
    def __init__(self, title='Devices'):
        super().__init__(title, 'Observed LOCAL devices only. Multiple addresses share one identity when supported by evidence. Internet destinations remain in Traffic, Connections and Topology.', DeviceModel())
        self.table.verticalHeader().setDefaultSectionSize(72)
        self.table.setIconSize(QSize(28, 28))
        self.attach_detail(DeviceDetails(), (500, 240))
        self.splitter.setChildrenCollapsible(False)
        self.detail.setMinimumHeight(210)
        # Keep activity and rates visible; full identity/timestamps stay in Details.
        # Keep the host list readable: show Device, Monitor, Hostname/OS/MAC/
        # Vendor, Packets and Activity; hide the rest (MAC/Vendor/Type/Scope are
        # already in the combined column; Bytes/Connections/rates are detail).
        for col in (2, 3, 4, 5, 7, 8, 10, 11, 13, 14):
            self.table.setColumnHidden(col, True)
        self.selected_identity = None
        self.revisions = 0
        self.live_status = QLabel('Stopped — start capture to receive live observations')
        self.live_status.setWordWrap(True)
        self.body_layout.insertWidget(1, self.live_status)
        self.discovery_status = QLabel('')
        self.discovery_status.setWordWrap(True)
        self.discovery_status.setToolTip('Names/models require device responses. Managed Wi-Fi '
                                         'capture usually sees this computer’s traffic; discovering '
                                         'a peer does not expose its Internet traffic.')
        self.body_layout.insertWidget(2, self.discovery_status)
        self.discover_button = QPushButton('Discover devices')
        self.discover_button.setToolTip('Active ARP and name discovery on the selected local IPv4 network. May request administrator authentication.')
        self.discover_button.clicked.connect(self.discovery_requested.emit)
        self.add_tool(self.discover_button)
        self.cancel_discovery = QPushButton('Cancel discovery')
        self.cancel_discovery.setVisible(False)
        self.cancel_discovery.clicked.connect(self.discovery_cancelled.emit)
        self.add_tool(self.cancel_discovery)
        self.engine = None
        self.category = QComboBox()
        self.category.addItems(['All Local', 'Gateway', 'Active', 'Unknown', 'High Traffic'])
        self.category.currentTextChanged.connect(self._category_changed)
        self.add_tool(self.category)
        self.monitor_delegate = MonitorButtonDelegate(self.table)
        self.monitor_delegate.monitor_requested.connect(self.monitor_requested.emit)
        self.table.setItemDelegateForColumn(12, self.monitor_delegate)
        self.table.horizontalHeader().moveSection(12, 1)
        self.monitor_button = QPushButton('Monitor selected device')
        self.monitor_button.setEnabled(False)
        self.monitor_button.clicked.connect(lambda: self.monitor_requested.emit(self.detail.ip) if self.detail.ip else None)
        self.add_tool(self.monitor_button)
        # Intercepter-NG "add to NAT": send the selected host(s) to the
        # engagement as MiTM targets, then jump to the Interception page.
        # Ctrl/Shift-click selects several rows at once.
        self.intercept_button = QPushButton('Send to Interception')
        self.intercept_button.setObjectName('Danger')
        self.intercept_button.setToolTip('Add the selected host(s) to the engagement as MiTM targets and open the Interception page. Ctrl/Shift-click to pick several.')
        self.intercept_button.setEnabled(False)
        self.intercept_button.clicked.connect(self._send_selected_to_intercept)
        self.add_tool(self.intercept_button)
        # Single click peeks at the inline detail; double-click (or Enter)
        # drills into the host's Selected Device tabs -- the host-centric flow.
        self.row_selected.connect(self._selected)
        self.row_activated.connect(self._activated)

    def set_discovery_status(self, text, running=False):
        self.discovery_status.setText(text)
        self.discover_button.setEnabled(not running)
        self.cancel_discovery.setVisible(running)

    def _category_changed(self, category):
        self.model.category = category
        self.model.replace_items(self.model._source)
        self.update_counts()

    def _selected_ips(self):
        """Every currently selected row's IP (Ctrl/Shift multi-select)."""
        ips, seen = [], set()
        sel = self.table.selectionModel()
        for index in (sel.selectedRows() if sel else []):
            d = self.model.object_at(index.row())
            ip = getattr(d, 'ip', '') if d else ''
            if ip and ip not in seen:
                seen.add(ip)
                ips.append(ip)
        if not ips and self.detail.ip:
            ips.append(self.detail.ip)
        return ips

    def _send_selected_to_intercept(self):
        ips = self._selected_ips()
        if ips:
            self.intercept_requested.emit(ips)

    def _selected(self, d):
        self.selected_identity = d.identity
        self.monitor_button.setEnabled(True)
        self.intercept_button.setEnabled(bool(getattr(d, 'ip', '')))
        if self.engine:
            self.detail.show_device(d, self.engine.relations_for_device(d.ip))

    def _activated(self, d):
        """Double-click / Enter: peek, then open the host's device view."""
        self._selected(d)
        ip = getattr(d, 'ip', '')
        if ip:
            self.monitor_requested.emit(ip)

    def set_capture_status(self, mode, running, interface, stats, interval_ms):
        state = ('● LIVE · ' + interface) if running else 'Offline file' if mode == 'offline' else 'Stopped'
        rate = f' · {stats.packets_per_sec:.1f} pkt/s' if running else ''
        self.live_status.setText(f'{state}{rate}')

    def refresh(self, devices):
        self.revisions += 1
        devices = sorted(devices, key=lambda d: (
            0 if d.device_type == 'This Device' else 1 if d.device_type == 'Gateway' else 2, d.ip))
        self.model.replace_items(devices)
        self.update_counts()
        visible = [self.model.object_at(i) for i in range(self.model.rowCount())]
        current = next((d for d in visible if d.identity == self.selected_identity), None)
        current = current or (visible[0] if visible else None)
        if current:
            row = next(i for i,d in enumerate(visible) if d.identity == current.identity)
            if self.table.currentIndex().row() != row: self.table.selectRow(row)
            self._selected(current)
        else:
            self.selected_identity = None
            self.detail.clear_detail()
            self.monitor_button.setEnabled(False)

    def select_device(self, ip):
        self.category.setCurrentText('All Local')
        self.set_filter_text('')
        for row in range(self.model.rowCount()):
            d = self.model.object_at(row)
            if ip == d.identity or ip in d.addresses:
                self.table.selectRow(row)
                self._selected(d)
                return True
        return False
