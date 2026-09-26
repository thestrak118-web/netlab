"""Interception: the page that declares a scope and then transmits.

Every other page in NetLab observes.  This one forges ARP replies, answers
DNS it was not asked to answer, terminates other people's TLS and hands out
DHCP leases, so it is built around the declaration rather than the buttons:
an engagement names the interface, the gateway and the hosts that are in
scope, the operator confirms it in a dialog that spells out what will be
transmitted, and only then does anything leave the card.

The scope is enforced below this page, in the privileged helper.  What it
does here is make sure the operator saw it.
"""

from __future__ import annotations

import time

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (QCheckBox, QDialog, QDialogButtonBox,
                               QDoubleSpinBox, QFormLayout, QGridLayout,
                               QGroupBox, QHBoxLayout, QLabel, QLineEdit,
                               QMessageBox, QPushButton, QSplitter,
                               QVBoxLayout, QWidget)

from netlab.gui import theme
from netlab.gui.models import InterceptEventModel, TargetModel
from netlab.gui.widgets import Banner, Card, make_table
from netlab.util.format import human_count

# Modules a beginner reaches for first are shown by default; the rest live
# under the "Ilg'or" (Advanced) toggle so the page is not a wall of options.
COMMON_MODULES = {"arp_poison", "sslstrip", "carve_files"}

MODULES = [
    ("arp_poison", "ARP poisoning",
     "Tell each target that the gateway is at this machine's MAC, and the "
     "gateway that each target is. Both directions of their traffic then "
     "arrive here. Restored automatically on disarm."),
    ("sslstrip", "SSL strip",
     "Rewrite https:// links and redirects to http:// on the way to the "
     "target and carry the request to the real server over TLS ourselves. "
     "The target sees no certificate warning - and no padlock."),
    ("ssl_mitm", "SSL MITM",
     "Terminate TLS with a certificate minted by NetLab's own CA and "
     "re-originate it upstream. Unless that CA is installed on the device "
     "under test, its browser will warn. NetLab does not hide the warning."),
    ("dns_spoof", "DNS spoofing",
     "Answer matching names with an address you choose. Every other name is "
     "forwarded to the real resolver and answered truthfully."),
    ("dhcp", "Rogue DHCP",
     "Answer DHCP requests with this host as router and resolver. This is "
     "the most disruptive module here: it competes with the real server for "
     "every lease on the segment."),
    ("cookie_killer", "Cookie killer",
     "Expire the cookies a target presents once per host, so the next page "
     "load forces a fresh login that can be read."),
    ("carve_files", "Capture files",
     "Write readable response bodies (images, documents, archives) to the "
     "engagement directory."),
    ("ntlm_relay", "NTLM relay",
     "Relay a target's SMB/NTLM authentication to the relay-target server "
     "below, live, instead of cracking it offline: the target authenticates "
     "you to that server. Fails against a server that requires SMB signing. "
     "The relay-target must be in scope."),
]


class ArmDialog(QDialog):
    """The confirmation that stands between a plan and a transmission."""

    def __init__(self, engagement: dict, modules: dict, targets: list,
                 parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Arm interception")
        self.setMinimumWidth(620)
        lay = QVBoxLayout(self)
        lay.setSpacing(12)

        title = QLabel("NetLab is about to transmit on %s"
                       % engagement.get("interface", "?"))
        title.setObjectName("PageTitle")
        lay.addWidget(title)

        active = [label for key, label, _ in MODULES if modules.get(key)]
        detail = QLabel(
            "<b>Engagement</b>: %s<br>"
            "<b>Gateway</b>: %s<br>"
            "<b>In scope</b>: %s<br>"
            "<b>Targets that answered ARP</b>: %d<br>"
            "<b>Modules</b>: %s"
            % (engagement.get("name") or "(unnamed)",
               engagement.get("gateway") or "auto-detected",
               ", ".join(engagement.get("targets", [])) or "nothing",
               len(targets), ", ".join(active) or "none"))
        detail.setTextFormat(Qt.TextFormat.RichText)
        detail.setWordWrap(True)
        lay.addWidget(detail)

        warning = QLabel(
            "Forged frames will be sent to these hosts and their traffic will "
            "be routed through this machine. Doing that to a network you have "
            "not been authorised to test is unlawful in most jurisdictions.\n\n"
            "Everything below is written to the engagement's audit log.")
        warning.setWordWrap(True)
        warning.setStyleSheet("color: %s;" % theme.AMBER)
        lay.addWidget(warning)

        self.authorised = QCheckBox(
            "I am authorised to test the hosts listed above")
        lay.addWidget(self.authorised)

        row = QHBoxLayout()
        row.addWidget(QLabel("Type ARM to confirm:"))
        self.confirm = QLineEdit()
        self.confirm.setPlaceholderText("ARM")
        row.addWidget(self.confirm, 1)
        lay.addLayout(row)

        self.buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok |
            QDialogButtonBox.StandardButton.Cancel)
        self.ok = self.buttons.button(QDialogButtonBox.StandardButton.Ok)
        self.ok.setText("Arm")
        self.ok.setObjectName("Danger")
        self.ok.setEnabled(False)
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        lay.addWidget(self.buttons)

        self.authorised.toggled.connect(self._revalidate)
        self.confirm.textChanged.connect(self._revalidate)

    def _revalidate(self) -> None:
        self.ok.setEnabled(self.authorised.isChecked()
                           and self.confirm.text().strip().upper() == "ARM")

    def authorisation_text(self) -> str:
        return ("operator confirmed authorisation at %s"
                % time.strftime("%Y-%m-%d %H:%M:%S"))


class MitmPage(QWidget):
    """Engagement setup, module selection, arming and live status."""

    arm_requested = Signal(dict, dict)       # engagement, modules
    disarm_requested = Signal()
    scan_requested = Signal(str)             # cidr
    promisc_requested = Signal()
    target_added = Signal(str)
    target_removed = Signal(str)
    ca_export_requested = Signal()

    def __init__(self, config, parent=None) -> None:
        super().__init__(parent)
        self._config = config
        self._armed = False
        self._hosts: dict[str, dict] = {}
        self._events: list[dict] = []
        self._status: dict = {}

        lay = QVBoxLayout(self)
        lay.setContentsMargins(18, 16, 18, 14)
        lay.setSpacing(10)

        head = QVBoxLayout()
        head.setSpacing(2)
        title = QLabel("Interception")
        title.setObjectName("PageTitle")
        head.addWidget(title)
        hint = QLabel(
            "Active man-in-the-middle. Declare an engagement, choose what to "
            "run, and arm it. Everything here transmits; the rest of NetLab "
            "does not.")
        hint.setObjectName("PageHint")
        hint.setWordWrap(True)
        head.addWidget(hint)
        lay.addLayout(head)

        self.banner = Banner("", "warn")
        lay.addWidget(self.banner)

        top = QHBoxLayout()
        top.setSpacing(12)
        top.addWidget(self._build_scope_box(), 3)
        top.addWidget(self._build_modules_box(), 4)
        lay.addLayout(top)

        lay.addLayout(self._build_status_row())
        lay.addLayout(self._build_controls())

        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.addWidget(self._build_targets())
        splitter.addWidget(self._build_events())
        splitter.setStretchFactor(0, 2)
        splitter.setStretchFactor(1, 3)
        splitter.setSizes([260, 320])
        lay.addWidget(splitter, 1)

        self._load_config()
        self.set_helper_state(False, "")

    # ----------------------------------------------------------------- UI

    def _build_scope_box(self) -> QGroupBox:
        box = QGroupBox("Engagement")
        form = QFormLayout(box)
        self._scope_form = form
        form.setContentsMargins(12, 10, 12, 10)
        form.setSpacing(7)

        self.name_edit = QLineEdit()
        self.name_edit.setPlaceholderText("lab-2026-09")
        form.addRow("Name", self.name_edit)

        self.interface_label = QLabel("-")
        form.addRow("Interface", self.interface_label)

        self.gateway_edit = QLineEdit()
        self.gateway_edit.setPlaceholderText("auto-detected from the route")
        form.addRow("Gateway", self.gateway_edit)

        self.targets_edit = QLineEdit()
        self.targets_edit.setPlaceholderText(
            "192.168.1.0/24, 10.0.0.5, 10.0.0.20-40")
        self.targets_edit.setToolTip(
            "Addresses, CIDR blocks and last-octet ranges. Nothing outside "
            "this list is touched, by any module.")
        form.addRow("In scope", self.targets_edit)

        self.relay_target_edit = QLineEdit()
        self.relay_target_edit.setPlaceholderText(
            "SMB server to relay to (only used by the NTLM relay module)")
        self.relay_target_edit.setToolTip(
            "When the NTLM relay module is on, a captured SMB authentication "
            "is relayed to this server. It must also be inside the scope above.")
        form.addRow("Relay target", self.relay_target_edit)

        self.note_edit = QLineEdit()
        self.note_edit.setPlaceholderText("optional: ticket or engagement ref")
        form.addRow("Note", self.note_edit)

        # Relay target and note are advanced; hidden until "Ilg'or" is on.
        self._advanced_rows = (self.relay_target_edit, self.note_edit)
        for widget in self._advanced_rows:
            widget.setVisible(False)
            label = form.labelForField(widget)
            if label is not None:
                label.setVisible(False)
        return box

    def _build_modules_box(self) -> QGroupBox:
        box = QGroupBox("Modules")
        outer = QVBoxLayout(box)
        outer.setContentsMargins(12, 10, 12, 10)
        outer.setSpacing(6)
        self.module_boxes: dict[str, QCheckBox] = {}

        # Common modules, always visible.
        common = QGridLayout()
        common.setHorizontalSpacing(16)
        common.setVerticalSpacing(5)
        row = 0
        for key, label, tip in MODULES:
            if key not in COMMON_MODULES:
                continue
            check = QCheckBox(label)
            check.setToolTip(tip)
            self.module_boxes[key] = check
            common.addWidget(check, row, 0)
            row += 1
        outer.addLayout(common)

        # The "Ilg'or" toggle reveals everything else.
        self.advanced_toggle = QCheckBox("Ilg'or modullar va sozlamalar")
        self.advanced_toggle.setToolTip(
            "SSL MITM, DNS spoofing, rogue DHCP, cookie killer, NTLM relay and "
            "the timing/relay options.")
        self.advanced_toggle.toggled.connect(self._toggle_advanced)
        outer.addWidget(self.advanced_toggle)

        self._advanced_box = QWidget()
        adv = QGridLayout(self._advanced_box)
        adv.setContentsMargins(0, 0, 0, 0)
        adv.setHorizontalSpacing(16)
        adv.setVerticalSpacing(5)
        r = 0
        for key, label, tip in MODULES:
            if key in COMMON_MODULES:
                continue
            check = QCheckBox(label)
            check.setToolTip(tip)
            self.module_boxes[key] = check
            adv.addWidget(check, r % 3, r // 3)
            r += 1

        interval_row = QHBoxLayout()
        interval_row.addWidget(QLabel("Re-poison every"))
        self.interval_spin = QDoubleSpinBox()
        self.interval_spin.setRange(0.5, 30.0)
        self.interval_spin.setSingleStep(0.5)
        self.interval_spin.setSuffix(" s")
        self.interval_spin.setToolTip(
            "How often the forged ARP replies are re-sent. Faster keeps the "
            "binding pinned against the target's own ARP traffic; slower is "
            "quieter.")
        interval_row.addWidget(self.interval_spin)
        interval_row.addStretch(1)
        self.ca_button = QPushButton("Export CA certificate")
        self.ca_button.setToolTip(
            "Write NetLab's interception CA so it can be installed on the "
            "device under test. Without it, SSL MITM produces a warning.")
        self.ca_button.clicked.connect(self.ca_export_requested.emit)
        interval_row.addWidget(self.ca_button)
        adv.addLayout(interval_row, (r % 3) + 1, 0, 1, 2)
        self._advanced_box.setVisible(False)
        outer.addWidget(self._advanced_box)
        outer.addStretch(1)
        return box

    def _toggle_advanced(self, on: bool) -> None:
        self._advanced_box.setVisible(on)
        # The relay target and note are advanced too; reveal them together.
        for widget in getattr(self, "_advanced_rows", ()):
            widget.setVisible(on)
            label = self._scope_form.labelForField(widget)
            if label is not None:
                label.setVisible(on)
        # ...as are the "Find sniffers" probe and the detail stat tiles.
        if hasattr(self, "promisc_button"):
            self.promisc_button.setVisible(on)
        for name in ("frames", "dns"):
            if name in getattr(self, "cards", {}):
                self.cards[name].setVisible(on)

    def _build_status_row(self) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setSpacing(10)
        self.cards = {
            "state": Card("State", "Idle", "nothing is transmitting"),
            "targets": Card("Poisoned", "0", "targets in the path"),
            "frames": Card("ARP frames", "0", "forged replies sent"),
            "stripped": Card("Stripped", "0", "hosts downgraded"),
            "creds": Card("Credentials", "0", "read in flight"),
            "dns": Card("DNS", "0", "answers forged"),
        }
        for card in self.cards.values():
            row.addWidget(card)
        # ARP frames and forged DNS are detail; hidden until "Ilg'or".
        self.cards["frames"].setVisible(False)
        self.cards["dns"].setVisible(False)
        row.addStretch(1)
        return row

    def _build_controls(self) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setSpacing(8)

        self.scan_button = QPushButton("Discover hosts")
        self.scan_button.setToolTip(
            "ARP sweep of the interface's own subnet. This transmits, but it "
            "only asks who is there.")
        self.scan_button.clicked.connect(
            lambda: self.scan_requested.emit(""))
        row.addWidget(self.scan_button)

        self.promisc_button = QPushButton("Find sniffers")
        self.promisc_button.setToolTip(
            "Probe in-scope hosts for promiscuous mode - another machine on "
            "the segment that is capturing everything.")
        self.promisc_button.clicked.connect(self.promisc_requested.emit)
        self.promisc_button.setVisible(False)          # advanced
        row.addWidget(self.promisc_button)

        self.use_selected = QPushButton("Scope to selection")
        self.use_selected.setToolTip(
            "Replace the in-scope list with the hosts selected below.")
        self.use_selected.clicked.connect(self._scope_to_selection)
        row.addWidget(self.use_selected)

        row.addStretch(1)

        self.arm_button = QPushButton("Arm interception")
        self.arm_button.setObjectName("Danger")
        self.arm_button.setMinimumWidth(170)
        self.arm_button.clicked.connect(self._arm)
        row.addWidget(self.arm_button)

        self.disarm_button = QPushButton("Disarm and restore")
        self.disarm_button.setMinimumWidth(170)
        self.disarm_button.setEnabled(False)
        self.disarm_button.clicked.connect(self.disarm_requested.emit)
        row.addWidget(self.disarm_button)
        return row

    def _build_targets(self) -> QWidget:
        panel = QWidget()
        lay = QVBoxLayout(panel)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(5)
        label = QLabel("Hosts on the segment")
        label.setObjectName("PageHint")
        lay.addWidget(label)
        self.target_model = TargetModel()
        self.target_table = make_table(self.target_model)
        lay.addWidget(self.target_table, 1)
        self.target_count = QLabel("")
        self.target_count.setObjectName("PageHint")
        lay.addWidget(self.target_count)
        return panel

    def _build_events(self) -> QWidget:
        panel = QWidget()
        lay = QVBoxLayout(panel)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(5)
        label = QLabel("What the active modules are doing")
        label.setObjectName("PageHint")
        lay.addWidget(label)
        self.event_model = InterceptEventModel()
        self.event_table = make_table(self.event_model)
        lay.addWidget(self.event_table, 1)
        self.audit_label = QLabel("")
        self.audit_label.setObjectName("PageHint")
        self.audit_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse)
        lay.addWidget(self.audit_label)
        return panel

    # ------------------------------------------------------------- config

    def _load_config(self) -> None:
        get = self._config.get
        self.name_edit.setText(str(get("engagement_name") or ""))
        self.targets_edit.setText(str(get("engagement_targets") or ""))
        self.relay_target_edit.setText(str(get("relay_target") or ""))
        self.interval_spin.setValue(float(get("mitm_poison_interval") or 2.0))
        for key, check in self.module_boxes.items():
            check.setChecked(bool(get("mitm_" + key if key not in
                                      ("arp_poison",) else "mitm_arp_poison",
                                      key == "arp_poison")))
        self.module_boxes["arp_poison"].setChecked(True)
        self.module_boxes["sslstrip"].setChecked(bool(get("mitm_sslstrip")))

    def save_config(self) -> None:
        self._config.set("engagement_name", self.name_edit.text().strip())
        self._config.set("engagement_targets", self.targets_edit.text().strip())
        self._config.set("relay_target", self.relay_target_edit.text().strip())
        self._config.set("mitm_poison_interval", self.interval_spin.value())
        for key, check in self.module_boxes.items():
            self._config.set("mitm_" + key, check.isChecked())

    def set_interface(self, name: str, gateway: str = "") -> None:
        self.interface_label.setText(name or "-")
        self._interface = name
        if gateway and not self.gateway_edit.text().strip():
            self.gateway_edit.setPlaceholderText("%s (detected)" % gateway)
            self._detected_gateway = gateway

    def add_target(self, ip: str) -> bool:
        """Append a host to the in-scope list (Intercepter-NG 'add to NAT').

        Returns True if it was newly added, False if already in scope. The
        gateway is never a valid target — poisoning your own gateway as a
        victim makes no sense — so it is refused.
        """
        ip = (ip or "").strip()
        if not ip:
            return False
        if ip == (self.gateway_edit.text().strip()
                  or getattr(self, "_detected_gateway", "")):
            return False
        existing = [t.strip() for t in self.targets_edit.text().split(",")
                    if t.strip()]
        if ip in existing:
            return False
        existing.append(ip)
        self.targets_edit.setText(", ".join(existing))
        self.save_config()
        return True

    # -------------------------------------------------------------- state

    def set_helper_state(self, running: bool, message: str) -> None:
        self._helper_running = running
        if self._armed:
            return
        if running:
            self.banner.set_text(
                "The privileged helper is running. Nothing is being "
                "transmitted until an engagement is armed.", "info")
        else:
            self.banner.set_text(
                message or "Arming starts a privileged helper through pkexec. "
                "NetLab itself stays unprivileged, and the helper restores "
                "the network if this window closes.", "warn")

    def set_armed(self, armed: bool, status: dict | None = None) -> None:
        self._armed = armed
        self._status = status or {}
        self.arm_button.setEnabled(not armed)
        self.disarm_button.setEnabled(armed)
        for widget in (self.name_edit, self.gateway_edit, self.targets_edit,
                       self.note_edit):
            widget.setReadOnly(armed)
        for check in self.module_boxes.values():
            check.setEnabled(not armed)
        if armed:
            modules = ", ".join(self._status.get("modules", []))
            self.banner.set_text(
                "ARMED on %s. %s. Forged frames are being transmitted to %d "
                "target(s); disarm to restore them."
                % (self._status.get("engagement", {}).get("interface", "?"),
                   modules or "no modules", len(self._status.get("targets", {}))),
                "error")
            audit = self._status.get("audit", {})
            if audit.get("path"):
                self.audit_label.setText("Audit log: %s" % audit["path"])
        else:
            self.set_helper_state(getattr(self, "_helper_running", False), "")
        self.update_status(self._status)

    def update_status(self, status: dict) -> None:
        if status:
            self._status = status
        s = self._status
        armed = bool(s.get("armed"))
        poisoner = s.get("poisoner", {})
        proxy = s.get("proxy", {})
        dns = s.get("dns", {})

        if armed:
            uptime = int(s.get("uptime", 0))
            self.cards["state"].set_value(
                "Armed", "%dm %02ds in the path" % (uptime // 60, uptime % 60),
                theme.RED)
        else:
            self.cards["state"].set_value("Idle", "nothing is transmitting",
                                          theme.MUTED)
        self.cards["targets"].set_value(
            human_count(len(s.get("targets", {}))),
            "restored" if poisoner.get("restored") else "targets in the path")
        self.cards["frames"].set_value(
            human_count(poisoner.get("frames", 0)),
            "%s rounds" % human_count(poisoner.get("rounds", 0)))
        self.cards["stripped"].set_value(
            human_count(proxy.get("stripped_hosts", 0)),
            "%s links rewritten" % human_count(proxy.get("stripped_links", 0)))
        self.cards["creds"].set_value(
            human_count(proxy.get("credentials", 0)), "read in flight",
            theme.RED if proxy.get("credentials") else None)
        self.cards["dns"].set_value(
            human_count(dns.get("spoofed", 0)),
            "%s forwarded" % human_count(dns.get("forwarded", 0)))

        poisoned = set(s.get("targets", {}))
        for ip, host in self._hosts.items():
            host["poisoned"] = ip in poisoned
        self._refresh_targets()

    # ------------------------------------------------------------- hosts

    def add_host(self, entry: dict) -> None:
        ip = entry.get("ip")
        if not ip:
            return
        host = self._hosts.setdefault(ip, {"ip": ip})
        host.update({k: v for k, v in entry.items() if v not in (None, "")})
        host.setdefault("in_scope", self._in_scope(ip))
        self._refresh_targets()

    def set_hosts(self, entries) -> None:
        for entry in entries:
            self.add_host(entry)

    def note_host(self, ip: str, note: str) -> None:
        if ip in self._hosts:
            self._hosts[ip]["note"] = note
            self._refresh_targets()

    def _in_scope(self, ip: str) -> bool:
        from netlab.intercept.scope import Engagement, parse_targets
        raw = self.targets_edit.text().strip()
        if not raw:
            return False
        try:
            eng = Engagement(targets=parse_targets(raw))
        except ValueError:
            return False
        return eng.contains(ip)

    def _refresh_targets(self) -> None:
        for ip, host in self._hosts.items():
            host["in_scope"] = self._in_scope(ip)
        rows = sorted(self._hosts.values(),
                      key=lambda h: tuple(int(p) for p in h["ip"].split("."))
                      if h["ip"].count(".") == 3 and
                      all(p.isdigit() for p in h["ip"].split(".")) else (0,))
        self.target_model.replace_items(rows)
        in_scope = sum(1 for h in rows if h.get("in_scope"))
        self.target_count.setText(
            "%d host(s) found   ·   %d in scope   ·   %d being poisoned"
            % (len(rows), in_scope,
               sum(1 for h in rows if h.get("poisoned"))))

    def _scope_to_selection(self) -> None:
        rows = self.target_table.selectionModel().selectedRows() \
            if self.target_table.selectionModel() else []
        chosen = [self.target_model.object_at(i.row()) for i in rows]
        addresses = [h["ip"] for h in chosen if h]
        if not addresses:
            QMessageBox.information(
                self, "Nothing selected",
                "Select one or more hosts in the table below first.")
            return
        self.targets_edit.setText(", ".join(addresses))
        self._refresh_targets()

    # ------------------------------------------------------------- events

    def add_event(self, name: str, data: dict) -> None:
        subject = (data.get("client") or data.get("host") or data.get("ip")
                   or data.get("name") or data.get("mac") or "")
        detail_bits = []
        for key, value in data.items():
            if key in ("client", "host", "ip", "mac") or value in ("", None):
                continue
            if isinstance(value, (dict, list)):
                value = "%d item(s)" % len(value)
            detail_bits.append("%s=%s" % (key, str(value)[:120]))
        row = {"ts": data.get("ts") or time.time(), "name": name,
               "subject": str(subject), "detail": "  ".join(detail_bits)[:400]}
        self._events.append(row)
        if len(self._events) > 4000:
            del self._events[:1000]
        self.event_model.append_items([row], cap=4000)
        if self.event_table.verticalScrollBar().value() >= \
                self.event_table.verticalScrollBar().maximum() - 40:
            self.event_table.scrollToBottom()

    def clear_events(self) -> None:
        self._events = []
        self.event_model.clear()

    # ---------------------------------------------------------------- arm

    def engagement_dict(self) -> dict | None:
        from netlab.intercept.scope import parse_targets
        raw = self.targets_edit.text().strip()
        if not raw:
            QMessageBox.information(
                self, "No scope",
                "Enter the addresses you are authorised to test before "
                "arming.\n\nNetLab will not transmit to a host that is not "
                "listed here.")
            return None
        try:
            targets = parse_targets(raw)
        except ValueError as exc:
            QMessageBox.warning(self, "Scope is not valid", str(exc))
            return None
        interface = getattr(self, "_interface", "") or ""
        if not interface:
            QMessageBox.information(
                self, "No interface",
                "Choose a capture interface in the toolbar first.")
            return None
        return {
            "name": self.name_edit.text().strip() or "engagement",
            "interface": interface,
            "gateway": self.gateway_edit.text().strip()
            or getattr(self, "_detected_gateway", ""),
            "targets": targets,
            "note": self.note_edit.text().strip(),
            "operator": "",
            "created": time.time(),
        }

    def modules_dict(self) -> dict:
        modules = {key: check.isChecked()
                   for key, check in self.module_boxes.items()}
        modules["poison_interval"] = self.interval_spin.value()
        modules["verify_upstream"] = bool(
            self._config.get("mitm_verify_upstream"))
        modules["upstream_dns"] = str(self._config.get("mitm_upstream_dns") or "")
        modules["changer_rules"] = list(self._config.get("changer_rules") or [])
        modules["dns_rules"] = list(self._config.get("dns_spoof_rules") or [])
        modules["http_port"] = int(self._config.get("mitm_http_port") or 18080)
        modules["tls_port"] = int(self._config.get("mitm_tls_port") or 18443)
        modules["dns_port"] = int(self._config.get("mitm_dns_port") or 15353)
        modules["relay_target"] = self.relay_target_edit.text().strip()
        return modules

    def watch(self, ip: str) -> None:
        """One-click 'Kuzat': scope to this one device, switch on the modules
        that let its traffic be read (ARP to get in the path, SSL strip, file
        capture), and go through arming."""
        self.targets_edit.setText(ip)
        for key in ("arp_poison", "sslstrip", "carve_files"):
            if key in self.module_boxes:
                self.module_boxes[key].setChecked(True)
        self._arm()

    def _arm(self) -> None:
        engagement = self.engagement_dict()
        if engagement is None:
            return
        modules = self.modules_dict()
        if not any(modules.get(key) for key, _l, _t in MODULES):
            QMessageBox.information(
                self, "Nothing to run",
                "Select at least one module before arming.")
            return
        in_scope = [h for h in self._hosts.values() if h.get("in_scope")]
        dialog = ArmDialog(engagement, modules, in_scope, self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        engagement["authorised"] = True
        engagement["authorisation_text"] = dialog.authorisation_text()
        self.save_config()
        self.arm_requested.emit(engagement, modules)
