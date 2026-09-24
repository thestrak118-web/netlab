"""Settings: capture defaults, storage, retention, limits and privileges."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (QCheckBox, QComboBox, QFileDialog, QFormLayout,
                               QGroupBox, QHBoxLayout, QLabel, QLineEdit,
                               QMessageBox, QPushButton, QScrollArea, QSpinBox,
                               QVBoxLayout, QWidget)

from netlab.capture.privileges import check as check_privileges
from netlab.capture.privileges import remediation_text
from netlab.config import config_path, default_capture_dir
from netlab.gui.pages.detail import DetailPane
from netlab.gui.widgets import Banner


class SettingsPage(QWidget):
    settings_saved = Signal()

    def __init__(self, config, parent=None) -> None:
        super().__init__(parent)
        self._config = config

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        outer.addWidget(scroll)
        body = QWidget()
        scroll.setWidget(body)
        lay = QVBoxLayout(body)
        lay.setContentsMargins(18, 16, 18, 18)
        lay.setSpacing(12)

        title = QLabel("Settings")
        title.setObjectName("PageTitle")
        lay.addWidget(title)
        hint = QLabel("Saved to %s" % config_path())
        hint.setObjectName("PageHint")
        lay.addWidget(hint)

        self.banner = Banner("", "info")
        self.banner.setVisible(False)
        lay.addWidget(self.banner)

        # ---- capture ----------------------------------------------------
        cap_box = QGroupBox("Capture")
        cap_form = QFormLayout(cap_box)
        self.interface = QLineEdit()
        self.interface.setPlaceholderText("Leave empty to choose each time")
        cap_form.addRow("Default interface", self.interface)

        self.bpf = QLineEdit()
        self.bpf.setPlaceholderText("e.g. not port 22")
        cap_form.addRow("Default BPF filter", self.bpf)

        self.fmt = QComboBox()
        self.fmt.addItem("pcapng (recommended)", "pcapng")
        self.fmt.addItem("pcap (classic)", "pcap")
        cap_form.addRow("Capture file format", self.fmt)

        self.snaplen = QSpinBox()
        self.snaplen.setRange(64, 262144)
        self.snaplen.setSingleStep(1024)
        self.snaplen.setSuffix(" bytes")
        self.snaplen.setToolTip(
            "Bytes captured per packet. Lower values save disk but truncate "
            "headers, which reduces what DNS/HTTP/TLS analysis can see.")
        cap_form.addRow("Snap length", self.snaplen)

        self.promisc = QCheckBox("Capture in promiscuous mode")
        cap_form.addRow("", self.promisc)
        lay.addWidget(cap_box)

        # ---- storage ----------------------------------------------------
        store_box = QGroupBox("Storage and retention")
        store_form = QFormLayout(store_box)
        dir_row = QHBoxLayout()
        self.capture_dir = QLineEdit()
        self.capture_dir.setPlaceholderText(str(default_capture_dir()))
        dir_row.addWidget(self.capture_dir, 1)
        browse = QPushButton("Browse…")
        browse.clicked.connect(self._browse_dir)
        dir_row.addWidget(browse)
        dir_wrap = QWidget()
        dir_wrap.setLayout(dir_row)
        store_form.addRow("Capture directory", dir_wrap)

        self.max_pcap = QSpinBox()
        self.max_pcap.setRange(1, 1024 * 64)
        self.max_pcap.setSuffix(" MB")
        self.max_pcap.setToolTip(
            "dumpcap stops the capture when the file reaches this size.")
        store_form.addRow("Maximum capture file size", self.max_pcap)

        self.retention_days = QSpinBox()
        self.retention_days.setRange(0, 3650)
        self.retention_days.setSuffix(" days  (0 = keep forever)")
        store_form.addRow("Delete captures older than", self.retention_days)

        self.retention_files = QSpinBox()
        self.retention_files.setRange(0, 100000)
        self.retention_files.setSuffix(" files  (0 = no limit)")
        store_form.addRow("Keep at most", self.retention_files)
        lay.addWidget(store_box)

        # ---- limits -----------------------------------------------------
        limit_box = QGroupBox("Memory limits")
        limit_form = QFormLayout(limit_box)
        limit_hint = QLabel(
            "These caps are what keep memory flat at high packet rates. When a "
            "cap is reached the oldest entries are dropped and the count is "
            "reported on the Dashboard. Changes take effect on restart.")
        limit_hint.setObjectName("PageHint")
        limit_hint.setWordWrap(True)
        limit_form.addRow(limit_hint)

        self.queue_packets = QSpinBox()
        self.queue_packets.setRange(1000, 5_000_000)
        self.queue_packets.setSingleStep(10000)
        limit_form.addRow("Capture queue (packets)", self.queue_packets)

        self.live_rows = QSpinBox()
        self.live_rows.setRange(1000, 5_000_000)
        self.live_rows.setSingleStep(10000)
        limit_form.addRow("Live Traffic rows", self.live_rows)

        self.max_flows = QSpinBox()
        self.max_flows.setRange(1000, 2_000_000)
        self.max_flows.setSingleStep(10000)
        limit_form.addRow("Connections tracked", self.max_flows)

        self.max_hosts = QSpinBox()
        self.max_hosts.setRange(1000, 2_000_000)
        self.max_hosts.setSingleStep(5000)
        limit_form.addRow("Hosts tracked", self.max_hosts)

        self.refresh_ms = QSpinBox()
        self.refresh_ms.setRange(100, 5000)
        self.refresh_ms.setSingleStep(100)
        self.refresh_ms.setSuffix(" ms")
        limit_form.addRow("GUI refresh interval", self.refresh_ms)
        lay.addWidget(limit_box)

        # ---- tools ------------------------------------------------------
        tool_box = QGroupBox("Tools")
        tool_form = QFormLayout(tool_box)
        self.nmap_path = QLineEdit()
        self.nmap_path.setPlaceholderText("nmap")
        tool_form.addRow("nmap executable", self.nmap_path)
        self.resolve_names = QCheckBox(
            "Attach hostnames learned from observed DNS answers and TLS SNI")
        tool_form.addRow("", self.resolve_names)
        lay.addWidget(tool_box)

        # ---- interception -----------------------------------------------
        icept_box = QGroupBox("Interception")
        icept_form = QFormLayout(icept_box)
        icept_hint = QLabel(
            "NetLab's passive analysis records that a credential header was "
            "present and throws the value away. Switching harvesting on keeps "
            "the value, so the Passwords page can show it. Nothing here "
            "transmits; arming an engagement on the Interception page does.")
        icept_hint.setWordWrap(True)
        icept_hint.setObjectName("PageHint")
        icept_form.addRow(icept_hint)
        self.harvest = QCheckBox(
            "Extract credentials and hashes from readable traffic")
        self.harvest.setToolTip(
            "FTP, Telnet, POP3, IMAP, SMTP, LDAP, SNMP, MSSQL and HTTP Basic "
            "put secrets on the wire in the clear. NTLM, MySQL, PostgreSQL, "
            "VNC, Kerberos and HTTP Digest give up a crackable hash.")
        icept_form.addRow("", self.harvest)
        self.verify_upstream = QCheckBox(
            "Verify upstream certificates while intercepting TLS")
        self.verify_upstream.setToolTip(
            "On: NetLab refuses to relay to a server whose own certificate "
            "does not verify, so a broken upstream is visible rather than "
            "masked. Off: relays anyway, which is what a lab with "
            "self-signed services usually needs.")
        icept_form.addRow("", self.verify_upstream)
        self.upstream_dns = QLineEdit()
        self.upstream_dns.setPlaceholderText(
            "blank = this machine's own resolver")
        icept_form.addRow("Forward unspoofed DNS to", self.upstream_dns)
        self.radius_secret = QLineEdit()
        self.radius_secret.setPlaceholderText(
            "blank = record RADIUS PAP username only")
        self.radius_secret.setToolTip(
            "RADIUS User-Password is encrypted with the shared secret. Given "
            "it, NetLab decrypts PAP logins; without it, only the username "
            "and the fact a password rode are recorded. CHAP is crackable "
            "either way.")
        icept_form.addRow("RADIUS shared secret", self.radius_secret)
        lay.addWidget(icept_box)

        # ---- privileges -------------------------------------------------
        priv_box = QGroupBox("Capture privileges")
        priv_lay = QVBoxLayout(priv_box)
        self.priv_detail = DetailPane("")
        self.priv_detail.setMaximumHeight(160)
        priv_lay.addWidget(self.priv_detail)
        recheck = QPushButton("Re-check privileges")
        recheck.clicked.connect(self.refresh_privileges)
        priv_lay.addWidget(recheck)
        lay.addWidget(priv_box)

        buttons = QHBoxLayout()
        buttons.addStretch(1)
        reset = QPushButton("Reset to defaults")
        reset.clicked.connect(self._reset)
        buttons.addWidget(reset)
        save = QPushButton("Save settings")
        save.setObjectName("Primary")
        save.clicked.connect(self._save)
        buttons.addWidget(save)
        lay.addLayout(buttons)
        lay.addStretch(1)

        self.load_from_config()
        self.refresh_privileges()

    # ------------------------------------------------------------------ data

    def load_from_config(self) -> None:
        c = self._config
        self.interface.setText(str(c.get("interface") or ""))
        self.bpf.setText(str(c.get("bpf_filter") or ""))
        idx = self.fmt.findData(c.get("capture_format"))
        self.fmt.setCurrentIndex(idx if idx >= 0 else 0)
        self.snaplen.setValue(int(c.get("snaplen")))
        self.promisc.setChecked(bool(c.get("promiscuous")))
        self.capture_dir.setText(str(c.get("capture_dir") or ""))
        self.max_pcap.setValue(int(c.get("max_pcap_mb")))
        self.retention_days.setValue(int(c.get("retention_days")))
        self.retention_files.setValue(int(c.get("retention_max_files")))
        self.queue_packets.setValue(int(c.get("queue_packets")))
        self.live_rows.setValue(int(c.get("live_rows")))
        self.max_flows.setValue(int(c.get("max_flows")))
        self.max_hosts.setValue(int(c.get("max_hosts")))
        self.refresh_ms.setValue(int(c.get("gui_refresh_ms")))
        self.nmap_path.setText(str(c.get("nmap_path") or "nmap"))
        self.resolve_names.setChecked(bool(c.get("resolve_dns_names")))
        self.harvest.setChecked(bool(c.get("harvest_credentials")))
        self.verify_upstream.setChecked(bool(c.get("mitm_verify_upstream")))
        self.upstream_dns.setText(str(c.get("mitm_upstream_dns") or ""))
        self.radius_secret.setText(str(c.get("radius_secret") or ""))

    def _browse_dir(self) -> None:
        start = self.capture_dir.text().strip() or str(default_capture_dir())
        chosen = QFileDialog.getExistingDirectory(
            self, "Choose capture directory", start)
        if chosen:
            self.capture_dir.setText(chosen)

    def _save(self) -> None:
        directory = self.capture_dir.text().strip()
        if directory:
            try:
                Path(directory).expanduser().mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                QMessageBox.critical(
                    self, "Capture directory",
                    "Cannot use that directory:\n%s" % exc)
                return

        self._config.update({
            "interface": self.interface.text().strip(),
            "bpf_filter": self.bpf.text().strip(),
            "capture_format": self.fmt.currentData(),
            "snaplen": self.snaplen.value(),
            "promiscuous": self.promisc.isChecked(),
            "capture_dir": directory,
            "max_pcap_mb": self.max_pcap.value(),
            "retention_days": self.retention_days.value(),
            "retention_max_files": self.retention_files.value(),
            "queue_packets": self.queue_packets.value(),
            "live_rows": self.live_rows.value(),
            "max_flows": self.max_flows.value(),
            "max_hosts": self.max_hosts.value(),
            "gui_refresh_ms": self.refresh_ms.value(),
            "nmap_path": self.nmap_path.text().strip() or "nmap",
            "resolve_dns_names": self.resolve_names.isChecked(),
            "harvest_credentials": self.harvest.isChecked(),
            "mitm_verify_upstream": self.verify_upstream.isChecked(),
            "mitm_upstream_dns": self.upstream_dns.text().strip(),
            "radius_secret": self.radius_secret.text().strip(),
        })
        ok, detail = self._config.save()
        if ok:
            self.banner.set_text(
                "Settings saved to %s. Memory limits apply after a restart."
                % detail, "info")
        else:
            self.banner.set_text("Could not save settings: %s" % detail, "error")
        self.banner.setVisible(True)
        self.settings_saved.emit()

    def _reset(self) -> None:
        from netlab.config import DEFAULTS
        answer = QMessageBox.question(
            self, "Reset settings",
            "Restore every setting to its default value?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No)
        if answer != QMessageBox.StandardButton.Yes:
            return
        self._config.update(dict(DEFAULTS))
        self.load_from_config()
        self.banner.set_text("Defaults restored. Click Save to keep them.",
                             "info")
        self.banner.setVisible(True)

    def refresh_privileges(self) -> None:
        self.priv_detail.setPlainText(remediation_text(check_privileges()))
