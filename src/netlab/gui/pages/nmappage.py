"""Nmap: the one page in NetLab that transmits."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QCheckBox, QComboBox, QHBoxLayout, QLabel,
                               QLineEdit, QMessageBox, QPlainTextEdit,
                               QPushButton, QSplitter, QTabWidget, QVBoxLayout,
                               QWidget)

from netlab.gui.models import NmapHostModel
from netlab.gui.widgets import Banner, make_table
from netlab.integrations.nmap import (PROFILES, NmapRunner, nmap_path,
                                      nmap_version)


class NmapPage(QWidget):
    def __init__(self, config, parent=None) -> None:
        super().__init__(parent)
        self._config = config
        self.runner = NmapRunner(self)
        self._result = None

        lay = QVBoxLayout(self)
        lay.setContentsMargins(18, 16, 18, 14)
        lay.setSpacing(10)

        title = QLabel("Nmap")
        title.setObjectName("PageTitle")
        lay.addWidget(title)
        hint = QLabel(
            "Active scanning. Unlike the rest of NetLab, this sends packets to "
            "the target and will be visible in its logs. Scan only systems you "
            "are authorised to test. Results are kept separate from the "
            "passive capture tables.")
        hint.setObjectName("PageHint")
        hint.setWordWrap(True)
        lay.addWidget(hint)

        self.banner = Banner("", "warn")
        self.banner.setVisible(False)
        lay.addWidget(self.banner)

        controls = QHBoxLayout()
        controls.setSpacing(8)
        self.target = QLineEdit()
        self.target.setPlaceholderText(
            "Target:  10.0.0.1   10.0.0.0/24   10.0.0.1-50   host.example")
        self.target.returnPressed.connect(self._start)
        controls.addWidget(self.target, 2)

        self.profile = QComboBox()
        for prof in PROFILES:
            self.profile.addItem(prof.name, prof)
        self.profile.currentIndexChanged.connect(self._profile_changed)
        controls.addWidget(self.profile, 1)

        self.elevate = QCheckBox("Run with pkexec")
        self.elevate.setToolTip(
            "Some scan types (SYN, UDP, OS detection) need root. pkexec will "
            "prompt for authorisation.")
        self.elevate.setChecked(bool(config.get("nmap_use_pkexec")))
        controls.addWidget(self.elevate)

        self.run_btn = QPushButton("Run scan")
        self.run_btn.setObjectName("Primary")
        self.run_btn.clicked.connect(self._start)
        controls.addWidget(self.run_btn)

        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setEnabled(False)
        self.cancel_btn.clicked.connect(self.runner.cancel)
        controls.addWidget(self.cancel_btn)
        lay.addLayout(controls)

        self.profile_hint = QLabel("")
        self.profile_hint.setObjectName("PageHint")
        lay.addWidget(self.profile_hint)

        self.model = NmapHostModel()
        self.table = make_table(self.model)
        self.output = QPlainTextEdit()
        self.output.setObjectName("Mono")
        self.output.setReadOnly(True)
        self.output.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.output.setPlainText("Scan output will appear here.")

        tabs = QTabWidget()
        tabs.addTab(self.table, "Hosts")
        tabs.addTab(self.output, "Raw output")
        lay.addWidget(tabs, 1)

        self.status = QLabel("")
        self.status.setObjectName("PageHint")
        lay.addWidget(self.status)

        self.runner.output.connect(self._append_output)
        self.runner.started_scan.connect(self._scan_started)
        self.runner.finished_scan.connect(self._scan_finished)
        self.runner.failed.connect(self._scan_failed)

        self._check_available()
        self._profile_changed()

    def _check_available(self) -> None:
        exe = nmap_path(self._config.get("nmap_path", "nmap"))
        if not exe:
            self.banner.set_text(
                "nmap was not found on PATH.\n\n"
                "Install it with:  sudo apt install nmap", "error")
            self.banner.setVisible(True)
            self.run_btn.setEnabled(False)
        else:
            self.status.setText("%s  (%s)" % (nmap_version(exe), exe))

    def _profile_changed(self) -> None:
        prof = self.profile.currentData()
        if prof is None:
            return
        text = prof.description
        if prof.needs_root:
            text += "   This scan type requires root - enable 'Run with pkexec'."
        self.profile_hint.setText(text)

    def _start(self) -> None:
        if self.runner.is_running:
            return
        prof = self.profile.currentData()
        target = self.target.text().strip()
        if not target:
            QMessageBox.information(self, "No target",
                                    "Enter a host, range or CIDR to scan.")
            return

        confirm = QMessageBox.question(
            self, "Start active scan",
            "This will actively send probe packets to:\n\n    %s\n\n"
            "using profile '%s'.\n\nScan only systems you are authorised to "
            "test. Continue?" % (target, prof.name),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No)
        if confirm != QMessageBox.StandardButton.Yes:
            return

        self.model.clear()
        self.output.setPlainText("")
        self._config.set("nmap_use_pkexec", self.elevate.isChecked())
        ok = self.runner.start(target, list(prof.args),
                               self._config.get("nmap_path", "nmap"),
                               self.elevate.isChecked())
        if ok:
            self.run_btn.setEnabled(False)
            self.cancel_btn.setEnabled(True)
            self.banner.setVisible(False)

    def _append_output(self, line: str) -> None:
        self.output.appendPlainText(line)

    def _scan_started(self, command: str) -> None:
        self.status.setText("Running:  %s" % command)
        self.output.appendPlainText("$ %s\n" % command)

    def _scan_finished(self, result) -> None:
        self._result = result
        self.run_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)
        self.model.replace_items(result.hosts)
        up = sum(1 for h in result.hosts if h.state == "up")
        ports = sum(len(h.open_ports) for h in result.hosts)
        self.status.setText(
            "%s   ·   %d host(s) reported, %d up, %d open port(s)   "
            "·   XML: %s"
            % (result.summary or "Scan finished", len(result.hosts), up, ports,
               result.raw_xml_path))

    def _scan_failed(self, message: str) -> None:
        self.run_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)
        self.banner.set_text(message, "error")
        self.banner.setVisible(True)
        self.status.setText(message.splitlines()[0] if message else "")

    def prefill_target(self, target: str) -> None:
        self.target.setText(target)
