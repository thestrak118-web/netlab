"""PCAP Viewer: open a capture file and inspect what was extracted from it."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (QFileDialog, QHBoxLayout, QLabel, QMessageBox,
                               QProgressBar, QPushButton, QVBoxLayout, QWidget)

from netlab.capture.pcapio import CaptureFormatError, probe_capture_file
from netlab.analyze.decode import LINKTYPE_NAMES
from netlab.gui.pages.detail import DetailPane, kv
from netlab.gui.widgets import Banner
from netlab.util.format import DASH, human_bytes, ts_full


class PcapViewerPage(QWidget):
    open_requested = Signal(str)
    show_packets = Signal(str)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._path: Path | None = None
        self.device_ip = None

        lay = QVBoxLayout(self)
        lay.setContentsMargins(18, 16, 18, 14)
        lay.setSpacing(10)

        title = QLabel("PCAP Viewer")
        title.setObjectName("PageTitle")
        lay.addWidget(title)
        hint = QLabel(
            "Open a pcap or pcapng file and analyse it with the same engine "
            "used for live capture. Opening a file replaces the current "
            "analysis view; the file itself is never modified.")
        hint.setObjectName("PageHint")
        hint.setWordWrap(True)
        lay.addWidget(hint)

        self.banner = Banner("No capture file is open.", "info")
        lay.addWidget(self.banner)

        bar = QHBoxLayout()
        bar.setSpacing(8)
        self.open_btn = QPushButton("Open capture file…")
        self.open_btn.setObjectName("Primary")
        self.open_btn.clicked.connect(self._choose)
        bar.addWidget(self.open_btn)

        self.packets_btn = QPushButton("Show packets")
        self.packets_btn.setEnabled(False)
        self.packets_btn.clicked.connect(lambda: self.show_packets.emit("device:" + "|".join(self.device_ip) if self.device_ip else ""))
        bar.addWidget(self.packets_btn)

        self.verify_btn = QPushButton("Verify with capinfos")
        self.verify_btn.setEnabled(False)
        self.verify_btn.clicked.connect(self._verify)
        bar.addWidget(self.verify_btn)

        self.export_btn = QPushButton("Export a copy…")
        self.export_btn.setEnabled(False)
        self.export_btn.clicked.connect(self._export)
        bar.addWidget(self.export_btn)
        bar.addStretch(1)
        lay.addLayout(bar)

        self.progress = QProgressBar()
        self.progress.setVisible(False)
        lay.addWidget(self.progress)

        self.detail = DetailPane(
            "Open a capture file to see its header, contents and what NetLab "
            "extracted from it.")
        lay.addWidget(self.detail, 1)

    # ---------------------------------------------------------------- actions

    def _choose(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Open capture file", str(Path.home()),
            "Capture files (*.pcap *.pcapng *.cap);;All files (*)")
        if path:
            self.open_requested.emit(path)

    def _export(self) -> None:
        if not self._path:
            return
        target, _ = QFileDialog.getSaveFileName(
            self, "Export capture file", str(Path.home() / self._path.name),
            "Capture files (*.pcapng *.pcap);;All files (*)")
        if not target:
            return
        try:
            if self.device_ip:
                from netlab.capture.export import export_device_pcap
                export_device_pcap(self._path, target, self.device_ip)
            else:
                shutil.copy2(self._path, target)
        except OSError as exc:
            QMessageBox.critical(self, "Export failed", str(exc))
            return
        QMessageBox.information(self, "Exported", "Copied to:\n%s" % target)

    def _verify(self) -> None:
        if not self._path:
            return
        exe = shutil.which("capinfos")
        if not exe:
            QMessageBox.information(
                self, "capinfos not found",
                "capinfos is part of wireshark-common.\n\n"
                "Install it with:  sudo apt install wireshark-common")
            return
        try:
            proc = subprocess.run([exe, str(self._path)], capture_output=True,
                                  text=True, timeout=120)
            report = (proc.stdout or "") + (proc.stderr or "")
        except (subprocess.TimeoutExpired, OSError) as exc:
            report = "capinfos failed: %s" % exc
        box = QMessageBox(self)
        box.setWindowTitle("capinfos - %s" % self._path.name)
        box.setText("Independent verification by capinfos")
        box.setDetailedText(report.strip() or "(no output)")
        box.exec()

    # ------------------------------------------------------------------ state

    def set_device_source(self, path, ip, stats):
        self.device_ip = (ip,) if isinstance(ip, str) else tuple(ip)
        if path and Path(path).exists():
            self.import_finished(stats.total_packets, str(path), stats)
            self.banner.set_text(f'Device {", ".join(self.device_ip)} in {Path(path).name}. Show packets filters this device; export writes only its packets.')
            self.export_btn.setText('Export device PCAP…')
        else:
            self._path = None
            self.export_btn.setEnabled(False)
            self.packets_btn.setEnabled(False)
            self.banner.set_text('No capture file available for this device.')

    def import_started(self, path: str) -> None:
        self.device_ip = None
        self.export_btn.setText("Export a copy…")
        self._path = Path(path)
        self.packets_btn.setEnabled(False)
        self.verify_btn.setEnabled(False)
        self.export_btn.setEnabled(False)
        self.progress.setVisible(True)
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.banner.set_text("Reading %s…" % self._path.name, "info")
        self.detail.show_lines(["Reading %s" % path])

    def import_progress(self, read: int, total: int) -> None:
        if total > 0:
            self.progress.setValue(int(read * 100 / total))

    def import_failed(self, message: str) -> None:
        self.progress.setVisible(False)
        self.banner.set_text(message, "error")
        self.detail.show_lines([message])

    def import_finished(self, packets: int, path: str, stats,
                        truncated: bool = False) -> None:
        self._path = Path(path)
        self.progress.setVisible(False)
        self.packets_btn.setEnabled(True)
        self.verify_btn.setEnabled(True)
        self.export_btn.setEnabled(True)

        try:
            info = probe_capture_file(self._path)
            fmt, linktype = info["format"], info["linktype"]
            size = info["size"]
        except (OSError, CaptureFormatError) as exc:
            self.banner.set_text("Could not read %s: %s" % (path, exc), "error")
            return

        history = stats.history
        first = history[0][0] if history else None

        self.banner.set_text(
            "Open: %s   ·   %s packets   ·   %s%s"
            % (self._path.name, "{:,}".format(packets), human_bytes(size),
               "   ·   ⚠ truncated file" if truncated else ""),
            "warn" if truncated else "info")

        lines = [
            str(self._path),
            "",
            "Capture file",
            kv("Format", fmt),
            kv("Link type", "%d (%s)" % (linktype,
                                         LINKTYPE_NAMES.get(linktype, "unknown"))),
            kv("File size", human_bytes(size)),
            kv("Packets read", "{:,}".format(packets)),
            "",
            "Extracted by NetLab",
            kv("Packets analysed", "{:,}".format(stats.total_packets)),
            kv("Bytes on the wire", human_bytes(stats.total_bytes)),
            kv("Connections", "{:,}".format(stats.flows)),
            kv("Hosts", "{:,}".format(stats.hosts)),
            kv("DNS events", "{:,}".format(stats.dns_events)),
            kv("HTTP transactions", "{:,}".format(stats.http_transactions)),
            kv("TLS sessions", "{:,}".format(stats.tls_sessions)),
            "",
            "Integrity",
            kv("Malformed frames", "{:,}".format(stats.malformed)),
            kv("Undecodable link type", "{:,}".format(stats.unsupported_linktype)),
            kv("Dropped before analysis", "{:,}".format(stats.queue_dropped)),
            kv("File ends mid-packet", "yes — truncated" if truncated else "no"),
        ]
        if truncated:
            lines += ["", "This file is truncated: it ends in the middle of a "
                          "packet record, so the last packet was cut off. The "
                          "%s complete packets before the cut were read; "
                          "anything after it is lost. capinfos will report the "
                          "same. (A live capture still being written looks like "
                          "this too, but this is a file on disk.)"
                          % "{:,}".format(packets)]
        elif stats.queue_dropped:
            lines += ["", "Some packets were dropped before analysis, so the "
                          "tables below the packet count are incomplete. The "
                          "file on disk is unaffected."]
        else:
            lines += ["", "Every packet in the file reached the analyser."]
        lines += ["", "Use 'Verify with capinfos' to have an independent tool "
                      "report on this same file."]
        self.detail.show_lines(lines)
