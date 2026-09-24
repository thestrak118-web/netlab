"""Captures: recording control, the files on disk, export and retention."""

from __future__ import annotations

import shutil
import subprocess
import time
from pathlib import Path

from PySide6.QtCore import Signal
from PySide6.QtWidgets import QFileDialog, QMessageBox, QPushButton

from netlab.capture.pcapio import CaptureFormatError, probe_capture_file
from netlab.gui import theme
from netlab.gui.models import LEFT, RIGHT, NetLabTableModel
from netlab.gui.widgets import TablePage
from netlab.util.format import DASH, human_bytes, ts_full


class CaptureFile:
    __slots__ = ("path", "size", "mtime", "fmt", "linktype", "error")

    def __init__(self, path: Path) -> None:
        self.path = path
        try:
            st = path.stat()
            self.size = st.st_size
            self.mtime = st.st_mtime
        except OSError:
            self.size = 0
            self.mtime = 0.0
        self.fmt = ""
        self.linktype = -1
        self.error = ""
        try:
            info = probe_capture_file(path)
            self.fmt = info["format"]
            self.linktype = info["linktype"]
        except (OSError, CaptureFormatError) as exc:
            self.error = str(exc)

    @property
    def name(self) -> str:
        return self.path.name


class CaptureFileModel(NetLabTableModel):
    COLUMNS = [
        ("File", 380, LEFT), ("Format", 90, LEFT), ("Size", 100, RIGHT),
        ("Modified", 170, LEFT), ("Link type", 90, RIGHT), ("Status", 260, LEFT),
    ]

    def cell(self, f: CaptureFile, col):
        return (
            f.name, f.fmt or DASH, human_bytes(f.size), ts_full(f.mtime),
            str(f.linktype) if f.linktype >= 0 else DASH,
            f.error or "readable",
        )[col]

    def fields(self, f):
        return {"name": f.path.name, "proto": f.fmt}

    def search_text(self, f):
        return "%s %s" % (f.name, f.fmt)

    def colour(self, f, col):
        if col == 5:
            return theme.RED if f.error else theme.GREEN
        return None

    def identity(self, f):
        return str(f.path)


class CapturesPage(TablePage):
    open_requested = Signal(str)
    start_requested = Signal()
    stop_requested = Signal()

    def __init__(self, config, parent=None) -> None:
        super().__init__(
            "Captures",
            "Capture files written by dumpcap. Every file here is a real "
            "pcap/pcapng and opens in Wireshark, tshark or tcpdump unchanged.",
            CaptureFileModel(), parent)
        self._config = config

        self.open_btn = QPushButton("Open in NetLab")
        self.open_btn.setObjectName("Primary")
        self.open_btn.clicked.connect(self._open_selected)
        self.add_tool(self.open_btn)

        self.export_btn = QPushButton("Export a copy\u2026")
        self.export_btn.clicked.connect(self._export_selected)
        self.add_tool(self.export_btn)

        self.verify_btn = QPushButton("Verify")
        self.verify_btn.setToolTip(
            "Run capinfos against the selected file and show its report.")
        self.verify_btn.clicked.connect(self._verify_selected)
        self.add_tool(self.verify_btn)

        self.delete_btn = QPushButton("Delete")
        self.delete_btn.setObjectName("Danger")
        self.delete_btn.clicked.connect(self._delete_selected)
        self.add_tool(self.delete_btn)

        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(self.refresh)
        self.add_tool(self.refresh_btn)

        self.row_activated.connect(lambda f: self.open_requested.emit(str(f.path)))
        self.refresh()

    # ------------------------------------------------------------------ data

    def refresh(self) -> None:
        directory = self._config.capture_dir()
        try:
            directory.mkdir(parents=True, exist_ok=True)
            paths = sorted(
                [p for p in directory.iterdir()
                 if p.is_file() and p.suffix in (".pcap", ".pcapng", ".cap")],
                key=lambda p: p.stat().st_mtime, reverse=True)
        except OSError as exc:
            self.banner.set_text("Cannot read the capture directory %s:\n%s"
                                 % (directory, exc), "error")
            self.banner.setVisible(True)
            self.model.clear()
            self.update_counts()
            return

        self.banner.set_text("Capture directory: %s" % directory, "info")
        self.banner.setVisible(True)
        files = [CaptureFile(p) for p in paths[:500]]
        self.model.replace_items(files)
        total = sum(f.size for f in files)
        self.update_counts("%s on disk" % human_bytes(total))

    def apply_retention(self) -> list[str]:
        """Delete captures past the configured age/count limits."""
        removed: list[str] = []
        directory = self._config.capture_dir()
        days = int(self._config.get("retention_days") or 0)
        max_files = int(self._config.get("retention_max_files") or 0)
        if not directory.is_dir() or (days <= 0 and max_files <= 0):
            return removed
        try:
            files = sorted(
                [p for p in directory.iterdir()
                 if p.is_file() and p.suffix in (".pcap", ".pcapng", ".cap")],
                key=lambda p: p.stat().st_mtime, reverse=True)
        except OSError:
            return removed

        cutoff = time.time() - days * 86400 if days > 0 else None
        for i, path in enumerate(files):
            drop = False
            if max_files > 0 and i >= max_files:
                drop = True
            if cutoff is not None:
                try:
                    if path.stat().st_mtime < cutoff:
                        drop = True
                except OSError:
                    continue
            if drop:
                try:
                    path.unlink()
                    removed.append(path.name)
                except OSError:
                    pass
        return removed

    # --------------------------------------------------------------- actions

    def _selected_file(self) -> CaptureFile | None:
        obj = self.selected_object()
        if obj is None:
            QMessageBox.information(self, "No file selected",
                                    "Select a capture file first.")
        return obj

    def _open_selected(self) -> None:
        f = self._selected_file()
        if f:
            self.open_requested.emit(str(f.path))

    def _export_selected(self) -> None:
        f = self._selected_file()
        if not f:
            return
        target, _ = QFileDialog.getSaveFileName(
            self, "Export capture file", str(Path.home() / f.name),
            "Capture files (*.pcapng *.pcap);;All files (*)")
        if not target:
            return
        try:
            shutil.copy2(f.path, target)
        except OSError as exc:
            QMessageBox.critical(self, "Export failed", str(exc))
            return
        QMessageBox.information(
            self, "Exported",
            "Copied to:\n%s\n\nThe file is unmodified and opens in Wireshark, "
            "tshark or tcpdump." % target)

    def _verify_selected(self) -> None:
        f = self._selected_file()
        if not f:
            return
        exe = shutil.which("capinfos")
        if not exe:
            QMessageBox.information(
                self, "capinfos not found",
                "capinfos is part of wireshark-common.\n\n"
                "Install it with:  sudo apt install wireshark-common")
            return
        try:
            proc = subprocess.run([exe, str(f.path)], capture_output=True,
                                  text=True, timeout=60)
            report = (proc.stdout or "") + (proc.stderr or "")
        except (subprocess.TimeoutExpired, OSError) as exc:
            report = "capinfos failed: %s" % exc
        box = QMessageBox(self)
        box.setWindowTitle("capinfos - %s" % f.name)
        box.setText("Independent verification of %s" % f.name)
        box.setDetailedText(report.strip() or "(no output)")
        box.exec()

    def _delete_selected(self) -> None:
        f = self._selected_file()
        if not f:
            return
        answer = QMessageBox.question(
            self, "Delete capture file",
            "Permanently delete this capture?\n\n%s\n\n%s\n\n"
            "This cannot be undone." % (f.path, human_bytes(f.size)),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No)
        if answer != QMessageBox.StandardButton.Yes:
            return
        try:
            f.path.unlink()
        except OSError as exc:
            QMessageBox.critical(self, "Delete failed", str(exc))
            return
        self.refresh()
