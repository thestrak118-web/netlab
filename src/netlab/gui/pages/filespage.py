"""Files: bodies reassembled out of traffic NetLab could read.

The equivalent of Intercepter-NG's Resurrection tab.  Anything carved is
written under the engagement directory, hashed, and listed here with the type
the *server* claimed for it -- which is a claim, not a verdict, so nothing is
opened or executed from this page.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import QMessageBox, QPushButton

from netlab.gui.models import CarvedFileModel
from netlab.gui.pages.detail import DetailPane, kv
from netlab.gui.widgets import TablePage
from netlab.util.format import human_bytes, ts_full


class FilesPage(TablePage):
    def __init__(self, parent=None) -> None:
        super().__init__(
            "Files",
            "Response bodies carved out of readable traffic while file "
            "capture was enabled. Files are written to the engagement "
            "directory; NetLab never opens or runs them.",
            CarvedFileModel(), parent)
        self.attach_detail(DetailPane("Select a file to see its record."))
        self.row_selected.connect(self._show_detail)

        self.folder_button = QPushButton("Open folder")
        self.folder_button.clicked.connect(self._open_folder)
        self.add_tool(self.folder_button)

        self.copy_button = QPushButton("Copy path")
        self.copy_button.clicked.connect(self._copy_path)
        self.add_tool(self.copy_button)
        self._directory = ""

    def set_files(self, files) -> None:
        self.model.replace_items(list(files))
        total = sum(int(f.get("bytes", 0)) for f in files)
        self.update_counts("%s carved" % human_bytes(total))
        for f in files:
            path = f.get("path")
            if path:
                self._directory = str(Path(path).parent)
                break

    def _show_detail(self, f) -> None:
        self.detail.show_lines([
            f.get("name", "(unnamed)"), "",
            kv("Time", ts_full(f.get("ts", 0.0))),
            kv("Size", human_bytes(f.get("bytes", 0))),
            kv("Declared type", f.get("content_type") or "-"),
            kv("From host", f.get("host") or "-"),
            kv("Requested by", f.get("client") or "-"),
            kv("Source", f.get("source") or "-"),
            kv("SHA-256", f.get("sha256") or "-"),
            kv("Saved to", f.get("path") or "-"),
            "",
            kv("URL", f.get("url") or "-"),
            "",
            "The type above is what the server said it was. NetLab does not "
            "verify it and does not open the file.",
        ])

    def _open_folder(self) -> None:
        if not self._directory:
            QMessageBox.information(self, "No files",
                                    "Nothing has been carved yet.")
            return
        try:
            subprocess.Popen(["xdg-open", self._directory],
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
        except OSError as exc:
            QMessageBox.warning(self, "Cannot open folder", str(exc))

    def _copy_path(self) -> None:
        f = self.selected_object()
        if f and f.get("path"):
            QGuiApplication.clipboard().setText(f["path"])
