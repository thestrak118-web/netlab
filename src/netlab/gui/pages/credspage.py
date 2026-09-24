"""Passwords: what the captured traffic gave away.

Cleartext secrets are shown as they crossed the wire.  Challenge/response
material is shown in the format its cracker expects, with the hashcat mode
attached, and can be written straight out to a file to feed one.
"""

from __future__ import annotations

import time
from pathlib import Path

from PySide6.QtCore import Signal
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (QFileDialog, QMessageBox, QPushButton)

from netlab.gui.models import CredentialModel
from netlab.gui.pages.detail import DetailPane, kv
from netlab.gui.widgets import TablePage
from netlab.util.format import ts_full


class CredentialsPage(TablePage):
    show_packets = Signal(str)

    def __init__(self, config, parent=None) -> None:
        super().__init__(
            "Passwords",
            "Credentials and authentication hashes recovered from traffic "
            "NetLab could read: cleartext protocols, and challenge/response "
            "exchanges where both halves were observed. Rows marked with an "
            "active source were read through interception, not passively.",
            CredentialModel(), parent)
        self._config = config
        self.attach_detail(
            DetailPane("Select a credential to see the full record."))
        self.row_selected.connect(self._show_detail)
        self.row_activated.connect(
            lambda c: self.show_packets.emit("ip:%s ip:%s" % (c.client, c.server)))

        self.copy_button = QPushButton("Copy secret")
        self.copy_button.setToolTip(
            "Copy the password, hash or token on the selected row.")
        self.copy_button.clicked.connect(self._copy)
        self.add_tool(self.copy_button)

        self.hash_button = QPushButton("Export hashes")
        self.hash_button.setToolTip(
            "Write every crackable hash to a file, one per line, ready for "
            "hashcat or john.")
        self.hash_button.clicked.connect(self._export_hashes)
        self.add_tool(self.hash_button)

        self.csv_button = QPushButton("Export CSV")
        self.csv_button.clicked.connect(self._export_csv)
        self.add_tool(self.csv_button)

    # ------------------------------------------------------------- updates

    def set_credentials(self, credentials) -> None:
        self.model.replace_items(list(credentials))
        cleartext = sum(1 for c in credentials if c.password)
        hashes = sum(1 for c in credentials if c.hash)
        active = sum(1 for c in credentials if c.source != "passive")
        self.update_counts(
            "%d cleartext   ·   %d hashes   ·   %d from interception"
            % (cleartext, hashes, active))

    # -------------------------------------------------------------- detail

    def _show_detail(self, c) -> None:
        lines = ["%s credential  (%s)" % (c.proto, c.kind), "",
                 kv("Time", ts_full(c.ts)),
                 kv("Client", c.client or "-"),
                 kv("Server", c.endpoint or "-"),
                 kv("User", c.user or "-")]
        if c.password:
            lines.append(kv("Password", c.password))
            lines += ["", "This password was readable by anyone on the path "
                          "between the two endpoints."]
        if c.hash:
            lines += ["", kv("Hash type", c.hash_type or "-"), "", c.hash, ""]
            if c.hashcat_mode:
                lines.append(kv("hashcat", "-m %d" % c.hashcat_mode))
            if c.john_format:
                lines.append(kv("john", "--format=%s" % c.john_format))
        token = c.extra.get("token") or c.extra.get("cookie")
        if token:
            lines += ["", kv("Token", token)]
        if c.context:
            lines += ["", kv("Context", c.context)]
        if c.source != "passive":
            lines += ["", kv("Source", "%s (active interception)" % c.source)]
        if c.packet_index:
            lines.append(kv("Packet", "#%d" % c.packet_index))
        extra = {k: v for k, v in c.extra.items()
                 if k not in ("token", "cookie") and v}
        if extra:
            lines += ["", "Additional fields"]
            for key, value in extra.items():
                text = value if isinstance(value, str) else repr(value)
                lines.append("  %-18s %s" % (key, text[:300]))
        self.detail.show_lines(lines)

    # ------------------------------------------------------------- actions

    def _copy(self) -> None:
        c = self.selected_object()
        if c is None:
            return
        secret = c.password or c.hash or c.extra.get("token", "")
        if not secret:
            QMessageBox.information(self, "Nothing to copy",
                                    "That row has no secret attached.")
            return
        QGuiApplication.clipboard().setText(secret)

    def _rows(self) -> list:
        return [self.model.object_at(i) for i in range(self.model.rowCount())]

    def _export_hashes(self) -> None:
        rows = [c for c in self._rows() if c and c.hash]
        if not rows:
            QMessageBox.information(
                self, "No hashes",
                "None of the visible rows carry a crackable hash.\n\n"
                "Cleartext passwords do not need cracking, and a "
                "challenge/response whose challenge was never observed "
                "cannot be turned into one.")
            return
        by_mode: dict[int, list] = {}
        for c in rows:
            by_mode.setdefault(c.hashcat_mode, []).append(c)
        default = "netlab-hashes-%s.txt" % time.strftime("%Y%m%d-%H%M%S")
        path, _ = QFileDialog.getSaveFileName(self, "Export hashes",
                                              str(Path.home() / default),
                                              "Text files (*.txt);;All files (*)")
        if not path:
            return
        lines = []
        for mode in sorted(by_mode):
            sample = by_mode[mode][0]
            lines.append("# %s   hashcat -m %d   (%d)" % (
                sample.hash_type or "hash", mode, len(by_mode[mode])))
            lines.extend(c.hash for c in by_mode[mode])
            lines.append("")
        try:
            Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")
        except OSError as exc:
            QMessageBox.warning(self, "Export failed", str(exc))
            return
        QMessageBox.information(
            self, "Hashes exported",
            "%d hashes in %d format(s) written to\n%s"
            % (len(rows), len(by_mode), path))

    def _export_csv(self) -> None:
        rows = [c for c in self._rows() if c]
        if not rows:
            return
        default = "netlab-credentials-%s.csv" % time.strftime("%Y%m%d-%H%M%S")
        path, _ = QFileDialog.getSaveFileName(self, "Export credentials",
                                              str(Path.home() / default),
                                              "CSV files (*.csv);;All files (*)")
        if not path:
            return
        import csv
        try:
            with open(path, "w", newline="", encoding="utf-8") as fh:
                writer = csv.writer(fh)
                writer.writerow(["time", "protocol", "kind", "client",
                                 "server", "port", "user", "password", "hash",
                                 "hash_type", "hashcat_mode", "source",
                                 "context"])
                for c in rows:
                    writer.writerow([ts_full(c.ts), c.proto, c.kind, c.client,
                                     c.server, c.port, c.user, c.password,
                                     c.hash, c.hash_type, c.hashcat_mode or "",
                                     c.source, c.context])
        except OSError as exc:
            QMessageBox.warning(self, "Export failed", str(exc))
            return
        QMessageBox.information(self, "Credentials exported",
                                "%d rows written to\n%s" % (len(rows), path))
