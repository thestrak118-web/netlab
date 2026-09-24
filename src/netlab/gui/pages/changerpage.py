"""Rules: what to rewrite in flight, and which names to answer for.

Both tables edit live.  While an engagement is armed, changing a rule is
pushed to the privileged helper immediately, so a rule can be tried, adjusted
and withdrawn without dropping the position in the path.

A traffic-changer rule only ever reaches traffic NetLab can already read:
cleartext HTTP, or HTTPS that is going through SSL strip or SSL MITM.  It
cannot alter a TLS session that is passing by untouched, and the page says so
rather than letting a rule look like it is doing something it is not.
"""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (QAbstractItemView, QCheckBox, QComboBox,
                               QGroupBox, QHBoxLayout, QHeaderView, QLabel,
                               QLineEdit, QMessageBox, QPushButton,
                               QTableWidget, QTableWidgetItem, QVBoxLayout,
                               QWidget)

from netlab.gui.widgets import Banner

CHANGER_COLUMNS = ["On", "Find", "Replace with", "Regex", "Direction",
                   "Host contains", "Content type", "Mode", "Anchor", "Hits"]
DNS_COLUMNS = ["On", "Name pattern", "Answer with", "Hits"]


def _checkbox_item(checked: bool) -> QTableWidgetItem:
    item = QTableWidgetItem()
    item.setFlags(Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled
                  | Qt.ItemFlag.ItemIsSelectable)
    item.setCheckState(Qt.CheckState.Checked if checked
                       else Qt.CheckState.Unchecked)
    return item


def _readonly_item(text: str) -> QTableWidgetItem:
    item = QTableWidgetItem(text)
    item.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)
    return item


class RulesPage(QWidget):
    changer_rules_changed = Signal(list)
    dns_rules_changed = Signal(list)

    def __init__(self, config, parent=None) -> None:
        super().__init__(parent)
        self._config = config
        self._loading = False

        lay = QVBoxLayout(self)
        lay.setContentsMargins(18, 16, 18, 14)
        lay.setSpacing(10)

        title = QLabel("Rules")
        title.setObjectName("PageTitle")
        lay.addWidget(title)
        hint = QLabel(
            "Traffic-changer rules rewrite readable traffic on its way "
            "through. DNS rules decide which names get an answer of your "
            "choosing; everything else is forwarded to the real resolver.")
        hint.setObjectName("PageHint")
        hint.setWordWrap(True)
        lay.addWidget(hint)

        self.banner = Banner(
            "A changer rule applies to cleartext HTTP, and to HTTPS only "
            "while SSL strip or SSL MITM is running. It cannot modify a TLS "
            "session that NetLab is not terminating.", "info")
        lay.addWidget(self.banner)

        lay.addWidget(self._build_changer(), 3)
        lay.addWidget(self._build_dns(), 2)
        self.load()

    # ------------------------------------------------------------- changer

    def _build_changer(self) -> QGroupBox:
        box = QGroupBox("Traffic changer")
        lay = QVBoxLayout(box)
        lay.setContentsMargins(12, 10, 12, 10)
        lay.setSpacing(7)

        self.changer_table = QTableWidget(0, len(CHANGER_COLUMNS))
        self.changer_table.setHorizontalHeaderLabels(CHANGER_COLUMNS)
        self.changer_table.verticalHeader().setVisible(False)
        self.changer_table.setAlternatingRowColors(True)
        self.changer_table.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows)
        header = self.changer_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        for i, width in enumerate((44, 210, 210, 56, 100, 130, 120, 78, 100, 56)):
            self.changer_table.setColumnWidth(i, width)
        header.setStretchLastSection(True)
        self.changer_table.itemChanged.connect(self._changer_edited)
        lay.addWidget(self.changer_table, 1)

        row = QHBoxLayout()
        row.setSpacing(8)
        self.find_edit = QLineEdit()
        self.find_edit.setPlaceholderText("text or pattern to find")
        row.addWidget(self.find_edit, 2)
        self.replace_edit = QLineEdit()
        self.replace_edit.setPlaceholderText("replace it with")
        row.addWidget(self.replace_edit, 2)
        self.regex_check = QCheckBox("Regex")
        self.regex_check.setToolTip(
            "Treat the pattern as a Python regular expression; the "
            "replacement may use backreferences such as \\1.")
        row.addWidget(self.regex_check)
        self.direction_combo = QComboBox()
        self.direction_combo.addItems(["response", "request", "both"])
        row.addWidget(self.direction_combo)
        self.mode_combo = QComboBox()
        self.mode_combo.addItems(["replace", "inject"])
        self.mode_combo.setToolTip(
            "replace: find/replace the pattern. inject: insert the "
            "replacement into HTML responses, before the anchor tag.")
        self.mode_combo.currentTextChanged.connect(self._mode_changed)
        row.addWidget(self.mode_combo)
        self.host_edit = QLineEdit()
        self.host_edit.setPlaceholderText("host contains (optional)")
        row.addWidget(self.host_edit, 1)
        self.anchor_edit = QLineEdit()
        self.anchor_edit.setPlaceholderText("inject before (e.g. </body>)")
        self.anchor_edit.setEnabled(False)
        row.addWidget(self.anchor_edit, 1)
        add = QPushButton("Add rule")
        add.setObjectName("Primary")
        add.clicked.connect(self._add_changer)
        row.addWidget(add)
        remove = QPushButton("Remove")
        remove.clicked.connect(lambda: self._remove(self.changer_table,
                                                    self._emit_changer))
        row.addWidget(remove)
        lay.addLayout(row)
        return box

    def _mode_changed(self, mode: str) -> None:
        inject = mode == "inject"
        self.anchor_edit.setEnabled(inject)
        self.find_edit.setEnabled(not inject)
        self.regex_check.setEnabled(not inject)
        if inject and not self.anchor_edit.text():
            self.anchor_edit.setText("</body>")

    def _add_changer(self) -> None:
        mode = self.mode_combo.currentText()
        pattern = self.find_edit.text()
        if mode == "inject":
            if not self.replace_edit.text():
                QMessageBox.information(self, "Nothing to inject",
                                        "Enter the content to inject.")
                return
        elif not pattern:
            QMessageBox.information(self, "Nothing to find",
                                    "Enter the text or pattern to look for.")
            return
        if mode == "replace" and self.regex_check.isChecked():
            import re
            try:
                re.compile(pattern)
            except re.error as exc:
                QMessageBox.warning(self, "Not a valid regex", str(exc))
                return
        self._append_changer({
            "enabled": True, "pattern": pattern if mode == "replace" else "",
            "replacement": self.replace_edit.text(),
            "is_regex": mode == "replace" and self.regex_check.isChecked(),
            "direction": self.direction_combo.currentText(),
            "host": self.host_edit.text().strip(),
            "content_type": "text/html" if mode == "inject" else "",
            "mode": mode,
            "anchor": self.anchor_edit.text().strip() or "</body>",
            "hits": 0})
        # Reset the qualifiers too: leaving "Regex" or a host filter set
        # would silently apply them to the next rule typed in.
        self.find_edit.clear()
        self.replace_edit.clear()
        self.regex_check.setChecked(False)
        self.host_edit.clear()
        self._emit_changer()

    def _append_changer(self, rule: dict) -> None:
        self._loading = True
        row = self.changer_table.rowCount()
        self.changer_table.insertRow(row)
        self.changer_table.setItem(row, 0,
                                   _checkbox_item(rule.get("enabled", True)))
        self.changer_table.setItem(row, 1,
                                   QTableWidgetItem(rule.get("pattern", "")))
        self.changer_table.setItem(row, 2,
                                   QTableWidgetItem(rule.get("replacement", "")))
        self.changer_table.setItem(row, 3,
                                   _checkbox_item(rule.get("is_regex", False)))
        self.changer_table.setItem(
            row, 4, QTableWidgetItem(rule.get("direction", "response")))
        self.changer_table.setItem(row, 5,
                                   QTableWidgetItem(rule.get("host", "")))
        self.changer_table.setItem(
            row, 6, QTableWidgetItem(rule.get("content_type", "")))
        self.changer_table.setItem(
            row, 7, QTableWidgetItem(rule.get("mode", "replace")))
        self.changer_table.setItem(
            row, 8, QTableWidgetItem(rule.get("anchor", "</body>")))
        self.changer_table.setItem(row, 9,
                                   _readonly_item(str(rule.get("hits", 0))))
        self._loading = False

    def changer_rules(self) -> list[dict]:
        out = []
        for row in range(self.changer_table.rowCount()):
            def cell(col: int) -> str:
                item = self.changer_table.item(row, col)
                return item.text() if item else ""

            def checked(col: int) -> bool:
                item = self.changer_table.item(row, col)
                return bool(item and item.checkState() == Qt.CheckState.Checked)

            pattern = cell(1)
            mode = cell(7) or "replace"
            replacement = cell(2)
            # An inject rule carries no find pattern, only content to insert.
            if not pattern and not (mode == "inject" and replacement):
                continue
            out.append({"enabled": checked(0), "pattern": pattern,
                        "replacement": replacement, "is_regex": checked(3),
                        "direction": cell(4) or "response", "host": cell(5),
                        "content_type": cell(6), "mode": mode,
                        "anchor": cell(8) or "</body>"})
        return out

    def _changer_edited(self, _item) -> None:
        if not self._loading:
            self._emit_changer()

    def _emit_changer(self) -> None:
        rules = self.changer_rules()
        self._config.set("changer_rules", rules)
        self.changer_rules_changed.emit(rules)

    # ----------------------------------------------------------------- DNS

    def _build_dns(self) -> QGroupBox:
        box = QGroupBox("DNS spoofing")
        lay = QVBoxLayout(box)
        lay.setContentsMargins(12, 10, 12, 10)
        lay.setSpacing(7)

        self.dns_table = QTableWidget(0, len(DNS_COLUMNS))
        self.dns_table.setHorizontalHeaderLabels(DNS_COLUMNS)
        self.dns_table.verticalHeader().setVisible(False)
        self.dns_table.setAlternatingRowColors(True)
        self.dns_table.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows)
        for i, width in enumerate((44, 320, 200, 60)):
            self.dns_table.setColumnWidth(i, width)
        self.dns_table.horizontalHeader().setStretchLastSection(True)
        self.dns_table.itemChanged.connect(self._dns_edited)
        lay.addWidget(self.dns_table, 1)

        row = QHBoxLayout()
        row.setSpacing(8)
        self.pattern_edit = QLineEdit()
        self.pattern_edit.setPlaceholderText("*.bank.lab   or   *   for every name")
        row.addWidget(self.pattern_edit, 2)
        self.answer_edit = QLineEdit()
        self.answer_edit.setPlaceholderText(
            "address to answer with (blank = this machine)")
        row.addWidget(self.answer_edit, 2)
        add = QPushButton("Add rule")
        add.setObjectName("Primary")
        add.clicked.connect(self._add_dns)
        row.addWidget(add)
        remove = QPushButton("Remove")
        remove.clicked.connect(lambda: self._remove(self.dns_table,
                                                    self._emit_dns))
        row.addWidget(remove)
        lay.addLayout(row)
        return box

    def _add_dns(self) -> None:
        pattern = self.pattern_edit.text().strip()
        if not pattern:
            QMessageBox.information(
                self, "No name", "Enter a name or pattern, such as *.bank.lab.")
            return
        self._append_dns({"enabled": True, "pattern": pattern,
                          "address": self.answer_edit.text().strip(),
                          "hits": 0})
        self.pattern_edit.clear()
        self._emit_dns()

    def _append_dns(self, rule: dict) -> None:
        self._loading = True
        row = self.dns_table.rowCount()
        self.dns_table.insertRow(row)
        self.dns_table.setItem(row, 0,
                               _checkbox_item(rule.get("enabled", True)))
        self.dns_table.setItem(row, 1, QTableWidgetItem(rule.get("pattern", "")))
        self.dns_table.setItem(row, 2, QTableWidgetItem(rule.get("address", "")))
        self.dns_table.setItem(row, 3, _readonly_item(str(rule.get("hits", 0))))
        self._loading = False

    def dns_rules(self) -> list[dict]:
        out = []
        for row in range(self.dns_table.rowCount()):
            pattern_item = self.dns_table.item(row, 1)
            if not pattern_item or not pattern_item.text().strip():
                continue
            enabled_item = self.dns_table.item(row, 0)
            address_item = self.dns_table.item(row, 2)
            out.append({
                "enabled": bool(enabled_item and enabled_item.checkState()
                                == Qt.CheckState.Checked),
                "pattern": pattern_item.text().strip(),
                "address": address_item.text().strip() if address_item else ""})
        return out

    def _dns_edited(self, _item) -> None:
        if not self._loading:
            self._emit_dns()

    def _emit_dns(self) -> None:
        rules = self.dns_rules()
        self._config.set("dns_spoof_rules", rules)
        self.dns_rules_changed.emit(rules)

    # ------------------------------------------------------------- shared

    @staticmethod
    def _remove(table, after) -> None:
        rows = sorted({i.row() for i in table.selectedIndexes()}, reverse=True)
        for row in rows:
            table.removeRow(row)
        if rows:
            after()

    def load(self) -> None:
        self._loading = True
        self.changer_table.setRowCount(0)
        for rule in (self._config.get("changer_rules") or []):
            self._append_changer(rule)
        self.dns_table.setRowCount(0)
        for rule in (self._config.get("dns_spoof_rules") or []):
            self._append_dns(rule)
        self._loading = False

    def update_hits(self, changer_stats, dns_stats) -> None:
        """Show, per rule, how often it actually fired."""
        self._loading = True
        for row, rule in enumerate(changer_stats or []):
            if row < self.changer_table.rowCount():
                self.changer_table.setItem(
                    row, 7, _readonly_item(str(rule.get("hits", 0))))
        for row, rule in enumerate(dns_stats or []):
            if row < self.dns_table.rowCount():
                self.dns_table.setItem(
                    row, 3, _readonly_item(str(rule.get("hits", 0))))
        self._loading = False
