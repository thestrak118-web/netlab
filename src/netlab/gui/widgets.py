"""Reusable widgets shared across pages."""

from __future__ import annotations

from PySide6.QtCore import QPoint, Qt, Signal
from PySide6.QtGui import QColor, QFont, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import (QAbstractItemView, QFrame, QHBoxLayout, QHeaderView,
                               QLabel, QLineEdit, QPushButton, QSizePolicy,
                               QTableView, QVBoxLayout, QWidget)

from netlab.gui import theme
from netlab.gui.filters import FILTER_HELP


class Card(QFrame):
    """A single dashboard statistic."""

    def __init__(self, label: str, value: str = "0", note: str = "",
                 parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("Card")
        self.setMinimumWidth(168)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 12, 14, 12)
        lay.setSpacing(3)
        self._label = QLabel(label.upper())
        self._label.setObjectName("CardLabel")
        self._value = QLabel(value)
        self._value.setObjectName("CardValue")
        self._note = QLabel(note)
        self._note.setObjectName("CardNote")
        self._note.setWordWrap(True)
        lay.addWidget(self._label)
        lay.addWidget(self._value)
        lay.addWidget(self._note)

    def set_value(self, value: str, note: str = None, colour: str = None) -> None:
        self._value.setText(value)
        if note is not None:
            self._note.setText(note)
        self._value.setStyleSheet("color: %s;" % colour if colour else "")


class Banner(QFrame):
    """Inline notice. `kind` is info, warn or error."""

    action_clicked = Signal()

    def __init__(self, text: str = "", kind: str = "info",
                 action: str = "", parent=None) -> None:
        super().__init__(parent)
        self._lay = QHBoxLayout(self)
        self._lay.setContentsMargins(12, 9, 12, 9)
        self._lay.setSpacing(10)
        self._label = QLabel(text)
        self._label.setWordWrap(True)
        self._label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse)
        self._lay.addWidget(self._label, 1)
        self._button = QPushButton(action)
        self._button.setVisible(bool(action))
        self._button.clicked.connect(self.action_clicked.emit)
        self._lay.addWidget(self._button, 0, Qt.AlignmentFlag.AlignTop)
        self.set_kind(kind)

    def set_kind(self, kind: str) -> None:
        self.setObjectName({"info": "BannerInfo", "warn": "Banner",
                            "error": "BannerError"}.get(kind, "BannerInfo"))
        self.style().unpolish(self)
        self.style().polish(self)

    def set_text(self, text: str, kind: str = None) -> None:
        self._label.setText(text)
        if kind:
            self.set_kind(kind)

    def set_action(self, label: str) -> None:
        self._button.setText(label)
        self._button.setVisible(bool(label))


class Sparkline(QWidget):
    """Tiny time-series plot for the dashboard rate history."""

    def __init__(self, colour: str = theme.ACCENT, parent=None) -> None:
        super().__init__(parent)
        self._values: list[float] = []
        self._colour = colour
        self.setMinimumHeight(64)
        self.setSizePolicy(QSizePolicy.Policy.Expanding,
                           QSizePolicy.Policy.Preferred)

    def set_values(self, values: list[float]) -> None:
        self._values = list(values)[-120:]
        self.update()

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()
        painter.fillRect(self.rect(), QColor(theme.PANEL))

        pen = QPen(QColor(theme.BORDER))
        pen.setWidth(1)
        painter.setPen(pen)
        for i in range(1, 4):
            y = h * i / 4
            painter.drawLine(0, int(y), w, int(y))

        if len(self._values) < 2:
            painter.setPen(QColor(theme.MUTED))
            painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter,
                             "waiting for data")
            return

        top = max(self._values) or 1.0
        n = len(self._values)
        step = w / max(1, n - 1)
        path = QPainterPath()
        fill = QPainterPath()
        fill.moveTo(0, h)
        for i, v in enumerate(self._values):
            x = i * step
            y = h - (v / top) * (h - 8) - 4
            if i == 0:
                path.moveTo(x, y)
            else:
                path.lineTo(x, y)
            fill.lineTo(x, y)
        fill.lineTo(w, h)
        fill.closeSubpath()

        colour = QColor(self._colour)
        faded = QColor(colour)
        faded.setAlpha(46)
        painter.fillPath(fill, faded)
        pen = QPen(colour)
        pen.setWidth(2)
        painter.setPen(pen)
        painter.drawPath(path)

        painter.setPen(QColor(theme.MUTED))
        f = QFont()
        f.setPointSize(8)
        painter.setFont(f)
        painter.drawText(QPoint(4, 12), "peak %.0f" % top)


class FilterEdit(QLineEdit):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setPlaceholderText(
            "Filter rows…  e.g.  ip:10.0.0.5   port:443   proto:tls   "
            "host:example.com   -proto:arp")
        self.setToolTip(FILTER_HELP)
        self.setClearButtonEnabled(True)


def make_table(model=None) -> QTableView:
    view = QTableView()
    view.setModel(model)
    view.setAlternatingRowColors(True)
    view.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    view.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
    view.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    view.setShowGrid(False)
    view.setWordWrap(False)
    view.verticalHeader().setVisible(False)
    view.verticalHeader().setDefaultSectionSize(23)
    view.horizontalHeader().setHighlightSections(False)
    view.horizontalHeader().setSectionResizeMode(
        QHeaderView.ResizeMode.Interactive)
    view.horizontalHeader().setStretchLastSection(True)
    view.setHorizontalScrollMode(
        QAbstractItemView.ScrollMode.ScrollPerPixel)
    view.setVerticalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
    if model is not None:
        for i, (_title, width, _align) in enumerate(model.COLUMNS):
            view.setColumnWidth(i, width)
    return view


class TablePage(QWidget):
    """Page header + filter box + table + row counter."""

    row_activated = Signal(object)
    row_selected = Signal(object)

    def __init__(self, title: str, hint: str, model, parent=None) -> None:
        super().__init__(parent)
        self.model = model
        lay = QVBoxLayout(self)
        lay.setContentsMargins(18, 16, 18, 14)
        lay.setSpacing(10)

        head = QVBoxLayout()
        head.setSpacing(2)
        label = QLabel(title)
        label.setObjectName("PageTitle")
        if hint:
            label.setToolTip(hint)          # the explanation lives on hover now
        head.addWidget(label)
        # The description is kept for callers that update it, but hidden by
        # default so the page shows content, not a paragraph of prose.
        self.hint = QLabel(hint)
        self.hint.setObjectName("PageHint")
        self.hint.setWordWrap(True)
        self.hint.setVisible(False)
        head.addWidget(self.hint)
        lay.addLayout(head)

        self.banner = Banner("", "info")
        self.banner.setVisible(False)
        lay.addWidget(self.banner)

        bar = QHBoxLayout()
        bar.setSpacing(8)
        self.filter_edit = FilterEdit()
        self.filter_edit.textChanged.connect(self._on_filter)
        bar.addWidget(self.filter_edit, 1)
        self.toolbar = QHBoxLayout()
        self.toolbar.setSpacing(8)
        bar.addLayout(self.toolbar, 0)
        lay.addLayout(bar)

        self.table = make_table(model)
        self.table.doubleClicked.connect(self._on_activate)
        sel = self.table.selectionModel()
        if sel is not None:
            sel.currentRowChanged.connect(self._on_current)
        lay.addWidget(self.table, 1)

        self.count_label = QLabel("")
        self.count_label.setObjectName("PageHint")
        lay.addWidget(self.count_label)

        self.body_layout = lay

    def add_tool(self, widget) -> None:
        self.toolbar.addWidget(widget)

    def attach_detail(self, widget, sizes=(560, 240)) -> None:
        """Put `widget` under the table in a vertical splitter."""
        from PySide6.QtWidgets import QSplitter
        self.body_layout.removeWidget(self.table)
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.addWidget(self.table)
        splitter.addWidget(widget)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes(list(sizes))
        self.body_layout.insertWidget(self.body_layout.count() - 1, splitter, 1)
        self.splitter = splitter
        self.detail = widget

    def _on_filter(self, text: str) -> None:
        self.model.set_filter(text)
        self.update_counts()

    def _on_activate(self, index) -> None:
        obj = self.model.object_at(index.row())
        if obj is not None:
            self.row_activated.emit(obj)

    def _on_current(self, current, _previous) -> None:
        if current is None or not current.isValid():
            return
        obj = self.model.object_at(current.row())
        if obj is not None:
            self.row_selected.emit(obj)

    def set_filter_text(self, text: str) -> None:
        self.filter_edit.setText(text)

    def update_counts(self, suffix: str = "") -> None:
        shown = self.model.rowCount()
        total = self.model.total_rows
        if shown == total:
            text = "%s rows" % "{:,}".format(total)
        else:
            text = "%s of %s rows shown by the current filter" % (
                "{:,}".format(shown), "{:,}".format(total))
        if suffix:
            text += "   ·   " + suffix
        self.count_label.setText(text)

    def selected_object(self):
        idx = self.table.currentIndex()
        return self.model.object_at(idx.row()) if idx.isValid() else None
