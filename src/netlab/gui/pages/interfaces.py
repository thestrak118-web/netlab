"""Interfaces: what can be captured on, and one-click capture start."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import QCheckBox, QPushButton

from netlab.capture.interfaces import Interface, InterfaceError, list_interfaces
from netlab.gui import theme
from netlab.gui.models import LEFT, RIGHT, NetLabTableModel
from netlab.gui.widgets import TablePage
from netlab.util.format import DASH, dash, human_bytes


class InterfaceModel(NetLabTableModel):
    COLUMNS = [
        ("Interface", 150, LEFT), ("Type", 96, LEFT), ("State", 80, LEFT),
        ("Addresses", 330, LEFT), ("MAC", 150, LEFT), ("MTU", 64, RIGHT),
        ("RX packets", 100, RIGHT), ("TX packets", 100, RIGHT),
        ("RX bytes", 96, RIGHT), ("Description", 200, LEFT),
    ]

    def cell(self, i: Interface, col):
        return (
            i.name, i.kind, "up" if i.is_up else i.operstate,
            ", ".join(i.addresses) or DASH, dash(i.mac), dash(i.mtu),
            "{:,}".format(i.rx_packets), "{:,}".format(i.tx_packets),
            human_bytes(i.rx_bytes), i.description or DASH,
        )[col]

    def fields(self, i):
        return {"name": i.name, "proto": i.kind, "state": i.operstate,
                "mac": i.mac or "", "src": " ".join(i.addresses)}

    def search_text(self, i):
        return "%s %s %s %s" % (i.name, i.kind, " ".join(i.addresses),
                                i.description)

    def colour(self, i, col):
        if col == 2:
            return theme.GREEN if i.is_up else theme.MUTED
        if col == 0 and i.is_pseudo:
            return theme.MUTED
        return None

    def identity(self, i):
        return i.name


class InterfacesPage(TablePage):
    capture_requested = Signal(str)

    def __init__(self, parent=None) -> None:
        super().__init__(
            "Interfaces",
            "Devices reported by dumpcap. Double-click an interface to start "
            "capturing on it.",
            InterfaceModel(), parent)

        self.show_pseudo = QCheckBox("Show pseudo-devices")
        self.show_pseudo.setToolTip(
            "Includes 'any', nflog, D-Bus and extcap devices.")
        self.show_pseudo.stateChanged.connect(lambda _s: self.refresh())
        self.add_tool(self.show_pseudo)

        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(self.refresh)
        self.add_tool(self.refresh_btn)

        self.capture_btn = QPushButton("Start capture")
        self.capture_btn.setObjectName("Primary")
        self.capture_btn.clicked.connect(self._start_selected)
        self.add_tool(self.capture_btn)

        self.row_activated.connect(self._activate)
        self.refresh()

    def _activate(self, iface: Interface) -> None:
        self.capture_requested.emit(iface.name)

    def _start_selected(self) -> None:
        iface = self.selected_object()
        if iface is not None:
            self.capture_requested.emit(iface.name)

    def refresh(self) -> None:
        try:
            items = list_interfaces(
                include_pseudo=self.show_pseudo.isChecked())
        except InterfaceError as exc:
            self.banner.set_text(
                "Could not list capture interfaces.\n\n%s" % exc, "error")
            self.banner.setVisible(True)
            self.model.clear()
            self.update_counts()
            return
        self.banner.setVisible(False)
        self.model.replace_items(items)
        self.update_counts("%d usable, %d pseudo-device(s)" % (
            sum(1 for i in items if not i.is_pseudo),
            sum(1 for i in items if i.is_pseudo)))

    def interface_names(self) -> list[str]:
        return [i.name for i in self.model._source if not i.is_pseudo]
