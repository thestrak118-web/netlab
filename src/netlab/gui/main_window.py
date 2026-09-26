"""NetLab main window."""

from __future__ import annotations

import threading
import time
from collections import deque
from pathlib import Path

from PySide6.QtCore import QObject, Qt, QTimer, QSize, Signal
from PySide6.QtGui import QAction, QColor, QIcon, QKeySequence
from PySide6.QtWidgets import (QComboBox, QFileDialog, QFrame, QHBoxLayout,
                               QLabel, QLineEdit, QMainWindow, QMessageBox,
                               QPushButton, QStackedWidget, QStatusBar, QTabBar,
                               QVBoxLayout, QWidget)

from netlab import __version__
from netlab.analyze.engine import AnalysisEngine
from netlab.analyze.devices import NetworkContext
from netlab.integrations.discovery import DiscoveryRunner
from netlab.gui.pages.devices import DevicesPage
from netlab.gui.pages.topology import TopologyPage
from netlab.gui.pages.monitor import MonitorPage
from netlab.gui.device_icons import device_icon
from netlab.capture.engine import (CaptureEngine, CaptureSession, FileImporter,
                                   default_capture_name)
from netlab.capture.interfaces import (InterfaceError, list_interfaces,
                                       validate_bpf)
from netlab.capture.pcapio import RandomAccessCapture
from netlab.capture.privileges import check as check_privileges
from netlab.capture.privileges import remediation_text
from netlab.config import CONFIG
from netlab.gui import theme
from netlab.gui.filters import FILTER_HELP
from netlab.gui.pages.captures import CapturesPage
from netlab.gui.pages.changerpage import RulesPage
from netlab.gui.pages.credspage import CredentialsPage
from netlab.gui.pages.filespage import FilesPage
from netlab.gui.pages.mitmpage import MitmPage
from netlab.gui.pages.console import ConsolePage
from netlab.gui.pages.connections import ConnectionsPage
from netlab.gui.pages.dashboard import DashboardPage
from netlab.gui.pages.dnspage import DnsPage
from netlab.gui.pages.httppage import HttpPage
from netlab.gui.pages.interfaces import InterfacesPage
from netlab.gui.pages.live import LiveTrafficPage
from netlab.gui.pages.nmappage import NmapPage
from netlab.gui.pages.pcapviewer import PcapViewerPage
from netlab.gui.pages.settingspage import SettingsPage
from netlab.gui.pages.tlspage import TlsPage
from netlab.priv import protocol as helper_protocol
from netlab.priv.client import HelperClient
from netlab.util.bounded import DropCountingQueue
from netlab.util.format import human_bytes, human_count

PAGES = [
    ("Dashboard", "dashboard"),
    ("Interfaces", "interfaces"),
    ("Live Traffic", "live"),
    ("Connections", "connections"),
    ("Hostlar", "devices"),
    ("Topology", "topology"),
    ("Selected Device", "monitor"),
    ("DNS", "dns"),
    ("HTTP", "http"),
    ("TLS", "tls"),
    ("Passwords", "creds"),
    ("Files", "files"),
    ("Interception", "mitm"),
    ("Rules", "rules"),
    ("Captures", "captures"),
    ("PCAP Viewer", "pcap"),
    ("Nmap", "nmap"),
    ("Settings", "settings"),
    ("Konsol", "console"),
]

# Host-centric: three top modes. SKANER lands on the host list; clicking a
# host drills into its Selected Device tabs (Faollik / DNS / HTTP / TLS /
# Parollar / Saytlar), so those are not top-level pages. KONSOL is the live
# read side, INTERCEPTION the active side. Each group is (stable_id, label,
# leaves); leaves point at PAGES keys. Pages not listed here (Selected Device,
# DNS/HTTP/TLS, Captures, PCAP, Settings, Interfaces, Dashboard) are reached by
# drilling in from a host or from the menu, not from a mode tab.
NAV_GROUPS = [
    ("scan", "SKANER", [("Hostlar", "devices"), ("Topologiya", "topology"),
                        ("Nmap skan", "nmap")]),
    ("traffik", "TRAFFIK", [("Jonli traffik", "live"),
                            ("Ulanishlar", "connections")]),
    ("passwords", "PAROLLAR", [("Parollar", "creds")]),
    ("konsol", "KONSOL", [("Konsol", "console")]),
    ("mitm", "MITM", [("Interception", "mitm"), ("Qoidalar", "rules"),
                      ("Tiklash", "files")]),
]


class BpfValidator(QObject):
    """Validates a BPF expression off the GUI thread."""

    result = Signal(str, bool, str)        # expression, ok, message

    def check(self, expression: str, interface: str) -> None:
        def run() -> None:
            ok, msg = validate_bpf(expression, interface or None)
            self.result.emit(expression, ok, msg)
        threading.Thread(target=run, daemon=True).start()


class MainWindow(QMainWindow):
    context_ready = Signal(int, object)
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("NetLab %s" % __version__)
        self.resize(1480, 920)

        self.config = CONFIG
        self.queue = DropCountingQueue(int(self.config.get("queue_packets")))
        self.analysis = AnalysisEngine(self.queue, self.config)
        self.analysis.start()
        self._apply_harvest()          # credential harvesting on by default
        self.capture = CaptureEngine(self.queue, self)
        self.importer = FileImporter(self.queue, self)

        self._context_generation = 0
        self._context_busy = False
        self._context_next = 0.0
        self._network_next = 0.0
        self._mode = "idle"                 # idle | live | offline
        self._live_marker = 0
        self._dns_marker = 0
        self._http_marker = 0
        # Separate markers feed the live console independently of which page is
        # open, so it shows the sites the traffic is reaching as they happen.
        self._console_tls_marker = 0
        self._console_http_marker = 0
        self._console_cred_keys: set = set()
        self._source_path: Path | None = None
        self._reader: RandomAccessCapture | None = None
        self._reader_path: Path | None = None
        self._bpf_ok = True
        self._rate_t0 = 0.0
        self._rate_n0 = 0
        self._captured_pps = 0.0
        self._capture_rate_history: deque = deque(maxlen=120)

        self.discovery = DiscoveryRunner(self)
        self._discovery_interface = None

        # Active interception lives in a separate, privileged process.
        self.helper = HelperClient(self)
        self._armed_state = False
        self._helper_requests: dict[int, str] = {}
        self._cred_marker = 0
        self._active_credentials: list = []
        self._carved_files: list = []
        self._status_next = 0.0
        # Created before the UI so the initial page's refresh (the host list
        # now lands first, and it reads timer.interval()) has it available.
        self.timer = QTimer(self)

        self._build_ui()
        self._build_menu()
        self._connect()

        self._check_privileges()
        self._apply_retention_on_start()
        self.refresh_interfaces()

        self.timer.timeout.connect(self._tick)
        self.timer.start(min(1000, max(250, int(self.config.get("gui_refresh_ms")))))

    # ------------------------------------------------------------------ build

    def _build_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # Canonical page order == the QStackedWidget add order below, so a
        # page key maps straight to its stack index.
        self._page_index = {key: i for i, (_label, key) in enumerate(PAGES)}

        # Intercepter-NG-style navigation: horizontal mode tabs on top instead
        # of a left sidebar. The first row is the mode (SKAN, TRAFFIK, ...);
        # the second, thinner row is the pages inside the chosen mode, and it
        # hides itself when a mode has only one page.
        self._group_order = [gid for gid, _lbl, _e in NAV_GROUPS]
        self._group_label = {gid: lbl for gid, lbl, _e in NAV_GROUPS}
        self._group_pages = {gid: list(entries)
                             for gid, _lbl, entries in NAV_GROUPS}
        self._page_group = {key: gid for gid, _lbl, entries in NAV_GROUPS
                            for _lbl2, key in entries}

        # Guard: adding tabs fires currentChanged before the page bar and
        # stack exist. Cleared once the first page is shown at the end of build.
        self._nav_updating = True
        self.mode_bar = QTabBar()
        self.mode_bar.setObjectName("ModeBar")
        self.mode_bar.setExpanding(False)
        self.mode_bar.setDrawBase(False)
        self.mode_bar.setIconSize(QSize(26, 26))
        mode_icons = {"scan": "mode-scan", "traffik": "mode-traffik",
                      "passwords": "mode-passwords", "konsol": "mode-konsol",
                      "files": "mode-files", "mitm": "mode-mitm"}
        icon_dir = Path(__file__).with_name("icons")
        for gid in self._group_order:
            idx = self.mode_bar.addTab(self._group_label[gid])
            self.mode_bar.setTabData(idx, gid)
            name = mode_icons.get(gid)
            if name:
                self.mode_bar.setTabIcon(idx, QIcon(str(icon_dir / (name + ".svg"))))
        self.mode_bar.currentChanged.connect(self._mode_tab_changed)
        self.mode_bar.tabBarClicked.connect(self._mode_tab_clicked)

        self.page_bar = QTabBar()
        self.page_bar.setObjectName("PageBar")
        self.page_bar.setExpanding(False)
        self.page_bar.setDrawBase(False)
        self.page_bar.currentChanged.connect(self._page_tab_changed)
        self.page_bar.tabBarClicked.connect(self._page_tab_clicked)

        right = QVBoxLayout()
        right.setContentsMargins(0, 0, 0, 0)
        right.setSpacing(0)

        toolbar = QWidget()
        toolbar.setObjectName("Toolbar")
        tb = QHBoxLayout(toolbar)
        tb.setContentsMargins(16, 10, 16, 10)
        tb.setSpacing(9)

        tb.addWidget(QLabel("Interface"))
        self.iface_combo = QComboBox()
        self.iface_combo.setMinimumWidth(230)
        tb.addWidget(self.iface_combo)

        self.refresh_btn = QPushButton("↻")
        self.refresh_btn.setFixedWidth(34)
        self.refresh_btn.setToolTip("Re-scan capture interfaces")
        tb.addWidget(self.refresh_btn)

        self.bpf_label = QLabel("BPF")
        tb.addWidget(self.bpf_label)
        self.bpf_edit = QLineEdit()
        self.bpf_edit.setPlaceholderText(
            "Capture filter (libpcap syntax) — e.g. tcp port 443 or not arp")
        self.bpf_edit.setToolTip(
            "A BPF capture filter is applied by libpcap before packets are "
            "written. Packets it excludes are never captured at all.\n"
            "To narrow what you are looking at without losing data, use the "
            "per-page filter box instead.")
        self.bpf_edit.setText(str(self.config.get("bpf_filter") or ""))
        tb.addWidget(self.bpf_edit, 1)
        # The capture filter is an advanced control -- a beginner does not need
        # libpcap syntax in their face. Hidden until toggled from the Capture
        # menu (or when a filter is preloaded with `netlab -f`).
        _show_bpf = bool(self.bpf_edit.text().strip())
        self.bpf_label.setVisible(_show_bpf)
        self.bpf_edit.setVisible(_show_bpf)

        self.start_btn = QPushButton("Start capture")
        self.start_btn.setObjectName("Primary")
        tb.addWidget(self.start_btn)

        self.stop_btn = QPushButton("Stop")
        self.stop_btn.setObjectName("Danger")
        self.stop_btn.setEnabled(False)
        tb.addWidget(self.stop_btn)

        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.VLine)
        sep.setObjectName("ToolbarSep")
        tb.addWidget(sep)

        # Intercepter-NG-style quick controls: scan the LAN, and arm/disarm the
        # MiTM in one click. The MiTM toggle still routes through the engagement
        # gate — it opens the Interception page and its confirmation dialog, it
        # never silently starts poisoning.
        self.scan_btn = QPushButton("⌖ Scan")
        self.scan_btn.setToolTip(
            "Discover hosts on the local network (ARP + name discovery). "
            "Same as Devices → Discover.")
        self.scan_btn.clicked.connect(self._toolbar_scan)
        tb.addWidget(self.scan_btn)

        self.mitm_btn = QPushButton("● MITM")
        self.mitm_btn.setCheckable(True)
        self.mitm_btn.setToolTip(
            "Arm or disarm interception. Arming opens the Interception page and "
            "asks you to confirm the engagement first.")
        self.mitm_btn.clicked.connect(self._toolbar_mitm_toggle)
        tb.addWidget(self.mitm_btn)

        # Intercepter-NG shows the packet tally right in the top bar.
        self.toolbar_packets = QLabel("Packets: 0")
        self.toolbar_packets.setObjectName("PacketTally")
        tb.addWidget(self.toolbar_packets)

        right.addWidget(toolbar)

        mode_row = QWidget()
        mode_row.setObjectName("ModeRow")
        mode_lay = QHBoxLayout(mode_row)
        mode_lay.setContentsMargins(12, 4, 12, 0)
        mode_lay.setSpacing(0)
        mode_lay.addWidget(self.mode_bar)
        mode_lay.addStretch(1)
        right.addWidget(mode_row)

        page_row = QWidget()
        page_row.setObjectName("PageRow")
        page_lay = QHBoxLayout(page_row)
        page_lay.setContentsMargins(12, 0, 12, 4)
        page_lay.setSpacing(0)
        page_lay.addWidget(self.page_bar)
        page_lay.addStretch(1)
        self._page_row = page_row
        right.addWidget(page_row)

        self.stack = QStackedWidget()
        self.dashboard = DashboardPage()
        self.interfaces_page = InterfacesPage()
        self.live_page = LiveTrafficPage()
        self.connections_page = ConnectionsPage()
        # One host list, labelled "Hostlar" (Hosts and Devices were the same
        # DevicesPage projection -- the duplicate is gone).
        self.devices_page = DevicesPage('Hostlar')
        self.topology_page = TopologyPage()
        self.monitor_page = MonitorPage(self.analysis, lambda: self._source_path,
                                        lambda: self.capture.is_running,
                                        creds_provider=self._all_credentials)
        self.devices_page.engine = self.analysis
        self.dns_page = DnsPage()
        self.http_page = HttpPage()
        self.tls_page = TlsPage()
        self.creds_page = CredentialsPage(self.config)
        self.files_page = FilesPage()
        self.mitm_page = MitmPage(self.config)
        self.rules_page = RulesPage(self.config)
        self.captures_page = CapturesPage(self.config)
        self.pcap_page = PcapViewerPage()
        self.nmap_page = NmapPage(self.config)
        self.settings_page = SettingsPage(self.config)
        self.console_page = ConsolePage()
        for page in (self.dashboard, self.interfaces_page, self.live_page,
                     self.connections_page, self.devices_page, self.topology_page, self.monitor_page, self.dns_page,
                     self.http_page, self.tls_page, self.creds_page,
                     self.files_page, self.mitm_page, self.rules_page,
                     self.captures_page,
                     self.pcap_page, self.nmap_page, self.settings_page,
                     self.console_page):
            self.stack.addWidget(page)
        right.addWidget(self.stack, 1)

        wrapper = QWidget()
        wrapper.setLayout(right)
        root.addWidget(wrapper, 1)

        self.status = QStatusBar()
        self.setStatusBar(self.status)
        self.status_source = QLabel("No capture running")
        self.status_counts = QLabel("")
        self.status_drops = QLabel("")
        self.status.addWidget(self.status_source, 2)
        self.monitor_status_icon = QLabel()
        self.status.addPermanentWidget(self.monitor_status_icon)
        self.monitor_indicator = QLabel('')
        self.status.addPermanentWidget(self.monitor_indicator)
        self.status.addPermanentWidget(self.status_counts)
        self.status.addPermanentWidget(self.status_drops)

        self.live_page.detail.set_reader_provider(self._current_reader)
        # Pages that correlate need to reach the analysis engine.
        self.live_page.set_engine(self.analysis)
        self.connections_page.set_engine(self.analysis)

    def _build_menu(self) -> None:
        bar = self.menuBar()

        file_menu = bar.addMenu("&File")
        act_open = QAction("&Open capture file…", self)
        act_open.setShortcut(QKeySequence.StandardKey.Open)
        act_open.triggered.connect(self._choose_pcap)
        file_menu.addAction(act_open)

        act_export = QAction("&Export current capture…", self)
        act_export.triggered.connect(self._export_current)
        file_menu.addAction(act_export)
        file_menu.addSeparator()

        # Settings and Interfaces are utilities, not modes — they live here.
        act_settings = QAction("&Sozlamalar", self)
        act_settings.setShortcut("Ctrl+,")
        act_settings.triggered.connect(lambda: self._show_page("settings"))
        file_menu.addAction(act_settings)
        act_ifaces = QAction("&Interfeyslar", self)
        act_ifaces.triggered.connect(lambda: self._show_page("interfaces"))
        file_menu.addAction(act_ifaces)
        # Capture management lives in the menu now, not a mode tab.
        act_captures = QAction("&Yozuvlar (Captures)", self)
        act_captures.triggered.connect(lambda: self._show_page("captures"))
        file_menu.addAction(act_captures)
        act_pcap = QAction("&PCAP ko'ruvchi", self)
        act_pcap.triggered.connect(lambda: self._show_page("pcap"))
        file_menu.addAction(act_pcap)
        file_menu.addSeparator()

        act_quit = QAction("&Quit", self)
        act_quit.setShortcut(QKeySequence.StandardKey.Quit)
        act_quit.triggered.connect(self.close)
        file_menu.addAction(act_quit)

        cap_menu = bar.addMenu("&Capture")
        self.act_start = QAction("&Start capture", self)
        self.act_start.setShortcut("Ctrl+R")
        self.act_start.triggered.connect(self.start_capture)
        cap_menu.addAction(self.act_start)

        self.act_stop = QAction("S&top capture", self)
        self.act_stop.setShortcut("Ctrl+T")
        self.act_stop.setEnabled(False)
        self.act_stop.triggered.connect(self.stop_capture)
        cap_menu.addAction(self.act_stop)

        cap_menu.addSeparator()
        self.act_bpf = QAction("Show capture &filter (BPF)", self)
        self.act_bpf.setCheckable(True)
        self.act_bpf.setChecked(self.bpf_edit.isVisible())
        self.act_bpf.toggled.connect(self._toggle_bpf)
        cap_menu.addAction(self.act_bpf)
        act_clear = QAction("&Clear analysis", self)
        act_clear.triggered.connect(self._clear_analysis_confirm)
        cap_menu.addAction(act_clear)

        help_menu = bar.addMenu("&Help")
        act_filter = QAction("&Filter syntax", self)
        act_filter.triggered.connect(
            lambda: QMessageBox.information(self, "Display filter syntax",
                                            FILTER_HELP))
        help_menu.addAction(act_filter)
        act_priv = QAction("Capture &privileges", self)
        act_priv.triggered.connect(
            lambda: QMessageBox.information(
                self, "Capture privileges",
                remediation_text(check_privileges())))
        help_menu.addAction(act_priv)
        act_about = QAction("&About NetLab", self)
        act_about.triggered.connect(self._about)
        help_menu.addAction(act_about)

    def _connect(self) -> None:
        self._show_page("devices")       # land on the host list, clear the nav guard
        self.refresh_btn.clicked.connect(self.refresh_interfaces)
        self.start_btn.clicked.connect(self.start_capture)
        self.stop_btn.clicked.connect(self.stop_capture)

        self.capture.started.connect(self._capture_started)
        self.capture.stopped.connect(self._capture_stopped)
        self.capture.failed.connect(self._capture_failed)
        self.capture.status.connect(self.status_source.setText)

        self.importer.progress.connect(self.pcap_page.import_progress)
        self.importer.finished.connect(self._import_finished)
        self.importer.failed.connect(self._import_failed)

        self.interfaces_page.capture_requested.connect(self._capture_on)
        self.captures_page.open_requested.connect(self.open_capture_file)
        self.pcap_page.open_requested.connect(self.open_capture_file)
        self.pcap_page.show_packets.connect(self._show_related_packets)
        self.settings_page.settings_saved.connect(self._settings_saved)

        for page in (self.connections_page, self.dns_page,
                     self.http_page, self.tls_page, self.creds_page):
            page.show_packets.connect(self._show_related_packets)

        self.mitm_page.arm_requested.connect(self._arm_interception)
        self.mitm_page.disarm_requested.connect(self._disarm_interception)
        self.mitm_page.scan_requested.connect(self._helper_scan)
        self.mitm_page.promisc_requested.connect(self._helper_promisc)
        self.mitm_page.ca_export_requested.connect(self._export_ca)
        self.rules_page.changer_rules_changed.connect(
            lambda rules: self._push_rules("changer_rules", rules))
        self.rules_page.dns_rules_changed.connect(
            lambda rules: self._push_rules("dns_rules", rules))
        self.helper.ready.connect(self._helper_ready)
        self.helper.event.connect(self._helper_event)
        self.helper.replied.connect(self._helper_replied)
        self.helper.closed.connect(self._helper_closed)
        self.helper.failed.connect(self._helper_failed)
        self.iface_combo.currentIndexChanged.connect(self._interface_changed)
        self.live_page.show_connection.connect(self._show_connection)
        self.context_ready.connect(self._apply_network_context)
        self.discovery.batch.connect(self._apply_discovery)
        self.discovery.progress.connect(lambda text: self._discovery_status(text, True))
        self.discovery.finished.connect(lambda text: self._discovery_status(text, False))
        self.discovery.failed.connect(lambda text: self._discovery_status('Discovery: ' + text, False))
        for page in (self.devices_page,):
            page.detail.navigate.connect(self._device_action)
            page.monitor_requested.connect(self._monitor_device)
            page.watch_requested.connect(self._watch_device)
            page.intercept_requested.connect(self._send_to_interception)
            page.discovery_requested.connect(self._start_discovery)
            page.discovery_cancelled.connect(self.discovery.cancel)
        self.monitor_page.open_connection.connect(self._show_connection)
        self.monitor_page.indicator_changed.connect(self._monitor_indicator)
        self.monitor_page.back_requested.connect(lambda: self._show_page("devices"))
        self.topology_page.device_selected.connect(self._open_device)
        self.topology_page.remote_action.connect(self._device_action)

        self._bpf_validator = BpfValidator(self)
        self._bpf_validator.result.connect(self._bpf_checked)
        self._bpf_timer = QTimer(self)
        self._bpf_timer.setSingleShot(True)
        self._bpf_timer.setInterval(600)
        self._bpf_timer.timeout.connect(self._validate_bpf)
        self.bpf_edit.textChanged.connect(lambda _t: self._bpf_timer.start())

    # ------------------------------------------------------------ navigation

    def _activate_page(self, key: str) -> None:
        self.stack.setCurrentIndex(self._page_index[key])
        self._refresh_current_page()

    def _rebuild_page_bar(self, group_id: str, select_key: str = "") -> None:
        """Fill the page row with the chosen mode's pages and open one."""
        self._nav_updating = True
        self.page_bar.blockSignals(True)
        while self.page_bar.count():
            self.page_bar.removeTab(0)
        pages = self._group_pages[group_id]
        target = 0
        for i, (label, key) in enumerate(pages):
            self.page_bar.addTab(label)
            self.page_bar.setTabData(i, key)
            if key == select_key:
                target = i
        self.page_bar.setCurrentIndex(target)
        self.page_bar.blockSignals(False)
        # A mode with a single page needs no second row.
        self._page_row.setVisible(len(pages) > 1)
        self._nav_updating = False
        self._activate_page(self.page_bar.tabData(target))

    def _mode_tab_changed(self, index: int) -> None:
        if self._nav_updating or index < 0:
            return
        self._rebuild_page_bar(self.mode_bar.tabData(index))

    def _page_tab_changed(self, index: int) -> None:
        if self._nav_updating or index < 0:
            return
        key = self.page_bar.tabData(index)
        if key:
            self._activate_page(key)

    def _toggle_bpf(self, show: bool) -> None:
        self.bpf_label.setVisible(show)
        self.bpf_edit.setVisible(show)
        if show:
            self.bpf_edit.setFocus()

    def _mode_tab_clicked(self, index: int) -> None:
        # tabBarClicked fires even for the already-current tab -- which is how
        # you return from an ungrouped drill-down (PCAP, Settings, Selected
        # Device) whose stack switch left this mode selected. currentChanged
        # would not fire then, so bring this mode's selected page back.
        if index < 0 or index != self.mode_bar.currentIndex():
            return
        key = self.page_bar.tabData(self.page_bar.currentIndex())
        if key:
            self._activate_page(key)
        else:
            self._rebuild_page_bar(self.mode_bar.tabData(index))

    def _page_tab_clicked(self, index: int) -> None:
        if index < 0 or index != self.page_bar.currentIndex():
            return
        key = self.page_bar.tabData(index)
        if key:
            self._activate_page(key)

    def _show_page(self, key: str) -> None:
        """Programmatic navigation: select the mode and page that hold `key`."""
        group_id = self._page_group.get(key)
        if group_id is None:
            # A utility page (Settings, Interfaces) reachable from the menu but
            # not a mode tab — open it directly.
            if key in self._page_index:
                self.stack.setCurrentIndex(self._page_index[key])
                self._refresh_current_page()
            return
        mode_index = self._group_order.index(group_id)
        self._nav_updating = True
        self.mode_bar.setCurrentIndex(mode_index)
        self._nav_updating = False
        self._rebuild_page_bar(group_id, select_key=key)

    def _goto(self, label: str) -> None:
        """Select a page by its PAGES label or by its key."""
        key = label if label in self._page_group else None
        if key is None:
            for name, k in PAGES:
                if name == label:
                    key = k
                    break
        if key:
            self._show_page(key)

    def _nav_to(self, key: str) -> None:
        self._show_page(key)

    def _show_related_packets(self, filter_text: str) -> None:
        self.live_page.set_filter_text(filter_text)
        self._show_page("live")

    def _show_connection(self, flow) -> None:
        """Jump from a packet to the connection it belongs to."""
        self.connections_page.model.replace_items(self.analysis.flows.ordered())
        self.connections_page.set_filter_text(
            "ip:%s ip:%s port:%s" % (flow.client, flow.server,
                                     flow.server_port or ""))
        self._show_page("connections")
        model = self.connections_page.model
        for row in range(model.rowCount()):
            candidate = model.object_at(row)
            if candidate is not None and candidate.key == flow.key:
                self.connections_page.table.selectRow(row)
                break

    def _monitor_device(self, ip):
        if self.analysis.resolve_device(ip) is None:
            self.status_source.setText('Remote destination: use View Traffic or View Connections.')
            return
        self.monitor_page.select_device(ip)
        self._show_page('monitor')

    def _watch_device(self, ip):
        """The headline flow: watch one device live -- its sites and any login
        it makes. Your own device is read passively; another device is put in
        the path first (ARP), which the arm dialog confirms."""
        if not ip:
            return
        dev = self.analysis.resolve_device(ip)
        # Watching (ARP/MITM) works on IPv4. Prefer the device's IPv4 address;
        # if only a link-local IPv6 (fe80::) has been seen, its IPv4 is not
        # known yet -- an ARP sweep finds it.
        if dev is not None and getattr(dev, "ipv4_addresses", ()):
            ip = dev.ipv4_addresses[0]
        elif ":" in ip:
            self._show_page("devices")
            self._discovery_status(
                "%s is only known by IPv6 so far — its IPv4 (needed to watch "
                "it) is not seen yet. Press 'Discover devices' to find it, "
                "then watch it." % ip, False)
            return
        if not self.config.get("harvest_credentials"):
            self.config.set("harvest_credentials", True)
            self._apply_harvest()
        self.monitor_page.engine = self.analysis
        own = dev is not None and getattr(dev, "device_type", "") == "This Device"
        if not own:
            if not self._ensure_helper():
                return
            self.mitm_page.watch(ip)        # scope + modules + arm confirmation
        try:
            self.monitor_page.select_device(ip)
            self._show_page("monitor")
        except ValueError:
            self.status_source.setText(
                "Cannot watch %s yet -- run Discover, then try again." % ip)

    def _send_to_interception(self, ips):
        """Intercepter-NG 'add to NAT': scanned host(s) become MiTM targets."""
        if isinstance(ips, str):
            ips = [ips]
        ips = [ip for ip in (ips or []) if ip]
        if not ips:
            return
        added = sum(1 for ip in ips if self.mitm_page.add_target(ip))
        self._show_page('mitm')
        if added:
            self.status_source.setText(
                '%d host(s) added to the engagement scope.' % added)
        else:
            self.status_source.setText(
                'No new hosts added (already in scope, or the gateway).')

    # ------------------------------------------------- toolbar quick controls

    def _toolbar_scan(self):
        """Toolbar Scan: same LAN discovery as the Devices page."""
        self._show_page('devices')
        self._start_discovery()

    def _toolbar_mitm_toggle(self):
        """Toolbar MITM: arm or disarm, always through the engagement gate."""
        self._show_page('mitm')
        if self._armed:
            self.mitm_page.disarm_requested.emit()
        else:
            # _arm() validates the scope, shows the confirmation dialog, and
            # only then emits arm_requested. If the operator cancels, nothing
            # is armed and the button falls back to its off state.
            self.mitm_page._arm()
        self._reflect_armed()

    @property
    def _armed(self) -> bool:
        return self._armed_state

    @_armed.setter
    def _armed(self, value: bool) -> None:
        self._armed_state = bool(value)
        self._reflect_armed()

    def _reflect_armed(self):
        """Keep the toolbar MITM toggle in step with the real armed state."""
        if not hasattr(self, "mitm_btn"):        # set before the toolbar exists
            return
        armed = bool(self._armed)
        self.mitm_btn.setChecked(armed)
        self.mitm_btn.setText("■ MITM on" if armed else "● MITM")
        self.mitm_btn.setObjectName("Danger" if armed else "")
        # Re-polish so the object-name-based style takes effect immediately.
        self.mitm_btn.style().unpolish(self.mitm_btn)
        self.mitm_btn.style().polish(self.mitm_btn)

    def _monitor_indicator(self, ip, state):
        host = self.analysis.hosts.get(ip) if ip else None
        if state != 'Stopped' and ip:
            self.monitor_status_icon.setPixmap(device_icon(host.device_type if host else 'Unknown').pixmap(22,22))
        else:
            self.monitor_status_icon.clear()
        self.monitor_indicator.setText(('MONITORING: ' if state == 'Monitoring' else 'PAUSED: ') + ip
                                       if state != 'Stopped' and ip else '')
        self.monitor_indicator.setToolTip('Passive observed traffic only; encrypted payloads remain unreadable.')

    def _open_device(self, ip):
        if self.analysis.resolve_device(ip) is None:
            self._device_action('Connections', ip)
            return
        self.devices_page.refresh(self.analysis.device_view()[0])
        self._show_page('devices')
        self.devices_page.select_device(ip)

    def _device_action(self, action, ip):
        if not ip:
            return
        # Same data stores and existing pages; never re-analyze a device.
        relations = self.analysis.relations_for_device(ip)
        addresses = self.analysis.addresses_for(ip)
        expression = 'device:' + '|'.join(sorted(addresses))
        if action == 'Traffic':
            self._show_related_packets(expression)
        elif action == 'PCAP':
            self.pcap_page.set_device_source(self._source_path, tuple(sorted(addresses)), self.analysis.stats())
            self._show_page('pcap')
        else:
            page = {'Connections': self.connections_page, 'DNS': self.dns_page,
                    'HTTP': self.http_page, 'TLS': self.tls_page}[action]
            page.set_filter_text(expression)
            self._goto(action)
            # relations_for_device is also used by the detail panel; page filters
            # remain live and evaluate new records on subsequent refreshes.
            page.update_counts(f'{len(relations[action.lower()])} related records retained')

    def _discovery_status(self, text, running):
        for page in (self.devices_page,):
            page.set_discovery_status(text, running)

    def _start_discovery(self):
        if self.discovery.is_running:
            return
        if self._mode == 'offline':
            self._discovery_status('Discovery is unavailable for offline captures. Start a live session first.', False)
            return
        interface = self.iface_combo.currentData()
        if not interface:
            self._discovery_status('Select a local capture interface first.', False)
            return
        if self.analysis.hosts.context.interface not in ('', interface):
            self._discovery_status('Start a new capture on this interface before discovering devices.', False)
            return
        self._discovery_interface = interface
        self._discovery_status('Starting local discovery…', True)
        self.discovery.start(interface, self._context_generation)

    def _apply_discovery(self, generation, context, records):
        if generation != self._context_generation or self._mode == 'offline' or context.interface != self.iface_combo.currentData():
            return
        if not self.analysis.hosts.context.interface:
            self.analysis.hosts.apply_context(context)
        self.analysis.hosts.apply_discovery(context, records)
        for page in (self.devices_page,):
            page.refresh(self.analysis.device_view()[0])
        self._network_next = 0

    def _discover_network_context(self):
        if self._mode != 'live' or self._context_busy:
            return
        self._context_busy = True
        generation = self._context_generation
        interface = self.capture.session.interface
        def run():
            context = NetworkContext.discover(interface)
            self.context_ready.emit(generation, context)
        threading.Thread(target=run, daemon=True).start()

    def _apply_network_context(self, generation, context):
        if generation != self._context_generation:
            return
        self._context_busy = False
        if self._mode != 'live':
            return
        self.analysis.hosts.apply_context(context)
        self._context_next = time.monotonic() + 10
        if context.errors:
            self.devices_page.banner.set_text('Network evidence incomplete: ' + '; '.join(context.errors), 'warn')
            self.devices_page.banner.setVisible(True)
        else:
            self.devices_page.banner.setVisible(False)

    # -------------------------------------------------------------- privileges

    def _check_privileges(self) -> None:
        report = check_privileges()
        if report.can_capture:
            self.dashboard.set_privilege_warning("")
            if report.running_as_root:
                self.dashboard.set_privilege_warning(
                    "NetLab is running as root. Capture works, but running as "
                    "a normal user in the 'wireshark' group is the safer "
                    "configuration.")
        else:
            self.dashboard.set_privilege_warning(remediation_text(report))
            self.start_btn.setEnabled(False)
        self.dashboard.priv_banner.action_clicked.connect(
            lambda: QMessageBox.information(
                self, "Capture privileges",
                remediation_text(check_privileges())))

    def _apply_retention_on_start(self) -> None:
        removed = self.captures_page.apply_retention()
        if removed:
            self.status_source.setText(
                "Retention removed %d old capture file(s)." % len(removed))
            self.captures_page.refresh()

    # ------------------------------------------------------------- interfaces

    def refresh_interfaces(self) -> None:
        current = self.iface_combo.currentData()
        self.iface_combo.clear()
        try:
            interfaces = list_interfaces(include_pseudo=False)
        except InterfaceError as exc:
            self.iface_combo.addItem("(no interfaces: %s)" % exc, None)
            self.start_btn.setEnabled(False)
            return
        self._iface_addr = {}
        for iface in interfaces:
            self.iface_combo.addItem(iface.label, iface.name)
            self._iface_addr[iface.name] = iface.primary_address
        self.interfaces_page.refresh()

        preferred = current or str(self.config.get("interface") or "")
        if preferred:
            idx = self.iface_combo.findData(preferred)
            if idx >= 0:
                self.iface_combo.setCurrentIndex(idx)

    def _capture_on(self, name: str) -> None:
        idx = self.iface_combo.findData(name)
        if idx < 0:
            self.refresh_interfaces()
            idx = self.iface_combo.findData(name)
        if idx >= 0:
            self.iface_combo.setCurrentIndex(idx)
        self.start_capture()

    # ------------------------------------------------------------------- BPF

    def _validate_bpf(self) -> None:
        expr = self.bpf_edit.text().strip()
        if not expr:
            self._bpf_ok = True
            self.bpf_edit.setProperty("invalid", False)
            self.bpf_edit.setToolTip("")
            self._repolish(self.bpf_edit)
            return
        self._bpf_validator.check(expr, self.iface_combo.currentData() or "")

    def _bpf_checked(self, expression: str, ok: bool, message: str) -> None:
        if expression != self.bpf_edit.text().strip():
            return                      # a newer edit superseded this check
        self._bpf_ok = ok
        self.bpf_edit.setProperty("invalid", not ok)
        self.bpf_edit.setToolTip(
            "" if ok else "libpcap rejected this filter: %s" % message)
        self._repolish(self.bpf_edit)

    @staticmethod
    def _repolish(widget) -> None:
        widget.style().unpolish(widget)
        widget.style().polish(widget)

    # --------------------------------------------------------------- capture

    def start_capture(self) -> None:
        if self.capture.is_running:
            return
        interface = self.iface_combo.currentData()
        if not interface:
            QMessageBox.warning(self, "No interface",
                                "Choose a capture interface first.")
            return

        bpf = self.bpf_edit.text().strip()
        if bpf:
            ok, message = validate_bpf(bpf, interface)
            if not ok:
                QMessageBox.critical(
                    self, "Invalid capture filter",
                    "libpcap rejected this capture filter:\n\n    %s\n\n%s"
                    % (bpf, message))
                return

        fmt = str(self.config.get("capture_format") or "pcapng")
        try:
            directory = self.config.ensure_capture_dir()
        except OSError as exc:
            QMessageBox.critical(self, "Capture directory",
                                 "Cannot create the capture directory:\n%s" % exc)
            return

        session = CaptureSession(
            interface=interface,
            bpf_filter=bpf,
            fmt=fmt,
            snaplen=int(self.config.get("snaplen")),
            promiscuous=bool(self.config.get("promiscuous")),
            output_path=directory / default_capture_name(interface, fmt),
            max_mb=int(self.config.get("max_pcap_mb")),
        )

        self._clear_analysis()
        self._set_source(session.output_path)
        if not self.capture.start(session):
            return
        self._mode = "live"
        self._discover_network_context()
        self.config.set("interface", interface)
        self.config.set("bpf_filter", bpf)

    def stop_capture(self) -> None:
        if not self.capture.is_running:
            return
        self.status_source.setText("Stopping capture…")
        self.capture.stop()

    def _capture_started(self, path: str) -> None:
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.act_start.setEnabled(False)
        self.act_stop.setEnabled(True)
        self.iface_combo.setEnabled(False)
        self.bpf_edit.setEnabled(False)
        name = self.iface_combo.currentData() or "?"
        bpf = self.bpf_edit.text().strip()
        self.live_page.set_source_hint(
            "Live capture on %s%s — writing to %s"
            % (name, "  (filter: %s)" % bpf if bpf else "", Path(path).name))
        self.console_page.capture_started(
            name, getattr(self, "_iface_addr", {}).get(name, ""), bpf)
        self._show_page("live")

    def _capture_stopped(self, reason: str) -> None:
        self._reset_capture_controls()
        self.status_source.setText(reason)
        self.console_page.capture_stopped(reason)
        self.captures_page.refresh()
        if self._source_path:
            self.live_page.set_source_hint(
                "Capture stopped — %s" % self._source_path.name)

    def _capture_failed(self, message: str) -> None:
        self._reset_capture_controls()
        self.status_source.setText(message.splitlines()[0] if message else "Capture failed")
        QMessageBox.critical(self, "Capture failed", message)
        self.captures_page.refresh()

    def _reset_capture_controls(self) -> None:
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.act_start.setEnabled(True)
        self.act_stop.setEnabled(False)
        self.iface_combo.setEnabled(True)
        self.bpf_edit.setEnabled(True)
        if self._mode == "live":
            self._mode = "idle"

    # ------------------------------------------------------------------ files

    def _choose_pcap(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Open capture file", str(Path.home()),
            "Capture files (*.pcap *.pcapng *.cap);;All files (*)")
        if path:
            self.open_capture_file(path)

    def open_capture_file(self, path: str) -> None:
        if self.capture.is_running:
            answer = QMessageBox.question(
                self, "Stop the running capture?",
                "A capture is running. Opening a file will stop it.\n\nStop "
                "the capture and open the file?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No)
            if answer != QMessageBox.StandardButton.Yes:
                return
            self.stop_capture()

        self._clear_analysis()
        self._set_source(Path(path))
        self._mode = "offline"
        self.pcap_page.import_started(path)
        self._show_page("pcap")
        self.importer.start(path)

    def _import_finished(self, count: int, path: str,
                         truncated: bool = False) -> None:
        # Let the analysis thread finish draining before reporting totals.
        QTimer.singleShot(400,
                          lambda: self._import_report(count, path, truncated))

    def _import_report(self, count: int, path: str,
                       truncated: bool = False) -> None:
        stats = self.analysis.stats()
        self.pcap_page.import_finished(count, path, stats, truncated)
        self.status_source.setText(
            "Opened %s — %s packets" % (Path(path).name,
                                             "{:,}".format(count)))
        self.live_page.set_source_hint("Offline file: %s" % path)
        self._refresh_current_page()

    def _import_failed(self, message: str) -> None:
        self._mode = "idle"
        self.pcap_page.import_failed(message)
        QMessageBox.critical(self, "Could not open capture file", message)

    def _export_current(self) -> None:
        if not self._source_path or not self._source_path.exists():
            QMessageBox.information(
                self, "Nothing to export",
                "Start a capture or open a file first.")
            return
        target, _ = QFileDialog.getSaveFileName(
            self, "Export capture", str(Path.home() / self._source_path.name),
            "Capture files (*.pcapng *.pcap);;All files (*)")
        if not target:
            return
        import shutil
        try:
            shutil.copy2(self._source_path, target)
        except OSError as exc:
            QMessageBox.critical(self, "Export failed", str(exc))
            return
        QMessageBox.information(
            self, "Exported",
            "Copied to:\n%s\n\nIf a capture is still running this is a "
            "snapshot of the file as it stands now." % target)

    def _set_source(self, path: Path | None) -> None:
        self._source_path = path
        self._reader = None
        self._reader_path = None

    def _current_reader(self):
        if self._source_path is None or not self._source_path.exists():
            return None
        if self._reader is not None and self._reader_path == self._source_path:
            return self._reader
        try:
            self._reader = RandomAccessCapture(self._source_path)
            self._reader_path = self._source_path
        except Exception:
            self._reader = None
        return self._reader

    # --------------------------------------------------------------- analysis

    def _clear_analysis(self) -> None:
        self.discovery.cancel()
        self._context_generation += 1
        self._context_busy = False
        self._context_next = 0
        self._network_next = 0
        self.topology_page.clear()
        self.monitor_page.reset()
        self.pcap_page.device_ip = None
        for page in (self.devices_page,):
            page.detail.clear_detail()
            page.model.clear()
            page.banner.setVisible(False)
        self.queue.reset()
        self.analysis.reset()
        self._live_marker = 0
        self._dns_marker = 0
        self._http_marker = 0
        self._rate_t0 = 0.0
        self._rate_n0 = 0
        self._captured_pps = 0.0
        self._capture_rate_history.clear()
        self.live_page.clear()
        for page in (self.connections_page, self.dns_page,
                     self.http_page, self.tls_page):
            page.model.clear()
            page.update_counts()

    def _clear_analysis_confirm(self) -> None:
        answer = QMessageBox.question(
            self, "Clear analysis",
            "Discard every packet, connection, host and protocol record "
            "currently held in memory?\n\nCapture files already written to "
            "disk are not touched.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No)
        if answer == QMessageBox.StandardButton.Yes:
            self._clear_analysis()

    def _settings_saved(self) -> None:
        self.timer.setInterval(min(1000, max(250, int(self.config.get("gui_refresh_ms")))))
        self._apply_harvest()
        self.captures_page.refresh()

    def _apply_harvest(self) -> None:
        """Turn credential harvesting on/off on the live engine to match the
        setting, so 'Watch device' and the Passwords page can read logins
        without a restart."""
        on = bool(self.config.get("harvest_credentials"))
        self.analysis.credentials.enabled = on
        if on:
            from netlab.analyze import http as httpmod
            httpmod.set_retain_sensitive(True)

    # ------------------------------------------------------------------ tick

    def _captured_packets(self, stats) -> int:
        """Packets the capture engine took off the wire.

        In live mode this comes from the capture reader, not from analysis:
        dumpcap keeps writing at full speed even when analysis falls behind,
        so the reader's count is the honest figure for what was captured.
        `idle` is a stopped live capture -- the reader still holds its final
        count, so it must keep reporting that, not drop to the (smaller)
        analysed total once the capture ends. Only a loaded file (`offline`),
        which has no reader, falls back to the analysed total.
        """
        if self._mode in ("live", "idle"):
            return max(self.capture.packets_read, stats.total_packets)
        return stats.total_packets

    def _update_capture_rate(self, captured: int) -> None:
        now = time.monotonic()
        if not self._rate_t0:
            self._rate_t0, self._rate_n0 = now, captured
            return
        elapsed = now - self._rate_t0
        if elapsed >= 1.0:
            self._captured_pps = max(0.0, (captured - self._rate_n0) / elapsed)
            self._capture_rate_history.append(self._captured_pps)
            self._rate_t0, self._rate_n0 = now, captured

    def _tick(self) -> None:
        self.monitor_page.refresh()
        now = time.monotonic()
        if self._mode == 'live' and now >= self._context_next:
            self._discover_network_context()
        if now >= self._network_next:
            # One bounded graph snapshot per batch, independent of packet rate.
            graph_time = None if self._mode != 'offline' else max((h.last_ts for h in self.analysis.hosts.snapshot()), default=time.time())
            network = self.analysis.network_view(graph_time)
            self.topology_page.update_snapshot(network)
            self.live_page.model.devices_by_address = {ip:d for d in network.devices for ip in d.addresses}
            self._network_next = now + .5
        cap = int(self.config.get("live_rows"))
        rows, self._live_marker = self.analysis.live.since(self._live_marker)
        if rows:
            self.live_page.append_rows(rows, cap)
            if self.stack.currentWidget() is self.live_page:
                self.live_page.update_counts()

        self._feed_console()

        if self._armed and self.helper.running and now >= self._status_next:
            self._status_next = now + 1.0
            self._helper_call("status")

        stats = self.analysis.stats()
        self._update_capture_rate(self._captured_packets(stats))
        self._refresh_current_page(stats)
        self._update_status(stats)

    def _feed_console(self) -> None:
        """Show live activity in the console regardless of the open page: the
        sites the traffic reaches (TLS SNI, HTTP host), and any cleartext
        credential read off the wire. Each site is shown once, so it does not
        flood."""
        new_tls, self._console_tls_marker = \
            self.analysis.tls_order.since(self._console_tls_marker)
        for sess in new_tls:
            sni = getattr(sess, "sni", None)
            if sni:
                self.console_page.note_site(sni, "HTTPS")
        new_http, self._console_http_marker = \
            self.analysis.http_txns.since(self._console_http_marker)
        for txn in new_http:
            host = getattr(txn, "host", None)
            if host:
                self.console_page.note_site(host, "HTTP")
        # Cleartext credentials read passively -- deduplicated by their key.
        for cred in self.analysis.credentials.snapshot():
            key = cred.key if hasattr(cred, "key") else id(cred)
            if key in self._console_cred_keys:
                continue
            self._console_cred_keys.add(key)
            self.console_page.feed("credential", {
                "proto": cred.proto, "server": cred.server,
                "port": cred.port, "context": cred.context,
                "user": cred.user, "password": cred.password,
                "hash": cred.hash, "hash_type": cred.hash_type})

    def _refresh_current_page(self, stats=None) -> None:
        page = self.stack.currentWidget()
        if page is self.creds_page:
            self._refresh_credentials()
        elif page is self.files_page:
            self.files_page.set_files(self._carved_files)
        if page is self.dashboard:
            stats = stats or self.analysis.stats()
            size = None
            if self._source_path and self._source_path.exists():
                try:
                    size = self._source_path.stat().st_size
                except OSError:
                    size = None
            state = {"live": "Capturing", "offline": "Offline file",
                     "idle": "Stopped"}.get(self._mode, "Stopped")
            label = self._source_path.name if self._source_path else ""
            captured = self._captured_packets(stats)
            self.dashboard.update_view(
                stats, state, self.iface_combo.currentData() or "",
                size, label, captured=captured,
                captured_pps=self._captured_pps,
                capture_rate_history=list(self._capture_rate_history))
        elif page is self.connections_page:
            self.connections_page.model.replace_items(self.analysis.flows.ordered())
            self.connections_page.update_counts()
        elif page in (self.devices_page,):
            page.refresh(self.analysis.device_view()[0])
            page.set_capture_status(self._mode, self.capture.is_running,
                                    self.iface_combo.currentData() or '',
                                    stats or self.analysis.stats(), self.timer.interval())
        elif page is self.dns_page:
            new, self._dns_marker = self.analysis.dns_events.since(self._dns_marker)
            if new:
                self.dns_page.model.append_items(
                    new, int(self.config.get("max_dns_events")))
            self.dns_page.update_counts()
        elif page is self.http_page:
            # HTTP rows are filled in later when the response arrives, so the
            # whole list is re-presented rather than only appended to.
            self.http_page.model.replace_items(self.analysis.http_txns.snapshot())
            self.http_page.update_counts()
        elif page is self.tls_page:
            self.tls_page.model.replace_items(self.analysis.tls_order.snapshot())
            self.tls_page.update_counts()
        elif page is self.live_page:
            self.live_page.update_counts()

    def _update_status(self, stats) -> None:
        if self._mode == "live" and self.capture.is_running:
            src = "Capturing on %s → %s" % (
                self.capture.session.interface if self.capture.session else "?",
                self._source_path.name if self._source_path else "?")
            self.status_source.setText(src)
        captured = self._captured_packets(stats)
        behind = captured - stats.total_packets
        packets_text = human_count(captured)
        if behind > 0:
            # Under overload these diverge; showing only one would misreport
            # either what was captured or what was actually analysed.
            packets_text += " captured / %s analysed" % human_count(
                stats.total_packets)
        self.status_counts.setText(
            "%s packets   \u00b7   %s   \u00b7   %.0f pkt/s   \u00b7   "
            "%s flows   \u00b7   %s hosts"
            % (packets_text, human_bytes(stats.total_bytes),
               self._captured_pps, human_count(stats.flows),
               human_count(stats.hosts)))
        self.toolbar_packets.setText(
            "Packets: %s (%s)" % (packets_text, human_bytes(stats.total_bytes)))
        if stats.queue_dropped:
            self.status_drops.setText(
                "  dropped before analysis: %s" % human_count(stats.queue_dropped))
            self.status_drops.setStyleSheet("color: %s;" % theme.AMBER)
        else:
            self.status_drops.setText("")

    # ----------------------------------------------------------------- about

    def _about(self) -> None:
        QMessageBox.about(
            self, "About NetLab",
            "<h3>NetLab %s</h3>"
            "<p>Network analysis and interception workbench for Kali Linux, "
            "with two halves.</p>"
            "<p><b>Passive:</b> capture by <code>dumpcap</code> (libpcap), then "
            "packet, flow, DNS, HTTP and TLS analysis and credential/hash "
            "extraction performed by NetLab on the real captured bytes. This "
            "half never transmits.</p>"
            "<p><b>Active (Interception):</b> ARP poisoning, SSL stripping, "
            "TLS interception with a local CA, DNS spoofing, rogue DHCP, "
            "traffic rewriting and NTLM relay. None of it runs without an "
            "engagement you name and confirm; every address is checked against "
            "that scope in the privileged helper, and the network is restored "
            "on disarm.</p>"
            "<p><b>NetLab does not decrypt a TLS session it is not "
            "terminating</b>, and SSL MITM announces itself to the victim's "
            "browser with a certificate warning it does not work around.</p>"
            % __version__)

    # ----------------------------------------------------------------- close


    # ------------------------------------------------------- interception

    def _interface_changed(self, *_args) -> None:
        name = self.iface_combo.currentData() or ""
        gateway = ""
        if name:
            try:
                from netlab.intercept.netcfg import default_gateway
                gateway = default_gateway(name)
            except Exception:
                gateway = ""
        self.mitm_page.set_interface(name, gateway)

    def _ensure_helper(self) -> bool:
        """Start the privileged helper if it is not already running."""
        if self.helper.running:
            return True
        self.status_source.setText(
            "Starting the NetLab helper - authorise the prompt to continue")
        return self.helper.start()

    def _helper_call(self, command: str, **args) -> int | None:
        if not self._ensure_helper():
            return None
        try:
            req_id = self.helper.call(command, **args)
        except helper_protocol.HelperError as exc:
            QMessageBox.warning(self, "Helper unavailable", str(exc))
            return None
        self._helper_requests[req_id] = command
        return req_id

    def _helper_ready(self, info: dict) -> None:
        self.mitm_page.set_helper_state(
            True, "")
        self.mitm_page.add_event("helper.ready", info)
        if not info.get("nftables"):
            self.mitm_page.banner.set_text(
                "nftables is not installed, so traffic cannot be redirected "
                "into the proxies. Install it with: sudo apt install nftables",
                "error")

    def _helper_failed(self, message: str) -> None:
        self.mitm_page.set_helper_state(False, message)
        QMessageBox.warning(self, "Cannot start the NetLab helper", message)

    def _helper_closed(self, reason: str) -> None:
        was_armed = self._armed
        self._armed = False
        self.mitm_page.set_armed(False)
        self.mitm_page.set_helper_state(False, reason)
        self.mitm_page.add_event("helper.closed", {"reason": reason})
        if was_armed:
            QMessageBox.warning(
                self, "Interception stopped",
                "The privileged helper exited, so interception stopped.\n\n"
                "%s\n\nThe helper restores ARP and forwarding before it "
                "exits, so the targets should be back on their normal path."
                % reason)

    def _helper_event(self, name: str, data: dict) -> None:
        if name == "credential":
            self._add_active_credential(data)
        elif name == "file.carved":
            self._carved_files.append(data)
            self.files_page.set_files(self._carved_files)
        elif name == "scan.host":
            self.mitm_page.add_host(data)
        elif name == "promisc.found":
            self.mitm_page.note_host(
                data.get("ip", ""),
                "promiscuous (%s confidence: %s)"
                % (data.get("confidence", "?"),
                   ", ".join(data.get("probes", []))))
        elif name == "armed":
            self._armed = True
            self.mitm_page.set_armed(True, data)
        elif name == "disarmed":
            self._armed = False
            self.mitm_page.set_armed(False)
        if name not in ("log", "http.exchange"):
            self.mitm_page.add_event(name, data)
            self.console_page.feed(name, data)
        elif name == "log" and data.get("level") in ("warn", "error"):
            self.mitm_page.add_event("log." + data["level"], data)
            self.console_page.feed("log." + data["level"], data)

    def _add_active_credential(self, data: dict) -> None:
        """A credential the proxies read, rendered like a passive one."""
        from netlab.analyze.creds import Credential
        cred = Credential(
            ts=data.get("ts") or time.time(),
            proto=data.get("proto", "HTTP"),
            client=data.get("client", ""), server=data.get("server", ""),
            port=int(data.get("port") or 0), user=data.get("user", ""),
            password=data.get("password", ""), hash=data.get("hash", ""),
            hash_type=data.get("hash_type", ""),
            hashcat_mode=int(data.get("hashcat_mode") or 0),
            context=data.get("context", ""),
            source=data.get("source", "intercept"),
            extra=data.get("extra") or {})
        self._active_credentials.append(cred)
        if len(self._active_credentials) > 5000:
            del self._active_credentials[:1000]

    def _helper_replied(self, req_id: int, ok: bool, payload) -> None:
        command = self._helper_requests.pop(req_id, "")
        if not ok:
            if command in ("status",):
                return
            self.mitm_page.add_event("error", {"command": command,
                                               "message": str(payload)})
            QMessageBox.warning(self, "Helper refused",
                                "%s failed:\n\n%s" % (command or "command",
                                                       payload))
            return
        if command == "arm":
            self._armed = True
            self.mitm_page.set_armed(True, payload)
            self._nav_to("mitm")
        elif command == "disarm":
            self._armed = False
            self.mitm_page.set_armed(False)
            self.mitm_page.add_event("disarmed", payload if isinstance(payload, dict) else {})
        elif command == "status" and isinstance(payload, dict):
            if payload.get("armed"):
                self._armed = True
                self.mitm_page.update_status(payload)
                self.rules_page.update_hits(
                    (payload.get("proxy") or {}).get("rules"),
                    (payload.get("dns") or {}).get("rules"))
        elif command == "arp_scan" and isinstance(payload, list):
            self.mitm_page.set_hosts(payload)
            self.mitm_page.add_event("scan.complete", {"hosts": len(payload)})
        elif command == "promisc_scan" and isinstance(payload, list):
            self.mitm_page.add_event("promisc.complete",
                                     {"found": len(payload)})
            if not payload:
                self.mitm_page.add_event(
                    "promisc.result",
                    {"detail": "no in-scope host answered a filtered probe"})
        elif command == "ca_info" and isinstance(payload, dict):
            self._show_ca_info(payload)

    def _arm_interception(self, engagement: dict, modules: dict) -> None:
        if not self._ensure_helper():
            return
        self.mitm_page.add_event("arming", {"targets": engagement.get("targets")})
        self._helper_call("arm", engagement=engagement, modules=modules,
                          ca_dir=str(self._ca_dir()))

    def _disarm_interception(self) -> None:
        if not self.helper.running:
            self._armed = False
            self.mitm_page.set_armed(False)
            return
        self._helper_call("disarm")

    def _helper_scan(self, cidr: str) -> None:
        interface = self.iface_combo.currentData() or ""
        if not interface:
            QMessageBox.information(self, "No interface",
                                    "Choose a capture interface first.")
            return
        self.mitm_page.add_event("scan.start",
                                 {"interface": interface, "cidr": cidr or "subnet"})
        self._helper_call("arp_scan", interface=interface, cidr=cidr)

    def _helper_promisc(self) -> None:
        if not self._armed:
            QMessageBox.information(
                self, "Not armed",
                "The sniffer probe runs inside an armed engagement, so it "
                "only ever probes hosts you declared in scope.")
            return
        self._helper_call("promisc_scan")

    def _push_rules(self, command: str, rules: list) -> None:
        if self._armed and self.helper.running:
            self._helper_call(command, rules=rules)

    def _ca_dir(self):
        from netlab.config import data_dir
        return data_dir() / "ca"

    def _export_ca(self) -> None:
        directory = self._ca_dir()
        try:
            from netlab.intercept.ca import CertificateAuthority
            info = CertificateAuthority(directory).ensure().info()
        except Exception as exc:
            QMessageBox.warning(self, "Cannot create the CA", str(exc))
            return
        self._show_ca_info(info)

    def _show_ca_info(self, info: dict) -> None:
        source = Path(info.get("path", ""))
        if not source.is_file():
            QMessageBox.warning(self, "No CA certificate",
                                "The interception CA has not been created.")
            return
        target, _ = QFileDialog.getSaveFileName(
            self, "Export the NetLab interception CA",
            str(Path.home() / "netlab-ca.crt"),
            "Certificates (*.crt *.pem);;All files (*)")
        if not target:
            return
        try:
            Path(target).write_bytes(source.read_bytes())
        except OSError as exc:
            QMessageBox.warning(self, "Export failed", str(exc))
            return
        QMessageBox.information(
            self, "CA exported",
            "Written to\n%s\n\nSHA-256 fingerprint:\n%s\n\n"
            "Install this on the device under test to intercept its TLS "
            "without a warning. Remove it when the engagement ends."
            % (target, info.get("fingerprint_sha256", "-")))

    def _all_credentials(self) -> list:
        """Every credential seen: passive harvest plus active MiTM."""
        rows = self.analysis.credentials.snapshot() + self._active_credentials
        rows.sort(key=lambda c: c.ts)
        return rows

    def _refresh_credentials(self) -> None:
        self.creds_page.set_credentials(self._all_credentials())

    def closeEvent(self, event) -> None:
        if self.capture.is_running:
            answer = QMessageBox.question(
                self, "Capture is running",
                "A capture is still running. Stop it and quit?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.Yes)
            if answer != QMessageBox.StandardButton.Yes:
                event.ignore()
                return
            self.capture.stop()
        if self._armed:
            answer = QMessageBox.question(
                self, "Interception is armed",
                "An engagement is still armed. Disarm it, restore the "
                "targets' ARP tables and quit?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.Yes)
            if answer != QMessageBox.StandardButton.Yes:
                event.ignore()
                return
        if self.helper.running:
            # Stopping the helper disarms it; closing the pipe would too, but
            # asking is faster and reports what was restored.
            self.status_source.setText("Disarming and restoring the network...")
            self.helper.stop()
        self.discovery.cancel()
        self.timer.stop()
        self.monitor_page.shutdown()
        self.importer.cancel()
        self.analysis.stop()
        self.config.save()
        event.accept()
