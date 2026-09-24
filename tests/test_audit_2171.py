"""Regression tests for the six findings in the 2.17.1 external audit.

Each asserts the fixed behaviour, mirroring the audit's own reproduction so a
future change that reintroduces a finding fails here.
"""

import os
import unittest
from types import SimpleNamespace
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PySide6.QtWidgets import QApplication  # noqa: F401
    HAVE_QT = True
except ImportError:                                    # pragma: no cover
    HAVE_QT = False


@unittest.skipUnless(HAVE_QT, "PySide6 is not installed")
class TestAudit2171(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tests.qtapp import get_app
        cls.app = get_app()

    # ---- F2 / F3: PacketModel domain handling (no MainWindow needed) ----

    def _model_with_row(self):
        from netlab.analyze.engine import PacketRow
        from netlab.gui.models import PacketModel
        row = PacketRow(1, 1700000000.0, '10.0.0.2', '203.0.113.8', 'TCP',
                        1234, 443, 80, 'ACK', 0, 1)
        model = PacketModel()
        model.append_items([row])
        return model, row

    def test_f3_visible_domain_is_filterable(self):
        model, row = self._model_with_row()
        model.engine = SimpleNamespace(
            flow_for_packet=lambda r: SimpleNamespace(service='observed.example'),
            hosts=SimpleNamespace(get=lambda ip: None))
        self.assertEqual(model.cell(row, 5), 'observed.example')
        model.set_filter('host:observed.example')
        self.assertEqual(model.rowCount(), 1)   # was 0 before the fix

    def test_f2_ambiguous_peer_is_marked_not_asserted(self):
        model, row = self._model_with_row()
        model.engine = SimpleNamespace(
            flow_for_packet=lambda r: None,
            hosts=SimpleNamespace(get=lambda ip: SimpleNamespace(
                dns_names={'alpha.example', 'zeta.example'},
                sni_names=set(), http_names=set())))
        # Two names for the IP, none tied to the flow: shown with a +N marker,
        # not a single certain site.
        self.assertEqual(model.cell(row, 5), 'alpha.example +1')
        # ...but either real name still matches the filter.
        model.set_filter('host:zeta.example')
        self.assertEqual(model.rowCount(), 1)

    def test_f2_single_name_is_shown_plainly(self):
        model, row = self._model_with_row()
        model.engine = SimpleNamespace(
            flow_for_packet=lambda r: None,
            hosts=SimpleNamespace(get=lambda ip: SimpleNamespace(
                dns_names={'only.example'}, sni_names=set(), http_names=set())))
        self.assertEqual(model.cell(row, 5), 'only.example')

    # ---- F5: offline monitor clock (no MainWindow needed) ----

    def test_f5_offline_monitor_uses_capture_time(self):
        from netlab.analyze.engine import AnalysisEngine
        from netlab.analyze.monitor import snapshot_for_device
        from netlab.capture.pcapio import StreamingCaptureParser
        from netlab.config import Config
        from netlab.gui.pages.monitor import MonitorPage
        from netlab.util.bounded import DropCountingQueue
        from tests.helpers import pcapng_file
        from tests.test_engine import build_capture, CLIENT
        from tests.test_phase3 import context

        engine = AnalysisEngine(DropCountingQueue(1000), Config())
        engine.hosts.apply_context(context())
        engine.ingest_batch(StreamingCaptureParser().feed(
            pcapng_file(build_capture())))

        offline = MonitorPage(engine, source_provider=lambda: '/x.pcapng',
                              capture_running=lambda: False)
        offline.engine = engine
        now = offline._snapshot_now()
        self.assertIsNotNone(now)               # capture time, not wall clock
        snap = snapshot_for_device(engine, CLIENT, now)
        self.assertGreater(snap.counts['active_connections'], 0)

        live = MonitorPage(engine, source_provider=lambda: '',
                           capture_running=lambda: True)
        live.engine = engine
        self.assertIsNone(live._snapshot_now())  # wall clock in live mode

    # ---- F1 / F4 / F6: need a MainWindow ----

    def _window(self):
        from netlab.gui.main_window import MainWindow
        w = MainWindow()
        w.timer.stop()
        w.analysis.stop()
        return w

    def test_f1_stopped_capture_keeps_the_captured_count(self):
        from netlab.analyze.engine import Stats
        w = self._window()
        try:
            stats = Stats(total_packets=10, queue_dropped=90)
            w.capture._packets_read = 100
            w._mode = 'live'
            self.assertEqual(w._captured_packets(stats), 100)
            w._reset_capture_controls()          # live -> idle
            # The captured figure must not drop to the analysed total.
            self.assertEqual(w._captured_packets(stats), 100)
        finally:
            w.close()

    def test_f4_clicking_current_tab_returns_from_drilldown(self):
        w = self._window()
        try:
            w._show_page('devices')
            w._show_page('pcap')                 # ungrouped drill-down
            self.assertIs(w.stack.currentWidget(), w.pcap_page)
            # Clicking the already-selected page tab must bring it back.
            w.page_bar.tabBarClicked.emit(w.page_bar.currentIndex())
            self.assertIs(w.stack.currentWidget(), w.devices_page)
        finally:
            w.close()

    def test_f6_about_describes_the_active_half(self):
        w = self._window()
        try:
            captured = []
            with patch('netlab.gui.main_window.QMessageBox.about',
                       side_effect=lambda *a: captured.append(a[2])):
                w._about()
            text = captured[0]
            self.assertNotIn('implements no active', text)
            self.assertIn('Interception', text)
        finally:
            w.close()


if __name__ == "__main__":
    unittest.main()
