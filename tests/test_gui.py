"""GUI smoke tests.

Run against the offscreen Qt platform so they work without a display.
"""

import os
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PySide6.QtWidgets import QApplication
    HAVE_QT = True
except ImportError:                                    # pragma: no cover
    HAVE_QT = False


@unittest.skipUnless(HAVE_QT, "PySide6 is not installed")
class TestGui(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tests.qtapp import get_app
        cls.app = get_app()

    def test_every_page_constructs(self):
        from netlab.gui.main_window import PAGES, MainWindow
        window = MainWindow()
        try:
            self.assertEqual(window.stack.count(), len(PAGES))
            # Most pages sit under a mode tab; a few (settings, interfaces) are
            # reachable only from the menu. Every page must still open.
            self.assertTrue(set(window._page_group).issubset({k for _l, k in PAGES}))
            for _label, key in PAGES:
                window._show_page(key)
                self.app.processEvents()
                self.assertIsNotNone(window.stack.currentWidget())
                self.assertIs(window.stack.currentWidget(),
                              window.stack.widget(window._page_index[key]))
        finally:
            window.analysis.stop()
            window.close()

    def test_models_render_every_column(self):
        from PySide6.QtCore import Qt

        from netlab.analyze.engine import AnalysisEngine
        from netlab.capture.pcapio import iter_capture_file
        from netlab.config import Config
        from netlab.gui.models import (DnsModel, FlowModel, HostModel,
                                       HttpModel, PacketModel, TlsModel)
        from netlab.util.bounded import DropCountingQueue
        import tempfile
        from pathlib import Path
        from tests.helpers import pcapng_file
        from tests.test_engine import build_capture

        with tempfile.NamedTemporaryFile(suffix=".pcapng", delete=False) as fh:
            fh.write(pcapng_file(build_capture()))
            path = Path(fh.name)
        try:
            engine = AnalysisEngine(DropCountingQueue(10000), Config())
            engine.ingest_batch(list(iter_capture_file(path)))

            cases = [
                (PacketModel(), engine.live.snapshot()),
                (FlowModel(), engine.flows.ordered()),
                (HostModel(), engine.hosts.ordered()),
                (DnsModel(), engine.dns_events.snapshot()),
                (HttpModel(), engine.http_txns.snapshot()),
                (TlsModel(), engine.tls_order.snapshot()),
            ]
            for model, items in cases:
                model.replace_items(items)
                self.assertGreater(model.rowCount(), 0, type(model).__name__)
                for row in range(model.rowCount()):
                    for col in range(model.columnCount()):
                        index = model.index(row, col)
                        value = model.data(index, Qt.ItemDataRole.DisplayRole)
                        self.assertIsInstance(
                            value, str,
                            "%s column %d returned %r"
                            % (type(model).__name__, col, value))
        finally:
            path.unlink(missing_ok=True)

    def test_model_filtering(self):
        from netlab.analyze.engine import PacketRow
        from netlab.gui.models import PacketModel

        rows = [
            PacketRow(1, 1.0, "10.0.0.1", "10.0.0.2", "TCP", 1234, 443,
                      60, "a", 0, 1, "TLS"),
            PacketRow(2, 2.0, "10.0.0.3", "10.0.0.4", "UDP", 5353, 5353,
                      80, "b", 0, 1, "mDNS"),
        ]
        model = PacketModel()
        model.append_items(rows)
        self.assertEqual(model.rowCount(), 2)
        model.set_filter("proto:tcp")
        self.assertEqual(model.rowCount(), 1)
        model.set_filter("port:5353")
        self.assertEqual(model.rowCount(), 1)
        model.set_filter("")
        self.assertEqual(model.rowCount(), 2)

    def test_packet_model_respects_its_row_cap(self):
        from netlab.analyze.engine import PacketRow
        from netlab.gui.models import PacketModel

        model = PacketModel()
        for i in range(500):
            model.append_items([PacketRow(i, float(i), "1.1.1.1", "2.2.2.2",
                                          "TCP", 1, 2, 60, "x", 0, 1)], cap=100)
        self.assertLessEqual(model.rowCount(), 100)


if __name__ == "__main__":
    unittest.main()
