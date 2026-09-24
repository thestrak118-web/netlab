"""Packet accounting must always close.

Under overload the capture reader outruns analysis. What must never happen is
a packet vanishing without being counted somewhere, or the UI reporting the
analysed rate under a label that means the capture rate.
"""

import unittest

from netlab.analyze.engine import AnalysisEngine
from netlab.capture.pcapio import StreamingCaptureParser
from netlab.config import Config
from netlab.util.bounded import DropCountingQueue
from tests.helpers import eth_ip_tcp, pcapng_file


def build_stream(n: int) -> bytes:
    frames = [(1_700_000_000.0 + i * 0.0001, 74,
               eth_ip_tcp(sport=10000 + (i % 5000))) for i in range(n)]
    return pcapng_file(frames)


class TestAccounting(unittest.TestCase):
    def test_analysed_plus_dropped_equals_captured(self):
        """The arithmetic must close exactly, however small the queue."""
        total = 5000
        blob = build_stream(total)

        queue = DropCountingQueue(50)          # far too small on purpose
        engine = AnalysisEngine(queue, Config())

        parser = StreamingCaptureParser()
        captured = 0
        for packet in parser.feed(blob):
            captured += 1
            queue.put(packet)                  # drops silently return False

        self.assertEqual(captured, total)
        # Drain whatever survived the queue.
        while True:
            batch = queue.get_batch(1000, timeout=0.01)
            if not batch:
                break
            engine.ingest_batch(batch)

        stats = engine.stats()
        self.assertGreater(stats.queue_dropped, 0,
                           "the queue should have overflowed")
        self.assertEqual(stats.total_packets + stats.queue_dropped, captured,
                         "packets went missing without being counted")

    def test_no_drops_when_the_queue_is_large_enough(self):
        total = 2000
        blob = build_stream(total)
        queue = DropCountingQueue(10000)
        engine = AnalysisEngine(queue, Config())
        packets = StreamingCaptureParser().feed(blob)
        for packet in packets:
            self.assertTrue(queue.put(packet))
        engine.ingest_batch(queue.get_batch(total, timeout=0.01))
        stats = engine.stats()
        self.assertEqual(stats.queue_dropped, 0)
        self.assertEqual(stats.total_packets, total)

    def test_dashboard_reports_captured_rate_not_analysed_rate(self):
        """Regression: the packets/sec card showed the analysed rate, which
        badly understates real traffic whenever analysis is behind."""
        from tests.qtapp import get_app
        from netlab.gui.pages.dashboard import DashboardPage

        get_app()
        page = DashboardPage()
        engine = AnalysisEngine(DropCountingQueue(100), Config())
        stats = engine.stats()
        stats.total_packets = 1000
        stats.packets_per_sec = 900.0
        stats.queue_dropped = 9000

        page.update_view(stats, "Capturing", "lo", 1234, "x.pcapng",
                         captured=10000, captured_pps=9500.0)

        self.assertEqual(page.cards["pps"]._value.text(), "9500")
        note = page.cards["packets"]._note.text()
        self.assertIn("10,000 captured", note)
        self.assertIn("1,000 analysed", note)
        # isVisible() is False while the parent window is not shown, so ask
        # whether the banner would be visible within its parent instead.
        self.assertTrue(page.drop_banner.isVisibleTo(page))
        self.assertIn("9,000", page.drop_banner._label.text())
        self.assertIn("capture on disk is still complete",
                      page.drop_banner._label.text())

    def test_dashboard_falls_back_to_analysed_when_offline(self):
        from tests.qtapp import get_app
        from netlab.gui.pages.dashboard import DashboardPage

        get_app()
        page = DashboardPage()
        stats = AnalysisEngine(DropCountingQueue(10), Config()).stats()
        stats.total_packets = 500
        stats.packets_per_sec = 120.0
        page.update_view(stats, "Offline file", "", 99, "f.pcapng")
        self.assertEqual(page.cards["pps"]._value.text(), "120")
        self.assertIn("500 exact", page.cards["packets"]._note.text())
        self.assertFalse(page.drop_banner.isVisibleTo(page))


if __name__ == "__main__":
    unittest.main()
