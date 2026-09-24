"""A capture cut short mid-packet is read as far as it goes, and flagged.

BUG-01 of the 2.17.1 GUI QA: NetLab read 58 packets from a file cut off in the
middle of the 59th and reported a clean, complete import. capinfos, by
contrast, says the file was cut short. These tests pin down that the reader
now reports the truncation and the viewer surfaces it.
"""

import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from netlab.capture.pcapio import read_capture_file

FIXTURE = Path(__file__).parent / "fixtures" / "http_fragmented.pcapng"
# The exact cut the QA used: 6500 of the fixture's 6716 bytes, mid-packet.
CUT_BYTES = 6500

try:
    from PySide6.QtWidgets import QApplication  # noqa: F401
    HAVE_QT = True
except ImportError:                                    # pragma: no cover
    HAVE_QT = False


def _truncated_copy(dir_):
    path = Path(dir_) / "truncated.pcapng"
    path.write_bytes(FIXTURE.read_bytes()[:CUT_BYTES])
    return path


@unittest.skipUnless(FIXTURE.is_file(), "fixture missing")
class TestTruncationDetection(unittest.TestCase):
    def test_intact_file_is_not_truncated(self):
        packets, truncated = read_capture_file(FIXTURE)
        self.assertFalse(truncated)
        self.assertEqual(len(packets), 60)

    def test_cut_file_is_truncated_but_still_readable(self):
        with tempfile.TemporaryDirectory() as d:
            cut = _truncated_copy(d)
            packets, truncated = read_capture_file(cut)
            self.assertTrue(truncated)
            # The complete packets before the cut are still recovered -- the
            # same 58 capinfos reports.
            self.assertEqual(len(packets), 58)


@unittest.skipUnless(HAVE_QT, "PySide6 is not installed")
class TestViewerFlagsTruncation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tests.qtapp import get_app
        cls.app = get_app()

    def _page_and_stats(self, cut):
        from netlab.analyze.engine import AnalysisEngine
        from netlab.capture.pcapio import iter_capture_file
        from netlab.config import Config
        from netlab.gui.pages.pcapviewer import PcapViewerPage
        from netlab.util.bounded import DropCountingQueue
        engine = AnalysisEngine(DropCountingQueue(50000), Config())
        engine.ingest_batch(list(iter_capture_file(cut)))
        return PcapViewerPage(), engine.stats()

    def test_truncated_import_is_surfaced(self):
        with tempfile.TemporaryDirectory() as d:
            cut = _truncated_copy(d)
            page, stats = self._page_and_stats(cut)
            page.import_finished(58, str(cut), stats, truncated=True)
            detail = page.detail.toPlainText().lower()
            self.assertIn("truncated", detail)
            self.assertIn("mid-packet", detail)
            # The banner carries the warning styling, not the calm "info" one.
            self.assertEqual(page.banner.objectName(), "Banner")

    def test_intact_import_is_not_flagged(self):
        page, stats = self._page_and_stats(FIXTURE)
        page.import_finished(60, str(FIXTURE), stats, truncated=False)
        detail = page.detail.toPlainText().lower()
        self.assertNotIn("truncated", detail)
        self.assertIn("every packet in the file reached the analyser", detail)


if __name__ == "__main__":
    unittest.main()
