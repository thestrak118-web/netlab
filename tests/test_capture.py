"""Live capture against the real dumpcap backend.

These tests exercise the actual capture path, so they are skipped when
dumpcap is missing or lacks capture privileges rather than being faked.
"""

import os
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

from netlab.capture.interfaces import (InterfaceError, list_interfaces,
                                       validate_bpf)
from netlab.capture.privileges import check as check_privileges

HAVE_DUMPCAP = shutil.which("dumpcap") is not None
CAN_CAPTURE = HAVE_DUMPCAP and check_privileges().can_capture


@unittest.skipUnless(HAVE_DUMPCAP, "dumpcap is not installed")
class TestInterfaces(unittest.TestCase):
    def test_list_interfaces(self):
        interfaces = list_interfaces()
        self.assertTrue(interfaces)
        self.assertTrue(any(i.name == "lo" for i in interfaces))

    def test_loopback_is_classified(self):
        lo = next(i for i in list_interfaces() if i.name == "lo")
        self.assertTrue(lo.loopback)
        self.assertEqual(lo.kind, "loopback")
        self.assertIn("127.0.0.1", lo.addresses)

    def test_pseudo_devices_can_be_excluded(self):
        everything = list_interfaces(include_pseudo=True)
        real = list_interfaces(include_pseudo=False)
        self.assertLessEqual(len(real), len(everything))
        self.assertFalse(any(i.name == "any" for i in real))

    def test_valid_bpf_accepted(self):
        ok, message = validate_bpf("tcp port 443", "lo")
        self.assertTrue(ok, message)

    def test_invalid_bpf_rejected_with_a_reason(self):
        ok, message = validate_bpf("tcp porrt 443", "lo")
        self.assertFalse(ok)
        self.assertTrue(message)

    def test_empty_bpf_is_valid(self):
        self.assertEqual(validate_bpf(""), (True, ""))


@unittest.skipUnless(CAN_CAPTURE, "no capture privileges in this environment")
@unittest.skipUnless(os.environ.get("NETLAB_LIVE_TESTS", "1") != "0",
                     "live capture tests disabled")
class TestLiveCapture(unittest.TestCase):
    """Captures real loopback traffic and verifies it end to end."""

    def test_capture_writes_a_readable_file_with_the_expected_packets(self):
        from tests.qtapp import get_app

        from netlab.analyze.engine import AnalysisEngine
        from netlab.capture.engine import CaptureEngine, CaptureSession
        from netlab.config import Config
        from netlab.util.bounded import DropCountingQueue

        app = get_app()
        tmpdir = Path(tempfile.mkdtemp(prefix="netlab-test-"))
        out = tmpdir / "capture.pcapng"
        try:
            queue = DropCountingQueue(50000)
            analysis = AnalysisEngine(queue, Config())
            analysis.start()
            capture = CaptureEngine(queue)

            session = CaptureSession(interface="lo", bpf_filter="icmp",
                                     output_path=out, max_mb=16)
            self.assertTrue(capture.start(session))

            deadline = time.time() + 4
            while time.time() < deadline and not out.exists():
                app.processEvents()
                time.sleep(0.05)
            self.assertTrue(out.exists(), "dumpcap did not create the file")

            subprocess.run(["ping", "-c", "4", "-i", "0.2", "-W", "1",
                            "127.0.0.1"], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=20)
            deadline = time.time() + 5
            while time.time() < deadline and analysis.stats().total_packets < 8:
                app.processEvents()
                time.sleep(0.1)

            capture.stop()
            app.processEvents()
            analysis.stop()

            stats = analysis.stats()
            # 4 echo requests and 4 replies, all matching the BPF filter.
            self.assertGreaterEqual(stats.total_packets, 8)
            self.assertEqual(stats.queue_dropped, 0)
            self.assertEqual(stats.malformed, 0)

            protos = {row.proto for row in analysis.live.snapshot()}
            self.assertEqual(protos, {"ICMP"},
                             "the BPF filter should have excluded everything else")

            # The file itself must be a valid capture readable by our parser.
            from netlab.capture.pcapio import iter_capture_file
            packets = list(iter_capture_file(out))
            self.assertGreaterEqual(len(packets), 8)

            # ...and by an independent tool, if one is available.
            capinfos = shutil.which("capinfos")
            if capinfos:
                proc = subprocess.run([capinfos, "-c", str(out)],
                                      capture_output=True, text=True,
                                      timeout=30)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertIn("Number of packets", proc.stdout)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_bad_interface_reports_a_useful_error(self):
        from tests.qtapp import get_app

        from netlab.capture.engine import CaptureEngine, CaptureSession
        from netlab.util.bounded import DropCountingQueue

        app = get_app()
        tmpdir = Path(tempfile.mkdtemp(prefix="netlab-test-"))
        try:
            errors = []
            capture = CaptureEngine(DropCountingQueue(100))
            capture.failed.connect(errors.append)
            capture.start(CaptureSession(
                interface="netlab-does-not-exist0",
                output_path=tmpdir / "x.pcapng"))
            deadline = time.time() + 8
            while time.time() < deadline and not errors:
                app.processEvents()
                time.sleep(0.05)
            self.assertTrue(errors, "no failure was reported")
            self.assertIn("netlab-does-not-exist0", errors[0])
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
