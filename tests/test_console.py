"""The KONSOL page: real events in, formatted console lines out.

Every line must trace to an event field -- these tests feed the page the same
event shapes the helper emits and assert the text reflects them, and that an
event with a missing field prints what was there without inventing the rest.
"""

import os
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PySide6.QtWidgets import QApplication  # noqa: F401
    HAVE_QT = True
except ImportError:                                    # pragma: no cover
    HAVE_QT = False


@unittest.skipUnless(HAVE_QT, "PySide6 is not installed")
class TestConsolePage(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tests.qtapp import get_app
        cls.app = get_app()

    def _page(self):
        from netlab.gui.pages.console import ConsolePage
        return ConsolePage()

    def test_capture_line(self):
        page = self._page()
        page.capture_started("wlan0", "192.168.1.141", "")
        text = page.view.toPlainText()
        self.assertIn("Starting capturing on wlan0", text)
        self.assertIn("192.168.1.141", text)
        self.assertIn("Pcap filter: [OK]", text)

    def test_armed_writes_gateway_and_poison_lines(self):
        page = self._page()
        page.feed("armed", {
            "engagement": {"interface": "wlan0"},
            "interface": {"interface": "wlan0", "ipv4": "192.168.1.141"},
            "gateway": "192.168.1.1", "gateway_mac": "88:ac:c0:5c:b7:30",
            "modules": ["arp-poison", "sslstrip"],
            "targets": {"192.168.1.169": "a8:96:09:74:16:5c",
                        "192.168.1.183": "4e:a5:db:3b:c3:c8"},
        })
        text = page.view.toPlainText()
        self.assertIn("Gateway: 192.168.1.1", text)
        self.assertIn("88:ac:c0:5c:b7:30", text)
        self.assertIn("Starting poisoning 192.168.1.169", text)
        self.assertIn("Starting poisoning 192.168.1.183", text)

    def test_armed_is_noted_once(self):
        page = self._page()
        payload = {"engagement": {"interface": "eth0"}, "gateway": "10.0.0.1",
                   "targets": {"10.0.0.5": "aa:bb:cc:dd:ee:ff"}}
        page.feed("armed", payload)
        page.feed("armed", payload)      # a duplicate event must not re-log
        text = page.view.toPlainText()
        self.assertEqual(text.count("Starting poisoning 10.0.0.5"), 1)

    def test_http_credential_block(self):
        page = self._page()
        page.feed("credential", {
            "proto": "HTTP", "server": "163.182.231.244", "port": 80,
            "context": "vbsca.ca/login/login_results.asp",
            "user": "admin", "password": "adada"})
        text = page.view.toPlainText()
        self.assertIn("HTTP Authorization intercepted", text)
        self.assertIn("Username=admin", text)
        self.assertIn("Password=adada", text)

    def test_missing_field_is_not_invented(self):
        page = self._page()
        # No password observed -- the line must be absent, not blank-filled.
        page.feed("credential", {"proto": "FTP", "server": "10.0.0.9",
                                 "user": "bob"})
        text = page.view.toPlainText()
        self.assertIn("FTP credential intercepted", text)
        self.assertIn("Username=bob", text)
        self.assertNotIn("Password=", text)

    def test_disarm_resets_arm_state(self):
        page = self._page()
        payload = {"engagement": {"interface": "eth0"}, "gateway": "10.0.0.1",
                   "targets": {"10.0.0.5": "aa:bb:cc:dd:ee:ff"}}
        page.feed("armed", payload)
        page.feed("disarmed", {})
        page.feed("armed", payload)      # a second engagement logs again
        text = page.view.toPlainText()
        self.assertEqual(text.count("Starting poisoning 10.0.0.5"), 2)
        self.assertIn("network restored", text)

    def test_strip_host_deduplicated(self):
        page = self._page()
        page.feed("strip.host", {"host": "example.com"})
        page.feed("strip.host", {"host": "example.com"})
        page.feed("strip.host", {"host": "other.com"})
        text = page.view.toPlainText()
        self.assertEqual(text.count("SSL strip   example.com"), 1)
        self.assertIn("SSL strip   other.com", text)


if __name__ == "__main__":
    unittest.main()
