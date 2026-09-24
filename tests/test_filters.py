"""Display filter compilation and matching."""

import unittest

from netlab.gui.filters import compile_filter


class TestDisplayFilter(unittest.TestCase):
    FIELDS = {"src": "10.0.0.5", "dst": "1.1.1.1", "proto": "TLS",
              "sport": 51000, "dport": 443, "host": "example.com"}
    TEXT = "10.0.0.5 1.1.1.1 TLS 443 example.com"

    def match(self, expr):
        return compile_filter(expr).matches(self.FIELDS, self.TEXT)

    def test_empty_matches_everything(self):
        self.assertTrue(compile_filter("").is_empty)
        self.assertTrue(self.match(""))

    def test_plain_substring(self):
        self.assertTrue(self.match("10.0.0.5"))
        self.assertFalse(self.match("10.0.0.6"))

    def test_field_match(self):
        self.assertTrue(self.match("src:10.0.0.5"))
        self.assertFalse(self.match("src:1.1.1.1"))
        self.assertTrue(self.match("ip:1.1.1.1"))

    def test_port_alias_checks_both_ends(self):
        self.assertTrue(self.match("port:443"))
        self.assertTrue(self.match("port:51000"))
        self.assertFalse(self.match("port:22"))

    def test_alternatives(self):
        self.assertTrue(self.match("proto:tls|http"))
        self.assertFalse(self.match("proto:dns|arp"))

    def test_negation(self):
        self.assertFalse(self.match("-proto:tls"))
        self.assertTrue(self.match("-proto:arp"))

    def test_terms_are_anded(self):
        self.assertTrue(self.match("ip:10.0.0.5 port:443"))
        self.assertFalse(self.match("ip:10.0.0.5 port:22"))

    def test_quoted_value(self):
        self.assertTrue(self.match('host:"example.com"'))

    def test_case_insensitive(self):
        self.assertTrue(self.match("PROTO:tls"))
        self.assertTrue(self.match("proto:TLS"))

    def test_missing_field_does_not_match(self):
        self.assertFalse(self.match("cipher:aes"))


if __name__ == "__main__":
    unittest.main()
