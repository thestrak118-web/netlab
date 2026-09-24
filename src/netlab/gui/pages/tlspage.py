"""TLS: handshake metadata for encrypted sessions."""

from __future__ import annotations

from PySide6.QtCore import Signal

from netlab.gui.models import TlsModel
from netlab.gui.pages.detail import DetailPane, kv
from netlab.gui.widgets import TablePage
from netlab.util.format import human_bytes, ts_full


class TlsPage(TablePage):
    show_packets = Signal(str)

    def __init__(self, parent=None) -> None:
        super().__init__(
            "TLS",
            "Handshake metadata observed on the wire. NetLab does not decrypt "
            "TLS, does not intercept certificates and does not strip TLS. "
            "The application payload of every session listed here is "
            "encrypted and was not read.",
            TlsModel(), parent)
        self.attach_detail(DetailPane("Select a session to see its detail."))
        self.row_selected.connect(self._show_detail)
        self.row_activated.connect(
            lambda s: self.show_packets.emit("ip:%s ip:%s port:%s" % (
                s.client, s.server, s.server_port or "")))

    def _show_detail(self, s) -> None:
        version = s.negotiated_version or s.server_version or s.client_version
        lines = [
            "%s:%s → %s:%s" % (s.client, s.client_port, s.server,
                                    s.server_port),
            "",
            "Observed on the wire",
            kv("First seen", ts_full(s.ts)),
            kv("SNI (client asked for)", s.sni),
            kv("Client offered", s.client_version),
            kv("Negotiated version", version),
            kv("Cipher suite", s.cipher_suite),
            kv("ALPN offered", ", ".join(s.alpn_offered) or None),
            kv("ALPN selected", s.alpn_selected),
            kv("Cipher suites offered", s.cipher_count_offered),
            kv("ClientHello seen", "yes" if s.saw_client_hello else "no"),
            kv("ServerHello seen", "yes" if s.saw_server_hello else "no"),
            kv("Alert seen", "yes" if s.saw_alert else "no"),
            "",
            "Certificate",
            kv("Availability", s.cert_availability),
            kv("Subject CN", s.cert_subject_cn),
            kv("Issuer CN", s.cert_issuer_cn),
            kv("Valid from", s.cert_not_before),
            kv("Valid until", s.cert_not_after),
            kv("Chain length", s.cert_chain_len),
            "",
            "Encrypted payload",
            kv("Application data", "%s in %d records" % (
                human_bytes(s.app_data_bytes), s.app_data_records)),
        ]
        if s.cert_subject_cn:
            lines += ["", "The certificate was sent before encryption began "
                          "(TLS 1.2 or earlier), so it could be read "
                          "passively. It was observed, not intercepted."]
        elif version == "TLS 1.3":
            lines += ["", "TLS 1.3 encrypts the certificate, so no "
                          "certificate fields are available to a passive "
                          "observer. They are left blank rather than guessed."]
        if s.notes:
            lines += ["", "Notes:"] + ["  - " + n for n in s.notes]
        lines += ["", "The payload of this session was NOT decrypted. Only the "
                      "metadata above was visible."]
        self.detail.show_lines(lines)
