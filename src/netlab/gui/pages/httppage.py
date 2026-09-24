"""HTTP: cleartext HTTP/1.x metadata."""

from __future__ import annotations

from PySide6.QtCore import Signal

from netlab.gui.models import HttpModel
from netlab.gui.pages.detail import DetailPane, kv
from netlab.gui.widgets import TablePage
from netlab.util.format import ts_full


class HttpPage(TablePage):
    show_packets = Signal(str)

    def __init__(self, parent=None) -> None:
        super().__init__(
            "HTTP",
            "Cleartext HTTP/1.x only. HTTPS is not decrypted and never appears "
            "here - encrypted sessions are listed on the TLS page instead. "
            "Credential-bearing headers are recorded as present but their "
            "values are deliberately not stored.",
            HttpModel(), parent)
        self.attach_detail(DetailPane("Select a transaction to see its detail."))
        self.row_selected.connect(self._show_detail)
        self.row_activated.connect(
            lambda t: self.show_packets.emit("ip:%s ip:%s port:%s" % (
                t.client, t.server, t.server_port or "")))

    def _show_detail(self, t) -> None:
        lines = [
            "%s %s" % (t.method or "?", t.url or "?"),
            "",
            "Request",
            kv("Time", ts_full(t.ts)),
            kv("Method", t.method),
            kv("Host", t.host),
            kv("Path", t.path),
            kv("HTTP version", t.version),
            kv("User-Agent", t.user_agent),
            kv("Referer", t.referer),
            kv("Content-Type", t.req_content_type),
            kv("Content-Length", t.req_content_length),
            kv("Client", "%s:%s" % (t.client, t.client_port)),
            kv("Server", "%s:%s" % (t.server, t.server_port)),
            "",
            "Response",
        ]
        if t.status is None:
            lines.append("  No response was observed for this request.")
        else:
            lines += [
                kv("Status", "%s %s" % (t.status, t.reason or "")),
                kv("Content-Type", t.content_type),
                kv("Content-Length", t.content_length),
                kv("Server", t.server_header),
                kv("Location", t.location),
                kv("Time taken", "%.0f ms" % t.duration_ms
                   if t.duration_ms is not None else None),
            ]
        flags = []
        if t.req_has_auth:
            flags.append("request carried an Authorization header")
        if t.req_has_cookie:
            flags.append("request carried a Cookie header")
        if t.resp_has_set_cookie:
            flags.append("response carried a Set-Cookie header")
        if flags:
            lines += ["", "Credential-bearing headers present (values not "
                          "recorded by design):"]
            lines += ["  - " + f for f in flags]
        if t.notes:
            lines += ["", "Notes:"] + ["  - " + n for n in t.notes]
        lines += ["", "This traffic was sent in the clear and was readable by "
                      "anyone on the path."]
        self.detail.show_lines(lines)
