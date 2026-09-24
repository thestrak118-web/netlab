"""DNS: queries and answers extracted from observed traffic."""

from __future__ import annotations

from PySide6.QtCore import Signal

from netlab.gui.models import DnsModel
from netlab.gui.pages.detail import DetailPane, kv
from netlab.gui.widgets import TablePage
from netlab.util.format import ts_full


class DnsPage(TablePage):
    show_packets = Signal(str)

    def __init__(self, parent=None) -> None:
        super().__init__(
            "DNS",
            "DNS, mDNS and LLMNR messages parsed from the captured packets. "
            "Encrypted resolvers (DoH/DoT) are not visible here - their "
            "queries appear as TLS or HTTPS instead.",
            DnsModel(), parent)
        self.attach_detail(DetailPane("Select a DNS message to see its detail."))
        self.row_selected.connect(self._show_detail)
        self.row_activated.connect(
            lambda e: self.show_packets.emit("ip:%s ip:%s" % (e.src, e.dst)))

    def _show_detail(self, e) -> None:
        lines = [
            "%s %s  (transaction 0x%04x)" % (e.protocol, e.kind, e.txid),
            "",
            kv("Time", ts_full(e.ts)),
            kv("Question", e.qname),
            kv("Type", e.qtype),
            kv("Transport", "%s  %s:%s -> %s:%s" % (
                e.transport, e.src, e.sport, e.dst, e.dport)),
        ]
        if e.kind == "response":
            lines.append(kv("Result code", e.rcode))
            lines += ["", "Answers"]
            if e.answers:
                for a in e.answers:
                    lines.append("  %-40s %-8s TTL %-7d %s" % (
                        a.name, a.rtype, a.ttl, a.value))
            else:
                lines.append("  (none returned)")
            if e.resolved_ips:
                lines += ["", kv("Addresses resolved", ", ".join(e.resolved_ips))]
        self.detail.show_lines(lines)
