"""Connections: one row per bidirectional conversation."""

from __future__ import annotations

from PySide6.QtCore import Signal

from netlab.gui.models import FlowModel
from netlab.gui.pages.detail import DetailPane, kv
from netlab.gui.widgets import TablePage
from netlab.util.format import duration, human_bytes, ts_full, ts_time


class ConnectionsPage(TablePage):
    show_packets = Signal(str)          # display filter for Live Traffic

    def __init__(self, parent=None) -> None:
        super().__init__(
            "Connections",
            "Conversations correlated from observed packets. Double-click a "
            "row to see the packets that belong to it.",
            FlowModel(), parent)
        self.attach_detail(DetailPane("Select a connection to see its detail."),
                           sizes=(430, 380))
        self.row_selected.connect(self._show_detail)
        self.row_activated.connect(self._drill_down)
        self.engine = None

    def set_engine(self, engine) -> None:
        self.engine = engine

    def _drill_down(self, flow) -> None:
        self.show_packets.emit("ip:%s ip:%s port:%s" % (
            flow.client, flow.server, flow.server_port or ""))

    def _show_detail(self, f) -> None:
        lines = [
            "%s  %s:%s  \u2194  %s:%s" % (f.proto, f.client, f.client_port,
                                          f.server, f.server_port),
            "",
            "Connection",
            kv("State", f.state),
            kv("Application", f.app_proto),
            kv("Service / SNI", f.service),
            kv("First seen", ts_full(f.first_ts)),
            kv("Last seen", ts_full(f.last_ts)),
            kv("Duration", duration(f.duration)),
            "",
            "Direction totals",
            kv("Packets total", "{:,}".format(f.packets)),
            kv("  client -> server", "{:,} packets, {}".format(
                f.pkts_c2s, human_bytes(f.bytes_c2s))),
            kv("  server -> client", "{:,} packets, {}".format(
                f.pkts_s2c, human_bytes(f.bytes_s2c))),
            kv("Bytes total", human_bytes(f.bytes)),
        ]
        if f.proto == "TCP":
            lines += ["", "TCP handshake observed",
                      kv("  SYN", "yes" if f.saw_syn else "not observed"),
                      kv("  SYN/ACK", "yes" if f.saw_synack else "not observed"),
                      kv("  FIN", "yes" if f.saw_fin else "not observed"),
                      kv("  RST", "yes" if f.saw_rst else "not observed")]

        relations = None
        if self.engine is not None:
            relations = self.engine.relations_for_flow(f)

        if relations is not None:
            lines += self._stream_lines(relations.get("summary"), f)
            lines += self._http_lines(relations.get("http"))
            lines += self._tls_lines(relations.get("tls"))
            lines += self._dns_lines(relations.get("dns"))
            packets = relations.get("packets") or []
            lines += ["", "Packets",
                      kv("Retained in the live view", "{:,}".format(len(packets)))]
            if packets:
                lines.append("  Double-click this row to list them in Live "
                             "Traffic.")
        if f.encrypted:
            lines += ["", "This conversation is TLS-encrypted. NetLab reads "
                          "handshake metadata only and never decrypts the "
                          "application payload."]
        self.detail.show_lines(lines)

    def _stream_lines(self, summary, flow) -> list:
        if summary is None:
            return []
        lines = ["", "TCP reassembly" + ("" if summary.live
                                         else "  (connection finished; "
                                              "buffers released)")]
        for d in summary.directions:
            lines.append("  %s:%s \u2192" % (d.endpoint[0], d.endpoint[1]))
            lines.append(kv("    Bytes reassembled",
                            "{:,}".format(d.bytes_delivered), 24))
            lines.append(kv("    Segments", "{:,}".format(d.segments), 24))
            lines.append(kv("    Retransmissions",
                            "{:,}".format(d.retransmissions), 24))
            lines.append(kv("    Out of order", "{:,}".format(d.out_of_order), 24))
            lines.append(kv("    Overlapping", "{:,}".format(d.overlaps), 24))
            if d.gaps:
                lines.append(kv("    Missing bytes", "%s in %d gap(s) - "
                                "never reconstructed"
                                % ("{:,}".format(d.gap_bytes), d.gaps), 24))
            else:
                lines.append(kv("    Missing bytes", "none", 24))
            lines.append(kv("    Flags seen", d.flags, 24))
            lines.append(kv("    Last ACK", d.last_ack, 24))
            if d.buffered:
                lines.append(kv("    Held out of order",
                                "%s bytes" % "{:,}".format(d.buffered), 24))
        return lines

    def _http_lines(self, txns) -> list:
        if not txns:
            return []
        lines = ["", "HTTP on this connection (%d)" % len(txns)]
        for t in txns[:10]:
            lines.append("  %s  %s %s  \u2192  %s %s" % (
                ts_time(t.ts), t.method or "?", t.path or "?",
                t.status if t.status is not None else "(no response)",
                t.reason or ""))
            detail = []
            if t.content_type:
                detail.append(t.content_type)
            if t.body_summary:
                detail.append(t.body_summary)
            if detail:
                lines.append("      " + "  \u00b7  ".join(detail))
            if t.saw_gap:
                lines.append("      stream gap: this transaction is incomplete")
        if len(txns) > 10:
            lines.append("  ... and %d more" % (len(txns) - 10))
        return lines

    def _tls_lines(self, sess) -> list:
        if sess is None:
            return []
        version = (sess.negotiated_version or sess.server_version
                   or sess.client_version)
        return [
            "", "TLS on this connection",
            kv("  SNI requested", sess.sni, 24),
            kv("  Negotiated version", version, 24),
            kv("  Cipher suite", sess.cipher_suite, 24),
            kv("  ALPN", sess.alpn_selected
               or (", ".join(sess.alpn_offered) or None), 24),
            kv("  Certificate", sess.cert_availability, 24),
            kv("  Certificate CN", sess.cert_subject_cn, 24),
            kv("  Encrypted payload", "%s in %d records" % (
                human_bytes(sess.app_data_bytes), sess.app_data_records), 24),
        ]

    def _dns_lines(self, events) -> list:
        if not events:
            return []
        lines = ["", "DNS that relates to this connection (%d)" % len(events)]
        for e in events[:6]:
            lines.append("  %s  %s %s %s  \u2192  %s" % (
                ts_time(e.ts), e.protocol, e.qname or "?", e.qtype or "",
                e.answer_summary or e.rcode or ""))
        lines.append("  Matched by the addresses this name resolved to.")
        return lines
