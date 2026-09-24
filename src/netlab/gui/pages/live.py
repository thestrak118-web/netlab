"""Live Traffic: the packet list plus a decoded detail and hex view."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (QCheckBox, QComboBox, QLabel, QPlainTextEdit, QPushButton,
                               QSplitter, QTabWidget, QVBoxLayout, QWidget)

from netlab.analyze.decode import LINKTYPE_NAMES, decode
from netlab.gui.models import PacketModel
from netlab.gui.widgets import TablePage
from netlab.util.format import DASH, human_bytes, hexdump, ts_full


class PacketDetailPane(QTabWidget):
    """Decoded fields and raw bytes for one selected packet.

    The bytes are not held in memory with the row; they are read back out of
    the capture file by offset when a packet is selected.
    """

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._reader_provider = None
        self._engine = None

        self.summary = QPlainTextEdit()
        self.summary.setObjectName("Mono")
        self.summary.setReadOnly(True)
        self.addTab(self.summary, "Details")

        self.hex = QPlainTextEdit()
        self.hex.setObjectName("Mono")
        self.hex.setReadOnly(True)
        self.hex.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.addTab(self.hex, "Bytes")

        self.flow = QPlainTextEdit()
        self.flow.setObjectName("Mono")
        self.flow.setReadOnly(True)
        self.flow.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.addTab(self.flow, "Flow")

        self.clear_packet()

    def set_reader_provider(self, provider) -> None:
        """`provider()` returns a RandomAccessCapture or None."""
        self._reader_provider = provider

    def set_engine(self, engine) -> None:
        self._engine = engine

    def clear_packet(self) -> None:
        self.summary.setPlainText(
            "Select a packet to see its decoded fields here.")
        self.hex.setPlainText("")
        self.flow.setPlainText(
            "Select a packet to see the connection it belongs to.")

    def show_packet(self, row) -> None:
        if row is None:
            self.clear_packet()
            return

        lines = [
            "Frame %d" % row.index,
            "  Time              %s" % ts_full(row.ts),
            "  Captured length   %d bytes on the wire" % row.length,
            "  Link type         %d (%s)" % (
                row.linktype, LINKTYPE_NAMES.get(row.linktype, "unknown")),
            "  File offset       %d" % row.offset,
            "",
            "Addresses",
            "  Source            %s%s" % (
                row.src or DASH, ":%d" % row.sport if row.sport else ""),
            "  Destination       %s%s" % (
                row.dst or DASH, ":%d" % row.dport if row.dport else ""),
            "  Protocol          %s" % row.proto,
            "  Application       %s" % (row.app or DASH),
            "",
            "Summary",
            "  %s" % (row.info or DASH),
        ]
        if row.malformed:
            lines += ["", "This frame was malformed or truncated; only the "
                          "fields above could be read."]

        raw = self._read_bytes(row)
        if raw is not None:
            pkt = decode(raw.data, raw.linktype, raw.ts, raw.wirelen, row.index)
            extra = []
            if pkt.src_mac or pkt.dst_mac:
                extra += ["", "Link layer",
                          "  Source MAC        %s" % (pkt.src_mac or DASH),
                          "  Destination MAC   %s" % (pkt.dst_mac or DASH)]
                if pkt.vlan is not None:
                    extra.append("  VLAN ID           %d" % pkt.vlan)
            if pkt.ip_version:
                extra += ["", "Network layer",
                          "  IP version        %d" % pkt.ip_version,
                          "  TTL / hop limit   %s" % (pkt.ttl if pkt.ttl
                                                      is not None else DASH)]
                if pkt.fragmented:
                    extra.append("  Fragmented        yes (not reassembled)")
            if pkt.tcp_flags:
                extra += ["", "Transport layer",
                          "  TCP flags         %s" % pkt.tcp_flags,
                          "  Sequence          %s" % (pkt.seq
                                                      if pkt.seq is not None
                                                      else DASH)]
            if pkt.payload:
                extra += ["", "Payload",
                          "  %d bytes of transport payload" % len(pkt.payload)]
            lines += extra
            self.hex.setPlainText(hexdump(raw.data))
        else:
            self.hex.setPlainText(
                "The raw bytes for this packet could not be read back from the "
                "capture file.\n\nThis happens when the capture file has been "
                "moved, deleted, or rotated since the packet was seen.")
        self.summary.setPlainText("\n".join(lines))
        self.flow.setPlainText("\n".join(self._flow_lines(row)))

    def _flow_lines(self, row) -> list:
        if self._engine is None:
            return ["Connection correlation is not available."]
        flow = self._engine.flow_for_packet(row)
        if flow is None:
            return ["This packet does not belong to a tracked connection.",
                    "",
                    "Connections are tracked for IP traffic; a frame with no "
                    "usable addresses (or one evicted from the bounded flow "
                    "table) will not have one."]
        lines = [
            "%s  %s:%s  \u2194  %s:%s" % (flow.proto, flow.client,
                                          flow.client_port, flow.server,
                                          flow.server_port),
            "",
            "  State            %s" % flow.state,
            "  Application      %s" % (flow.app_proto or DASH),
            "  Service / SNI    %s" % (flow.service or DASH),
            "  Packets          %s  (%s out, %s in)" % (
                "{:,}".format(flow.packets), "{:,}".format(flow.pkts_c2s),
                "{:,}".format(flow.pkts_s2c)),
            "  Bytes            %s" % human_bytes(flow.bytes),
        ]
        summary = self._engine.stream_summary_for_flow(flow)
        if summary is not None:
            lines += ["", "TCP reassembly" + ("" if summary.live
                                              else "  (connection finished)")]
            for d in summary.directions:
                lines.append("  %s:%s" % (d.endpoint[0], d.endpoint[1]))
                lines.append("      %s bytes, %s segments, %s retransmitted, "
                             "%s out of order"
                             % ("{:,}".format(d.bytes_delivered),
                                "{:,}".format(d.segments),
                                "{:,}".format(d.retransmissions),
                                "{:,}".format(d.out_of_order)))
                if d.gaps:
                    lines.append("      %s bytes missing in %d gap(s) - "
                                 "not reconstructed"
                                 % ("{:,}".format(d.gap_bytes), d.gaps))
        relations = self._engine.relations_for_flow(flow)
        http = relations.get("http") or []
        if http:
            lines += ["", "HTTP on this connection (%d)" % len(http)]
            for t in http[:6]:
                lines.append("  %s %s -> %s" % (
                    t.method or "?", t.path or "?",
                    t.status if t.status is not None else "(no response)"))
        tls = relations.get("tls")
        if tls is not None:
            lines += ["", "TLS on this connection",
                      "  SNI              %s" % (tls.sni or DASH),
                      "  Version          %s" % (tls.negotiated_version
                                                 or tls.server_version or DASH),
                      "  Cipher           %s" % (tls.cipher_suite or DASH),
                      "  Certificate      %s" % tls.cert_availability]
        dns = relations.get("dns") or []
        if dns:
            lines += ["", "DNS that relates to this connection"]
            for e in dns[:4]:
                lines.append("  %s %s -> %s" % (
                    e.protocol, e.qname or "?",
                    e.answer_summary or e.rcode or ""))
        lines += ["", "Double-click the packet row to open this connection "
                      "in the Connections page."]
        return lines

    def _read_bytes(self, row):
        if self._reader_provider is None:
            return None
        reader = self._reader_provider()
        if reader is None:
            return None
        try:
            return reader.read_at(row.offset)
        except Exception:
            return None


class LiveTrafficPage(TablePage):
    """Packet list for the active source: a live capture or an opened file."""

    show_connection = Signal(object)        # the flow a packet belongs to

    def __init__(self, parent=None) -> None:
        super().__init__(
            "Live Traffic",
            "Every frame the capture engine handed to the analyser, in the "
            "order it was observed.",
            PacketModel(), parent)

        self.scope_combo = QComboBox()
        self.scope_combo.addItems(['All', 'Local', 'Remote'])
        self.scope_combo.currentTextChanged.connect(self._scope_changed)
        self.add_tool(self.scope_combo)
        self.auto_scroll = QCheckBox("Follow new packets")
        self.auto_scroll.setChecked(True)
        self.add_tool(self.auto_scroll)

        self.clear_filter_btn = QPushButton("Clear filter")
        self.clear_filter_btn.clicked.connect(lambda: self.set_filter_text(""))
        self.add_tool(self.clear_filter_btn)

        # Re-house the table inside a splitter with the detail pane.
        self.body_layout.removeWidget(self.table)
        self.detail = PacketDetailPane()
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.addWidget(self.table)
        splitter.addWidget(self.detail)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        splitter.setSizes([520, 300])
        self.body_layout.insertWidget(self.body_layout.count() - 1, splitter, 1)
        self.splitter = splitter

        self.row_selected.connect(self.detail.show_packet)
        self.row_activated.connect(self._open_connection)
        self._engine = None

    def _scope_changed(self, scope):
        self.model.traffic_scope = scope
        self.model._rebuild()
        self.update_counts()

    def set_engine(self, engine) -> None:
        self._engine = engine
        self.model.engine = engine
        self.detail.set_engine(engine)

    def _open_connection(self, row) -> None:
        if self._engine is None:
            return
        flow = self._engine.flow_for_packet(row)
        if flow is not None:
            self.show_connection.emit(flow)

    def append_rows(self, rows, cap: int) -> None:
        if not rows:
            return
        at_bottom = self.auto_scroll.isChecked()
        self.model.append_items(rows, cap)
        if at_bottom:
            self.table.scrollToBottom()

    def set_source_hint(self, text: str) -> None:
        self.hint.setText(text)
        self.hint.setVisible(bool(text))

    def clear(self) -> None:
        self.model.clear()
        self.detail.clear_packet()
        self.update_counts()
