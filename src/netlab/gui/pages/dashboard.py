"""Dashboard: capture state and the headline counters."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QGridLayout, QHBoxLayout, QLabel, QScrollArea,
                               QVBoxLayout, QWidget)

from netlab.gui import theme
from netlab.gui.widgets import Banner, Card, Sparkline
from netlab.util.format import (DASH, human_bytes, human_count, human_rate)


class DashboardPage(QWidget):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        outer.addWidget(scroll)

        body = QWidget()
        scroll.setWidget(body)
        lay = QVBoxLayout(body)
        lay.setContentsMargins(18, 16, 18, 18)
        lay.setSpacing(12)

        title = QLabel("Dashboard")
        title.setObjectName("PageTitle")
        lay.addWidget(title)
        hint = QLabel("Passive observation only. NetLab does not transmit, "
                      "inject or modify traffic; the Nmap page is the one "
                      "place that actively sends packets.")
        hint.setObjectName("PageHint")
        hint.setWordWrap(True)
        lay.addWidget(hint)

        self.priv_banner = Banner("", "warn", "How to fix")
        self.priv_banner.setVisible(False)
        lay.addWidget(self.priv_banner)

        self.drop_banner = Banner("", "warn")
        self.drop_banner.setVisible(False)
        lay.addWidget(self.drop_banner)

        self.cards: dict[str, Card] = {}
        grid = QGridLayout()
        grid.setSpacing(10)
        spec = [
            ("status", "Capture status"), ("interface", "Interface"),
            ("pps", "Packets / sec"), ("bps", "Bytes / sec"),
            ("packets", "Total packets"), ("bytes", "Total bytes"),
            ("flows", "Active connections"), ("hosts", "Observed hosts"),
            ("dns", "DNS events"), ("http", "HTTP transactions"),
            ("tls", "TLS sessions"), ("pcap", "Capture file size"),
            ("streams", "TCP streams"), ("reassembled", "Reassembled"),
            ("http_msgs", "HTTP messages parsed"),
            ("handshakes", "TLS handshakes parsed"),
        ]
        for i, (key, label) in enumerate(spec):
            card = Card(label, DASH)
            self.cards[key] = card
            grid.addWidget(card, i // 4, i % 4)
        lay.addLayout(grid)

        charts = QHBoxLayout()
        charts.setSpacing(10)
        for key, label, colour in (
                ("pps", "Packets per second (captured)", theme.ACCENT),
                ("bps", "Bytes per second (analysed)", theme.CYAN)):
            box = QVBoxLayout()
            cap = QLabel(label)
            cap.setObjectName("CardLabel")
            box.addWidget(cap)
            spark = Sparkline(colour)
            setattr(self, "spark_" + key, spark)
            box.addWidget(spark)
            wrapper = QWidget()
            wrapper.setLayout(box)
            charts.addWidget(wrapper)
        lay.addLayout(charts)

        self.reassembly = QLabel("")
        self.reassembly.setObjectName("PageHint")
        self.reassembly.setWordWrap(True)
        self.reassembly.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse)
        lay.addWidget(self.reassembly)

        self.integrity = QLabel("")
        self.integrity.setObjectName("PageHint")
        self.integrity.setWordWrap(True)
        self.integrity.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse)
        lay.addWidget(self.integrity)
        lay.addStretch(1)

    def set_privilege_warning(self, text: str) -> None:
        if text:
            self.priv_banner.set_text(text, "warn")
            self.priv_banner.setVisible(True)
        else:
            self.priv_banner.setVisible(False)

    def update_view(self, stats, capture_state: str, interface: str,
                    pcap_size: int | None, source_label: str,
                    captured: int | None = None,
                    captured_pps: float | None = None,
                    capture_rate_history: list | None = None) -> None:
        """Render the counters.

        `captured` / `captured_pps` describe what the capture engine actually
        took off the wire. They are reported separately from what analysis
        managed to process, because under overload those two numbers diverge
        and showing only the analysed figure would understate the real traffic
        rate.
        """
        colours = {"Capturing": theme.GREEN, "Stopped": theme.MUTED,
                   "Offline file": theme.CYAN, "Error": theme.RED}
        self.cards["status"].set_value(
            capture_state, source_label, colours.get(capture_state))
        self.cards["interface"].set_value(interface or DASH)
        shown_pps = captured_pps if captured_pps is not None \
            else stats.packets_per_sec
        total = captured if captured is not None else stats.total_packets
        behind = total - stats.total_packets

        self.cards["pps"].set_value(
            "%.0f" % shown_pps,
            "captured off the wire" if captured_pps is not None
            else "peak %.0f/s analysed" % stats.peak_pps)
        self.cards["bps"].set_value(human_rate(stats.bytes_per_sec),
                                    "of analysed packets")
        self.cards["packets"].set_value(
            human_count(total),
            "{:,} captured \u00b7 {:,} analysed".format(total, stats.total_packets)
            if behind > 0 else "{:,} exact".format(total))
        self.cards["bytes"].set_value(human_bytes(stats.total_bytes))
        self.cards["flows"].set_value(
            human_count(stats.active_flows),
            "%s tracked in total" % human_count(stats.flows))
        self.cards["hosts"].set_value(human_count(stats.hosts))
        self.cards["dns"].set_value(human_count(stats.dns_events))
        self.cards["http"].set_value(human_count(stats.http_transactions))
        self.cards["tls"].set_value(human_count(stats.tls_sessions),
                                    "metadata only, never decrypted")
        self.cards["pcap"].set_value(
            human_bytes(pcap_size) if pcap_size is not None else DASH)
        self.cards["streams"].set_value(
            human_count(stats.streams),
            "%s seen, %s expired" % (human_count(stats.streams_created),
                                     human_count(stats.streams_expired)))
        self.cards["reassembled"].set_value(
            human_bytes(stats.reassembled_bytes),
            "%s segments" % human_count(stats.reassembly_segments))
        self.cards["http_msgs"].set_value(
            human_count(stats.http_messages),
            "requests and responses")
        self.cards["handshakes"].set_value(
            human_count(stats.tls_handshakes),
            "metadata only, never decrypted")

        # Plot what was captured, so the chart agrees with the packets/sec
        # card instead of quietly showing the slower analysed rate.
        if capture_rate_history:
            self.spark_pps.set_values(list(capture_rate_history))
        else:
            self.spark_pps.set_values([h[1] for h in stats.history])
        self.spark_bps.set_values([h[2] for h in stats.history])

        notes = []
        if stats.queue_dropped:
            notes.append(
                "%s packets reached the capture file but were dropped before "
                "analysis because the bounded queue was full. The capture on "
                "disk is still complete."
                % "{:,}".format(stats.queue_dropped))
        if stats.flows_evicted:
            notes.append("%s of the oldest connections were evicted from the "
                         "in-memory table (cap reached)."
                         % "{:,}".format(stats.flows_evicted))
        if stats.hosts_evicted:
            notes.append("%s of the oldest hosts were evicted from the "
                         "in-memory table (cap reached)."
                         % "{:,}".format(stats.hosts_evicted))
        if notes:
            self.drop_banner.set_text("  ".join(notes), "warn")
            self.drop_banner.setVisible(True)
        else:
            self.drop_banner.setVisible(False)

        reasm = []
        if stats.retransmissions:
            reasm.append("%s retransmitted segment(s)"
                         % "{:,}".format(stats.retransmissions))
        if stats.out_of_order:
            reasm.append("%s out-of-order segment(s)"
                         % "{:,}".format(stats.out_of_order))
        if stats.stream_gaps:
            reasm.append("%s byte(s) missing in %s gap(s) - reported, never "
                         "reconstructed" % ("{:,}".format(stats.stream_gap_bytes),
                                            "{:,}".format(stats.stream_gaps)))
        if stats.http_resyncs:
            reasm.append("%s HTTP resynchronisation(s) after a gap"
                         % "{:,}".format(stats.http_resyncs))
        if stats.streams_evicted:
            reasm.append("%s stream(s) evicted at the tracking cap"
                         % "{:,}".format(stats.streams_evicted))
        self.reassembly.setText(
            "TCP reassembly:  " + ("   ".join(reasm) if reasm
                                   else "no loss, reordering or duplication "
                                        "observed.")
            + "   Held out of order: %s (peak %s)."
            % (human_bytes(stats.reasm_buffered_bytes),
               human_bytes(stats.reasm_peak_buffered)))

        integrity = []
        if stats.malformed:
            integrity.append("%s malformed or truncated frames were counted "
                             "and skipped." % "{:,}".format(stats.malformed))
        if stats.unsupported_linktype:
            integrity.append("%s frames used a link type NetLab does not "
                             "decode." % "{:,}".format(stats.unsupported_linktype))
        integrity.append("Analysis queue depth: %s." % "{:,}".format(stats.queue_depth))
        self.integrity.setText("   ".join(integrity))
