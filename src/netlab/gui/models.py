"""Qt table models.

All models share one refresh discipline: the analysis thread owns the data,
the GUI copies only what is new on a timer, and filtering happens inside the
model so no proxy has to re-scan every row on every tick.
"""

from __future__ import annotations

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt
from PySide6.QtGui import QColor, QFont

from netlab.gui import theme
from netlab.gui.filters import compile_filter
from netlab.util.format import (DASH, dash, human_bytes, ts_full, ts_time,
                                duration as fmt_duration)

RIGHT = int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
LEFT = int(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
CENTER = int(Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignVCenter)


class NetLabTableModel(QAbstractTableModel):
    """Base model: append-oriented, filtered in place."""

    COLUMNS: list[tuple[str, int, int]] = []

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._source: list = []
        self._rows: list = []
        self._filter = compile_filter("")
        self._mono = QFont("DejaVu Sans Mono")
        self._mono.setPointSize(9)

    # ---- Qt plumbing

    def rowCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.COLUMNS)

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if orientation != Qt.Orientation.Horizontal:
            return None
        if role == Qt.ItemDataRole.DisplayRole and 0 <= section < len(self.COLUMNS):
            return self.COLUMNS[section][0]
        return None

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        row = index.row()
        if row >= len(self._rows):
            return None
        obj = self._rows[row]
        col = index.column()
        if role == Qt.ItemDataRole.DisplayRole:
            return self.cell(obj, col)
        if role == Qt.ItemDataRole.TextAlignmentRole:
            return self.COLUMNS[col][2]
        if role == Qt.ItemDataRole.ForegroundRole:
            colour = self.colour(obj, col)
            if colour:
                return QColor(colour)
            if self.cell(obj, col) == DASH:
                return QColor(theme.MUTED)
        if role == Qt.ItemDataRole.ToolTipRole:
            return self.tooltip(obj, col)
        return None

    # ---- to override

    def cell(self, obj, col: int) -> str:
        raise NotImplementedError

    def fields(self, obj) -> dict:
        return {}

    def search_text(self, obj) -> str:
        return " ".join(str(v) for v in self.fields(obj).values() if v is not None)

    def colour(self, obj, col: int):
        return None

    def tooltip(self, obj, col: int):
        return None

    def identity(self, obj):
        return id(obj)

    # ---- data flow

    def object_at(self, row: int):
        if 0 <= row < len(self._rows):
            return self._rows[row]
        return None

    def set_filter(self, text: str) -> None:
        self._filter = compile_filter(text)
        self._rebuild()

    @property
    def filter_text(self) -> str:
        return self._filter.source

    @property
    def total_rows(self) -> int:
        return len(self._source)

    def _passes(self, obj) -> bool:
        if self._filter.is_empty:
            return True
        return self._filter.matches(self.fields(obj), self.search_text(obj))

    def _rebuild(self) -> None:
        self.beginResetModel()
        self._rows = [o for o in self._source if self._passes(o)]
        self.endResetModel()

    def clear(self) -> None:
        self.beginResetModel()
        self._source = []
        self._rows = []
        self.endResetModel()

    def append_items(self, items: list, cap: int = 0) -> None:
        """Append newly observed rows without disturbing the existing view."""
        if not items:
            return
        self._source.extend(items)
        if cap and len(self._source) > cap:
            self._source = self._source[-cap:]
        fresh = [o for o in items if self._passes(o)]
        if fresh:
            start = len(self._rows)
            self.beginInsertRows(QModelIndex(), start, start + len(fresh) - 1)
            self._rows.extend(fresh)
            self.endInsertRows()
        if cap and len(self._rows) > cap:
            excess = len(self._rows) - cap
            self.beginRemoveRows(QModelIndex(), 0, excess - 1)
            del self._rows[:excess]
            self.endRemoveRows()

    def replace_items(self, items: list) -> None:
        """Refresh a table whose rows can change in place (flows, hosts)."""
        items = list(items)
        passing = [o for o in items if self._passes(o)]
        same = [self.identity(o) for o in passing] == [self.identity(o) for o in self._rows]
        self._source = items
        if same:
            self._rows = passing
            if passing:
                self.dataChanged.emit(self.index(0, 0), self.index(len(passing)-1, len(self.COLUMNS)-1))
        else:
            self._rebuild()


class PacketModel(NetLabTableModel):
    engine = None
    COLUMNS = [
        ("Device", 195, LEFT), ("Direction", 100, LEFT), ("Protocol", 85, LEFT),
        ("Source", 170, LEFT), ("Destination", 170, LEFT), ("Domain", 200, LEFT),
        ("Size", 75, RIGHT), ("#", 72, RIGHT), ("Time", 108, LEFT),
        ("S.Port", 66, RIGHT), ("D.Port", 66, RIGHT), ("Info", 380, LEFT),
    ]

    traffic_scope = 'All'
    devices_by_address = {}

    def _passes(self, r):
        if self.traffic_scope != 'All':
            local = r.src in self.devices_by_address and r.dst in self.devices_by_address
            if (self.traffic_scope == 'Local') != local: return False
        return super()._passes(r)

    def correlation(self, r):
        d = self.devices_by_address.get(r.src) or self.devices_by_address.get(r.dst)
        if d:
            label = (d.device_type if d.device_type != 'Unknown' else 'Unknown Device') + ' · ' + d.ip
            direction = 'Local' if r.src in d.addresses and r.dst in d.addresses else 'Upload' if r.src in d.addresses else 'Download'
        else:
            label, direction = 'Unknown local device', 'Observed'
        flow = self.engine.flow_for_packet(r) if self.engine else None
        domain = (flow.service if flow and flow.service else '') \
            or self._peer_domain(r) or 'Unknown'
        return label, direction, domain

    def _peer_domain(self, r):
        """The site behind the remote IP: the name DNS resolved to it, or the
        TLS SNI seen for it. This is why a bare ACK still shows its domain."""
        if not self.engine:
            return ''
        local = self.devices_by_address
        peer = r.dst if r.src in local else r.src if r.dst in local else r.dst
        host = self.engine.hosts.get(peer)
        if host:
            for names in (host.dns_names, host.sni_names, host.http_names):
                if names:
                    return sorted(names)[0]
        return ''

    def cell(self, r, col):
        if col in (0, 1, 5):
            values = self.correlation(r)
            return values[{0: 0, 1: 1, 5: 2}[col]]
        return {2: r.app or r.proto, 3: r.src or 'Unknown', 4: r.dst or 'Unknown',
                6: str(r.length), 7: str(r.index), 8: ts_time(r.ts),
                9: dash(r.sport), 10: dash(r.dport), 11: r.info}.get(col, 'Unknown')

    def fields(self, r):
        return {"src": r.src, "dst": r.dst, "sport": r.sport, "dport": r.dport,
                "proto": r.proto, "app": r.app, "info": r.info}

    def search_text(self, r):
        return "%s %s %s %s %s %s" % (r.src or "", r.dst or "", r.sport or "",
                                      r.dport or "", r.proto, r.info)

    def colour(self, r, col):
        if r.malformed:
            return theme.RED
        if col == 2:
            return theme.PROTO_COLORS.get(r.app or r.proto)
        return None

    def identity(self, r):
        return r.index

    def tooltip(self, r, col):
        if col == 9:
            return r.info
        return None


class FlowModel(NetLabTableModel):
    COLUMNS = [
        ("Protocol", 78, LEFT), ("Client", 150, LEFT), ("C.Port", 66, RIGHT),
        ("Server", 150, LEFT), ("S.Port", 66, RIGHT), ("App", 66, LEFT),
        ("Service / SNI", 210, LEFT), ("State", 100, LEFT),
        ("Packets", 76, RIGHT), ("Bytes", 84, RIGHT),
        ("Out", 78, RIGHT), ("In", 78, RIGHT),
        ("Duration", 84, RIGHT), ("Last seen", 96, LEFT),
    ]

    def cell(self, f, col):
        return (
            f.proto, dash(f.client), dash(f.client_port), dash(f.server),
            dash(f.server_port), dash(f.app_proto), dash(f.service), f.state,
            "{:,}".format(f.packets), human_bytes(f.bytes),
            human_bytes(f.bytes_c2s), human_bytes(f.bytes_s2c),
            fmt_duration(f.duration), ts_time(f.last_ts),
        )[col]

    def fields(self, f):
        return {"src": f.client, "dst": f.server, "sport": f.client_port,
                "dport": f.server_port, "proto": f.proto, "app": f.app_proto,
                "service": f.service, "state": f.state}

    def search_text(self, f):
        return "%s %s %s %s %s %s %s" % (
            f.proto, f.client, f.client_port, f.server, f.server_port,
            f.app_proto or "", f.service or "")

    def colour(self, f, col):
        if col == 0:
            return theme.PROTO_COLORS.get(f.proto)
        if col == 5 and f.app_proto:
            return theme.PROTO_COLORS.get(f.app_proto)
        if col == 7:
            return {"RESET": theme.RED, "ESTABLISHED": theme.GREEN,
                    "CLOSING": theme.AMBER}.get(f.state)
        return None

    def identity(self, f):
        return f.key

    def tooltip(self, f, col):
        note = "Encrypted (TLS). NetLab does not decrypt it." if f.encrypted else None
        if col == 6 and f.service:
            return "%s%s" % (f.service, "\n" + note if note else "")
        return note


class HostModel(NetLabTableModel):
    COLUMNS = [
        ("IP address", 170, LEFT), ("DNS names", 210, LEFT),
        ("TLS SNI names", 190, LEFT), ("MAC", 146, LEFT),
        ("Scope", 70, LEFT), ("Flows", 58, RIGHT), ("Active", 58, RIGHT),
        ("Packets", 78, RIGHT), ("Bytes", 86, RIGHT),
        ("Sent", 84, RIGHT), ("Received", 84, RIGHT),
        ("Observed listening ports", 220, LEFT), ("First seen", 92, LEFT),
        ("Last seen", 92, LEFT),
    ]

    @staticmethod
    def _names(values) -> str:
        if not values:
            return DASH
        ordered = sorted(values)
        if len(ordered) == 1:
            return ordered[0]
        return "%s  (+%d)" % (ordered[0], len(ordered) - 1)

    def cell(self, h, col):
        return (
            h.ip, self._names(h.dns_names), self._names(h.sni_names),
            dash(h.mac), "local" if h.local else "remote",
            "{:,}".format(h.total_flows), "{:,}".format(h.active_flows),
            "{:,}".format(h.packets), human_bytes(h.bytes),
            human_bytes(h.bytes_sent), human_bytes(h.bytes_recv),
            h.ports_summary or DASH, ts_time(h.first_ts), ts_time(h.last_ts),
        )[col]

    def fields(self, h):
        return {"src": h.ip, "dst": h.ip,
                "hostname": " ".join(sorted(h.hostnames)),
                "sni": " ".join(sorted(h.sni_names)),
                "mac": h.mac or "", "state": "local" if h.local else "remote"}

    def search_text(self, h):
        return "%s %s %s %s" % (h.ip, h.hostname or "", h.mac or "",
                                " ".join(sorted(h.hostnames)))

    def colour(self, h, col):
        if col == 4:
            return theme.CYAN if h.local else theme.MUTED
        if col == 6 and h.active_flows:
            return theme.GREEN
        return None

    def identity(self, h):
        return h.ip

    def tooltip(self, h, col):
        if col == 1 and h.dns_names:
            return ("Names a resolver actually answered with for this "
                    "address, plus HTTP Host headers sent to it:\n  "
                    + "\n  ".join(sorted(h.dns_names))
                    + "\n\nSeveral unrelated names can share one address "
                      "(a CDN, for example). They are listed side by side, "
                      "not merged into one identity.")
        if col == 2 and h.sni_names:
            return ("Names clients *asked for* over TLS on this address:\n  "
                    + "\n  ".join(sorted(h.sni_names))
                    + "\n\nSNI is a claim by the client, not a verified "
                      "identity, so it is kept apart from resolver answers.")
        if col == 11:
            return ("Ports where this host was seen answering.\n"
                    "TCP ports are listed only after a SYN/ACK was observed.")
        return None


class DnsModel(NetLabTableModel):
    COLUMNS = [
        ("Time", 108, LEFT), ("Protocol", 74, LEFT), ("Kind", 76, LEFT),
        ("Transport", 78, LEFT), ("Query", 280, LEFT), ("Type", 66, LEFT),
        ("Result", 90, LEFT), ("Answer", 300, LEFT),
        ("Client", 150, LEFT), ("Server", 150, LEFT),
    ]

    def cell(self, e, col):
        return (
            ts_time(e.ts), e.protocol, e.kind, e.transport, dash(e.qname),
            dash(e.qtype), dash(e.rcode), e.answer_summary or DASH,
            dash(e.src if e.kind == "query" else e.dst),
            dash(e.dst if e.kind == "query" else e.src),
        )[col]

    def fields(self, e):
        return {"device": (e.src, e.dst, *e.resolved_ips), "src": e.src, "dst": e.dst, "qname": e.qname or "",
                "name": e.qname or "", "qtype": e.qtype or "",
                "proto": e.protocol, "type": e.qtype or ""}

    def search_text(self, e):
        return "%s %s %s %s %s" % (e.qname or "", e.qtype or "",
                                   e.answer_summary, e.src or "", e.dst or "")

    def colour(self, e, col):
        if col == 6 and e.rcode and e.rcode != "NOERROR":
            return theme.AMBER
        if col == 1:
            return theme.PROTO_COLORS.get(e.protocol)
        return None

    def identity(self, e):
        return (e.ts, e.txid, e.kind, e.packet_index)

    def tooltip(self, e, col):
        if col == 7 and e.answers:
            return "\n".join("%s  %s  %s  TTL %d" % (a.name, a.rtype, a.value, a.ttl)
                             for a in e.answers)
        return None


class HttpModel(NetLabTableModel):
    COLUMNS = [
        ("Time", 108, LEFT), ("Method", 74, LEFT), ("Host", 210, LEFT),
        ("Path", 330, LEFT), ("Status", 62, RIGHT), ("Reason", 150, LEFT),
        ("Content type", 160, LEFT), ("Size", 78, RIGHT),
        ("Server", 150, LEFT), ("Time taken", 84, RIGHT),
        ("Client", 140, LEFT), ("Notes", 220, LEFT),
    ]

    def cell(self, t, col):
        if col == 7:
            try:
                return human_bytes(int(t.content_length)) if t.content_length \
                    else DASH
            except (TypeError, ValueError):
                return dash(t.content_length)
        if col == 9:
            d = t.duration_ms
            return "%.0f ms" % d if d is not None else DASH
        return (
            ts_time(t.ts), dash(t.method), dash(t.host), dash(t.path),
            dash(t.status), dash(t.reason), dash(t.content_type), "",
            dash(t.server_header), "", dash(t.client),
            "; ".join(t.notes) if t.notes else DASH,
        )[col]

    def fields(self, t):
        return {"src": t.client, "dst": t.server, "host": t.host or "",
                "method": t.method or "", "status": t.status,
                "sport": t.client_port, "dport": t.server_port,
                "proto": "HTTP"}

    def search_text(self, t):
        return "%s %s %s %s %s" % (t.method or "", t.host or "", t.path or "",
                                   t.status or "", t.content_type or "")

    def colour(self, t, col):
        if col == 4 and t.status:
            if t.status >= 500:
                return theme.RED
            if t.status >= 400:
                return theme.AMBER
            if t.status >= 300:
                return theme.CYAN
            return theme.GREEN
        if col == 1:
            return theme.AMBER
        return None

    def identity(self, t):
        return (t.ts, t.req_packet_index)

    def tooltip(self, t, col):
        bits = ["Cleartext HTTP observed on the wire."]
        if t.user_agent:
            bits.append("User-Agent: %s" % t.user_agent)
        if t.referer:
            bits.append("Referer: %s" % t.referer)
        if t.req_has_auth:
            bits.append("Request carried an Authorization header "
                        "(value not recorded).")
        if t.req_has_cookie:
            bits.append("Request carried a Cookie header (value not recorded).")
        if t.resp_has_set_cookie:
            bits.append("Response carried Set-Cookie (value not recorded).")
        if t.notes:
            bits.extend(t.notes)
        return "\n".join(bits)


class TlsModel(NetLabTableModel):
    COLUMNS = [
        ("Time", 108, LEFT), ("SNI (requested name)", 230, LEFT),
        ("Client", 150, LEFT), ("Server", 150, LEFT), ("Port", 60, RIGHT),
        ("Version", 82, LEFT), ("Cipher suite", 260, LEFT),
        ("ALPN", 90, LEFT), ("Certificate", 140, LEFT),
        ("Cert CN", 200, LEFT), ("Issuer CN", 200, LEFT),
        ("Valid until", 150, LEFT), ("App data", 90, RIGHT),
        ("Payload", 100, LEFT),
    ]

    def cell(self, s, col):
        return (
            ts_time(s.ts), dash(s.sni), dash(s.client), dash(s.server),
            dash(s.server_port),
            dash(s.negotiated_version or s.server_version or s.client_version),
            dash(s.cipher_suite),
            dash(s.alpn_selected or (",".join(s.alpn_offered) or None)),
            s.cert_availability, dash(s.cert_subject_cn), dash(s.cert_issuer_cn),
            dash(s.cert_not_after), human_bytes(s.app_data_bytes),
            "ENCRYPTED",
        )[col]

    def fields(self, s):
        return {"src": s.client, "dst": s.server, "sni": s.sni or "",
                "host": s.sni or "", "dport": s.server_port,
                "cipher": s.cipher_suite or "", "proto": "TLS",
                "version": s.negotiated_version or s.server_version or ""}

    def search_text(self, s):
        return "%s %s %s %s %s" % (s.sni or "", s.client or "", s.server or "",
                                   s.cipher_suite or "",
                                   s.negotiated_version or "")

    def colour(self, s, col):
        if col == 13:
            return theme.GREEN
        if col == 8:
            return theme.GREEN if s.cert_subject_cn else theme.MUTED
        if col == 5:
            v = s.negotiated_version or s.server_version or ""
            if v in ("SSL 3.0", "TLS 1.0", "TLS 1.1"):
                return theme.AMBER
            return theme.CYAN
        if col == 6 and s.notes:
            return theme.AMBER
        return None

    def identity(self, s):
        return s.flow_key

    def tooltip(self, s, col):
        bits = ["NetLab does not decrypt TLS. Only handshake metadata is shown; "
                "the application payload stays encrypted."]
        if col == 1:
            bits.append("SNI is the name the *client* asked for. It is a claim "
                        "by the client, not a verified identity.")
        if col == 8:
            if s.cert_subject_cn:
                bits.append("Certificate was sent in the clear (TLS 1.2 or "
                            "earlier) and could be read passively.")
            elif (s.negotiated_version or s.server_version) == "TLS 1.3":
                bits.append("TLS 1.3 encrypts the certificate, so it is not "
                            "observable passively.")
            else:
                bits.append("No certificate message was observed on this flow.")
        if s.notes:
            bits.extend(s.notes)
        return "\n\n".join(bits)


class NmapHostModel(NetLabTableModel):
    COLUMNS = [
        ("Host", 170, LEFT), ("Hostname", 220, LEFT), ("State", 80, LEFT),
        ("MAC", 150, LEFT), ("Vendor", 170, LEFT), ("Open ports", 90, RIGHT),
        ("Services", 420, LEFT), ("OS guess", 260, LEFT),
    ]

    def cell(self, h, col):
        open_ports = h.open_ports
        return (
            h.address, ", ".join(h.hostnames) or DASH, h.state,
            dash(h.mac), dash(h.vendor), str(len(open_ports)),
            ", ".join("%d/%s %s" % (p.port, p.protocol, p.service_text)
                      for p in open_ports[:10]) or DASH,
            "; ".join(h.os_matches) or DASH,
        )[col]

    def fields(self, h):
        return {"src": h.address, "hostname": ", ".join(h.hostnames),
                "state": h.state, "mac": h.mac}

    def search_text(self, h):
        return "%s %s %s" % (h.address, " ".join(h.hostnames),
                             " ".join(str(p.port) for p in h.ports))

    def colour(self, h, col):
        if col == 2:
            return theme.GREEN if h.state == "up" else theme.MUTED
        return None

    def identity(self, h):
        return h.address


class CredentialModel(NetLabTableModel):
    """The Passwords table: what the network gave away, and how crackable."""

    COLUMNS = [
        ("Time", 106, LEFT), ("Protocol", 82, LEFT), ("Kind", 78, LEFT),
        ("Client", 140, LEFT), ("Server", 165, LEFT), ("User", 190, LEFT),
        ("Secret", 300, LEFT), ("Crack with", 130, LEFT),
        ("Source", 84, LEFT), ("Context", 420, LEFT),
    ]

    def cell(self, c, col):
        return (
            ts_time(c.ts), c.proto, c.kind, dash(c.client), dash(c.endpoint),
            dash(c.user), self.secret_text(c), self.crack_text(c),
            c.source, dash(c.context),
        )[col]

    @staticmethod
    def secret_text(c) -> str:
        if c.password:
            return c.password
        if c.hash:
            return c.hash if len(c.hash) <= 96 else c.hash[:93] + "..."
        token = c.extra.get("token") or c.extra.get("cookie") or ""
        return token[:96] if token else DASH

    @staticmethod
    def crack_text(c) -> str:
        if c.hashcat_mode:
            return "hashcat -m %d" % c.hashcat_mode
        if c.john_format:
            return "john --format=%s" % c.john_format
        return DASH if c.hash else "not needed"

    def fields(self, c):
        return {"proto": c.proto, "ip": c.client, "host": c.server,
                "user": c.user, "port": c.port, "kind": c.kind,
                "source": c.source}

    def search_text(self, c):
        return " ".join((c.proto, c.client, c.server, c.user, c.password,
                         c.hash_type, c.context, c.source))

    def colour(self, c, col):
        if col == 2:
            return {"cleartext": theme.RED, "hash": theme.AMBER}.get(
                c.kind, theme.CYAN)
        if col == 6 and c.password:
            return theme.RED
        if col == 8 and c.source != "passive":
            return theme.PURPLE
        return None

    def tooltip(self, c, col):
        bits = ["%s credential observed on %s" % (c.kind, c.endpoint)]
        if c.password:
            bits.append("This password crossed the network in a form anyone "
                        "on the path could read.")
        if c.hash:
            bits.append("%s\n\n%s" % (c.hash_type or "hash", c.hash))
            if c.crack_command():
                bits.append(c.crack_command())
        if c.source != "passive":
            bits.append("Read through active interception (%s), not from "
                        "passive capture." % c.source)
        if c.context:
            bits.append(c.context)
        return "\n\n".join(bits)

    def identity(self, c):
        return c.identity()


class CarvedFileModel(NetLabTableModel):
    """Files reassembled out of readable traffic."""

    COLUMNS = [
        ("Time", 106, LEFT), ("Name", 240, LEFT), ("Type", 190, LEFT),
        ("Size", 90, RIGHT), ("Host", 180, LEFT), ("Client", 140, LEFT),
        ("SHA-256", 150, LEFT), ("URL", 460, LEFT),
    ]

    def cell(self, f, col):
        return (
            ts_time(f.get("ts", 0.0)), f.get("name", DASH),
            (f.get("content_type") or DASH).split(";")[0],
            human_bytes(f.get("bytes", 0)), dash(f.get("host")),
            dash(f.get("client")), (f.get("sha256") or "")[:16],
            dash(f.get("url")),
        )[col]

    def fields(self, f):
        return {"host": f.get("host", ""), "ip": f.get("client", ""),
                "name": f.get("name", "")}

    def search_text(self, f):
        return "%s %s %s" % (f.get("name", ""), f.get("url", ""),
                             f.get("content_type", ""))

    def identity(self, f):
        return f.get("path", "") or f.get("sha256", "")


class InterceptEventModel(NetLabTableModel):
    """The running log of what the active modules did."""

    COLUMNS = [
        ("Time", 106, LEFT), ("Event", 150, LEFT), ("Subject", 260, LEFT),
        ("Detail", 700, LEFT),
    ]

    def cell(self, e, col):
        return (ts_time(e.get("ts", 0.0)), e.get("name", ""),
                e.get("subject", DASH), e.get("detail", ""))[col]

    def fields(self, e):
        return {"event": e.get("name", ""), "host": e.get("subject", "")}

    def search_text(self, e):
        return "%s %s %s" % (e.get("name", ""), e.get("subject", ""),
                             e.get("detail", ""))

    def colour(self, e, col):
        name = e.get("name", "")
        if name.startswith(("error", "log.error", "proxy.out-of-scope",
                            "tls.rejected")):
            return theme.RED
        if col == 1:
            if name.startswith("credential"):
                return theme.RED
            if name.startswith(("arp", "dhcp")):
                return theme.PURPLE
            if name.startswith("dns"):
                return theme.CYAN
            if name.startswith(("strip", "cookie", "changer")):
                return theme.AMBER
        return None


class TargetModel(NetLabTableModel):
    """Hosts found on the segment, and whether they are being poisoned."""

    COLUMNS = [
        ("Address", 150, LEFT), ("MAC", 160, LEFT), ("Vendor", 200, LEFT),
        ("In scope", 90, LEFT), ("Poisoned", 90, LEFT), ("Note", 300, LEFT),
    ]

    def cell(self, h, col):
        return (
            h.get("ip", DASH), dash(h.get("mac")), dash(h.get("vendor")),
            "yes" if h.get("in_scope") else "no",
            "yes" if h.get("poisoned") else "no", dash(h.get("note")),
        )[col]

    def fields(self, h):
        return {"ip": h.get("ip", ""), "mac": h.get("mac", "")}

    def search_text(self, h):
        return "%s %s %s" % (h.get("ip", ""), h.get("mac", ""),
                             h.get("vendor", ""))

    def colour(self, h, col):
        if col == 3:
            return theme.GREEN if h.get("in_scope") else theme.MUTED
        if col == 4:
            return theme.RED if h.get("poisoned") else theme.MUTED
        return None

    def identity(self, h):
        return h.get("ip", "")
