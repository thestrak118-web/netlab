"""Asynchronous analysis engine.

Runs on its own thread, draining a bounded queue fed by the capture reader.
The GUI never touches this thread; it polls immutable snapshots on a timer.
Every store it writes into is bounded, so sustained high packet rates cost
CPU but not unbounded memory.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field, replace

from netlab.analyze import dns as dnsmod
from netlab.analyze import http as httpmod
from netlab.analyze import names as namesmod
from netlab.analyze import quic as quicmod
from netlab.analyze import tls as tlsmod
from netlab.analyze.decode import SUPPORTED_LINKTYPES, decode
from netlab.analyze.flows import FlowTable, HostTable, make_flow_key
from netlab.analyze.creds import CredentialHarvester
from netlab.analyze.reassembly import TcpReassembler
from netlab.analyze.devices import topology_snapshot, local_devices, valid_ip
from netlab.util.bounded import BoundedLRUDict, BoundedRing


MAX_CRED_BODY = 65536


class _PacketRef:
    """The two packet fields a credential record needs, without the packet."""

    __slots__ = ("ts", "index")

    def __init__(self, ts: float, index: int) -> None:
        self.ts = ts
        self.index = index


@dataclass(slots=True)
class PacketRow:
    """One row of the Live Traffic table. Deliberately small."""

    index: int
    ts: float
    src: str | None
    dst: str | None
    proto: str
    sport: int | None
    dport: int | None
    length: int
    info: str
    offset: int
    linktype: int
    app: str | None = None
    malformed: bool = False


@dataclass
class Stats:
    total_packets: int = 0
    total_bytes: int = 0
    packets_per_sec: float = 0.0
    bytes_per_sec: float = 0.0
    peak_pps: float = 0.0
    flows: int = 0
    active_flows: int = 0
    hosts: int = 0
    dns_events: int = 0
    http_transactions: int = 0
    tls_sessions: int = 0
    credentials: int = 0
    malformed: int = 0
    queue_dropped: int = 0
    queue_depth: int = 0
    flows_evicted: int = 0
    hosts_evicted: int = 0
    unsupported_linktype: int = 0
    history: list = field(default_factory=list)

    # Reassembly and protocol parsing. "analysed" above is packets that
    # reached the decoder; these describe what was done with them.
    streams: int = 0
    streams_created: int = 0
    streams_expired: int = 0
    streams_evicted: int = 0
    reassembled_bytes: int = 0
    reassembly_segments: int = 0
    retransmissions: int = 0
    out_of_order: int = 0
    stream_gaps: int = 0
    stream_gap_bytes: int = 0
    reasm_buffered_bytes: int = 0
    reasm_peak_buffered: int = 0
    http_messages: int = 0
    http_resyncs: int = 0
    tls_handshakes: int = 0


class AnalysisEngine:
    """Owns every derived table. Thread-safe for single-writer/many-readers."""

    def __init__(self, queue, config) -> None:
        self._queue = queue
        self._cfg = config
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._lock = threading.Lock()

        cap = config.get
        self.live = BoundedRing(cap("live_rows"))
        self.flows = FlowTable(cap("max_flows"))
        self.hosts = HostTable(cap("max_hosts"))
        self._quic_sni = quicmod.QuicSni()
        self.dns_events = BoundedRing(cap("max_dns_events"))
        self.http_txns = BoundedRing(cap("max_http_events"))
        self.tls_sessions = BoundedLRUDict(cap("max_tls_events"))
        self.tls_order = BoundedRing(cap("max_tls_events"))
        self._http_pending = BoundedLRUDict(8192)

        # Credential harvesting is the one analyser that reads what a
        # protocol was trying to keep to itself, so it is a separate switch
        # and it is the switch Intercepter mode turns on.
        self.credentials = CredentialHarvester(
            config, max_credentials=int(cap("max_credentials")))
        self.credentials.enabled = bool(config.get("harvest_credentials"))
        if self.credentials.enabled:
            # The HTTP parser redacts credential headers unless told not to.
            httpmod.set_retain_sensitive(True)

        self._reassembly_enabled = bool(config.get("tcp_reassembly"))
        self.reassembler = TcpReassembler(
            config, on_data=self._on_stream_data, on_gap=self._on_stream_gap,
            on_close=self._on_stream_close, on_retire=self._on_stream_retire)
        self._http_messages = 0
        self._http_resyncs = 0
        self._tls_handshakes = 0

        self._index = 0
        self._total_packets = 0
        self._total_bytes = 0
        self._malformed = 0
        self._unsupported_lt = 0
        self._peak_pps = 0.0
        self._pps = 0.0
        self._bps = 0.0
        self._history: deque = deque(maxlen=120)
        self._win_start = time.monotonic()
        self._win_pkts = 0
        self._win_bytes = 0

    # ------------------------------------------------------------- lifecycle

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="netlab-analysis",
                                        daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 2.0) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout)
            self._thread = None

    def reset(self) -> None:
        with self._lock:
            self.live.clear()
            self.flows.clear()
            self.hosts.clear()
            self.dns_events.clear()
            self.http_txns.clear()
            self.tls_sessions.clear()
            self.tls_order.clear()
            self._http_pending.clear()
            self.credentials.reset()
            self.reassembler.reset()
            self._http_messages = 0
            self._http_resyncs = 0
            self._tls_handshakes = 0
            self._index = 0
            self._total_packets = 0
            self._total_bytes = 0
            self._malformed = 0
            self._unsupported_lt = 0
            self._peak_pps = 0.0
            self._pps = 0.0
            self._bps = 0.0
            self._history.clear()
            self._win_start = time.monotonic()
            self._win_pkts = 0
            self._win_bytes = 0

    # ------------------------------------------------------------- main loop

    def _run(self) -> None:
        while not self._stop.is_set():
            batch = self._queue.get_batch(2048, timeout=0.2)
            if batch:
                self.ingest_batch(batch)
            self._roll_rates()
            if self._reassembly_enabled:
                self.reassembler.expire()

    def _roll_rates(self) -> None:
        now = time.monotonic()
        elapsed = now - self._win_start
        if elapsed < 1.0:
            return
        with self._lock:
            self._pps = self._win_pkts / elapsed
            self._bps = self._win_bytes / elapsed
            self._peak_pps = max(self._peak_pps, self._pps)
            self._history.append((time.time(), self._pps, self._bps))
            self._win_start = now
            self._win_pkts = 0
            self._win_bytes = 0

    # --------------------------------------------------------------- ingest

    def ingest_batch(self, raw_packets) -> None:
        rows = []
        for raw in raw_packets:
            row = self._ingest_one(raw)
            if row is not None:
                rows.append(row)
        if rows:
            self.live.extend(rows)

    def _ingest_one(self, raw) -> PacketRow | None:
        with self._lock:
            self._index += 1
            idx = self._index
            self._total_packets += 1
            self._total_bytes += raw.wirelen
            self._win_pkts += 1
            self._win_bytes += raw.wirelen

        if raw.linktype not in SUPPORTED_LINKTYPES:
            with self._lock:
                self._unsupported_lt += 1

        pkt = decode(raw.data, raw.linktype, raw.ts, raw.wirelen, idx)
        if pkt.error:
            with self._lock:
                self._malformed += 1

        flow = self.flows.update(pkt)
        self.hosts.update(pkt, flow)

        app = None
        try:
            app = self._analyze_application(pkt, flow)
        except Exception:
            # An analyzer bug must never take down the capture pipeline.
            with self._lock:
                self._malformed += 1

        if app and flow is not None and flow.app_proto is None:
            flow.app_proto = app

        return PacketRow(
            index=idx, ts=pkt.ts, src=pkt.src, dst=pkt.dst,
            proto=pkt.proto, sport=pkt.sport, dport=pkt.dport,
            length=pkt.wirelen, info=pkt.info, offset=raw.offset,
            linktype=raw.linktype, app=app, malformed=bool(pkt.error),
        )

    # ---------------------------------------------------- protocol dispatch

    def _analyze_application(self, pkt, flow) -> str | None:
        payload = pkt.payload

        if pkt.proto == "UDP":
            if payload and self.credentials.enabled:
                self.credentials.feed_datagram(pkt, payload)
            if payload and ((pkt.sport in dnsmod.DNS_PORTS)
                            or (pkt.dport in dnsmod.DNS_PORTS)):
                evt = dnsmod.extract_from_udp(payload, pkt.ts, pkt.src, pkt.dst,
                                              pkt.sport, pkt.dport, pkt.index)
                if evt:
                    self._record_dns(evt, flow)
                    return evt.protocol
            # QUIC (HTTP/3, UDP 443): the sites that no longer use TCP TLS --
            # Instagram, YouTube, Google, Facebook. The Initial's ClientHello is
            # readable, so the SNI is recovered the same way as for TLS.
            if payload and (pkt.dport == 443 or pkt.sport == 443):
                if quicmod.is_initial(payload):
                    if flow.app_proto is None:
                        flow.app_proto = "QUIC"
                    name = self._quic_sni.observe(payload)
                    if name:
                        if not flow.service:
                            flow.service = name
                        server = pkt.dst if pkt.dport == 443 else pkt.src
                        self.hosts.add_sni_name(server, name, pkt.ts)
                    return "QUIC"
            # DHCP (67/68) and NetBIOS name service (137): a device's own name.
            if payload and pkt.sport in (67, 68) or pkt.dport in (67, 68):
                info = namesmod.dhcp_hostname(payload)
                os_hint = namesmod.dhcp_os(payload)
                if info:
                    mac, name = info
                    self.hosts.add_hostname_by_mac(mac, name, pkt.ts,
                                                   "DHCP option 12")
                    os_hint = os_hint or namesmod.os_from_hostname(name)
                    if valid_ip(pkt.src):
                        self.hosts.add_device_name(pkt.src, name, pkt.ts,
                                                   "DHCP option 12")
                    if os_hint:
                        self.hosts.add_os_by_mac(mac, os_hint, pkt.ts,
                                                 "DHCP vendor/hostname")
                        if valid_ip(pkt.src):
                            self.hosts.add_os(pkt.src, os_hint, pkt.ts,
                                              "DHCP vendor/hostname")
                    return "DHCP"
            if payload and (pkt.sport == 137 or pkt.dport == 137):
                name = namesmod.nbns_name(payload)
                if name and valid_ip(pkt.src):
                    self.hosts.add_device_name(pkt.src, name, pkt.ts,
                                               "NetBIOS name service")
                    return "NBNS"
            return None

        if pkt.proto != "TCP":
            return None

        # DNS over TCP is a length-prefixed message that in practice arrives
        # whole; it is read per packet rather than through reassembly.
        if payload and (pkt.sport == 53 or pkt.dport == 53):
            evt = dnsmod.extract_from_tcp(payload, pkt.ts, pkt.src, pkt.dst,
                                          pkt.sport, pkt.dport, pkt.index)
            if evt:
                self._record_dns(evt, flow)
                return "DNS"

        if self._reassembly_enabled:
            # HTTP and TLS are parsed from the reassembled byte stream, so
            # this hands the segment over and lets the stream handlers decide.
            self.reassembler.push(pkt, flow)
            return flow.app_proto if flow is not None else None

        return self._analyze_packet_payload(pkt, flow, payload)

    def _analyze_packet_payload(self, pkt, flow, payload) -> str | None:
        """Per-packet fallback used when reassembly is switched off."""
        if not payload:
            return None
        if tlsmod.looks_like_tls(payload) and flow is not None:
            known = self.tls_sessions.get(flow.key) is not None
            port_hint = (flow.server_port in tlsmod.COMMON_TLS_PORTS
                         or flow.client_port in tlsmod.COMMON_TLS_PORTS)
            if known or port_hint or tlsmod.is_handshake_start(payload):
                sess = self._tls_session(flow, pkt.ts, pkt.index)
                tlsmod.feed_payload(payload, sess, pkt.src == flow.client)
                self._tls_observed(flow, sess, pkt.ts)
                return "TLS"
        if httpmod.looks_like_http(payload):
            msg = httpmod.parse_message(payload)
            if msg is not None and flow is not None:
                self._http_apply(flow, msg, pkt.src, pkt.sport, pkt.dst,
                                 pkt.dport, pkt.ts, pkt.index)
                return "HTTP"
        return None

    # ------------------------------------------------- reassembled streams

    def _stream_state(self, stream, index) -> dict:
        state = stream.app_state.get(index)
        if state is None:
            state = {"kind": None, "sniffs": 0, "http": None, "tls": None}
            stream.app_state[index] = state
        return state

    def _classify(self, stream, index, data, flow) -> str | None:
        """Decide once per direction what this byte stream is."""
        state = self._stream_state(stream, index)
        if state["kind"] is not None:
            return state["kind"]

        sibling = stream.app_state.get(1 - index)
        if sibling and sibling.get("kind") in ("tls", "http"):
            state["kind"] = sibling["kind"]
            return state["kind"]

        port_hint = False
        if flow is not None:
            port_hint = (flow.server_port in tlsmod.COMMON_TLS_PORTS
                         or flow.client_port in tlsmod.COMMON_TLS_PORTS)
        if tlsmod.looks_like_tls(data) and (port_hint
                                            or tlsmod.is_handshake_start(data)):
            state["kind"] = "tls"
        elif httpmod.looks_like_http(data):
            state["kind"] = "http"
        else:
            state["sniffs"] += 1
            if state["sniffs"] >= 4:
                # Stop paying for detection on a stream that is neither.
                state["kind"] = "other"
        return state["kind"]

    def _on_stream_data(self, stream, index, data, pkt, flow) -> None:
        state = self._stream_state(stream, index)
        if state["kind"] is None:
            prefix = state.pop("prefix", b"") + data
            # Detection needs only a bounded prefix, but must survive even
            # one-byte TCP segments at the beginning of a conversation.
            probe = prefix[:32]
            signatures = [m + b" " for m in httpmod.METHODS] + [b"HTTP/"]
            partial_http = len(probe) < 16 and any(
                signature.startswith(probe) or probe.startswith(signature)
                for signature in signatures)
            partial_tls = len(probe) < 5 and probe[:1] in (b"\x16", b"\x14", b"\x15", b"\x17")
            if len(prefix) < 32 and (partial_http or partial_tls):
                state["prefix"] = prefix
                return
            data = prefix
        if self.credentials.enabled and flow is not None:
            try:
                self.credentials.feed_stream(stream.key, index, data, flow, pkt)
            except Exception:
                # A protocol handler must never break the capture pipeline.
                with self._lock:
                    self._malformed += 1
        kind = self._classify(stream, index, data, flow)
        if kind == "tls":
            self._feed_tls_stream(stream, index, data, pkt, flow)
        elif kind == "http":
            self._feed_http_stream(stream, index, data, pkt, flow)

    def _on_stream_gap(self, stream, index, nbytes, flow) -> None:
        state = stream.app_state.get(index)
        if not state:
            return
        state.pop("prefix", None)
        if state.get("http") is not None:
            state["http"].on_gap(nbytes)
            self._http_resyncs += 1
        if state.get("tls") is not None:
            state["tls"].on_gap(nbytes)

    def _on_stream_retire(self, stream) -> None:
        """Keep a retired stream's statistics on its flow before it is freed."""
        flow = self.flows.get(stream.key)
        if flow is not None:
            flow.reasm = stream.summary(live=False)

    def _on_stream_close(self, stream, index, reason, flow) -> None:
        state = stream.app_state.get(index)
        if not state:
            return
        if state.get("http") is not None:
            state["http"].on_close(reason)

    # ------------------------------------------------------------ TLS glue

    def _tls_session(self, flow, ts, packet_index):
        sess, created = self.tls_sessions.get_or_create(
            flow.key, lambda: tlsmod.TlsSession(
                ts=ts, flow_key=flow.key, client=flow.client,
                server=flow.server, client_port=flow.client_port,
                server_port=flow.server_port, packet_index=packet_index))
        if created:
            self.tls_order.append(sess)
        return sess

    def _tls_observed(self, flow, sess, ts) -> None:
        flow.encrypted = True
        flow.app_proto = "TLS"
        if sess.sni:
            if not flow.service:
                flow.service = sess.sni
            self.hosts.add_sni_name(sess.server or flow.server, sess.sni, ts)

    def _feed_tls_stream(self, stream, index, data, pkt, flow) -> None:
        if flow is None:
            return
        state = self._stream_state(stream, index)
        sess = self._tls_session(flow, pkt.ts, pkt.index)
        parser = state.get("tls")
        if parser is None:
            parser = tlsmod.TlsRecordAssembler(
                int(self._cfg.get("tls_handshake_limit")))
            state["tls"] = parser
        had_hello = sess.saw_client_hello or sess.saw_server_hello
        parser.feed(data, sess, stream.endpoint(index) == (flow.client, flow.client_port))
        if not had_hello and (sess.saw_client_hello or sess.saw_server_hello):
            self._tls_handshakes += 1
        self._tls_observed(flow, sess, pkt.ts)

    # ----------------------------------------------------------- HTTP glue

    def _feed_http_stream(self, stream, index, data, pkt, flow) -> None:
        if flow is None:
            return
        state = self._stream_state(stream, index)
        parser = state.get("http")
        if parser is None:
            parser = httpmod.HttpStreamParser(
                int(self._cfg.get("http_header_limit")))
            parser.on_message = (
                lambda msg, prs, st=stream, ix=index:
                self._http_stream_message(st, ix, msg, prs))
            parser.on_body_end = (
                lambda msg, n, chunks, transfer, complete, gap,
                st=stream, ix=index, prs=parser:
                self._http_stream_body(st, ix, msg, n, chunks, transfer,
                                       complete, gap, prs))
            if self.credentials.enabled:
                parser.on_body_data = (
                    lambda msg, chunk, st=stream, ix=index:
                    self._http_stream_body_data(st, ix, msg, chunk))
            state["http"] = parser
        state["last_ts"] = pkt.ts
        state["last_index"] = pkt.index
        parser.feed(data)

    def _http_stream_message(self, stream, index, msg, parser) -> None:
        flow = self.flows.get(stream.key)
        if flow is None:
            return
        state = self._stream_state(stream, index)
        ts = state.get("last_ts", 0.0)
        packet_index = state.get("last_index", 0)
        src_ip, src_port = stream.endpoint(index)
        dst_ip, dst_port = stream.endpoint(1 - index)
        self._http_messages += 1
        txn = self._http_apply(flow, msg, src_ip, src_port, dst_ip, dst_port,
                               ts, packet_index)
        parser.netlab_txn = txn
        if msg.kind == "response" and txn is not None:
            msg.response_to_method = txn.method
        if self.credentials.enabled and msg.kind == "request":
            state["cred_body"] = bytearray()
            self.credentials.feed_http(msg, flow, _PacketRef(ts, packet_index))

    def _http_stream_body_data(self, stream, index, msg, chunk) -> None:
        """A request body arrives after its headers, so the form-field pass
        runs again once enough of it has been seen."""
        if msg is None or getattr(msg, "kind", "") != "request":
            return
        state = self._stream_state(stream, index)
        body = state.get("cred_body")
        if body is None:
            body = bytearray()
            state["cred_body"] = body
        if len(body) >= MAX_CRED_BODY:
            return
        body.extend(chunk[:MAX_CRED_BODY - len(body)])
        flow = self.flows.get(stream.key)
        if flow is None:
            return
        self.credentials.feed_http(
            msg, flow, _PacketRef(state.get("last_ts", 0.0),
                                  state.get("last_index", 0)),
            body=bytes(body))

    def _http_stream_body(self, stream, index, msg, nbytes, chunks, transfer,
                          complete, gap, parser) -> None:
        txn = getattr(parser, "netlab_txn", None)
        if txn is None or (msg.kind == "response" and 100 <= (msg.status or 0) < 200):
            return
        if msg.kind == "request":
            txn.req_body_bytes = nbytes
            txn.req_chunks = chunks
            txn.req_transfer = transfer
            txn.req_body_complete = complete
        else:
            txn.resp_body_bytes = nbytes
            txn.resp_chunks = chunks
            txn.resp_transfer = transfer
            txn.resp_body_complete = complete
        if gap:
            txn.saw_gap = True
            if "stream gap: body truncated" not in txn.notes:
                txn.notes.append("stream gap: body truncated")

    def _http_apply(self, flow, msg, src_ip, src_port, dst_ip, dst_port,
                    ts, packet_index):
        """Create or complete a transaction from a parsed HTTP message."""
        key = flow.key
        pending, _ = self._http_pending.get_or_create(key, lambda: deque(maxlen=8))

        if msg.kind == "request":
            host = msg.headers.get("host")
            txn = httpmod.HttpTransaction(
                ts=ts, flow_key=key, client=src_ip, server=dst_ip,
                client_port=src_port, server_port=dst_port,
                method=msg.method, host=host, path=msg.target,
                version=msg.version,
                user_agent=msg.headers.get("user-agent"),
                referer=msg.headers.get("referer"),
                req_content_type=msg.headers.get("content-type"),
                req_content_length=msg.headers.get("content-length"),
                req_has_auth=msg.has_auth_header,
                req_has_cookie=msg.has_cookie_header,
                req_packet_index=packet_index,
            )
            if msg.headers_truncated:
                txn.notes.append("request headers truncated")
            self.http_txns.append(txn)
            pending.append(txn)
            flow.app_proto = "HTTP"
            if host and not flow.service:
                flow.service = host
            ua_os = namesmod.os_from_user_agent(msg.headers.get("user-agent") or "")
            if ua_os:
                self.hosts.add_os(src_ip, ua_os, ts, "HTTP User-Agent")
            if host:
                self.hosts.add_dns_name(dst_ip, host.split(":")[0], ts,
                                        source="http-host")
            return txn

        if 100 <= (msg.status or 0) < 200 and msg.status != 101:
            # Interim responses do not consume a pending request.
            return pending[0] if pending else None
        txn = None
        while pending:
            candidate = pending.popleft()
            if candidate.status is None:
                txn = candidate
                break
        if txn is None:
            txn = httpmod.HttpTransaction(
                ts=ts, flow_key=key, client=dst_ip, server=src_ip,
                client_port=dst_port, server_port=src_port,
                req_packet_index=packet_index)
            txn.notes.append("response seen without a matching request")
            self.http_txns.append(txn)
        txn.status = msg.status
        txn.reason = msg.reason
        txn.content_type = msg.headers.get("content-type")
        txn.content_length = msg.headers.get("content-length")
        txn.server_header = msg.headers.get("server")
        txn.location = msg.headers.get("location")
        txn.resp_has_set_cookie = msg.has_cookie_header
        txn.resp_ts = ts
        txn.resp_packet_index = packet_index
        if msg.headers_truncated:
            txn.notes.append("response headers truncated")
        flow.app_proto = "HTTP"
        return txn

    def _record_dns(self, evt, flow) -> None:
        self.dns_events.append(evt)
        self.hosts.note_dns(evt.src if evt.kind == "query" else evt.dst, evt.qname, evt.ts)
        if flow is not None:
            flow.app_proto = evt.protocol
            if evt.qname and not flow.service:
                flow.service = evt.qname
        if self._cfg.get("resolve_dns_names"):
            for answer in evt.answers:
                if answer.rtype in ("A", "AAAA") and answer.name:
                    self.hosts.add_dns_name(answer.value, answer.name, evt.ts)
            for ans in evt.answers:
                if ans.rtype == "PTR" and evt.qname and \
                        evt.qname.endswith(".in-addr.arpa"):
                    octets = evt.qname.split(".")[:4][::-1]
                    if len(octets) == 4 and all(o.isdigit() for o in octets):
                        self.hosts.add_dns_name(".".join(octets), ans.value,
                                                evt.ts)

    def stats(self) -> Stats:
        with self._lock:
            s = Stats(
                total_packets=self._total_packets,
                total_bytes=self._total_bytes,
                packets_per_sec=self._pps,
                bytes_per_sec=self._bps,
                peak_pps=self._peak_pps,
                malformed=self._malformed,
                unsupported_linktype=self._unsupported_lt,
                history=list(self._history),
            )
        s.flows = len(self.flows)
        s.active_flows = self.flows.active_count()
        s.hosts = len(self.hosts)
        s.dns_events = self.dns_events.total_seen
        s.http_transactions = self.http_txns.total_seen
        s.tls_sessions = len(self.tls_sessions)
        s.credentials = self.credentials.found
        s.queue_dropped = self._queue.dropped
        s.queue_depth = self._queue.qsize()
        s.flows_evicted = self.flows.evicted
        s.hosts_evicted = self.hosts.evicted

        r = self.reassembler.stats()
        s.streams = r.streams
        s.streams_created = r.streams_created
        s.streams_expired = r.streams_expired
        s.streams_evicted = r.streams_evicted
        s.reassembled_bytes = r.bytes_reassembled
        s.reassembly_segments = r.segments
        s.retransmissions = r.retransmissions
        s.out_of_order = r.out_of_order
        s.stream_gaps = r.gaps
        s.stream_gap_bytes = r.gap_bytes
        s.reasm_buffered_bytes = r.buffered_bytes
        s.reasm_peak_buffered = r.peak_buffered_bytes
        s.http_messages = self._http_messages
        s.http_resyncs = self._http_resyncs
        s.tls_handshakes = self._tls_handshakes
        return s

    def packets_for_flow(self, key) -> list[PacketRow]:
        """Rows belonging to one conversation, for double-click drill-down."""
        out = []
        for row in self.live.snapshot():
            if row.src is None or row.dst is None:
                continue
            rkey, _ = make_flow_key(row.proto, row.src, row.sport,
                                    row.dst, row.dport)
            if rkey == key:
                out.append(row)
        return out

    def relations_for_flow(self, flow) -> dict:
        """Everything known about one connection, for the flow detail view.

        Called on selection, not on the refresh timer, so a linear scan of
        the bounded protocol rings is the right trade here.
        """
        key = flow.key
        http = [t for t in self.http_txns.snapshot() if t.flow_key == key]
        tls = self.tls_sessions.get(key)
        stream = self.reassembler.get(key) if self._reassembly_enabled else None
        summary = stream.summary(live=True) if stream is not None else flow.reasm

        dns = []
        wanted = {flow.server, flow.client}
        service = (flow.service or "").rstrip(".")
        for evt in self.dns_events.snapshot():
            if any(ip in wanted for ip in evt.resolved_ips):
                dns.append(evt)
            elif service and evt.qname and evt.qname.rstrip(".") == service:
                dns.append(evt)
        return {"http": http, "tls": tls, "dns": dns[-10:], "stream": stream,
                "summary": summary, "packets": self.packets_for_flow(key)}

    def stream_for_flow(self, key):
        return self.reassembler.get(key) if self._reassembly_enabled else None

    def stream_summary_for_flow(self, flow):
        """Live stream statistics if it is still tracked, otherwise the
        summary kept when it was retired."""
        if flow is None:
            return None
        stream = self.stream_for_flow(flow.key)
        if stream is not None:
            return stream.summary(live=True)
        return flow.reasm

    def flow_for_packet(self, row):
        """Resolve the connection a Live Traffic row belongs to."""
        if row is None or row.src is None or row.dst is None:
            return None
        key, _ = make_flow_key(row.proto, row.src, row.sport, row.dst, row.dport)
        return self.flows.get(key)

    def packets_for_host(self, ip: str) -> list[PacketRow]:
        return [r for r in self.live.snapshot() if r.src == ip or r.dst == ip]


    def endpoint_view(self, now=None):
        now = time.time() if now is None else now
        flows = [replace(f) for f in self.flows.snapshot()]
        active = {}
        for flow in flows:
            if flow.is_active(now):
                for ip in {flow.client, flow.server}:
                    active[ip] = active.get(ip, 0) + 1
        return self.hosts.device_snapshots(now, active), flows

    def device_view(self, now=None):
        now = time.time() if now is None else now
        endpoints, flows = self.endpoint_view(now)
        return local_devices(endpoints, flows, self.hosts.context, now), flows

    def resolve_device(self, reference, now=None):
        reference = valid_ip(reference) or reference
        return next((d for d in self.device_view(now)[0]
                     if reference == d.identity or reference in d.addresses), None)

    def addresses_for(self, reference):
        if isinstance(reference, (tuple, list, set, frozenset)):
            return set(reference)
        device = self.resolve_device(reference)
        return set(device.addresses) if device else {valid_ip(reference)} - {None}

    def network_view(self, now=None):
        now = time.time() if now is None else now
        endpoints, flows = self.endpoint_view(now)
        devices = local_devices(endpoints, flows, self.hosts.context, now)
        local_ips = {ip for d in devices for ip in d.addresses}
        return topology_snapshot(devices, flows, self.hosts.context, now,
                                 endpoints=tuple(e for e in endpoints if e.ip not in local_ips
                                                 and not self.hosts.context.on_link(e.ip)
                                                 and (e.packets or e.evidence)))

    def relations_for_device(self, ip):
        addresses = self.addresses_for(ip)
        flows = [f for f in self.flows.snapshot() if addresses.intersection((f.client, f.server))]
        destinations = {}
        for flow in flows:
            other = flow.server if flow.client in addresses else flow.client
            packets, nbytes = destinations.get(other, (0, 0))
            destinations[other] = (packets + flow.packets, nbytes + flow.bytes)
        return {
            "connections": flows,
            "dns": [e for e in self.dns_events.snapshot() if addresses.intersection((e.src, e.dst, *e.resolved_ips))],
            "http": [t for t in self.http_txns.snapshot() if addresses.intersection((t.client, t.server))],
            "tls": [t for t in self.tls_order.snapshot() if addresses.intersection((t.client, t.server))],
            "destinations": sorted(destinations.items(), key=lambda item: item[1][1], reverse=True)[:12],
        }
