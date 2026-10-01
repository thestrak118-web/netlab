"""Flow (connection) and host correlation.

A flow is one bidirectional conversation keyed on
`(proto, ip_a, port_a, ip_b, port_b)` with the endpoints ordered
canonically so both directions land on the same record.  The side that was
seen first (or that sent the TCP SYN) is remembered as the client.

Both tables are bounded LRU structures; when the cap is reached the least
recently active entries are evicted and counted, and the GUI reports that
so the operator is never shown a silently truncated picture.
"""

from __future__ import annotations

import ipaddress
import time
import threading
from collections import deque
from functools import wraps
from netlab.analyze.devices import (Confidence, Evidence, NetworkContext, OuiDatabase, EndpointSnapshot, valid_ip, valid_mac)
from netlab.analyze import names as namesmod
from dataclasses import dataclass, field

from netlab.util.bounded import BoundedLRUDict, BoundedRing

FlowKey = tuple


def make_flow_key(proto: str, src: str, sport, dst: str, dport) -> tuple[FlowKey, bool]:
    """Return (canonical_key, src_is_side_a)."""
    a = (src, sport if sport is not None else -1)
    b = (dst, dport if dport is not None else -1)
    if a <= b:
        return (proto, a[0], a[1], b[0], b[1]), True
    return (proto, b[0], b[1], a[0], a[1]), False


def is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return bool(addr.is_private or addr.is_loopback or addr.is_link_local)


@dataclass(slots=True)
class Flow:
    key: FlowKey
    proto: str
    client: str
    client_port: int | None
    server: str
    server_port: int | None
    first_ts: float = 0.0
    last_ts: float = 0.0

    pkts_c2s: int = 0
    pkts_s2c: int = 0
    bytes_c2s: int = 0
    bytes_s2c: int = 0

    saw_syn: bool = False
    saw_synack: bool = False
    saw_fin: bool = False
    saw_rst: bool = False

    app_proto: str | None = None       # "TLS", "HTTP", "DNS", ...
    service: str | None = None         # SNI / HTTP Host / DNS qname
    encrypted: bool = False
    first_packet_index: int = 0
    # Reassembly facts, retained after the stream itself is retired.
    reasm: object | None = None

    @property
    def packets(self) -> int:
        return self.pkts_c2s + self.pkts_s2c

    @property
    def bytes(self) -> int:
        return self.bytes_c2s + self.bytes_s2c

    @property
    def duration(self) -> float:
        return max(0.0, self.last_ts - self.first_ts)

    @property
    def state(self) -> str:
        if self.proto != "TCP":
            return "-"
        if self.saw_rst:
            return "RESET"
        if self.saw_fin:
            return "CLOSING"
        if self.saw_synack:
            return "ESTABLISHED"
        if self.saw_syn:
            return "SYN_SENT"
        return "ONGOING"

    def is_active(self, now: float, idle_timeout: float = 60.0) -> bool:
        return not (self.saw_fin or self.saw_rst) and (now - self.last_ts) <= idle_timeout


MAX_NAMES_PER_HOST = 16
MAX_FLOWS_PER_HOST = 512


@dataclass(slots=True)
class Host:
    ip: str
    macs: set[str] = field(default_factory=set)
    # Names are kept apart by where they came from. A CDN address can serve
    # many unrelated sites, so observing several names for one IP is a fact
    # about the address, not evidence that the names belong together - and a
    # name a client *asked for* (SNI/Host) is a weaker claim than one a
    # resolver actually *answered* with.
    dns_names: set[str] = field(default_factory=set)
    sni_names: set[str] = field(default_factory=set)
    http_names: set[str] = field(default_factory=set)
    flow_keys: set = field(default_factory=set)
    active_flows: int = 0
    total_flows: int = 0
    first_ts: float = 0.0
    last_ts: float = 0.0
    pkts_sent: int = 0
    pkts_recv: int = 0
    bytes_sent: int = 0
    bytes_recv: int = 0
    tcp_ports_served: set[int] = field(default_factory=set)
    udp_ports_served: set[int] = field(default_factory=set)
    local: bool = False
    evidence: dict = field(default_factory=dict)
    contacted_names: set = field(default_factory=set)
    recent: deque = field(default_factory=lambda: deque(maxlen=60))
    device_type: str = "Unknown"
    manufacturer: str = "Unknown"
    os: str = "Unknown"
    scope: str = "Unknown"

    def observe(self, field_name, value, source, level, ts):
        if not value or value == "Unknown":
            return
        key = (field_name, value, source)
        if key in self.evidence or len(self.evidence) < 128:
            self.evidence[key] = Evidence(field_name, value, source, level, ts)

    def traffic(self, ts, size):
        second = int(ts)
        if self.recent and self.recent[-1][0] == second:
            t, count, nbytes = self.recent.pop()
            self.recent.append((t, count + 1, nbytes + size))
        else:
            self.recent.append((second, 1, size))

    @property
    def packets(self) -> int:
        return self.pkts_sent + self.pkts_recv

    @property
    def bytes(self) -> int:
        return self.bytes_sent + self.bytes_recv

    @property
    def mac(self) -> str | None:
        return sorted(self.macs)[0] if self.macs else None

    @property
    def hostnames(self) -> set[str]:
        """Every name observed for this address, from any source."""
        return self.dns_names | self.sni_names | self.http_names

    @property
    def all_names(self) -> list[str]:
        return sorted(self.hostnames)

    @property
    def hostname(self) -> str | None:
        names = self.all_names
        return names[0] if names else None

    @property
    def names_display(self) -> str | None:
        """Never collapses several names into one implied identity."""
        names = self.all_names
        if not names:
            return None
        if len(names) == 1:
            return names[0]
        return "%s  (+%d more)" % (names[0], len(names) - 1)

    @property
    def ports_summary(self) -> str:
        parts = []
        if self.tcp_ports_served:
            parts.append("tcp/" + ",".join(str(p) for p in
                                           sorted(self.tcp_ports_served)[:12]))
        if self.udp_ports_served:
            parts.append("udp/" + ",".join(str(p) for p in
                                           sorted(self.udp_ports_served)[:12]))
        return "  ".join(parts)


class FlowTable:
    def __init__(self, capacity: int) -> None:
        self._flows = BoundedLRUDict(capacity)
        # LRU order shifts every time a flow is touched, which would make the
        # table reshuffle under the operator on every refresh. Keep a separate
        # creation-ordered ring purely for display.
        self._order = BoundedRing(capacity)

    @property
    def evicted(self) -> int:
        return self._flows.evicted

    def __len__(self) -> int:
        return len(self._flows)

    def clear(self) -> None:
        self._flows.clear()
        self._order.clear()

    def ordered(self) -> list[Flow]:
        """Flows in the order they were first observed (stable for the GUI)."""
        return self._order.snapshot()

    def get(self, key: FlowKey) -> Flow | None:
        return self._flows.get(key)

    def update(self, pkt) -> Flow | None:
        """Fold one decoded packet into its flow. Returns the flow."""
        if pkt.src is None or pkt.dst is None:
            return None
        proto = pkt.proto if pkt.proto in ("TCP", "UDP", "ICMP", "ICMPv6",
                                           "SCTP", "ARP") else pkt.proto
        key, src_is_a = make_flow_key(proto, pkt.src, pkt.sport, pkt.dst, pkt.dport)

        def _new() -> Flow:
            # The first packet seen defines the provisional client side.
            return Flow(key=key, proto=proto, client=pkt.src,
                        client_port=pkt.sport, server=pkt.dst,
                        server_port=pkt.dport, first_ts=pkt.ts,
                        last_ts=pkt.ts, first_packet_index=pkt.index)

        flow, created = self._flows.get_or_create(key, _new)
        if created:
            self._order.append(flow)

        if pkt.proto == "TCP" and pkt.tcp_flags:
            flags = pkt.tcp_flags
            syn = "SYN" in flags
            ack = "ACK" in flags
            if syn and not ack:
                flow.saw_syn = True
                # A SYN is authoritative about which side is the client.
                if flow.client != pkt.src:
                    flow.client, flow.server = pkt.src, pkt.dst
                    flow.client_port, flow.server_port = pkt.sport, pkt.dport
            elif syn and ack:
                flow.saw_synack = True
                if flow.server != pkt.src:
                    flow.client, flow.server = pkt.dst, pkt.src
                    flow.client_port, flow.server_port = pkt.dport, pkt.sport
            if "FIN" in flags:
                flow.saw_fin = True
            if "RST" in flags:
                flow.saw_rst = True

        forward = (pkt.src == flow.client and pkt.sport == flow.client_port)
        if forward:
            flow.pkts_c2s += 1
            flow.bytes_c2s += pkt.wirelen
        else:
            flow.pkts_s2c += 1
            flow.bytes_s2c += pkt.wirelen
        if pkt.ts:
            if not flow.first_ts:
                flow.first_ts = pkt.ts
            flow.last_ts = max(flow.last_ts, pkt.ts)
        return flow

    def snapshot(self) -> list[Flow]:
        return self._flows.values()

    def active_count(self, idle_timeout: float = 60.0) -> int:
        now = time.time()
        return sum(1 for f in self._flows.values() if f.is_active(now, idle_timeout))


def host_locked(fn):
    @wraps(fn)
    def wrapped(self, *args, **kwargs):
        with self.lock:
            return fn(self, *args, **kwargs)
    return wrapped


class HostTable:
    def __init__(self, capacity: int) -> None:
        self.lock = threading.RLock()
        self.context = NetworkContext()
        self.oui = OuiDatabase()
        self._hosts = BoundedLRUDict(capacity)
        self._order = BoundedRing(capacity)
        self._mac_hostnames: dict[str, tuple[str, str]] = {}
        self._mac_os: dict[str, tuple[str, str]] = {}
        self._ttl_seen: set[str] = set()

    @property
    def evicted(self) -> int:
        return self._hosts.evicted

    def __len__(self) -> int:
        return len(self._hosts)

    @host_locked
    def clear(self) -> None:
        self.context = NetworkContext()
        self._hosts.clear()
        self._order.clear()

    @host_locked
    def ordered(self) -> list[Host]:
        """Hosts in the order they were first observed."""
        return self._hosts.values()

    @host_locked
    def get(self, ip: str) -> Host | None:
        return self._hosts.get(valid_ip(ip) or ip)

    def _touch(self, ip: str, ts: float) -> Host:
        host, created = self._hosts.get_or_create(
            ip, lambda: Host(ip=ip, first_ts=ts))
        if created:
            self._order.append(host)
            try:
                if ipaddress.ip_address(ip).is_global:
                    host.scope = "Remote"
            except ValueError:
                pass
            if self.context.on_link(ip):
                host.scope = "Local"
                host.local = True
        if ts:
            if not host.first_ts:
                host.first_ts = ts
            host.last_ts = max(host.last_ts, ts)
        return host

    @host_locked
    def update(self, pkt, flow: Flow | None) -> None:
        if pkt.error:
            return
        src_ip, dst_ip = valid_ip(pkt.src), valid_ip(pkt.dst)
        # An ARP question is not evidence that its target exists. Only a valid
        # target hardware binding can establish the other host.
        if pkt.proto == 'ARP' and not valid_mac(pkt.arp_target_mac):
            if dst_ip:
                # Retain the referenced endpoint for existing HostTable callers,
                # with no traffic, MAC binding or presence evidence.
                self._touch(dst_ip, 0)
            dst_ip = None
        if src_ip is None and dst_ip is None:
            return
        # Multicast/broadcast endpoints are not devices; still count the
        # valid peer's traffic without adding a fictitious broadcast host.
        if src_ip is None or dst_ip is None:
            ip = src_ip or dst_ip
            host = self._touch(ip, pkt.ts)
            if src_ip:
                host.pkts_sent += 1; host.bytes_sent += pkt.wirelen
            else:
                host.pkts_recv += 1; host.bytes_recv += pkt.wirelen
            host.traffic(pkt.ts, pkt.wirelen)
            host.observe("IP", ip, "Captured endpoint", Confidence.OBSERVED, pkt.ts)
            if pkt.proto == 'ARP' and valid_mac(pkt.arp_sender_mac):
                self._observe_mac(host, pkt.arp_sender_mac, 'ARP address binding', pkt.ts)
                host.local = True
                host.scope = 'Local'
            elif self.context.on_link(ip):
                self._observe_mac(host, pkt.src_mac if src_ip else pkt.dst_mac,
                                  "Ethernet frame + on-link routing prefix", pkt.ts)
            return
        src = self._touch(src_ip, pkt.ts)
        dst = self._touch(dst_ip, pkt.ts)
        src.pkts_sent += 1
        src.bytes_sent += pkt.wirelen
        dst.pkts_recv += 1
        dst.bytes_recv += pkt.wirelen

        for host, mac, arp_mac in ((src, pkt.src_mac, pkt.arp_sender_mac),
                                    (dst, pkt.dst_mac, pkt.arp_target_mac)):
            host.observe("IP", host.ip, "Captured " + pkt.proto + " endpoint", Confidence.OBSERVED, pkt.ts)
            host.traffic(pkt.ts, pkt.wirelen)
            if valid_mac(arp_mac):
                self._observe_mac(host, arp_mac, "ARP address binding", pkt.ts)
                host.local = True
                host.scope = "Local"
            elif self.context.on_link(host.ip):
                self._observe_mac(host, mac, "Ethernet frame + on-link routing prefix", pkt.ts)

        # A local host's TTL reveals its OS family (Unix / Windows / network
        # device) even when it never DHCPs or browses — like Intercepter-NG's
        # passive fingerprint. Done once per host to stay cheap.
        if (pkt.ttl and src_ip not in self._ttl_seen
                and (src.local or self.context.on_link(src_ip))):
            self._ttl_seen.add(src_ip)
            os = namesmod.os_from_ttl(pkt.ttl)
            if os:
                # The TTL value is the fingerprint basis; kept in the source so
                # the device detail shows how the OS was guessed.
                src.observe("OS", os, "TCP/IP TTL=%d" % pkt.ttl,
                            Confidence.OBSERVED, pkt.ts)

        if flow is not None:
            for host in (src, dst):
                if flow.key in host.flow_keys:
                    continue
                host.total_flows += 1
                if len(host.flow_keys) < MAX_FLOWS_PER_HOST:
                    host.flow_keys.add(flow.key)

        # Record a listening port only when we actually saw the server
        # accept (SYN/ACK) or answer, not merely because someone probed it.
        if flow and flow.server == pkt.src and flow.server_port:
            if pkt.proto == "TCP" and flow.saw_synack:
                src.tcp_ports_served.add(flow.server_port)
            elif pkt.proto == "UDP":
                src.udp_ports_served.add(flow.server_port)

    @host_locked
    def add_dns_name(self, ip: str, name: str, ts: float = 0.0,
                     source: str = "dns") -> None:
        """A name a resolver answered with, or an HTTP Host header."""
        ip = valid_ip(ip)
        if not ip or not name:
            return
        host = self._touch(ip, ts)
        names = host.http_names if source == "http-host" else host.dns_names
        if len(names) < MAX_NAMES_PER_HOST:
            names.add(name.rstrip("."))
            host.observe("Hostname" if source == "dns" else "HTTP Host", name.rstrip("."),
                         "DNS answer" if source == "dns" else "HTTP request Host", Confidence.OBSERVED, ts)

    @host_locked
    def add_sni_name(self, ip: str, name: str, ts: float = 0.0) -> None:
        """A name a *client asked for*. Kept apart from resolver answers."""
        ip = valid_ip(ip)
        if not ip or not name:
            return
        host = self._touch(ip, ts)
        if len(host.sni_names) < MAX_NAMES_PER_HOST:
            host.sni_names.add(name.rstrip("."))
            host.observe("TLS SNI", name.rstrip("."), "TLS ClientHello", Confidence.OBSERVED, ts)

    # Kept for callers that do not distinguish the source.
    def add_hostname(self, ip: str, name: str, ts: float = 0.0) -> None:
        self.add_dns_name(ip, name, ts)

    @host_locked
    def add_os(self, ip: str, os: str, ts: float = 0.0,
               source: str = "DHCP vendor class") -> None:
        """The device's operating system (Windows / Android / …)."""
        ip = valid_ip(ip)
        if not ip or not os:
            return
        self._touch(ip, ts).observe("OS", os, source, Confidence.OBSERVED, ts)

    @host_locked
    def add_os_by_mac(self, mac: str, os: str, ts: float = 0.0,
                      source: str = "DHCP vendor class") -> None:
        """OS learned by MAC (a DHCP DISCOVER before the host has an IP)."""
        mac = valid_mac(mac)
        if not mac or not os:
            return
        self._mac_os[mac] = (os, source)
        if len(self._mac_os) > 4096:
            self._mac_os.clear()
            self._mac_os[mac] = (os, source)
        for host in self._hosts.values():
            if mac in host.macs:
                host.observe("OS", os, source, Confidence.OBSERVED, ts)

    @host_locked
    def add_device_name(self, ip: str, name: str, ts: float = 0.0,
                        source: str = "DHCP option 12") -> None:
        """A device's own advertised name, bound to its IP (DHCP renewal, NBNS)."""
        ip = valid_ip(ip)
        if not ip or not name:
            return
        host = self._touch(ip, ts)
        if len(host.dns_names) < MAX_NAMES_PER_HOST:
            host.dns_names.add(name.rstrip("."))
            host.observe("Hostname", name.rstrip("."), source,
                         Confidence.OBSERVED, ts)

    @host_locked
    def add_hostname_by_mac(self, mac: str, name: str, ts: float = 0.0,
                            source: str = "DHCP option 12") -> None:
        """A device's own name, learned from DHCP/NBNS and keyed by MAC.

        It is cached so a DISCOVER seen before the host has an IP still names
        the host later, and applied immediately to any host already on record
        with this MAC.
        """
        mac = valid_mac(mac)
        if not mac or not name:
            return
        self._mac_hostnames[mac] = (name, source)
        if len(self._mac_hostnames) > 4096:
            self._mac_hostnames.clear()
            self._mac_hostnames[mac] = (name, source)
        for host in self._hosts.values():
            if mac in host.macs and len(host.dns_names) < MAX_NAMES_PER_HOST:
                host.dns_names.add(name)
                host.observe("Hostname", name, source, Confidence.OBSERVED, ts)

    @host_locked
    def note_flow(self, ip: str, key, ts: float = 0.0) -> None:
        if not ip:
            return
        host = self._touch(ip, ts)
        if key not in host.flow_keys:
            host.total_flows += 1
            if len(host.flow_keys) < MAX_FLOWS_PER_HOST:
                host.flow_keys.add(key)

    @host_locked
    def recount_active(self, flow_table, idle_timeout: float = 60.0) -> None:
        """Refresh per-host active-flow counts from the live flow table."""
        now = time.time()
        counts: dict[str, int] = {}
        for flow in flow_table.snapshot():
            if not flow.is_active(now, idle_timeout):
                continue
            counts[flow.client] = counts.get(flow.client, 0) + 1
            counts[flow.server] = counts.get(flow.server, 0) + 1
        for host in self._hosts.values():
            host.active_flows = counts.get(host.ip, 0)

    @host_locked
    def snapshot(self) -> list[Host]:
        return self._hosts.values()


    def _observe_mac(self, host, mac, source, ts):
        mac = valid_mac(mac)
        if not mac:
            return
        own_macs = {m for _, m, _ in self.context.addresses if m}
        own_ips = {ip for ip, _, _ in self.context.addresses}
        # Locally forwarded traffic and our own MITM ARP announcements use
        # this interface's MAC for someone else's IP. They remain captured
        # packets, but are not evidence of that peer's hardware identity.
        if mac in own_macs and host.ip not in own_ips:
            return
        if source == 'Ethernet frame + on-link routing prefix':
            gateways = {ip for _, ip in self.context.gateways}
            next_hop_macs = {m for ip, m in self.context.neighbors if ip in gateways}
            bindings = dict(self.context.neighbors)
            if host.ip in bindings and mac != bindings[host.ip] and mac in bindings.values():
                return
            # A link-local address (fe80::) is the device's own, never a routed
            # peer behind the gateway's next-hop MAC -- so the MAC on its frame
            # really is that device's, and must be recorded (it is what merges a
            # router's IPv4 with its own fe80:: into one device).
            try:
                is_link_local = ipaddress.ip_address(host.ip).is_link_local
            except ValueError:
                is_link_local = False
            if not is_link_local and (
                    (mac in next_hop_macs and host.ip not in gateways)
                    or (mac in own_macs and host.ip not in own_ips)):
                return
        if host.macs and mac not in host.macs:
            host.evidence = {k:e for k,e in host.evidence.items()
                             if not e.source.startswith('Active discovery:')}
        if len(host.macs) < 8:
            host.macs.add(mac)
            host.observe("MAC", mac, source, Confidence.OBSERVED, ts)
            vendor = self.oui.lookup(mac)
            if vendor != "Unknown":
                host.manufacturer = vendor
                host.observe("Manufacturer", vendor, "OUI registry: " + self.oui.path,
                             Confidence.OBSERVED, ts)
            # A name learned by MAC (DHCP DISCOVER, before this host had an IP)
            # binds now that the MAC↔IP mapping is known.
            cached = self._mac_hostnames.get(mac)
            if cached and len(host.dns_names) < MAX_NAMES_PER_HOST:
                host.dns_names.add(cached[0])
                host.observe("Hostname", cached[0], cached[1],
                             Confidence.OBSERVED, ts)
            cached_os = self._mac_os.get(mac)
            if cached_os:
                host.observe("OS", cached_os[0], cached_os[1],
                             Confidence.OBSERVED, ts)

    @host_locked
    def apply_context(self, context):
        # Refresh current system roles without treating a periodic route read
        # as new captured traffic, or keeping a vanished gateway confirmed.
        own_macs = {mac for _, mac, _ in context.addresses if mac}
        own_ips = {ip for ip, _, _ in context.addresses}
        for host in self._hosts.values():
            # Capture may have started before interface discovery completed.
            # Reconcile only proven local-MAC contamination; preserve real
            # conflicts between two remote MACs instead of forcing a merge.
            if host.ip not in own_ips and host.macs & own_macs:
                host.macs.difference_update(own_macs)
                host.evidence = {k: e for k, e in host.evidence.items()
                                 if not (e.field == 'MAC' and e.value in own_macs)
                                 and not e.source.startswith('OUI registry:')}
                vendors = set()
                for mac in host.macs:
                    vendor = self.oui.lookup(mac)
                    if vendor != 'Unknown':
                        vendors.add(vendor)
                        host.observe('Manufacturer', vendor,
                                     'OUI registry: ' + self.oui.path,
                                     Confidence.OBSERVED, context.ts)
                host.manufacturer = next(iter(vendors)) if len(vendors) == 1 else 'Unknown'
            host.evidence = {k: e for k, e in host.evidence.items()
                             if not (e.source.startswith('System interface') or
                                     e.source in ('Routing table', 'Local operating system', 'Local system hostname'))}
            if host.device_type in ('This Device', 'Gateway'):
                host.device_type = 'Unknown'
                host.os = 'Unknown'
            if context.on_link(host.ip):
                host.scope = 'Local'
                host.local = True
        self.context = context
        def system_host(ip):
            return self._hosts.get(ip) or self._touch(ip, context.ts)
        for ip, mac, prefix in context.addresses:
            host = system_host(ip)
            host.device_type = "This Device"
            host.os = "Linux"
            host.scope = "Local"
            host.local = True
            host.observe("IP", ip, "System interface " + context.interface, Confidence.OBSERVED, context.ts)
            host.observe("Device type", host.device_type, "System interface " + context.interface, Confidence.CONFIRMED, context.ts)
            host.observe("OS", "Linux", "Local operating system", Confidence.CONFIRMED, context.ts)
            self._observe_mac(host, mac, "System interface " + context.interface, context.ts)
            if context.hostname:
                host.observe("Hostname", context.hostname, "Local system hostname", Confidence.CONFIRMED, context.ts)
        for _, ip in context.gateways:
            host = system_host(ip)
            if host.device_type != "This Device":
                host.device_type = "Gateway"
            host.local = True
            host.scope = "Local"
            host.observe("Device type", "Gateway", "Routing table", Confidence.CONFIRMED, context.ts)
            host.observe("IP", ip, "Routing table", Confidence.CONFIRMED, context.ts)
        for ip, mac in context.neighbors:
            host = system_host(ip)
            host.local = True
            host.scope = "Local"
            self._observe_mac(host, mac, "Kernel neighbor table", context.ts)
            host.observe("IP", ip, "Kernel neighbor table", Confidence.OBSERVED, context.ts)

    @host_locked
    def apply_discovery(self, context, records):
        """Attach explicitly requested local discovery evidence, never traffic."""
        if context.interface != self.context.interface:
            return
        for record in records:
            if not self.context.on_link(record.ip):
                continue
            host = self._hosts.get(record.ip) or self._touch(record.ip, record.ts)
            # A new binding must not inherit an old peer's advertised identity.
            if record.mac and host.macs and record.mac not in host.macs:
                host.evidence = {k:e for k,e in host.evidence.items()
                                 if not e.source.startswith('Active discovery:')}
            host.local = True
            host.scope = 'Local'
            if record.mac:
                self._observe_mac(host, record.mac, 'Active discovery: Nmap on-link address binding', record.ts)
            for e in record.evidence:
                if e.field == 'MAC':
                    self._observe_mac(host, e.value, e.source, e.ts)
                else:
                    host.observe(e.field, e.value, e.source, e.confidence, e.ts)

    @host_locked
    def note_dns(self, ip, name, ts):
        ip = valid_ip(ip)
        if not ip or not name:
            return
        host = self._touch(ip, ts)
        if len(host.contacted_names) < 128:
            host.contacted_names.add(name.rstrip('.'))

    @host_locked
    def device_snapshots(self, now, active_counts=None):
        active_counts = active_counts or {}
        result = []
        for h in self._hosts.values():
            names = sorted({e.value for e in h.evidence.values() if e.field == "Hostname"})
            recent = tuple(h.recent)
            window = [r for r in recent if 0 <= now - r[0] < 5]
            status = ("Active" if recent and 0 <= now - h.last_ts < 30 else
                      "Inactive" if recent else "System known" if h.device_type != "Unknown" else "Referenced only")
            result.append(EndpointSnapshot(h.ip, h.ip if ':' in h.ip else "Unknown",
                ', '.join(sorted(h.macs)) or "Unknown", ', '.join(names) or "Unknown",
                h.manufacturer, h.os, h.device_type, h.scope, status, h.first_ts, h.last_ts,
                h.packets, h.bytes_sent, h.bytes_recv, active_counts.get(h.ip,0),
                sum(r[1] for r in window)/5, sum(r[2] for r in window)/5,
                tuple(sorted(h.contacted_names)), tuple(h.evidence.values()), recent))
        return tuple(result)
