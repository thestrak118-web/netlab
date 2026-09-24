"""Evidence and immutable device/topology projections of the existing HostTable.

No probing, DNS lookups or device fingerprint guesses are performed here.
System evidence is injected only for live sessions; offline files never inherit
this machine's routing table.
"""
from __future__ import annotations
from dataclasses import dataclass, field, replace
from enum import StrEnum
import ipaddress
import json
from pathlib import Path
import re
import socket
import subprocess
import time


class Confidence(StrEnum):
    CONFIRMED = 'CONFIRMED'
    OBSERVED = 'OBSERVED'
    INFERRED = 'INFERRED'
    UNKNOWN = 'UNKNOWN'


@dataclass(frozen=True)
class Evidence:
    field: str
    value: str
    source: str
    confidence: Confidence
    ts: float


def valid_ip(value):
    try:
        ip = ipaddress.ip_address(value)
        if ip.is_multicast or ip.is_unspecified or str(ip) == '255.255.255.255':
            return None
        return str(ip)
    except (ValueError, TypeError):
        return None


def valid_mac(value):
    if not value or not re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', value):
        return None
    value = value.lower()
    if value == '00:00:00:00:00:00' or int(value[:2], 16) & 1:
        return None
    return value


@dataclass(frozen=True)
class NetworkContext:
    interface: str = ''
    addresses: tuple = ()                 # (IP, MAC, prefix length)
    gateways: tuple = ()                  # (source IP, gateway IP)
    neighbors: tuple = ()                 # (IP, MAC)
    hostname: str = ''
    ts: float = 0.0
    errors: tuple = ()

    def on_link(self, ip):
        try:
            addr = ipaddress.ip_address(ip)
            return any(addr in ipaddress.ip_network(f'{local}/{prefix}', strict=False)
                       for local, _, prefix in self.addresses
                       if ipaddress.ip_address(local).version == addr.version)
        except ValueError:
            return False

    @classmethod
    def from_json(cls, interface, addresses, routes, neighbors=(), hostname='', ts=0):
        own, gateways, peers = [], [], []
        for item in addresses:
            if item.get('ifname') != interface:
                continue
            for addr in item.get('addr_info', []):
                ip = valid_ip(addr.get('local'))
                if ip:
                    own.append((ip, valid_mac(item.get('address')), int(addr.get('prefixlen', 0))))
        for route in routes:
            gateway = valid_ip(route.get('gateway'))
            if route.get('dev') == interface and gateway and route.get('dst') == 'default':
                for ip, _, _ in own:
                    if ipaddress.ip_address(ip).version == ipaddress.ip_address(gateway).version:
                        gateways.append((ip, gateway))
        for peer in neighbors:
            ip, mac = valid_ip(peer.get('dst')), valid_mac(peer.get('lladdr'))
            if peer.get('dev') == interface and ip and mac and not set(peer.get('state', [])).intersection({'FAILED','INCOMPLETE'}):
                peers.append((ip, mac))
        return cls(interface, tuple(own), tuple(gateways), tuple(peers), hostname, ts)

    @classmethod
    def discover(cls, interface):
        errors = []
        def read(*args):
            try:
                p = subprocess.run(['ip', '-j', *args], capture_output=True, text=True, timeout=3, check=True)
                return json.loads(p.stdout)
            except (OSError, ValueError, subprocess.SubprocessError) as exc:
                errors.append(str(exc))
                return []
        addresses = read('address', 'show', 'dev', interface)
        routes = read('-4', 'route', 'show', 'default') + read('-6', 'route', 'show', 'default')
        # Keep dev in JSON records: ip omits it when filtered with 'dev'.
        neighbors = read('neighbor', 'show')
        result = cls.from_json(interface, addresses, routes, neighbors, socket.gethostname(), time.time())
        return cls(result.interface, result.addresses, result.gateways, result.neighbors,
                   result.hostname, result.ts, tuple(errors))


class OuiDatabase:
    """Optional local OUI registry. Locally administered MACs stay Unknown."""
    def __init__(self, path=None):
        self.vendors = {}
        self.path = ''
        candidates = [Path(path)] if path else [Path('/usr/share/nmap/nmap-mac-prefixes'), Path('/usr/share/ieee-data/oui.txt')]
        for candidate in candidates:
            if not candidate.is_file():
                continue
            try:
                with candidate.open(errors='replace') as f:
                    for line in f:
                        match = re.match(r'^([0-9A-Fa-f]{6})\s+(.+)$', line.strip())
                        ieee = re.match(r'^([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})\s+\(hex\)\s+(.+)', line.strip())
                        if match:
                            self.vendors[match[1].upper()] = match[2].strip()
                        elif ieee:
                            self.vendors[''.join(ieee.group(i) for i in (1,2,3)).upper()] = ieee[4].strip()
                        if len(self.vendors) >= 100000:
                            break
                self.path = str(candidate)
                break
            except OSError:
                continue

    def lookup(self, mac):
        mac = valid_mac(mac)
        if not mac or int(mac[:2], 16) & 2:
            return 'Unknown'
        return self.vendors.get(mac.replace(':','')[:6].upper(), 'Unknown')


@dataclass(frozen=True)
class EndpointSnapshot:
    ip: str
    ipv6: str
    mac: str
    hostname: str
    manufacturer: str
    os: str
    device_type: str
    scope: str
    status: str
    first_seen: float
    last_seen: float
    packets: int
    upload: int
    download: int
    active_connections: int
    packets_sec: float
    bytes_sec: float
    dns_names: tuple
    evidence: tuple
    recent: tuple
    @property
    def bytes(self): return self.upload + self.download


@dataclass(frozen=True)
class DeviceSnapshot(EndpointSnapshot):
    """An evidenced on-link identity, possibly with several endpoint addresses."""
    identity: str = ''
    addresses: tuple = ()
    mac_addresses: tuple = ()
    hostnames: tuple = ()
    local_evidence: tuple = ()

    @property
    def model(self):
        return self.attribute('Exact device model')

    def attribute(self, field):
        values = sorted({e.value for e in self.evidence if e.field == field})
        return ', '.join(values) or 'Unknown'

    @property
    def display_name(self):
        # Prefer a real name, then a hostname, then the device type; failing
        # all of those, fall back to the manufacturer (like Intercepter-NG
        # showing a vendor) so a device is rarely just "Unknown".
        for candidate in (self.attribute('Friendly name'), self.hostname,
                          self.device_type, self.attribute('Manufacturer')):
            if candidate and candidate != 'Unknown':
                return candidate
        return 'Unknown Device'

    @property
    def ipv4_addresses(self): return tuple(ip for ip in self.addresses if ':' not in ip)
    @property
    def ipv6_addresses(self): return tuple(ip for ip in self.addresses if ':' in ip)
    @property
    def monitor_eligible(self): return bool(self.local_evidence)


def local_devices(endpoints, flows, context, now):
    """Project local identities from HostTable; never promotes Internet endpoints.

    DNS names do not establish identity. Shared gateway MACs and conflicting MAC
    histories cannot merge peers. Explicit interface membership overrides MAC
    ambiguity for this machine's own addresses.
    """
    own = {ip for ip, _, _ in context.addresses}
    gateways = {ip for _, ip in context.gateways}
    neighbors = {ip: mac for ip, mac in context.neighbors}
    gateway_macs = {e.value for d in endpoints if d.ip in gateways for e in d.evidence if e.field == 'MAC'}
    own_macs = {mac for _, mac, _ in context.addresses if mac}
    groups = {}
    reasons = {}
    for endpoint in endpoints:
        ip = endpoint.ip
        if ip in own:
            reason = 'Selected interface ' + context.interface
        elif ip in gateways:
            reason = 'Routing table default gateway'
        elif ip in neighbors:
            reason = 'Kernel neighbor binding on ' + context.interface
        elif any(e.source == 'ARP address binding' for e in endpoint.evidence):
            reason = 'Observed ARP address binding'
        elif context.on_link(ip) and any(e.field == 'IP' and e.source.startswith('Active discovery:') for e in endpoint.evidence):
            reason = 'Active discovery response on selected interface ' + context.interface
        elif context.on_link(ip) and endpoint.packets > 0:
            reason = 'Captured endpoint in selected interface on-link prefix'
        else:
            continue
        macs = {e.value for e in endpoint.evidence if e.field == 'MAC'}
        stable = next(iter(macs)) if len(macs) == 1 else None
        if ip in own:
            identity = 'interface:' + (context.interface or 'selected')
        elif stable and (ip in gateways or stable not in gateway_macs | own_macs):
            identity = ('gateway:' if ip in gateways else 'mac:') + context.interface + ':' + stable
        else:
            identity = ('gateway-ip:' if ip in gateways else 'ip:') + context.interface + ':' + ip
        groups.setdefault(identity, []).append(endpoint)
        reasons.setdefault(identity, []).append(reason)
    devices = []
    for identity, members in groups.items():
        members.sort(key=lambda d: (':' in d.ip, d.ip))
        primary = members[0]
        addresses = tuple(d.ip for d in members)
        address_set = set(addresses)
        evidence = tuple(dict.fromkeys(e for d in members for e in d.evidence))
        macs = tuple(sorted({e.value for e in evidence if e.field == 'MAC'}))
        names = tuple(sorted({e.value for e in evidence if e.field == 'Hostname'}))
        vendors = {d.manufacturer for d in members if d.manufacturer != 'Unknown'}
        role = 'This Device' if address_set & own else 'Gateway' if address_set & gateways else 'Unknown'
        # A shared next-hop MAC or conflicting bindings cannot identify this peer's vendor.
        if len(macs) != 1 or (role == 'Unknown' and set(macs) & (gateway_macs | own_macs)):
            vendors.clear()
        advertised_types = {e.value for e in evidence if e.field == 'Device type' and e.source.startswith('Active discovery:')}
        kind = role if role != 'Unknown' else next(iter(advertised_types)) if len(advertised_types) == 1 else 'Unknown'
        advertised_vendors = {e.value for e in evidence if e.field == 'Manufacturer' and e.source.startswith('Active discovery:')}
        if len(advertised_vendors) == 1:
            vendors = advertised_vendors
        operating_systems = {e.value for e in evidence if e.field == 'OS'}
        # A precise OS (from DHCP/UA/hostname) wins over the coarse TTL family,
        # so a phone shows "Android", not "Android, Unix".
        precise_os = {o for o in operating_systems
                      if o not in ('Unix', 'Network device')}
        if precise_os:
            operating_systems = precise_os
        active = sum(1 for f in flows if f.proto != 'ARP' and f.is_active(now) and address_set.intersection((f.client,f.server)))
        recent = tuple(r for d in members for r in d.recent)
        window = [r for r in recent if 0 <= now-r[0] < 5]
        devices.append(DeviceSnapshot(primary.ip, ', '.join(a for a in addresses if ':' in a) or 'Unknown',
            ', '.join(macs) or 'Unknown', ', '.join(names) or 'Unknown',
            next(iter(vendors)) if len(vendors)==1 else 'Unknown',
            ', '.join(sorted(operating_systems)) or 'Unknown', kind, 'Local',
            'Active' if any(d.status=='Active' for d in members) else 'Discovered' if any(e.source.startswith('Active discovery:') and 0 <= now-e.ts < 30 for e in evidence) else 'Inactive',
            min(d.first_seen for d in members), max(d.last_seen for d in members),
            sum(d.packets for d in members), sum(d.upload for d in members), sum(d.download for d in members),
            active, sum(r[1] for r in window)/5, sum(r[2] for r in window)/5,
            tuple(sorted({n for d in members for n in d.dns_names})), evidence, recent,
            identity, addresses, macs, names, tuple(sorted(set(reasons[identity])))))
    return tuple(devices)


@dataclass(frozen=True)
class TopologyEdge:
    source: str
    destination: str
    kind: str
    bytes: int = 0
    packets: int = 0
    last_seen: float = 0
    evidence: str = 'Observed IP traffic'

    @property
    def key(self): return (self.source, self.destination, self.kind)


@dataclass(frozen=True)
class NetworkSnapshot:
    devices: tuple
    edges: tuple
    total_devices: int
    omitted_nodes: int
    omitted_edges: int
    ts: float
    endpoints: tuple = ()


def topology_snapshot(devices, flows, context, now, node_limit=80, edge_limit=160, edge_ttl=120, endpoints=()):
    """Bounded graph projection. Edges are traffic observations or explicit routes."""
    priority = sorted(devices, key=lambda d: (d.device_type in ('This Device','Gateway'), d.bytes), reverse=True)
    nodes = tuple(priority[:node_limit])
    aliases = {ip: d.ip for d in nodes for ip in d.addresses}
    remote = tuple(sorted((e for e in endpoints if e.ip not in aliases), key=lambda e:e.bytes, reverse=True)[:max(0,node_limit-len(nodes))])
    ips = {d.ip for d in nodes} | {e.ip for e in remote}
    aliases.update({e.ip:e.ip for e in remote})
    edges = {}
    for flow in flows:
        if flow.proto == 'ARP' or flow.client not in aliases or flow.server not in aliases or now - flow.last_ts > edge_ttl:
            continue
        for src,dst,size,count in ((flow.client,flow.server,flow.bytes_c2s,flow.pkts_c2s),
                                    (flow.server,flow.client,flow.bytes_s2c,flow.pkts_s2c)):
            src, dst = aliases[src], aliases[dst]
            if count and src != dst:
                key=(src,dst,'traffic'); old=edges.get(key)
                edges[key]=TopologyEdge(src,dst,'traffic',size+(old.bytes if old else 0),
                    count+(old.packets if old else 0),max(flow.last_ts,old.last_seen if old else 0))
    traffic=sorted(edges.values(),key=lambda e:e.bytes,reverse=True)
    routes=[TopologyEdge(aliases[src],aliases[dst],'route',evidence='Routing table: default gateway')
            for src,dst in context.gateways if src in aliases and dst in aliases]
    all_edges=list({e.key:e for e in routes}.values())+traffic
    return NetworkSnapshot(nodes,tuple(all_edges[:edge_limit]),len(devices),max(0,len(devices)+len(endpoints)-len(nodes)-len(remote)),
                           max(0,len(all_edges)-edge_limit),now,remote)
