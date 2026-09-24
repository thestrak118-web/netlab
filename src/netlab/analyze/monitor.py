"""Read-only monitor projections keyed by evidenced local device identity."""
from dataclasses import dataclass, field, replace
from enum import StrEnum
import copy
import ipaddress
import time
from netlab.analyze.flows import make_flow_key


class MonitorState(StrEnum):
    MONITORING = 'Monitoring'
    PAUSED = 'Paused'
    STOPPED = 'Stopped'


@dataclass
class Subscription:
    ip: str
    state: MonitorState = MonitorState.MONITORING
    generation: int = 0


class MonitorRegistry:
    """Bounded multi-subscription model; the GUI uses select_one only."""
    def __init__(self, capacity=8):
        self.capacity = capacity
        self.subscriptions = {}
        self.generation = 0

    def subscribe(self, ip):
        try: ip = str(ipaddress.ip_address(ip))
        except ValueError: ip = str(ip)
        if ip not in self.subscriptions and len(self.subscriptions) >= self.capacity:
            raise ValueError('Monitor subscription limit reached')
        self.generation += 1
        sub = Subscription(ip, generation=self.generation)
        self.subscriptions[ip] = sub
        return sub

    def select_one(self, ip):
        try: ip = str(ipaddress.ip_address(ip))
        except ValueError: ip = str(ip)
        self.subscriptions.clear()
        return self.subscribe(ip)

    def transition(self, ip, state):
        sub = self.subscriptions[ip]
        self.generation += 1
        sub.state, sub.generation = state, self.generation
        return sub

    def clear(self):
        self.generation += 1
        self.subscriptions.clear()


@dataclass(frozen=True)
class Activity:
    index: int
    ts: float
    direction: str
    destination: str
    domain: str
    protocol: str
    bytes: int
    flow_key: tuple
    src: str
    dst: str


@dataclass(frozen=True)
class MonitorSnapshot:
    ip: str
    ts: float
    device: object
    activity: tuple
    connections: tuple
    dns: tuple
    http: tuple
    tls: tuple
    counts: dict
    omitted: dict
    tls_bytes: dict
    identity: str = ""
    addresses: tuple = ()


def snapshot_for_device(engine, ip, now=None, row_limit=1000, previous=None):
    """Called off the GUI thread. Only joins existing metadata/IDs; no packet decode."""
    now = time.time() if now is None else now
    device = engine.resolve_device(ip, now)
    if device is None:
        if previous is None:
            raise ValueError('Monitor is available only for observed local devices')
        return MonitorSnapshot(previous.ip, now, None, (), (), (), (), (),
            dict(dns=0,http=0,tls=0,active_connections=0,activity=0), {}, {}, previous.identity, previous.addresses)
    addresses = set(device.addresses)
    ip = device.ip
    relations = engine.relations_for_device(device.addresses)
    flows = {f.key: replace(f) for f in relations['connections']}
    dns_names = {e.packet_index: e.qname for e in relations['dns'] if e.qname}
    rows = [r for r in engine.live.snapshot() if addresses.intersection((r.src,r.dst))]
    activity = []
    for row in rows[-row_limit:]:
        key, _ = make_flow_key(row.proto, row.src, row.sport, row.dst, row.dport)
        flow = flows.get(key)
        direction = 'LOCAL' if row.src in addresses and row.dst in addresses else 'OUT' if row.src in addresses else 'IN'
        peer = row.dst if row.src in addresses else row.src
        domain = dns_names.get(row.index) or (flow.service if flow else None) or 'Unknown'
        activity.append(Activity(row.index, row.ts, direction, peer, domain,
                                 row.app or (flow.app_proto if flow else None) or row.proto,
                                 row.length, key, row.src, row.dst))
    active = tuple(f for f in flows.values() if f.proto != 'ARP' and f.is_active(now))
    counts = {name: len(relations[name]) for name in ('dns', 'http', 'tls')}
    counts['active_connections'] = len(active)
    counts['activity'] = len(rows)
    omitted = {name: max(0, counts[name]-row_limit) for name in counts}
    # Detach mutable protocol records so Pause truly freezes all displayed values.
    return MonitorSnapshot(ip, now, device, tuple(activity), active[-row_limit:],
        tuple(copy.deepcopy(relations['dns'][-row_limit:])),
        tuple(copy.deepcopy(relations['http'][-row_limit:])),
        tuple(copy.deepcopy(relations['tls'][-row_limit:])), counts, omitted,
        {key: (f.bytes, f.first_ts, f.last_ts) for key, f in flows.items()}, device.identity, device.addresses)
