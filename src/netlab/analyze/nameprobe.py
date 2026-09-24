"""Native device-name resolution -- no nmap, no root.

Device names are the thing people most want from a scan and the thing that is
most often just missing: a MAC-randomised phone announces nothing, and the
heavier nmap path needs `nmap` installed and a `pkexec` prompt.  This module
resolves what *can* be resolved with a plain socket the unprivileged GUI
already has:

* **Reverse DNS (PTR)** -- the router usually answers for the hosts it leased,
  which is how the gateway and other DHCP clients get a name.
* **NBNS node status (UDP/137)** -- Windows, Samba, many NAS boxes and printers
  answer their own name to a node-status request.

Neither needs elevation.  Silent, randomised devices still resolve to nothing,
and that is reported honestly rather than invented.
"""

from __future__ import annotations

import ipaddress
import re
import socket
import struct
import threading
import urllib.request
from concurrent.futures import ThreadPoolExecutor

# A NetBIOS node-status request for the wildcard name "*", first-level encoded.
_NBNS_WILDCARD = b"CK" + b"AA" * 15
_NBSTAT, _IN = 0x0021, 0x0001


def reverse_dns(ip: str, timeout: float = 1.0) -> str | None:
    """The PTR name for `ip`, or None. Bounded by `timeout`."""
    if not _routable(ip):
        return None
    prev = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        name = socket.gethostbyaddr(ip)[0]
    except (OSError, socket.herror, socket.gaierror):
        return None
    finally:
        socket.setdefaulttimeout(prev)
    name = (name or "").strip().rstrip(".")
    # A bare in-addr.arpa echo, or the IP itself, is not a name.
    if not name or name == ip or name.endswith(".in-addr.arpa"):
        return None
    # Keep the first label for a FQDN like host.lan; it reads better in a list.
    return name


def nbns_query(ip: str, timeout: float = 1.0) -> str | None:
    """The NetBIOS name `ip` reports for a node-status request, or None."""
    if not _routable(ip):
        return None
    query = struct.pack(">HHHHHH", 0x4E45, 0x0000, 1, 0, 0, 0)
    query += bytes([len(_NBNS_WILDCARD)]) + _NBNS_WILDCARD + b"\x00"
    query += struct.pack(">HH", _NBSTAT, _IN)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(query, (ip, 137))
        data, _ = sock.recvfrom(4096)
    except OSError:
        return None
    finally:
        sock.close()
    return _parse_nbstat(data)


def _parse_nbstat(data: bytes) -> str | None:
    try:
        off = 12                                   # header
        while data[off]:                           # question name
            off += 1 + data[off]
        off += 1 + 4                               # null + qtype + qclass
        while data[off]:                           # answer name
            off += 1 + data[off]
        off += 1 + 10                              # null + type/class/ttl/rdlen
        count = data[off]
        off += 1
        best = None
        for _ in range(count):
            name = data[off:off + 15].decode("ascii", "replace").strip()
            suffix = data[off + 15]
            flags = struct.unpack(">H", data[off + 16:off + 18])[0]
            off += 18
            group = bool(flags & 0x8000)
            if name and suffix == 0x00 and not group:   # unique workstation
                return name
            if best is None and name and not group:
                best = name
        return best
    except (IndexError, struct.error):
        return None


def _routable(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_multicast or addr.is_unspecified or addr.is_reserved)


def resolve_names(ips, timeout: float = 1.0, workers: int = 24,
                  on_name=None, cancel: threading.Event | None = None) -> dict:
    """Resolve names for `ips` concurrently. Returns ``{ip: (name, source)}``.

    Each IP is tried by reverse DNS first (quiet, often the router's lease
    name), then NBNS. `on_name(ip, name, source)` fires per hit as it lands.
    """
    targets = [ip for ip in dict.fromkeys(ips) if _routable(ip)]
    found: dict[str, tuple[str, str]] = {}

    def one(ip: str):
        if cancel is not None and cancel.is_set():
            return
        name = reverse_dns(ip, timeout)
        source = "reverse DNS"
        if not name:
            name = nbns_query(ip, timeout)
            source = "NBNS"
        if name:
            found[ip] = (name, source)
            if on_name:
                on_name(ip, name, source)

    if targets:
        with ThreadPoolExecutor(max_workers=min(workers, len(targets))) as pool:
            list(pool.map(one, targets))
    return found


# --------------------------------------------------------------- SSDP / UPnP

_SSDP_ADDR = ("239.255.255.250", 1900)
_MSEARCH = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    'MAN: "ssdp:discover"\r\n'
    "MX: 2\r\n"
    "ST: ssdp:all\r\n\r\n").encode()


def _http_header(text: str, name: str) -> str:
    m = re.search(r"(?im)^%s:\s*(.+)$" % re.escape(name), text)
    return m.group(1).strip() if m else ""


def upnp_friendly_name(location: str, timeout: float = 2.0) -> str | None:
    """Fetch a UPnP device description and return its friendlyName/modelName."""
    if not location.lower().startswith("http://"):
        return None
    try:
        with urllib.request.urlopen(location, timeout=timeout) as resp:
            xml = resp.read(65536).decode("utf-8", "replace")
    except Exception:
        return None
    for tag in ("friendlyName", "modelName"):
        m = re.search(r"<%s>(.*?)</%s>" % (tag, tag), xml, re.S)
        if m:
            value = re.sub(r"\s+", " ", m.group(1)).strip()
            if value:
                return value[:120]
    return None


def ssdp_discover(timeout: float = 3.0, on_name=None,
                  cancel: threading.Event | None = None,
                  fetch=upnp_friendly_name) -> dict:
    """Send an SSDP M-SEARCH and name every device that answers.

    Routers, smart TVs, media players and many IoT devices answer, giving a
    LOCATION whose description carries a friendly name; when there is none, the
    SERVER string (its product) is used. Returns ``{ip: (name, "UPnP")}``.
    """
    found: dict[str, tuple[str, str]] = {}
    locations: dict[str, str] = {}
    servers: dict[str, str] = {}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    sock.settimeout(0.5)
    try:
        sock.sendto(_MSEARCH, _SSDP_ADDR)
        sock.sendto(_MSEARCH, _SSDP_ADDR)
        import time as _t
        deadline = _t.monotonic() + timeout
        while _t.monotonic() < deadline:
            if cancel is not None and cancel.is_set():
                break
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            ip = addr[0]
            text = data.decode("utf-8", "replace")
            loc = _http_header(text, "LOCATION")
            if loc and ip not in locations:
                locations[ip] = loc
            srv = _http_header(text, "SERVER")
            if srv and ip not in servers:
                servers[ip] = srv
    finally:
        sock.close()
    for ip in locations:
        if not _routable(ip):
            continue
        name = fetch(locations[ip]) if fetch else None
        if not name:
            name = _server_product(servers.get(ip, ""))
        if name:
            found[ip] = (name, "UPnP")
            if on_name:
                on_name(ip, name, "UPnP")
    return found


def _server_product(server: str) -> str | None:
    """Pick the product token out of an SSDP SERVER string, e.g.
    'Linux/3.4 UPnP/1.0 R8000/1.0' -> 'R8000'."""
    for token in reversed(server.split()):
        head = token.split("/")[0].strip()
        if head and not head.lower().startswith(("upnp", "linux", "unix",
                                                 "windows")) and len(head) > 2:
            return head[:120]
    return None


# ------------------------------------------------------------------- mDNS

_MDNS_ADDR = ("224.0.0.251", 5353)
_MDNS_QUERIES = ("_services._dns-sd._udp.local", "_device-info._tcp.local",
                 "_workstation._tcp.local", "_googlecast._tcp.local",
                 "_airplay._tcp.local", "_ipp._tcp.local")


def _encode_dns_name(name: str) -> bytes:
    out = b""
    for label in name.split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def _mdns_hostname(data: bytes) -> str | None:
    """Best-effort: the `.local` host label in an mDNS answer. Literal labels
    only -- enough to read a name off a device's own reply."""
    labels, i = [], 0
    while i < len(data) - 1:
        length = data[i]
        if 1 <= length <= 63 and i + 1 + length <= len(data):
            frag = data[i + 1:i + 1 + length]
            if all(32 <= b < 127 for b in frag):
                labels.append(frag.decode())
        i += 1
    # A device's own name is a single label whose service record ends in .local;
    # prefer a label that is not a service/protocol token.
    skip = {"_tcp", "_udp", "local", "_services", "_dns-sd", "_device-info"}
    for label in labels:
        if label not in skip and not label.startswith("_") and len(label) > 1:
            return label[:120]
    return None


def mdns_discover(timeout: float = 3.0, on_name=None,
                  cancel: threading.Event | None = None) -> dict:
    """Query mDNS for the common device services and name every responder.

    Returns ``{ip: (name, "mDNS")}``. Apple, Chromecast, printers and Linux
    hosts with Avahi answer; a device that is not advertising stays unnamed.
    """
    found: dict[str, tuple[str, str]] = {}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    sock.settimeout(0.5)
    try:
        for qname in _MDNS_QUERIES:
            query = struct.pack(">HHHHHH", 0, 0, 1, 0, 0, 0)
            query += _encode_dns_name(qname) + struct.pack(">HH", 12, 1)
            try:
                sock.sendto(query, _MDNS_ADDR)
            except OSError:
                break
        import time as _t
        deadline = _t.monotonic() + timeout
        while _t.monotonic() < deadline:
            if cancel is not None and cancel.is_set():
                break
            try:
                data, addr = sock.recvfrom(9000)
            except socket.timeout:
                continue
            except OSError:
                break
            ip = addr[0]
            if ip in found or not _routable(ip):
                continue
            name = _mdns_hostname(data)
            if name:
                found[ip] = (name, "mDNS")
                if on_name:
                    on_name(ip, name, "mDNS")
    finally:
        sock.close()
    return found
