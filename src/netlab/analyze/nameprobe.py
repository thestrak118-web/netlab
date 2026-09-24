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
import socket
import struct
import threading
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
