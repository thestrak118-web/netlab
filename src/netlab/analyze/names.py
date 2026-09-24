"""Passive device-name extraction from DHCP and NetBIOS.

Intercepter-NG's host list shows device names because it reads the names
devices announce for themselves. NetLab already learns names from mDNS/DNS
A-records; this adds the two other places a device volunteers its own name
without being asked:

* **DHCP** (option 12, Host Name). Every device sends this when it joins the
  Wi-Fi, so it is the most reliable source of all — "Erwins-iPhone",
  "Galaxy-S21", "DESKTOP-7F3A". A DISCOVER has no client IP yet, only the
  hardware address, so the name is returned with the MAC and bound to the host
  once its IP is known.
* **NetBIOS name service** (UDP 137). Windows and some NAS/printers register
  and answer with their NetBIOS name, sent from the device's own address.

Both are parsed defensively: a malformed packet yields nothing, never an
exception.
"""

from __future__ import annotations

import struct

DHCP_MAGIC = b"\x63\x82\x53\x63"
DHCP_OPT_HOSTNAME = 12
DHCP_OPT_FQDN = 81
DHCP_OPT_END = 255
DHCP_OPT_PAD = 0


def dhcp_hostname(payload: bytes) -> tuple[str, str] | None:
    """Return (client_mac, hostname) from a DHCP message, or None.

    The MAC is the BOOTP chaddr (client hardware address); the hostname is
    option 12, or the FQDN in option 81 when 12 is absent.
    """
    if len(payload) < 240 or payload[236:240] != DHCP_MAGIC:
        return None
    hlen = payload[2]
    mac = ""
    if hlen == 6:
        mac = ":".join("%02x" % b for b in payload[28:34])
    hostname = ""
    fqdn = ""
    off = 240
    end = len(payload)
    while off < end:
        opt = payload[off]
        if opt == DHCP_OPT_END:
            break
        if opt == DHCP_OPT_PAD:
            off += 1
            continue
        if off + 1 >= end:
            break
        length = payload[off + 1]
        value = payload[off + 2:off + 2 + length]
        if len(value) != length:
            break
        if opt == DHCP_OPT_HOSTNAME:
            hostname = _clean(value)
        elif opt == DHCP_OPT_FQDN and length > 3:
            # Option 81: flags(1) rcode1(1) rcode2(1) then the name, which may
            # be a plain string or DNS-label-encoded.
            fqdn = _clean(_fqdn_name(value[3:]))
        off += 2 + length
    name = hostname or fqdn
    if not name:
        return None
    return (mac, name)


def _fqdn_name(raw: bytes) -> bytes:
    """Decode option-81's name, which is either DNS labels or a plain string."""
    if not raw:
        return b""
    # DNS-label form: <len><label><len><label>...; a printable first byte that
    # is not a plausible label length means it is already a plain string.
    if raw[0] < 0x20 and raw[0] < len(raw):
        out, off = [], 0
        while off < len(raw) and raw[off]:
            n = raw[off]
            out.append(raw[off + 1:off + 1 + n])
            off += 1 + n
        return b".".join(out)
    return raw


def _clean(value) -> str:
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    value = value.strip().strip(".").replace("\x00", "")
    # A name is printable and has no whitespace or control characters.
    if not value or not all(32 < ord(c) < 127 or ord(c) > 160 for c in value):
        return ""
    return value[:64]


def nbns_name(payload: bytes) -> str | None:
    """The NetBIOS name from a name-service (UDP 137) registration or reply."""
    if len(payload) < 12:
        return None
    # DNS-style header: id(2) flags(2) qd(2) an(2) ns(2) ar(2), then the name.
    qd, an = struct.unpack_from(">HH", payload, 4)
    if qd == 0 and an == 0:
        return None
    off = 12
    if off >= len(payload) or payload[off] != 0x20:   # encoded names are 32 long
        return None
    encoded = payload[off + 1:off + 1 + 32]
    if len(encoded) < 32:
        return None
    return _nb_decode(encoded)


def _nb_decode(encoded: bytes) -> str | None:
    """Undo NetBIOS first-level (half-ASCII) name encoding."""
    try:
        chars = []
        for i in range(0, 32, 2):
            hi = encoded[i] - 0x41
            lo = encoded[i + 1] - 0x41
            if not (0 <= hi <= 15 and 0 <= lo <= 15):
                return None
            chars.append((hi << 4) | lo)
        name = bytes(chars[:15]).decode("ascii", "replace").strip()
        name = name.strip("\x00").strip()
        if not name or not name.isprintable():
            return None
        return name
    except (IndexError, ValueError):
        return None


# ------------------------------------------------------- OS / platform hints

def _os_from_vendor_class(v: str) -> str:
    v = (v or "").lower()
    if v.startswith("msft"):
        return "Windows"
    if "android" in v:
        return "Android"
    if v.startswith(("dhcpcd", "udhcp", "dhclient")):
        return "Linux"
    return ""


def dhcp_os(payload: bytes) -> str:
    """OS from a DHCP message's vendor-class option (60): Windows, Android…"""
    if len(payload) < 240 or payload[236:240] != DHCP_MAGIC:
        return ""
    off, end = 240, len(payload)
    while off < end:
        opt = payload[off]
        if opt == DHCP_OPT_END:
            break
        if opt == DHCP_OPT_PAD:
            off += 1
            continue
        if off + 1 >= end:
            break
        length = payload[off + 1]
        value = payload[off + 2:off + 2 + length]
        if len(value) != length:
            break
        if opt == 60:                      # Vendor class identifier
            return _os_from_vendor_class(value.decode("latin-1", "replace"))
        off += 2 + length
    return ""


def os_from_hostname(name: str) -> str:
    n = (name or "").lower()
    if "android" in n:
        return "Android"
    if "iphone" in n or "ipad" in n:
        return "iOS"
    if n.startswith(("desktop-", "win-")) or "windows" in n:
        return "Windows"
    if "macbook" in n or "imac" in n:
        return "macOS"
    return ""


def os_from_user_agent(ua: str) -> str:
    u = ua or ""
    if "Windows NT" in u:
        return "Windows"
    if "Android" in u:
        return "Android"
    if "iPhone" in u:
        return "iOS"
    if "iPad" in u:
        return "iPadOS"
    if "Mac OS X" in u or "Macintosh" in u:
        return "macOS"
    if "CrOS" in u:
        return "ChromeOS"
    if "Linux" in u:
        return "Linux"
    return ""


def os_from_ttl(ttl) -> str:
    """Coarse OS family from an observed IP TTL / IPv6 hop-limit.

    Initial TTLs cluster at 64 (Linux/Android/macOS/iOS/Unix), 128 (Windows)
    and 255 (routers, printers, embedded). A few hops only lower the value, so
    rounding up to the next cluster keeps the guess stable across the LAN. This
    is the same coarse signal Intercepter-NG shows as "Unix" / "Windows".
    """
    if not ttl or ttl <= 0:
        return ""
    if ttl <= 64:
        return "Unix"
    if ttl <= 128:
        return "Windows"
    return "Network device"
