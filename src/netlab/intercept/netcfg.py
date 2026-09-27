"""Host network state that interception has to change, and put back.

Three things here are borrowed from the kernel for the duration of an
engagement and must be returned exactly as they were found:

* `net.ipv4.ip_forward` / `net.ipv6.conf.all.forwarding` -- without these the
  machine drops the traffic it just poisoned its way into, which is a denial
  of service against the target rather than an interception of it.
* `net.ipv4.conf.*.send_redirects` -- left on, the kernel helpfully tells the
  victim to stop routing through us.
* one nftables table, `inet netlab`, holding the redirect rules that hand
  forwarded traffic to the local proxies.

Every mutation is recorded with its previous value so `restore()` is exact,
and `restore()` is safe to call twice.
"""

from __future__ import annotations

import ipaddress
import os
import re
import shutil
import socket
import struct
import subprocess

NFT_TABLE = "netlab"
NFT_FAMILY = "inet"

# getsockopt levels for recovering the pre-DNAT destination of a redirected
# connection.  SO_ORIGINAL_DST is how a transparent proxy learns where the
# client actually meant to go.
SO_ORIGINAL_DST = 80
IP6T_SO_ORIGINAL_DST = 80


class NetcfgError(Exception):
    pass


def _run(argv: list[str], timeout: float = 8.0) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(argv, capture_output=True, text=True,
                              timeout=timeout)
    except FileNotFoundError as exc:
        raise NetcfgError("%s is not installed" % argv[0]) from exc
    except subprocess.TimeoutExpired as exc:
        raise NetcfgError("%s timed out" % argv[0]) from exc
    return proc.returncode, (proc.stdout or "").strip(), (proc.stderr or "").strip()


# ------------------------------------------------------------------ interface

def interface_info(name: str) -> dict:
    """Address, netmask, MAC and MTU for `name`, from the kernel."""
    info = {"interface": name, "ipv4": "", "prefix": 0, "cidr": "",
            "mac": "", "mtu": 0, "up": False, "ipv6": ""}
    code, out, err = _run(["ip", "-j", "addr", "show", "dev", name])
    if code != 0:
        raise NetcfgError(err or "no such interface: %s" % name)
    import json
    try:
        entries = json.loads(out)
    except ValueError:
        entries = []
    for entry in entries:
        info["mac"] = entry.get("address", "") or info["mac"]
        info["mtu"] = int(entry.get("mtu", 0) or 0)
        info["up"] = "UP" in (entry.get("flags") or [])
        for addr in entry.get("addr_info", []):
            if addr.get("family") == "inet" and not info["ipv4"]:
                info["ipv4"] = addr.get("local", "")
                info["prefix"] = int(addr.get("prefixlen", 0) or 0)
            elif addr.get("family") == "inet6" and not info["ipv6"]:
                if not str(addr.get("local", "")).startswith("fe80"):
                    info["ipv6"] = addr.get("local", "")
    if info["ipv4"] and info["prefix"]:
        net = ipaddress.ip_network("%s/%d" % (info["ipv4"], info["prefix"]),
                                   strict=False)
        info["cidr"] = str(net)
    return info


def default_gateway(interface: str = "") -> str:
    """The next hop this machine uses, which is the usual poisoning partner."""
    argv = ["ip", "-o", "route", "show", "default"]
    if interface:
        argv += ["dev", interface]
    code, out, _ = _run(argv)
    if code != 0 or not out:
        return ""
    m = re.search(r"default\s+via\s+(\S+)", out.splitlines()[0])
    return m.group(1) if m else ""


# --------------------------------------------------------------- monitor mode

def monitor_start(interface: str, channel="") -> dict:
    """Put `interface` into 802.11 monitor mode, locked to `channel` if given,
    so the radio hands up EVERY frame on the air -- including other stations',
    which a managed client never sees. Takes the interface off the network.
    Root only; the same `iw`/`ip` sequence verified live on iwlwifi."""
    if not interface:
        raise NetcfgError("an interface is required")
    _run(["nmcli", "device", "set", interface, "managed", "no"])   # best effort
    code, _o, err = _run(["ip", "link", "set", interface, "down"])
    if code != 0:
        raise NetcfgError(err or ("could not bring %s down" % interface))
    code, _o, err = _run(["iw", "dev", interface, "set", "monitor", "control"])
    if code != 0:                                    # stricter drivers
        code, _o, err = _run(["iw", "dev", interface, "set", "type", "monitor"])
        if code != 0:
            _run(["ip", "link", "set", interface, "up"])
            raise NetcfgError(
                err or ("%s does not support monitor mode" % interface))
    _run(["ip", "link", "set", interface, "up"])
    if channel:
        _run(["iw", "dev", interface, "set", "channel", str(channel)])
    _code, out, _e = _run(["iw", "dev", interface, "info"])
    if "type monitor" not in out:
        raise NetcfgError("%s did not enter monitor mode" % interface)
    return {"interface": interface, "mode": "monitor",
            "channel": str(channel or "")}


def monitor_stop(interface: str, reconnect: str = "") -> dict:
    """Restore `interface` to managed mode and reconnect it. Idempotent and
    best-effort: it is also what the helper runs on shutdown, so a crash never
    leaves the radio stuck off the network."""
    if not interface:
        return {"interface": interface, "mode": "managed"}
    _run(["ip", "link", "set", interface, "down"])
    _run(["iw", "dev", interface, "set", "type", "managed"])
    _run(["ip", "link", "set", interface, "up"])
    _run(["nmcli", "device", "set", interface, "managed", "yes"])
    if reconnect:
        _run(["nmcli", "connection", "up", reconnect], timeout=25)
    else:
        _run(["nmcli", "device", "connect", interface], timeout=25)
    return {"interface": interface, "mode": "managed"}


def arp_table() -> dict[str, str]:
    """The kernel neighbour cache, as {ip: mac}."""
    out_map: dict[str, str] = {}
    code, out, _ = _run(["ip", "-o", "neigh", "show"])
    if code != 0:
        return out_map
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 5 and "lladdr" in parts:
            ip = parts[0]
            mac = parts[parts.index("lladdr") + 1]
            if mac and mac != "00:00:00:00:00:00":
                out_map[ip] = mac.lower()
    return out_map


# --------------------------------------------------------------------- sysctl

def _sysctl_read(key: str) -> str | None:
    path = "/proc/sys/" + key.replace(".", "/")
    try:
        with open(path, "r", encoding="ascii") as fh:
            return fh.read().strip()
    except OSError:
        return None


def _sysctl_write(key: str, value: str) -> bool:
    path = "/proc/sys/" + key.replace(".", "/")
    try:
        with open(path, "w", encoding="ascii") as fh:
            fh.write(value)
        return True
    except OSError:
        return False


class KernelState:
    """Borrow forwarding and redirect settings; give them back unchanged."""

    def __init__(self, interface: str = "") -> None:
        self.interface = interface
        self._saved: dict[str, str] = {}
        self.applied = False

    def _keys(self) -> list[str]:
        keys = ["net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding",
                "net.ipv4.conf.all.send_redirects",
                "net.ipv4.conf.default.send_redirects"]
        if self.interface:
            keys.append("net.ipv4.conf.%s.send_redirects" % self.interface)
        return keys

    def enable_forwarding(self) -> dict:
        """Turn routing on and redirects off, remembering the old values."""
        changed = {}
        wanted = {"net.ipv4.ip_forward": "1",
                  "net.ipv6.conf.all.forwarding": "1",
                  "net.ipv4.conf.all.send_redirects": "0",
                  "net.ipv4.conf.default.send_redirects": "0"}
        if self.interface:
            wanted["net.ipv4.conf.%s.send_redirects" % self.interface] = "0"
        for key, value in wanted.items():
            current = _sysctl_read(key)
            if current is None:
                continue
            self._saved.setdefault(key, current)
            if current != value and _sysctl_write(key, value):
                changed[key] = (current, value)
        self.applied = True
        return changed

    def restore(self) -> dict:
        restored = {}
        for key, value in list(self._saved.items()):
            current = _sysctl_read(key)
            if current is not None and current != value:
                if _sysctl_write(key, value):
                    restored[key] = (current, value)
        self._saved.clear()
        self.applied = False
        return restored

    def snapshot(self) -> dict:
        return {k: _sysctl_read(k) for k in self._keys()}


# ------------------------------------------------------------------ nftables

class RedirectRules:
    """One private nftables table holding every redirect we install.

    Keeping the rules in their own table means teardown is a single
    `nft delete table`, which cannot damage a firewall someone else set up.
    """

    def __init__(self, interface: str, family: str = NFT_FAMILY,
                 table: str = NFT_TABLE) -> None:
        self.interface = interface
        self.family = family
        self.table = table
        self.rules: list[str] = []
        self.installed = False

    @staticmethod
    def available() -> bool:
        return shutil.which("nft") is not None

    def _apply(self, script: str) -> None:
        try:
            proc = subprocess.run(["nft", "-f", "-"], input=script, text=True,
                                  capture_output=True, timeout=10)
        except FileNotFoundError as exc:
            raise NetcfgError("nft is not installed (apt install nftables)") from exc
        except subprocess.TimeoutExpired as exc:
            raise NetcfgError("nft timed out") from exc
        if proc.returncode != 0:
            raise NetcfgError((proc.stderr or "nft failed").strip())

    def install(self, redirects: list[tuple[str, int, int]]) -> list[str]:
        """`redirects` is a list of (protocol, original_port, local_port)."""
        self.destroy()
        lines = [
            "table %s %s {" % (self.family, self.table),
            "  chain prerouting {",
            "    type nat hook prerouting priority dstnat; policy accept;",
        ]
        described = []
        for proto, dport, to_port in redirects:
            proto = proto.lower()
            if proto not in ("tcp", "udp"):
                continue
            lines.append("    iifname \"%s\" %s dport %d redirect to :%d"
                         % (self.interface, proto, int(dport), int(to_port)))
            described.append("%s/%d -> localhost:%d" % (proto, dport, to_port))
        lines.append("  }")
        lines.append("}")
        script = "\n".join(lines) + "\n"
        self._apply(script)
        self.rules = described
        self.installed = True
        return described

    def destroy(self) -> bool:
        if not shutil.which("nft"):
            return False
        # `nft delete table` on a table that does not exist is an error, so
        # the table is created first and then deleted: idempotent and quiet.
        script = ("table %s %s { }\ndelete table %s %s\n"
                  % (self.family, self.table, self.family, self.table))
        try:
            proc = subprocess.run(["nft", "-f", "-"], input=script, text=True,
                                  capture_output=True, timeout=10)
        except (OSError, subprocess.TimeoutExpired):
            return False
        self.installed = False
        self.rules = []
        return proc.returncode == 0

    def list_ruleset(self) -> str:
        code, out, _ = _run(["nft", "list", "table", self.family, self.table])
        return out if code == 0 else ""


# --------------------------------------------------------- transparent proxy

def original_destination(sock: socket.socket) -> tuple[str, int] | None:
    """Where the client was actually heading before netfilter redirected it.

    Returns None when the socket was not redirected.  That case needs care:
    on Linux the SO_ORIGINAL_DST lookup does not fail for an unNATed socket,
    it answers with the socket's *own* local address.  Handing that back to a
    proxy makes the proxy connect to itself, forever, so a destination equal
    to our own accept address is reported as "no original destination".
    """
    try:
        local = sock.getsockname()
    except OSError:
        local = None
    result = _original_destination(sock)
    if result is not None and local is not None and \
            result[0] == local[0] and result[1] == local[1]:
        return None
    return result


def _original_destination(sock: socket.socket) -> tuple[str, int] | None:
    try:
        family = sock.family
        if family == socket.AF_INET6:
            try:
                data = sock.getsockopt(socket.IPPROTO_IPV6,
                                       IP6T_SO_ORIGINAL_DST, 28)
                port, = struct.unpack_from("!H", data, 2)
                addr = socket.inet_ntop(socket.AF_INET6, data[8:24])
                return addr, port
            except OSError:
                # A v4-mapped connection answers on the IPv4 option instead.
                pass
        data = sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
        port, = struct.unpack_from("!H", data, 2)
        addr = socket.inet_ntoa(data[4:8])
        return addr, port
    except OSError:
        return None


def local_addresses() -> set[str]:
    """Every address on this machine, so proxies never relay back to self."""
    out = {"127.0.0.1", "::1"}
    code, text, _ = _run(["ip", "-j", "addr", "show"])
    if code != 0:
        return out
    import json
    try:
        entries = json.loads(text)
    except ValueError:
        return out
    for entry in entries:
        for addr in entry.get("addr_info", []):
            local = addr.get("local")
            if local:
                out.add(local)
    return out


def free_port(preferred: int) -> int:
    """`preferred` if it binds, otherwise whatever the kernel hands out."""
    for candidate in (preferred, 0):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("0.0.0.0", candidate))
            port = s.getsockname()[1]
            return port
        except OSError:
            continue
        finally:
            s.close()
    return preferred
