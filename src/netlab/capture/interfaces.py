"""Capture interface discovery.

Primary source is `dumpcap -D -M`, which reports exactly the devices the
capture backend can actually open.  That is then enriched from sysfs with
link state, MAC address, driver kind and counters.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

SYS_NET = Path("/sys/class/net")

# Pseudo-devices dumpcap offers that are rarely what an operator wants first.
PSEUDO = {"any", "nflog", "nfqueue", "dbus-system", "dbus-session",
          "bluetooth-monitor", "ciscodump", "randpkt", "sshdump", "udpdump",
          "wifidump", "sdjournal"}


@dataclass(slots=True)
class Interface:
    name: str
    description: str = ""
    addresses: list[str] = field(default_factory=list)
    loopback: bool = False
    extcap: bool = False
    kind: str = "other"
    mac: str | None = None
    operstate: str = "unknown"
    mtu: int | None = None
    rx_packets: int = 0
    tx_packets: int = 0
    rx_bytes: int = 0
    tx_bytes: int = 0

    @property
    def is_up(self) -> bool:
        return self.operstate == "up" or (self.loopback and
                                          self.operstate in ("unknown", "up"))

    @property
    def is_pseudo(self) -> bool:
        return self.name in PSEUDO or self.extcap

    @property
    def primary_address(self) -> str:
        for a in self.addresses:
            if ":" not in a:
                return a
        return self.addresses[0] if self.addresses else ""

    @property
    def label(self) -> str:
        bits = [self.name]
        if self.primary_address:
            bits.append(self.primary_address)
        if self.kind not in ("other", "ethernet"):
            bits.append(self.kind)
        return "  -  ".join(bits)


class InterfaceError(Exception):
    pass


def _sysfs_int(path: Path, default: int = 0) -> int:
    try:
        return int(path.read_text().strip())
    except (OSError, ValueError):
        return default


def _sysfs_text(path: Path, default: str = "") -> str:
    try:
        return path.read_text().strip()
    except OSError:
        return default


def _classify(name: str) -> str:
    base = SYS_NET / name
    if not base.exists():
        return "other"
    if (base / "wireless").exists() or (base / "phy80211").exists():
        return "wireless"
    if (base / "bridge").exists():
        return "bridge"
    if (base / "tun_flags").exists():
        return "tun/tap"
    if name == "lo":
        return "loopback"
    try:
        target = str((base / "device").resolve())
        if "virtual" in str(base.resolve()) and not (base / "device").exists():
            return "virtual"
        if target:
            return "ethernet"
    except OSError:
        pass
    return "virtual"


def _enrich(iface: Interface) -> None:
    base = SYS_NET / iface.name
    if not base.exists():
        return
    iface.mac = _sysfs_text(base / "address") or None
    iface.operstate = _sysfs_text(base / "operstate", "unknown")
    iface.mtu = _sysfs_int(base / "mtu", 0) or None
    stats = base / "statistics"
    iface.rx_packets = _sysfs_int(stats / "rx_packets")
    iface.tx_packets = _sysfs_int(stats / "tx_packets")
    iface.rx_bytes = _sysfs_int(stats / "rx_bytes")
    iface.tx_bytes = _sysfs_int(stats / "tx_bytes")
    iface.kind = _classify(iface.name)


def dumpcap_path() -> str | None:
    return shutil.which("dumpcap")


def list_interfaces(include_pseudo: bool = True,
                    timeout: float = 8.0) -> list[Interface]:
    """Enumerate capture interfaces via dumpcap, enriched from sysfs."""
    exe = dumpcap_path()
    if not exe:
        raise InterfaceError(
            "dumpcap was not found on PATH. Install it with: "
            "sudo apt install wireshark-common")
    try:
        proc = subprocess.run([exe, "-D", "-M"], capture_output=True,
                              timeout=timeout, text=True)
    except subprocess.TimeoutExpired:
        raise InterfaceError("dumpcap -D timed out after %.0fs" % timeout)
    except OSError as exc:
        raise InterfaceError("could not run dumpcap: %s" % exc)

    if proc.returncode != 0:
        err = (proc.stderr or "").strip() or "dumpcap exited %d" % proc.returncode
        raise InterfaceError(err)

    try:
        raw = json.loads(proc.stdout)
    except ValueError:
        raise InterfaceError("could not parse the dumpcap interface list")

    out: list[Interface] = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        for name, meta in entry.items():
            meta = meta or {}
            iface = Interface(
                name=name,
                description=(meta.get("friendly_name")
                             or meta.get("vendor_description") or ""),
                addresses=[a for a in (meta.get("addrs") or []) if a],
                loopback=bool(meta.get("loopback")),
                extcap=bool(meta.get("extcap")),
            )
            _enrich(iface)
            if iface.loopback:
                iface.kind = "loopback"
            out.append(iface)

    if not include_pseudo:
        out = [i for i in out if not i.is_pseudo]

    def sort_key(i: Interface):
        # Live, addressed, physical interfaces first - that is what an
        # operator almost always wants to click.
        return (
            0 if i.is_up else 1,
            0 if i.addresses else 1,
            {"wireless": 0, "ethernet": 1, "bridge": 2, "loopback": 3}.get(i.kind, 4),
            1 if i.is_pseudo else 0,
            i.name,
        )

    return sorted(out, key=sort_key)


def interface_exists(name: str) -> bool:
    if (SYS_NET / name).exists():
        return True
    try:
        return any(i.name == name for i in list_interfaces())
    except InterfaceError:
        return False


def validate_bpf(expression: str, interface: str | None = None,
                 timeout: float = 6.0) -> tuple[bool, str]:
    """Ask the real capture backend whether a BPF filter compiles.

    `dumpcap -d` exits 0 even for a filter it rejected, so the exit status is
    useless here and the output has to be read instead: a filter that
    compiled is echoed back as BPF opcodes, a rejected one produces an
    "Invalid capture filter" diagnostic.
    """
    expr = (expression or "").strip()
    if not expr:
        return True, ""
    exe = dumpcap_path()
    if not exe:
        return False, "dumpcap not available to validate the filter"
    args = [exe, "-d", "-f", expr]
    if interface:
        args[1:1] = ["-i", interface]
    try:
        proc = subprocess.run(args, capture_output=True, text=True,
                              timeout=timeout)
    except (subprocess.TimeoutExpired, OSError) as exc:
        return False, "could not validate filter: %s" % exc

    out = (proc.stdout or "") + "\n" + (proc.stderr or "")
    low = out.lower()

    if "invalid capture filter" in low or "isn't a valid capture filter" in low:
        detail = ""
        match = re.search(r"\(([^()]*(?:parse|syntax|unknown|invalid)[^()]*)\)",
                          out, re.IGNORECASE)
        if match:
            detail = match.group(1).strip()
        else:
            for line in out.splitlines():
                if "isn't a valid capture filter" in line.lower():
                    detail = line.strip()
                    break
        return False, detail or "libpcap rejected the filter expression"

    if "permission" in low or "you don't have permission" in low:
        return False, "no permission to open %s for filter validation" % (
            interface or "the capture device")

    # A compiled filter is printed as numbered BPF instructions.
    if re.search(r"^\(\d{3}\)", out, re.MULTILINE):
        return True, ""

    if proc.returncode != 0:
        first = next((l.strip() for l in out.splitlines() if l.strip()), "")
        return False, first or "filter rejected by libpcap"

    return True, ""
