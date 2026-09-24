"""Nmap integration.

Nmap is the one part of NetLab that transmits: it actively probes a target,
unlike everything else here, which only observes.  Results are kept in their
own store and are never mixed into the passive capture tables.

The scan is executed with an argument vector (never a shell string), and the
target is validated before launch.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
import threading
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

from PySide6.QtCore import QObject, Signal


@dataclass(slots=True)
class NmapProfile:
    name: str
    args: list[str]
    description: str
    needs_root: bool = False


PROFILES: list[NmapProfile] = [
    NmapProfile("Ping sweep (host discovery)", ["-sn"],
                "Find live hosts without scanning ports."),
    NmapProfile("Quick scan (top 100 ports)", ["-T4", "-F"],
                "Fast TCP connect scan of the 100 most common ports."),
    NmapProfile("Standard scan (top 1000 ports)", ["-T4"],
                "Default TCP scan of the 1000 most common ports."),
    NmapProfile("Service and version detection", ["-T4", "-sV"],
                "Identify the service and version behind each open port."),
    NmapProfile("Full TCP port scan", ["-T4", "-p-"],
                "All 65535 TCP ports. Slow."),
    NmapProfile("SYN stealth scan", ["-T4", "-sS"],
                "Half-open TCP scan. Requires root.", needs_root=True),
    NmapProfile("UDP top 100 ports", ["-sU", "--top-ports", "100"],
                "UDP scan. Requires root and is slow.", needs_root=True),
    NmapProfile("OS and service detection", ["-T4", "-A"],
                "Aggressive: OS, versions, scripts, traceroute.",
                needs_root=True),
]

# Accepts hostnames, IPv4/IPv6 literals, CIDR ranges and nmap octet ranges.
_TARGET_RE = re.compile(r"^[A-Za-z0-9_.:\-/\[\],*]+$")


@dataclass(slots=True)
class NmapPort:
    port: int
    protocol: str
    state: str
    service: str = ""
    product: str = ""
    version: str = ""
    extra: str = ""

    @property
    def service_text(self) -> str:
        bits = [b for b in (self.service, self.product, self.version) if b]
        return " ".join(bits) if bits else "-"


@dataclass(slots=True)
class NmapHost:
    address: str
    addr_type: str = "ipv4"
    mac: str = ""
    vendor: str = ""
    hostnames: list[str] = field(default_factory=list)
    state: str = "unknown"
    ports: list[NmapPort] = field(default_factory=list)
    os_matches: list[str] = field(default_factory=list)

    @property
    def open_ports(self) -> list[NmapPort]:
        return [p for p in self.ports if p.state == "open"]


@dataclass
class NmapResult:
    command: str = ""
    args: str = ""
    started: str = ""
    finished: str = ""
    summary: str = ""
    hosts: list[NmapHost] = field(default_factory=list)
    raw_xml_path: str = ""
    exit_code: int = 0


def nmap_path(configured: str = "nmap") -> str | None:
    return shutil.which(configured or "nmap")


def nmap_version(exe: str) -> str:
    try:
        proc = subprocess.run([exe, "--version"], capture_output=True,
                              text=True, timeout=6)
        first = (proc.stdout or "").splitlines()
        return first[0].strip() if first else ""
    except (subprocess.TimeoutExpired, OSError):
        return ""


def validate_target(target: str) -> tuple[bool, str]:
    t = (target or "").strip()
    if not t:
        return False, "Enter a target host, range or CIDR."
    if len(t) > 512:
        return False, "Target is too long."
    for part in t.split():
        if not _TARGET_RE.match(part):
            return False, ("%r contains characters that are not valid in an "
                           "nmap target." % part)
    return True, ""


def parse_xml(path: str | Path) -> NmapResult:
    """Parse an nmap -oX report into structured results."""
    result = NmapResult(raw_xml_path=str(path))
    try:
        tree = ET.parse(str(path))
    except (ET.ParseError, OSError) as exc:
        result.summary = "Could not parse the nmap XML report: %s" % exc
        return result
    root = tree.getroot()
    result.args = root.get("args", "")
    result.started = root.get("startstr", "")

    for host_el in root.findall("host"):
        host = NmapHost(address="")
        status = host_el.find("status")
        if status is not None:
            host.state = status.get("state", "unknown")
        for addr in host_el.findall("address"):
            atype = addr.get("addrtype", "")
            if atype in ("ipv4", "ipv6"):
                host.address = addr.get("addr", "")
                host.addr_type = atype
            elif atype == "mac":
                host.mac = addr.get("addr", "")
                host.vendor = addr.get("vendor", "")
        names = host_el.find("hostnames")
        if names is not None:
            for hn in names.findall("hostname"):
                name = hn.get("name")
                if name:
                    host.hostnames.append(name)
        ports_el = host_el.find("ports")
        if ports_el is not None:
            for p in ports_el.findall("port"):
                st = p.find("state")
                svc = p.find("service")
                try:
                    num = int(p.get("portid", "0"))
                except ValueError:
                    continue
                host.ports.append(NmapPort(
                    port=num,
                    protocol=p.get("protocol", ""),
                    state=st.get("state", "") if st is not None else "",
                    service=svc.get("name", "") if svc is not None else "",
                    product=svc.get("product", "") if svc is not None else "",
                    version=svc.get("version", "") if svc is not None else "",
                    extra=svc.get("extrainfo", "") if svc is not None else "",
                ))
        os_el = host_el.find("os")
        if os_el is not None:
            for m in os_el.findall("osmatch"):
                name = m.get("name")
                if name:
                    host.os_matches.append(
                        "%s (%s%%)" % (name, m.get("accuracy", "?")))
        if host.address:
            result.hosts.append(host)

    run = root.find("runstats/finished")
    if run is not None:
        result.finished = run.get("timestr", "")
        result.summary = run.get("summary", "")
    return result


class NmapRunner(QObject):
    """Runs one nmap scan in a background thread and streams its output."""

    output = Signal(str)
    started_scan = Signal(str)          # command line
    finished_scan = Signal(object)      # NmapResult
    failed = Signal(str)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._proc: subprocess.Popen | None = None
        self._thread: threading.Thread | None = None
        self._cancel = threading.Event()

    @property
    def is_running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def start(self, target: str, extra_args: list[str], exe: str = "nmap",
              use_pkexec: bool = False) -> bool:
        if self.is_running:
            self.failed.emit("A scan is already running.")
            return False

        ok, msg = validate_target(target)
        if not ok:
            self.failed.emit(msg)
            return False

        resolved = nmap_path(exe)
        if not resolved:
            self.failed.emit(
                "nmap was not found.\n\nInstall it with:  sudo apt install nmap")
            return False

        tmp = tempfile.NamedTemporaryFile(prefix="netlab-nmap-", suffix=".xml",
                                          delete=False)
        tmp.close()
        argv = [resolved, *extra_args, "-oX", tmp.name, *target.split()]
        if use_pkexec:
            pk = shutil.which("pkexec")
            if not pk:
                self.failed.emit(
                    "pkexec was not found, so the scan cannot be elevated.\n\n"
                    "Install it with:  sudo apt install pkexec")
                return False
            argv = [pk, *argv]

        self._cancel.clear()
        self._thread = threading.Thread(
            target=self._run, args=(argv, tmp.name), name="netlab-nmap",
            daemon=True)
        self._thread.start()
        self.started_scan.emit(" ".join(argv))
        return True

    def cancel(self) -> None:
        self._cancel.set()
        proc = self._proc
        if proc and proc.poll() is None:
            try:
                proc.terminate()
            except OSError:
                pass

    def _run(self, argv: list[str], xml_path: str) -> None:
        try:
            self._proc = subprocess.Popen(
                argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1)
        except OSError as exc:
            self.failed.emit("Could not start nmap:\n%s" % exc)
            return

        try:
            assert self._proc.stdout is not None
            for line in self._proc.stdout:
                self.output.emit(line.rstrip("\n"))
        except (OSError, ValueError):
            pass

        rc = self._proc.wait()
        if self._cancel.is_set():
            self.failed.emit("Scan cancelled.")
            return
        if rc != 0 and not Path(xml_path).stat().st_size:
            self.failed.emit("nmap exited with status %d." % rc)
            return
        result = parse_xml(xml_path)
        result.command = " ".join(argv)
        result.exit_code = rc
        self.finished_scan.emit(result)
