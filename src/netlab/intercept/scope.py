"""Engagement scope and audit trail for active interception.

NetLab's passive side only observes.  Everything under `netlab.intercept`
*transmits*, and transmitting on a network nobody asked you to test is the
difference between a penetration test and an offence.

So nothing in this package runs without an **engagement**: a named record of
which interface, which gateway and which targets the operator declared to be
in scope.  It is written to disk before the first forged frame leaves the
card, every active module checks each address against it, and every action is
appended to a JSONL audit log that can be attached to a report.

The scope is a real gate, not a warning banner: `Engagement.check()` raises
on an out-of-scope address and the callers let that propagate.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import threading
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path

from netlab.config import data_dir

SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


class ScopeError(Exception):
    """An action was requested against an address outside the engagement."""


def engagements_dir() -> Path:
    return data_dir() / "engagements"


def slug(name: str) -> str:
    s = SAFE_NAME.sub("-", (name or "").strip()).strip("-")
    return s[:64] or "engagement"


def parse_targets(raw) -> list[str]:
    """Normalise a target specification into a list of CIDR strings.

    Accepts single addresses, CIDR blocks, `a.b.c.d-e` last-octet ranges and
    comma/whitespace separated lists of any of those.
    """
    if isinstance(raw, str):
        items = [p for p in re.split(r"[,\s]+", raw) if p]
    else:
        items = [str(p).strip() for p in (raw or []) if str(p).strip()]

    out: list[str] = []
    for item in items:
        m = re.fullmatch(r"(\d+\.\d+\.\d+)\.(\d+)-(\d+)", item)
        if m:
            base, lo, hi = m.group(1), int(m.group(2)), int(m.group(3))
            if not 0 <= lo <= hi <= 255:
                raise ValueError("bad address range: %s" % item)
            for last in range(lo, hi + 1):
                out.append(str(ipaddress.ip_network("%s.%d/32" % (base, last))))
            continue
        try:
            net = ipaddress.ip_network(item, strict=False)
        except ValueError as exc:
            raise ValueError("not an address or network: %s" % item) from exc
        out.append(str(net))
    if not out:
        raise ValueError("no targets given")
    return out


@dataclass
class Engagement:
    """A declared, on-disk authorisation to transmit."""

    name: str = ""
    operator: str = ""
    interface: str = ""
    gateway: str = ""
    targets: list[str] = field(default_factory=list)
    note: str = ""
    created: float = 0.0
    # Set once the operator has confirmed the arming dialog.
    authorised: bool = False
    authorisation_text: str = ""

    _networks: list = field(default_factory=list, repr=False, compare=False)

    # --------------------------------------------------------------- build

    def __post_init__(self) -> None:
        self.compile()

    def compile(self) -> None:
        nets = []
        for t in self.targets:
            try:
                nets.append(ipaddress.ip_network(t, strict=False))
            except ValueError:
                continue
        self._networks = nets

    @classmethod
    def create(cls, name: str, interface: str, gateway: str, targets,
               operator: str = "", note: str = "") -> "Engagement":
        eng = cls(name=name.strip() or "engagement",
                  operator=operator or os.environ.get("USER", ""),
                  interface=interface.strip(),
                  gateway=(gateway or "").strip(),
                  targets=parse_targets(targets),
                  note=note,
                  created=time.time())
        if not eng.interface:
            raise ValueError("an interface must be chosen")
        return eng

    # --------------------------------------------------------------- query

    @property
    def host_count(self) -> int:
        return sum(net.num_addresses for net in self._networks)

    def contains(self, ip: str | None) -> bool:
        if not ip:
            return False
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self._networks)

    def check(self, ip: str | None, what: str = "target") -> str:
        """Return `ip`, or raise ScopeError if it is not in the engagement."""
        if not self.authorised:
            raise ScopeError(
                "engagement '%s' has not been authorised; arm it first"
                % self.name)
        if not self.contains(ip):
            raise ScopeError(
                "%s %s is outside engagement '%s' (in scope: %s)"
                % (what, ip, self.name, ", ".join(self.targets) or "nothing"))
        return ip or ""

    def hosts(self, limit: int = 4096) -> list[str]:
        """Expand the scope into individual addresses, bounded."""
        out: list[str] = []
        for net in self._networks:
            if net.prefixlen == net.max_prefixlen:
                out.append(str(net.network_address))
                continue
            for host in net.hosts():
                out.append(str(host))
                if len(out) >= limit:
                    return out
        return out

    # ---------------------------------------------------------- persistence

    def to_dict(self) -> dict:
        d = asdict(self)
        d.pop("_networks", None)
        return d

    @classmethod
    def from_dict(cls, data: dict) -> "Engagement":
        known = {f for f in cls.__dataclass_fields__ if not f.startswith("_")}
        return cls(**{k: v for k, v in (data or {}).items() if k in known})

    def directory(self) -> Path:
        stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime(self.created or time.time()))
        return engagements_dir() / ("%s-%s" % (stamp, slug(self.name)))

    def save(self) -> Path:
        d = self.directory()
        d.mkdir(parents=True, exist_ok=True)
        path = d / "engagement.json"
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(self.to_dict(), indent=2) + "\n",
                       encoding="utf-8")
        tmp.replace(path)
        return path

    @classmethod
    def load(cls, path) -> "Engagement":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls.from_dict(data)

    @classmethod
    def recent(cls, limit: int = 20) -> list["Engagement"]:
        out = []
        base = engagements_dir()
        if not base.is_dir():
            return out
        for d in sorted(base.iterdir(), reverse=True):
            f = d / "engagement.json"
            if f.is_file():
                try:
                    out.append(cls.load(f))
                except (OSError, ValueError):
                    continue
            if len(out) >= limit:
                break
        return out

    def summary(self) -> str:
        return "%s  ·  %s  ·  gw %s  ·  %s" % (
            self.name, self.interface, self.gateway or "-",
            ", ".join(self.targets[:4]) + ("  (+%d)" % (len(self.targets) - 4)
                                           if len(self.targets) > 4 else ""))


class AuditLog:
    """Append-only JSONL record of every active action in an engagement."""

    def __init__(self, path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()
        self._count = 0
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass

    @property
    def count(self) -> int:
        return self._count

    def record(self, action: str, **fields) -> dict:
        entry = {"ts": time.time(),
                 "iso": time.strftime("%Y-%m-%dT%H:%M:%S"),
                 "pid": os.getpid(),
                 "uid": os.geteuid(),
                 "action": action}
        entry.update(fields)
        line = json.dumps(entry, default=str, sort_keys=True)
        with self._lock:
            self._count += 1
            try:
                with self.path.open("a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
                    fh.flush()
                    os.fsync(fh.fileno())
            except OSError:
                # An unwritable audit log must not silently stop an engagement
                # that is already running, but it is reported upward.
                entry["audit_write_failed"] = True
        return entry

    def read(self, limit: int = 2000) -> list[dict]:
        try:
            lines = self.path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return []
        out = []
        for line in lines[-limit:]:
            try:
                out.append(json.loads(line))
            except ValueError:
                continue
        return out
