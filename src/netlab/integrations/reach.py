"""Unprivileged liveness probe: wake an on-link host and confirm it is present.

Before arming interception on a target, NetLab checks the target actually
answers right now. A phone asleep on Wi-Fi does not reply to a single ARP, so
the privileged helper would refuse the arm ("no target answered ARP"); poisoning
a host that is not there just fails. A few non-blocking TCP connects force the
kernel to (re)resolve the target's MAC -- the SYN queues behind ARP, which also
nudges a dozing radio awake -- and the neighbour table is then read as ground
truth. No raw sockets, no elevation, at most one SYN per port.
"""
from __future__ import annotations

import json
import select
import socket
import subprocess


def neighbour_present(ip: str) -> bool:
    """True when the kernel has a usable L2 binding for `ip` (a MAC, not a
    FAILED/INCOMPLETE lookup) -- i.e. the host answered ARP at some point."""
    if not ip:
        return False
    try:
        out = subprocess.run(["ip", "-j", "neighbor", "show", "to", ip],
                             capture_output=True, text=True,
                             timeout=2, check=True).stdout
        for row in json.loads(out or "[]"):
            state = row.get("state") or []
            if row.get("lladdr") and not set(state) & {"FAILED", "INCOMPLETE"}:
                return True
    except (OSError, ValueError, subprocess.SubprocessError):
        pass
    return False


def _nudge(ip: str, ports, settle: float) -> None:
    socks = []
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setblocking(False)
            s.connect_ex((ip, port))   # queues a SYN behind ARP; result ignored
            socks.append(s)
        except OSError:
            pass
    if socks:
        select.select([], socks, [], settle)
        for s in socks:
            try:
                s.close()
            except OSError:
                pass


def host_reachable(ip: str, attempts: int = 3, settle: float = 0.4,
                   ports=(80, 443, 22, 9)) -> bool:
    """True when the on-link host is present at L2 now. Returns immediately if
    it is already in the neighbour table, otherwise nudges it awake and rechecks
    up to `attempts` times (bounded by attempts*settle seconds)."""
    if not ip:
        return False
    for _ in range(max(1, attempts)):
        if neighbour_present(ip):
            return True
        _nudge(ip, ports, settle)
    return neighbour_present(ip)
