"""Finding the other sniffer on the segment.

A network card in normal operation hands the kernel only frames addressed to
its own MAC, to broadcast, or to a multicast group it joined.  In
promiscuous mode it hands up everything, and the ARP layer above it then
answers requests that were never addressed to it.

So each candidate is sent an ARP request for its own address, several times,
each with a destination MAC that a filtering card drops and a promiscuous one
does not.  A reply to one of those is the tell.  The test is not conclusive
-- some stacks filter in software, some hypervisors change the answer -- so
results are reported with the probe that triggered them rather than as a
verdict.
"""

from __future__ import annotations

import threading
import time

from netlab.intercept.arp import ARPOP_REQUEST, ArpSocket, build_arp, \
    ip_bytes, mac_bytes

# Destination MACs that a card in normal mode filters out.  The name is what
# the operator sees next to a host that answered it.
PROBES: list[tuple[str, str]] = [
    ("ff:ff:ff:ff:ff:fe", "31-bit broadcast"),
    ("ff:ff:00:00:00:00", "16-bit broadcast"),
    ("ff:00:00:00:00:00", "8-bit broadcast"),
    ("01:00:00:00:00:00", "group bit only"),
    ("01:00:5e:00:00:01", "all-hosts multicast"),
    ("01:00:5e:00:00:03", "unused multicast"),
    ("00:00:00:00:00:00", "null destination"),
]


class PromiscScanner:
    """ARP probes with destinations only a promiscuous host will accept."""

    def __init__(self, interface: str, local_mac: str, local_ip: str,
                 scope=None, audit=None, on_event=None) -> None:
        self.interface = interface
        self.local_mac = local_mac
        self.local_ip = local_ip
        self.scope = scope
        self.audit = audit
        self.on_event = on_event

    def scan(self, targets: list[str], rounds: int = 2,
             timeout: float = 2.5) -> list[dict]:
        """Probe `targets` and return the hosts that answered, with evidence."""
        in_scope = [t for t in targets
                    if self.scope is None or self.scope.contains(t)]
        if not in_scope:
            return []
        results: dict[str, dict] = {}
        src_mac = mac_bytes(self.local_mac)
        src_ip = ip_bytes(self.local_ip)

        with ArpSocket(self.interface, self.local_mac, self.local_ip) as sock:
            stop = threading.Event()

            def reader() -> None:
                while not stop.is_set():
                    for oper, sha, spa, _tha, tpa in sock.drain(0.3):
                        if oper != 2 or spa not in in_scope:
                            continue
                        entry = results.setdefault(
                            spa, {"ip": spa, "mac": sha, "probes": [],
                                  "replies": 0, "ts": time.time()})
                        entry["replies"] += 1

            thread = threading.Thread(target=reader, daemon=True)
            thread.start()
            for _round in range(max(1, rounds)):
                for dst_mac, label in PROBES:
                    before = {ip: results.get(ip, {}).get("replies", 0)
                              for ip in in_scope}
                    for ip in in_scope:
                        sock.send(build_arp(ARPOP_REQUEST, src_mac, src_ip,
                                            b"\x00" * 6, ip_bytes(ip),
                                            eth_dst=mac_bytes(dst_mac)))
                        time.sleep(0.002)
                    time.sleep(timeout / len(PROBES))
                    for ip, entry in results.items():
                        if entry["replies"] > before.get(ip, 0) and \
                                label not in entry["probes"]:
                            entry["probes"].append(label)
            time.sleep(0.5)
            stop.set()
            thread.join(timeout=1.0)

        found = []
        for entry in results.values():
            if not entry["probes"]:
                continue
            entry["likely_promiscuous"] = len(entry["probes"]) >= 1
            entry["confidence"] = ("high" if len(entry["probes"]) >= 3
                                   else "medium" if len(entry["probes"]) == 2
                                   else "low")
            found.append(entry)
            if self.on_event:
                self.on_event("promisc.found", entry)
        found.sort(key=lambda e: (-len(e["probes"]), e["ip"]))
        if self.audit:
            self.audit.record("promisc.scan", targets=len(in_scope),
                              found=[e["ip"] for e in found])
        return found
