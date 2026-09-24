"""netlab-helper: the only part of NetLab that runs as root.

The GUI stays unprivileged and drives this over a pipe.  Everything that
needs CAP_NET_RAW or CAP_NET_ADMIN -- raw ARP frames, sysctl, nftables, a
DHCP socket on port 67 -- happens here and nowhere else, so the attack
surface of running NetLab is one small, auditable process rather than a Qt
application.

The helper owns the promise that the network is put back.  It disarms on the
stop command, on SIGTERM and SIGINT, when stdin reaches end of file (which is
what happens when the GUI exits or is killed), and from an atexit hook if
something else goes wrong.
"""

from __future__ import annotations

import io
import json
import logging
import os
import signal
import sys
import threading
import traceback

if __name__ == "__main__" and __package__ in (None, ""):
    # Started by path rather than as a module (pkexec runs an absolute
    # path, and an uninstalled checkout has no netlab on sys.path).
    import pathlib as _pathlib
    sys.path.insert(0, str(_pathlib.Path(__file__).resolve().parents[2]))

from netlab import __version__
from netlab.intercept import netcfg
from netlab.intercept.scope import Engagement, ScopeError
from netlab.intercept.session import InterceptError, InterceptSession
from netlab.priv import protocol

log = logging.getLogger("netlab.helper")


class Helper:
    """Reads commands from stdin, writes replies and events to stdout."""

    def __init__(self, stdin=None, stdout=None) -> None:
        self.stdin = stdin if stdin is not None else sys.stdin.buffer
        self.stdout = stdout if stdout is not None else sys.stdout.buffer
        self.session: InterceptSession | None = None
        self._write_lock = threading.Lock()
        # Commands run on their own threads (see _dispatch), so two of them can
        # touch self.session at once.  This lock guards the short critical
        # sections that create, swap out or clear it, so a second arm cannot
        # slip past the "already armed" check and a disarm cannot race an arm.
        self._session_lock = threading.Lock()
        self._stop = threading.Event()
        self._workers: list[threading.Thread] = []

    # ---------------------------------------------------------------- send

    def send(self, obj: dict) -> None:
        payload = protocol.encode(obj)
        with self._write_lock:
            try:
                self.stdout.write(payload)
                self.stdout.flush()
            except (OSError, ValueError):
                self._stop.set()

    def emit(self, name: str, data) -> None:
        self.send(protocol.event(name, data if isinstance(data, dict)
                                 else {"value": data}))

    def log(self, message: str, level: str = "info") -> None:
        self.emit("log", {"level": level, "message": message})

    # ----------------------------------------------------------------- run

    def run(self) -> int:
        # Signals can only be installed from the main thread; running the
        # helper anywhere else (a test harness, an embedded use) is allowed,
        # it just loses the signal path and keeps the stdin-EOF one.
        for name in ("SIGTERM", "SIGINT", "SIGHUP"):
            number = getattr(signal, name, None)
            if number is None:
                continue
            try:
                signal.signal(number, self._signal)
            except (ValueError, OSError):
                pass

        self.emit("ready", self._hello())
        try:
            for raw in self.stdin:
                if self._stop.is_set():
                    break
                try:
                    message = protocol.decode(raw)
                except protocol.ProtocolError as exc:
                    self.log("ignored an unreadable line: %s" % exc, "warn")
                    continue
                self._dispatch(message)
        except (OSError, ValueError):
            pass
        finally:
            # End of file on stdin means the GUI is gone.
            self.shutdown("stdin closed")
        return 0

    def _signal(self, signum, _frame) -> None:
        self.shutdown("signal %d" % signum)
        self._stop.set()

    def shutdown(self, reason: str = "") -> dict:
        report = {}
        with self._session_lock:
            session, self.session = self.session, None
        if session is not None:
            try:
                report = session.disarm()
            except Exception as exc:             # pragma: no cover
                report = {"errors": [str(exc)]}
            self.emit("shutdown", {"reason": reason, "report": report})
        self._stop.set()
        return report

    # ------------------------------------------------------------ dispatch

    def _dispatch(self, message: dict) -> None:
        req_id = message.get("id", 0)
        command = str(message.get("cmd", ""))
        args = message.get("args") or {}
        if command not in protocol.COMMANDS:
            self.send(protocol.failure(req_id, "unknown command: %s" % command,
                                       "unknown"))
            return
        handler = getattr(self, "cmd_" + command, None)
        if handler is None:                      # pragma: no cover
            self.send(protocol.failure(req_id, "unimplemented: %s" % command))
            return

        def run() -> None:
            try:
                result = handler(**args) if args else handler()
                self.send(protocol.reply(req_id, result))
            except ScopeError as exc:
                self.send(protocol.failure(req_id, str(exc), "scope"))
            except (InterceptError, netcfg.NetcfgError) as exc:
                self.send(protocol.failure(req_id, str(exc), "intercept"))
            except TypeError as exc:
                self.send(protocol.failure(req_id, "bad arguments: %s" % exc,
                                           "arguments"))
            except Exception as exc:
                log.debug("command %s failed", command, exc_info=True)
                self.send(protocol.failure(
                    req_id, "%s: %s" % (type(exc).__name__, exc), "internal"))

        # Commands run off the reader thread so a slow scan cannot block the
        # stop command that would end it.
        thread = threading.Thread(target=run, name="cmd-%s" % command,
                                  daemon=True)
        self._workers = [t for t in self._workers if t.is_alive()]
        self._workers.append(thread)
        thread.start()

    # -------------------------------------------------------------- commands

    def _hello(self) -> dict:
        return {
            "protocol": protocol.PROTOCOL_VERSION,
            "version": __version__,
            "pid": os.getpid(),
            "euid": os.geteuid(),
            "root": os.geteuid() == 0,
            "nftables": netcfg.RedirectRules.available(),
            "owner_uid": _owner_uid(),
        }

    def cmd_hello(self) -> dict:
        return self._hello()

    def cmd_interfaces(self) -> list:
        from netlab.capture.interfaces import list_interfaces
        out = []
        for iface in list_interfaces(include_pseudo=False):
            try:
                info = netcfg.interface_info(iface.name)
            except netcfg.NetcfgError:
                continue
            info["gateway"] = netcfg.default_gateway(iface.name)
            out.append(info)
        return out

    def cmd_iface(self, interface: str) -> dict:
        info = netcfg.interface_info(interface)
        info["gateway"] = netcfg.default_gateway(interface)
        info["neighbours"] = netcfg.arp_table()
        return info

    def cmd_gateway(self, interface: str = "") -> dict:
        return {"gateway": netcfg.default_gateway(interface)}

    def cmd_resolve(self, interface: str, ip: str) -> dict:
        from netlab.intercept.arp import ArpSocket
        info = netcfg.interface_info(interface)
        with ArpSocket(interface, info["mac"], info["ipv4"]) as sock:
            return {"ip": ip, "mac": sock.resolve(ip) or ""}

    def cmd_arp_scan(self, interface: str = "", cidr: str = "",
                     timeout: float = 3.0) -> list:
        from netlab.intercept.arp import scan
        if self.session is not None and not interface:
            return self.session.scan(cidr, timeout)
        info = netcfg.interface_info(interface)
        target = cidr or info.get("cidr", "")
        if not target:
            raise InterceptError("%s has no network to scan" % interface)
        return scan(interface, info["mac"], info["ipv4"], target,
                    timeout=float(timeout),
                    on_host=lambda h: self.emit("scan.host", h))

    def cmd_arm(self, engagement: dict, modules: dict | None = None,
                ca_dir: str = "") -> dict:
        eng = Engagement.from_dict(engagement)
        if not eng.authorised:
            raise ScopeError(
                "the engagement was sent without an authorisation; NetLab "
                "will not transmit until the operator confirms the scope")
        session = InterceptSession(eng, modules or {}, ca_dir=ca_dir,
                                   owner_uid=_owner_uid(),
                                   on_event=self.emit)
        # Claim the slot under the lock *before* arming: a session that exists
        # but has not finished arming still blocks a second arm, so two racing
        # cmd_arm calls cannot both start poisoning.
        with self._session_lock:
            if self.session is not None:
                raise InterceptError(
                    "an engagement is already armed; disarm first")
            self.session = session
        try:
            return session.arm()
        except Exception:
            with self._session_lock:
                if self.session is session:
                    self.session = None
            raise

    def cmd_disarm(self) -> dict:
        with self._session_lock:
            session, self.session = self.session, None
        if session is None:
            return {"armed": False, "note": "nothing was armed"}
        return session.disarm()

    def cmd_status(self) -> dict:
        session = self.session
        if session is None:
            return {"armed": False, "helper": self._hello()}
        status = session.status()
        status["helper"] = self._hello()
        return status

    def cmd_add_target(self, ip: str) -> dict:
        return self._session().add_target(ip)

    def cmd_remove_target(self, ip: str) -> dict:
        return self._session().remove_target(ip)

    def cmd_changer_rules(self, rules: list | None = None) -> dict:
        return {"rules": self._session().set_changer_rules(rules or [])}

    def cmd_dns_rules(self, rules: list | None = None) -> dict:
        return {"rules": self._session().set_dns_rules(rules or [])}

    def cmd_promisc_scan(self, targets: list | None = None) -> list:
        return self._session().promisc_scan(targets)

    def cmd_ca_info(self, ca_dir: str = "") -> dict:
        from netlab.intercept.ca import CertificateAuthority
        if self.session is not None and not ca_dir:
            return self.session.ca.ensure(_owner_uid()).info()
        return CertificateAuthority(ca_dir).ensure(_owner_uid()).info()

    def cmd_credentials(self, since: int = 0) -> list:
        session = self.session
        return session.credentials[int(since):] if session else []

    def cmd_files(self, since: int = 0) -> list:
        session = self.session
        return session.carved[int(since):] if session else []

    def cmd_shutdown(self) -> dict:
        report = self.shutdown("requested")
        return {"stopped": True, "report": report}

    def _session(self) -> InterceptSession:
        if self.session is None:
            raise InterceptError("no engagement is armed")
        return self.session


def _owner_uid() -> int:
    """The desktop user behind pkexec, so files land owned by them."""
    for var in ("PKEXEC_UID", "SUDO_UID"):
        value = os.environ.get(var)
        if value and value.isdigit():
            return int(value)
    return os.getuid()


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if "--version" in argv:
        print("netlab-helper %s" % __version__)
        return 0
    if "--check" in argv:
        print("netlab-helper %s" % __version__)
        print("euid: %d (%s)" % (os.geteuid(),
                                 "root" if os.geteuid() == 0 else "not root"))
        print("nftables: %s" % ("available"
                                if netcfg.RedirectRules.available()
                                else "MISSING - apt install nftables"))
        return 0 if os.geteuid() == 0 else 1

    if os.geteuid() != 0:
        sys.stderr.write(
            "netlab-helper must run as root; it is started by NetLab through "
            "pkexec and is not meant to be run by hand.\n")
        return 2

    logging.basicConfig(level=logging.WARNING, stream=sys.stderr,
                        format="netlab-helper: %(message)s")

    # stdout is the protocol channel: take a private copy of it and point
    # everything else at stderr, so a stray print cannot corrupt a reply.
    channel = os.fdopen(os.dup(1), "wb", buffering=0)
    os.dup2(2, 1)
    sys.stdout = io.TextIOWrapper(os.fdopen(os.dup(2), "wb"), line_buffering=True)

    helper = Helper(stdin=sys.stdin.buffer, stdout=channel)
    try:
        return helper.run()
    except Exception:                            # pragma: no cover
        traceback.print_exc(file=sys.stderr)
        helper.shutdown("crash")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
