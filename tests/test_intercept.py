"""Active interception: the scope gate, the frames, the proxies, the helper.

Nothing here needs root or touches a real network.  The modules that would
transmit are exercised over loopback or through their pure builders, and the
tests that matter most are the refusals: what NetLab declines to do when the
engagement does not cover it.
"""

from __future__ import annotations

import base64
import gzip
import http.server
import os
import socket
import ssl
import struct
import threading

import pytest

from netlab.analyze import credfmt
from netlab.intercept import arp, dhcp, netcfg
from netlab.intercept.ca import CertificateAuthority
from netlab.intercept.carve import safe_name
from netlab.intercept.dns import (DnsSpoofer, SpoofRule, build_response,
                                  parse_question)
from netlab.intercept.proxy import (ChangerRule, InterceptContext,
                                    TransparentHttpProxy, TransparentTlsProxy,
                                    expire_cookies, strip_body)
from netlab.intercept.scope import (AuditLog, Engagement, ScopeError,
                                    parse_targets)
from netlab.priv import protocol
from netlab.priv.helper import Helper


# ----------------------------------------------------------------- the scope

def test_targets_accept_addresses_cidrs_and_ranges():
    assert parse_targets("10.0.0.5") == ["10.0.0.5/32"]
    assert parse_targets("192.168.1.0/24") == ["192.168.1.0/24"]
    assert parse_targets("10.0.0.10-12") == ["10.0.0.10/32", "10.0.0.11/32",
                                             "10.0.0.12/32"]
    assert len(parse_targets("10.0.0.1, 10.0.0.2  10.0.0.3")) == 3


@pytest.mark.parametrize("bad", ["", "not-an-address", "10.0.0.1/99",
                                 "10.0.0.20-10"])
def test_bad_targets_are_refused(bad):
    with pytest.raises(ValueError):
        parse_targets(bad)


def test_an_unauthorised_engagement_refuses_every_address():
    engagement = Engagement.create("lab", "eth0", "192.168.1.1",
                                   "192.168.1.0/24")
    assert engagement.contains("192.168.1.55")
    with pytest.raises(ScopeError, match="not been authorised"):
        engagement.check("192.168.1.55")


def test_an_authorised_engagement_still_refuses_what_is_out_of_scope():
    engagement = Engagement.create("lab", "eth0", "192.168.1.1",
                                   "192.168.1.0/24")
    engagement.authorised = True
    assert engagement.check("192.168.1.55") == "192.168.1.55"
    for outside in ("8.8.8.8", "10.0.0.1", "192.168.2.1", "", None):
        with pytest.raises(ScopeError):
            engagement.check(outside)


def test_an_engagement_survives_a_round_trip_through_disk(tmp_path, monkeypatch):
    monkeypatch.setattr("netlab.intercept.scope.engagements_dir",
                        lambda: tmp_path)
    original = Engagement.create("round trip", "eth0", "10.0.0.1",
                                 "10.0.0.0/29", note="ticket-7")
    original.authorised = True
    path = original.save()
    restored = Engagement.load(path)
    assert restored.targets == original.targets
    assert restored.note == "ticket-7"
    assert restored.contains("10.0.0.3")


def test_the_audit_log_is_append_only_json(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    log.record("arp.poison.start", targets=["10.0.0.5"])
    log.record("disarm.complete", restored=True)
    entries = log.read()
    assert [e["action"] for e in entries] == ["arp.poison.start",
                                              "disarm.complete"]
    assert entries[0]["targets"] == ["10.0.0.5"]
    assert all("ts" in e and "uid" in e for e in entries)
    assert log.count == 2


# ------------------------------------------------------------------- the ARP

def test_an_arp_frame_is_built_and_read_back():
    frame = arp.build_arp(arp.ARPOP_REPLY,
                          arp.mac_bytes("aa:bb:cc:dd:ee:ff"),
                          arp.ip_bytes("192.168.1.1"),
                          arp.mac_bytes("11:22:33:44:55:66"),
                          arp.ip_bytes("192.168.1.50"))
    assert len(frame) == 60                      # padded to the Ethernet floor
    assert arp.parse_arp(frame) == (2, "aa:bb:cc:dd:ee:ff", "192.168.1.1",
                                    "11:22:33:44:55:66", "192.168.1.50")


def test_a_request_goes_to_broadcast_and_carries_no_target_mac():
    frame = arp.build_arp(arp.ARPOP_REQUEST, arp.mac_bytes("aa:bb:cc:dd:ee:ff"),
                          arp.ip_bytes("192.168.1.13"), b"\x00" * 6,
                          arp.ip_bytes("192.168.1.7"),
                          eth_dst=b"\xff" * 6)
    assert frame[:6] == b"\xff" * 6
    assert arp.parse_arp(frame)[3] == "00:00:00:00:00:00"


def test_a_frame_that_is_not_arp_is_not_parsed():
    assert arp.parse_arp(b"\x00" * 42) is None
    assert arp.parse_arp(b"short") is None


def test_mac_helpers_reject_nonsense():
    assert arp.mac_str(arp.mac_bytes("AA-BB-CC-DD-EE-FF")) == "aa:bb:cc:dd:ee:ff"
    with pytest.raises(ValueError):
        arp.mac_bytes("not a mac")


# ------------------------------------------------------------------- the DNS

def dns_query(name, qtype=1, txid=0x1234):
    question = b"".join(bytes([len(l)]) + l.encode() for l in name.split("."))
    return (struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
            + question + b"\x00" + struct.pack("!HH", qtype, 1))


def test_a_question_is_parsed_and_a_response_built():
    txid, name, qtype, end = parse_question(dns_query("shop.lab.local"))
    assert (txid, name, qtype) == (0x1234, "shop.lab.local", 1)
    reply = build_response(dns_query("shop.lab.local"), end, name, qtype,
                           "192.168.1.13")
    assert struct.unpack_from("!H", reply, 6)[0] == 1        # one answer
    assert socket.inet_ntoa(reply[-4:]) == "192.168.1.13"


def test_a_response_is_not_treated_as_a_query():
    response = bytearray(dns_query("x.lab"))
    struct.pack_into("!H", response, 2, 0x8180)
    assert parse_question(bytes(response)) is None


def test_spoof_rules_match_the_way_the_operator_expects():
    rule = SpoofRule("*.bank.lab", "10.0.0.1")
    assert rule.matches("www.bank.lab")
    assert rule.matches("bank.lab")
    assert not rule.matches("bank.lab.evil.uz")
    assert not rule.matches("other.lab")
    assert SpoofRule("*", "10.0.0.1").matches("anything.at.all")
    assert not SpoofRule("*", "10.0.0.1", enabled=False).matches("anything")


def test_the_spoofer_answers_matched_names_and_only_those():
    spoofer = DnsSpoofer(0, upstream="127.0.0.1",
                         rules=[SpoofRule("*.lab.local", "192.168.1.13")],
                         upstream_timeout=0.4)
    port = spoofer.start()
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.settimeout(3)
        client.sendto(dns_query("shop.lab.local"), ("127.0.0.1", port))
        answer, _ = client.recvfrom(2048)
        assert socket.inet_ntoa(answer[-4:]) == "192.168.1.13"

        # Unmatched names are forwarded; with no resolver behind the test the
        # forward fails, and the point is that nothing was invented for it.
        client.sendto(dns_query("example.com"), ("127.0.0.1", port))
        with pytest.raises(socket.timeout):
            client.recvfrom(2048)
    finally:
        spoofer.stop()
    assert spoofer.spoofed == 1


def test_the_spoofer_will_not_answer_a_client_outside_the_engagement():
    engagement = Engagement.create("lab", "eth0", "10.0.0.1", "10.0.0.0/24")
    engagement.authorised = True
    spoofer = DnsSpoofer(0, upstream="127.0.0.1",
                         rules=[SpoofRule("*", "10.0.0.1")],
                         scope=engagement, upstream_timeout=0.4)
    port = spoofer.start()
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.settimeout(1.5)
        client.sendto(dns_query("anything.lab"), ("127.0.0.1", port))
        with pytest.raises(socket.timeout):
            client.recvfrom(2048)
    finally:
        spoofer.stop()
    assert spoofer.spoofed == 0


# -------------------------------------------------------------------- the CA

def test_the_ca_mints_a_leaf_that_a_trusting_client_accepts(tmp_path):
    ca = CertificateAuthority(tmp_path).ensure()
    assert ca.exists
    context = ca.context_for("bank.lab.local")
    assert ca.context_for("bank.lab.local") is context     # cached

    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    def serve():
        conn, _ = server.accept()
        with context.wrap_socket(conn, server_side=True) as tls:
            tls.send(b"intercepted")

    threading.Thread(target=serve, daemon=True).start()
    client_context = ssl.create_default_context(cafile=str(ca.cert_path))
    with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
        with client_context.wrap_socket(raw,
                                        server_hostname="bank.lab.local") as tls:
            subject = dict(x[0] for x in tls.getpeercert()["subject"])
            assert subject["commonName"] == "bank.lab.local"
            assert tls.recv(32) == b"intercepted"
    server.close()


def test_a_client_that_does_not_trust_the_ca_is_not_fooled(tmp_path):
    ca = CertificateAuthority(tmp_path).ensure()
    context = ca.context_for("bank.lab.local")
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    def serve():
        conn, _ = server.accept()
        try:
            context.wrap_socket(conn, server_side=True)
        except ssl.SSLError:
            pass

    threading.Thread(target=serve, daemon=True).start()
    with pytest.raises(ssl.SSLCertVerificationError):
        with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
            ssl.create_default_context().wrap_socket(
                raw, server_hostname="bank.lab.local")
    server.close()


def test_the_ca_is_reused_rather_than_regenerated(tmp_path):
    first = CertificateAuthority(tmp_path).ensure().fingerprint()
    second = CertificateAuthority(tmp_path).ensure().fingerprint()
    assert first == second


# ------------------------------------------------------------- the rewriting

def test_stripping_rewrites_links_and_removes_what_would_block_it():
    ctx = InterceptContext()
    body = (b'<a href="https://bank.lab/login">x</a>'
            b'<script src="https://cdn.lab/a.js" integrity="sha384-AA"></script>'
            b'<meta http-equiv="Content-Security-Policy" '
            b'content="upgrade-insecure-requests">')
    out, count = strip_body(body, ctx)
    assert count == 2
    assert b"https://" not in out
    assert b"integrity=" not in out
    assert b"upgrade-insecure-requests" not in out
    assert set(ctx.stripped_hosts()) == {"bank.lab", "cdn.lab"}


def test_escaped_and_encoded_https_forms_are_rewritten_too():
    ctx = InterceptContext()
    out, count = strip_body(b'{"u":"https:\\/\\/a.lab"} https%3A%2F%2Fb.lab',
                            ctx)
    assert count == 2
    assert b"http:\\/\\/a.lab" in out and b"http%3A%2F%2Fb.lab" in out


def test_cookie_expiry_covers_every_cookie_presented():
    lines = expire_cookies("SESSION=abc; token=def", "shop.lab")
    assert any(line.startswith("SESSION=;") for line in lines)
    assert any(line.startswith("token=;") for line in lines)
    assert all("Max-Age=0" in line for line in lines)


def test_a_changer_rule_only_fires_where_it_was_scoped():
    rule = ChangerRule(pattern="100000", replacement="1",
                       direction="response", host="shop.lab")
    assert rule.applies("response", "shop.lab", "text/html")
    assert not rule.applies("request", "shop.lab", "text/html")
    assert not rule.applies("response", "other.lab", "text/html")
    out, count = rule.apply(b"Narx: 100000")
    assert out == b"Narx: 1" and count == 1


def test_a_regex_rule_with_a_backreference():
    rule = ChangerRule(pattern=r"Balans: (\d+)", replacement=r"Balans: 0 (was \1)",
                       is_regex=True, direction="response")
    out, count = rule.apply(b"Balans: 5000")
    assert out == b"Balans: 0 (was 5000)" and count == 1


def test_http_injection_rule_inserts_before_the_anchor():
    rule = ChangerRule(mode="inject", replacement="<script>x()</script>",
                       anchor="</body>", direction="response",
                       content_type="text/html")
    # inject needs no find pattern
    assert rule.applies("response", "shop.lab", "text/html")
    out, count = rule.apply(b"<html><body>hi</body></html>")
    assert out == b"<html><body>hi<script>x()</script></body></html>"
    assert count == 1


def test_http_injection_appends_when_anchor_is_absent():
    rule = ChangerRule(mode="inject", replacement="<!--tag-->",
                       anchor="</body>", direction="response")
    out, count = rule.apply(b"plain response with no body tag")
    assert out == b"plain response with no body tag<!--tag-->" and count == 1


def test_injection_survives_a_round_trip_through_config():
    rule = ChangerRule.from_dict(ChangerRule(
        mode="inject", replacement="<i>", anchor="</head>").to_dict())
    assert rule.mode == "inject" and rule.anchor == "</head>"
    out, count = rule.apply(b"<head></head>")
    assert out == b"<head><i></head>" and count == 1


def test_an_invalid_regex_is_reported_and_dropped_rather_than_raised():
    events = []
    ctx = InterceptContext(on_event=lambda n, d: events.append((n, d)))
    ctx.set_rules([{"pattern": "([unclosed", "is_regex": True,
                    "replacement": "x"}])
    assert ctx.active_rules() == []
    assert events and events[0][0] == "rule.error"


def test_the_cookie_killer_only_fires_once_per_client_and_host():
    ctx = InterceptContext()
    ctx.cookie_killer = True
    assert ctx.should_kill_cookies("10.0.0.5", "shop.lab")
    assert not ctx.should_kill_cookies("10.0.0.5", "shop.lab")
    assert ctx.should_kill_cookies("10.0.0.6", "shop.lab")


# ----------------------------------------------------------- the proxy, live

class _Origin(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    PAGE = (b'<html><a href="https://bank.lab/login">go</a>'
            b"<p>Narx: 100000</p></html>")

    def log_message(self, *args):
        pass

    def do_GET(self):
        body = gzip.compress(self.PAGE)
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Encoding", "gzip")
        self.send_header("Strict-Transport-Security", "max-age=63072000")
        self.send_header("Set-Cookie", "SESSION=abc; Path=/; Secure")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")


@pytest.fixture
def origin():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Origin)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server.server_address[1]
    server.shutdown()


@pytest.fixture
def tls_origin(tmp_path):
    """A genuine HTTPS server, with a certificate NetLab's CA did not sign."""
    own_ca = CertificateAuthority(tmp_path / "origin-ca").ensure()
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Origin)
    server.socket = own_ca.context_for("bank.lab.local").wrap_socket(
        server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server.server_address[1]
    server.shutdown()


def speak(port, request: bytes) -> bytes:
    sock = socket.create_connection(("127.0.0.1", port), timeout=10)
    sock.sendall(request)
    out = b""
    while True:
        try:
            chunk = sock.recv(65536)
        except OSError:
            break
        if not chunk:
            break
        out += chunk
    sock.close()
    return out


def test_the_http_proxy_strips_rewrites_and_harvests(origin):
    creds = []
    ctx = InterceptContext(on_credential=creds.append)
    ctx.set_rules([ChangerRule(pattern="100000", replacement="1",
                               direction="response")])
    proxy = TransparentHttpProxy(ctx, 0)
    port = proxy.start()
    try:
        host = "127.0.0.1:%d" % origin
        response = speak(port, ("GET / HTTP/1.1\r\nHost: %s\r\n"
                                "Accept-Encoding: gzip\r\n"
                                "Connection: close\r\n\r\n" % host).encode())
        head, _, body = response.partition(b"\r\n\r\n")
        assert b"http://bank.lab/login" in body
        assert b"https://" not in body
        assert b"Narx: 1" in body
        assert b"strict-transport-security" not in head.lower()
        assert b"Secure" not in head.split(b"Set-Cookie:")[1].split(b"\r\n")[0]

        form = b"username=erwin&password=Qw3rty!"
        speak(port, (("POST /auth HTTP/1.1\r\nHost: %s\r\n"
                      "Content-Type: application/x-www-form-urlencoded\r\n"
                      "Authorization: Basic %s\r\n"
                      "Content-Length: %d\r\nConnection: close\r\n\r\n"
                      % (host, base64.b64encode(b"svc:svcpw").decode(),
                         len(form))).encode() + form))
    finally:
        proxy.stop()

    secrets = {(c["user"], c.get("password")) for c in creds}
    assert ("svc", "svcpw") in secrets
    assert ("erwin", "Qw3rty!") in secrets
    assert ctx.stats.stripped_links >= 1


def test_the_proxy_refuses_a_client_outside_the_engagement(origin):
    engagement = Engagement.create("lab", "eth0", "10.0.0.1", "10.0.0.0/24")
    engagement.authorised = True
    events = []
    ctx = InterceptContext(scope=engagement,
                           on_event=lambda n, d: events.append((n, d)))
    proxy = TransparentHttpProxy(ctx, 0)
    port = proxy.start()
    try:
        response = speak(port, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    finally:
        proxy.stop()
    assert response == b""
    assert any(name == "proxy.out-of-scope" for name, _ in events)


def test_the_tls_proxy_reads_the_plaintext_inside(tmp_path, tls_origin):
    origin = tls_origin
    ca = CertificateAuthority(tmp_path / "mitm-ca").ensure()
    creds = []
    ctx = InterceptContext(on_credential=creds.append, ca=ca)
    ctx.set_rules([ChangerRule(pattern="100000", replacement="0",
                               direction="response")])
    proxy = TransparentTlsProxy(ctx, 0)
    port = proxy.start()
    try:
        client_context = ssl.create_default_context(cafile=str(ca.cert_path))
        request = ("GET / HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n"
                   "Authorization: Basic %s\r\nConnection: close\r\n\r\n"
                   % (origin, base64.b64encode(b"tls:inside").decode()))
        with socket.create_connection(("127.0.0.1", port), timeout=10) as raw:
            with client_context.wrap_socket(
                    raw, server_hostname="bank.lab.local") as tls:
                subject = dict(x[0] for x in tls.getpeercert()["subject"])
                assert subject["commonName"] == "bank.lab.local"
                tls.sendall(request.encode())
                out = b""
                while True:
                    chunk = tls.recv(65536)
                    if not chunk:
                        break
                    out += chunk
    finally:
        proxy.stop()
    assert b"Narx: 0" in out
    assert ("tls", "inside") in {(c["user"], c["password"]) for c in creds}
    assert all(c["source"] == "ssl-mitm" for c in creds)


def test_a_redirect_that_points_at_the_proxy_itself_is_not_followed():
    ctx = InterceptContext()
    ctx.local_addresses = {"127.0.0.1"}
    proxy = TransparentHttpProxy(ctx, 0)
    port = proxy.start()
    try:
        response = speak(port, ("GET / HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n"
                                "Connection: close\r\n\r\n" % port).encode())
    finally:
        proxy.stop()
    assert b"502" in response.split(b"\r\n")[0]
    assert ctx.stats.upstream_failures == 1


# ------------------------------------------------------------------ the DHCP

def dhcp_discover(mac=b"\xaa\xbb\xcc\xdd\xee\xff", xid=0x12345678):
    packet = struct.pack("!BBBB", 1, 1, 6, 0)
    packet += struct.pack("!IHH", xid, 0, 0x8000)
    packet += b"\x00" * 16 + mac.ljust(16, b"\x00")
    packet += b"\x00" * 64 + b"\x00" * 128 + dhcp.MAGIC_COOKIE
    packet += bytes([53, 1, dhcp.DISCOVER]) + bytes([12, 4]) + b"kali"
    return packet + bytes([255])


def test_a_dhcp_offer_names_us_as_router_and_resolver():
    request = dhcp.parse_packet(dhcp_discover())
    assert request["type_name"] == "DISCOVER"
    assert request["mac"] == "aa:bb:cc:dd:ee:ff"
    assert request["hostname"] == "kali"

    reply = dhcp.build_reply(request, dhcp.OFFER, "10.0.0.150", "10.0.0.13",
                             "255.255.255.0", "10.0.0.13", ["10.0.0.13"], 600)
    parsed = dhcp.parse_packet(reply)
    assert parsed["op"] == 2 and parsed["type_name"] == "OFFER"
    assert parsed["yiaddr"] == "10.0.0.150"
    assert socket.inet_ntoa(parsed["options"][dhcp.OPT_ROUTER]) == "10.0.0.13"
    assert socket.inet_ntoa(parsed["options"][dhcp.OPT_DNS]) == "10.0.0.13"
    assert struct.unpack("!I", parsed["options"][dhcp.OPT_LEASE])[0] == 600


def test_a_packet_without_the_magic_cookie_is_not_dhcp():
    assert dhcp.parse_packet(b"\x01" * 300) is None
    assert dhcp.parse_packet(b"") is None


# ----------------------------------------------------------------- the carve

@pytest.mark.parametrize("url,ctype,expected", [
    ("https://x.uz/files/hisobot%20final.pdf?v=2", "application/pdf",
     "hisobot_final.pdf"),
    ("https://x.uz/img/", "image/png", "img.png"),
    ("https://x.uz/", "text/html", "index.bin"),
    ("https://x.uz/../../etc/passwd", "text/plain", "passwd.txt"),
])
def test_a_carved_name_is_derived_safely(url, ctype, expected):
    name = safe_name(url, ctype)
    assert name == expected
    assert "/" not in name and not name.startswith(".")


# ---------------------------------------------------------------- the helper

class _Pipes:
    """Drive a Helper over a pair of real pipes."""

    def __init__(self):
        self.to_helper_r, self.to_helper_w = os.pipe()
        self.from_helper_r, self.from_helper_w = os.pipe()
        self.helper = Helper(stdin=os.fdopen(self.to_helper_r, "rb"),
                             stdout=os.fdopen(self.from_helper_w, "wb",
                                              buffering=0))
        self.out = os.fdopen(self.from_helper_r, "rb")
        self._id = 0

    def send(self, command, **args):
        self._id += 1
        os.write(self.to_helper_w,
                 protocol.encode(protocol.request(self._id, command, **args)))
        return self._id

    def read(self):
        line = self.out.readline()
        return protocol.decode(line) if line else {}

    def close(self):
        os.close(self.to_helper_w)


@pytest.fixture
def helper():
    pipes = _Pipes()
    thread = threading.Thread(target=pipes.helper.run, daemon=True)
    thread.start()
    assert pipes.read()["event"] == "ready"
    yield pipes
    pipes.close()
    thread.join(timeout=3)


def test_the_helper_answers_hello(helper):
    helper.send("hello")
    result = helper.read()["result"]
    assert result["protocol"] == protocol.PROTOCOL_VERSION
    assert result["root"] is (os.geteuid() == 0)


def test_the_helper_refuses_a_command_it_does_not_have(helper):
    helper.send("rm_rf_slash")
    reply = helper.read()
    assert reply["ok"] is False and reply["kind"] == "unknown"


def test_the_helper_refuses_to_arm_without_an_authorisation(helper):
    helper.send("arm", engagement={"name": "x", "interface": "lo",
                                   "targets": ["127.0.0.1/32"],
                                   "authorised": False})
    reply = helper.read()
    assert reply["ok"] is False and reply["kind"] == "scope"
    assert "authorisation" in reply["error"]


@pytest.mark.skipif(os.geteuid() == 0, reason="the refusal only applies to non-root")
def test_arming_without_root_is_refused_rather_than_half_done(helper):
    helper.send("arm", engagement={"name": "x", "interface": "lo",
                                   "targets": ["127.0.0.1/32"],
                                   "authorised": True})
    reply = helper.read()
    assert reply["ok"] is False
    assert "root" in reply["error"]


def test_status_before_anything_is_armed(helper):
    helper.send("status")
    assert helper.read()["result"]["armed"] is False


def test_the_protocol_refuses_what_is_not_a_json_object():
    with pytest.raises(protocol.ProtocolError):
        protocol.decode(b"not json")
    with pytest.raises(protocol.ProtocolError):
        protocol.decode(b"[1, 2, 3]")
    with pytest.raises(protocol.ProtocolError):
        protocol.decode(b"")


def test_bytes_survive_encoding_as_hex():
    payload = protocol.decode(protocol.encode(
        protocol.event("x", {"blob": b"\xde\xad"})))
    assert payload["data"]["blob"] == "dead"


# ----------------------------------------------------------------- the netcfg

def test_an_unredirected_socket_reports_no_original_destination():
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    client = socket.create_connection(("127.0.0.1", port), timeout=5)
    accepted, _ = server.accept()
    try:
        # Without netfilter the kernel answers with the socket's own address;
        # treating that as a destination is what makes a proxy loop.
        assert netcfg.original_destination(accepted) is None
    finally:
        accepted.close()
        client.close()
        server.close()


def test_netmask_and_free_port_helpers():
    from netlab.intercept.session import _netmask
    assert _netmask(24) == "255.255.255.0"
    assert _netmask(16) == "255.255.0.0"
    assert _netmask(30) == "255.255.255.252"
    assert 1 <= netcfg.free_port(0) <= 65535
