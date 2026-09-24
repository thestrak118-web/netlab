"""Credential extraction: decoders, and the conversations they live in."""

from __future__ import annotations

import base64
import struct

import pytest

from netlab.analyze import credfmt as fmt
from netlab.analyze.creds import CredentialHarvester, _strip_telnet


# ------------------------------------------------------------------ helpers

class Flow:
    def __init__(self, client, cport, server, sport):
        self.client, self.client_port = client, cport
        self.server, self.server_port = server, sport
        a, b = (client, cport), (server, sport)
        self.key = ("tcp",) + (a + b if a <= b else b + a)


class Pkt:
    ts = 1_758_600_000.0
    index = 7
    src = "192.168.1.50"
    dst = "192.168.1.10"
    sport = 40000
    dport = 161


def converse(port, exchanges, client="192.168.1.50", server="192.168.1.10"):
    """Feed one conversation through the harvester and return what it found."""
    harvester = CredentialHarvester()
    flow = Flow(client, 51000, server, port)
    a_is_client = (flow.key[1], flow.key[2]) == (client, 51000)
    for to_server, data in exchanges:
        index = 0 if (to_server == a_is_client) else 1
        harvester.feed_stream(flow.key, index, data, flow, Pkt())
    return harvester.snapshot()


def ntlm_challenge(challenge, target="LAB"):
    name = target.encode("utf-16-le")
    return (fmt.NTLMSSP_SIGNATURE + struct.pack("<I", 2)
            + struct.pack("<HHI", len(name), len(name), 56)
            + struct.pack("<I", 1) + challenge + b"\x00" * 8
            + struct.pack("<HHI", 0, 0, 56) + b"\x00" * 8 + name)


def ntlm_auth(user, domain, host, lm, nt):
    enc = lambda s: s.encode("utf-16-le")
    offset, fields, payload = 64, {}, []
    for name, value in (("lm", lm), ("nt", nt), ("domain", enc(domain)),
                        ("user", enc(user)), ("host", enc(host)), ("key", b"")):
        fields[name] = (len(value), offset)
        payload.append(value)
        offset += len(value)
    head = fmt.NTLMSSP_SIGNATURE + struct.pack("<I", 3)
    for name in ("lm", "nt", "domain", "user", "host", "key"):
        length, at = fields[name]
        head += struct.pack("<HHI", length, length, at)
    return head + struct.pack("<I", 1) + b"".join(payload)


def snmp_message(community, version=1):
    body = (bytes([0x02, 0x01, version])
            + bytes([0x04, len(community)]) + community.encode()
            + bytes([0xA0, 0x02, 0x05, 0x00]))
    return bytes([0x30, len(body)]) + body


# ------------------------------------------------------------- pure decoders

def test_mssql_password_obfuscation_is_reversible():
    def obfuscate(text):
        return bytes((((b << 4) | (b >> 4)) & 0xFF) ^ 0xA5
                     for b in text.encode("utf-16-le"))

    for password in ("Summer2026!", "", "parol", "a" * 40, "Ω-unicode"):
        assert fmt.decode_mssql_password(obfuscate(password)) == password


def test_ntlm_challenge_and_v2_response_pair_into_a_hashcat_line():
    challenge = bytes.fromhex("1122334455667788")
    parsed = fmt.parse_ntlm_challenge(ntlm_challenge(challenge))
    assert parsed["challenge"] == challenge
    assert parsed["target"] == "LAB"

    nt = bytes(range(16)) + b"\x01\x01\x00\x00" + b"\xAA" * 40
    auth = fmt.parse_ntlm_auth(ntlm_auth("erwin", "LAB", "KALI", b"\x00" * 24, nt))
    assert (auth["user"], auth["domain"], auth["host"]) == ("erwin", "LAB", "KALI")

    result = fmt.netntlm_hash(auth, challenge)
    assert result["hashcat_mode"] == 5600
    assert result["hash"].startswith(
        "erwin::LAB:1122334455667788:000102030405060708090a0b0c0d0e0f:")


def test_ntlm_v1_response_uses_the_other_mode():
    auth = fmt.parse_ntlm_auth(
        ntlm_auth("bob", "CORP", "WS1", b"\x11" * 24, b"\x22" * 24))
    result = fmt.netntlm_hash(auth, bytes.fromhex("1122334455667788"))
    assert result["hashcat_mode"] == 5500
    assert result["hash_type"] == "NetNTLMv1"


def test_a_response_without_its_challenge_is_not_turned_into_a_hash():
    auth = fmt.parse_ntlm_auth(
        ntlm_auth("bob", "CORP", "WS1", b"\x11" * 24, b"\x22" * 24))
    assert fmt.netntlm_hash(auth, b"") is None


def test_ntlmssp_is_found_inside_an_smb_carrier():
    blob = ntlm_auth("erwin", "LAB", "KALI", b"\x00" * 24, b"\xCC" * 40)
    carrier = b"\xfeSMB" + b"\x00" * 60 + blob + b"trailing"
    assert fmt.parse_ntlm_auth(fmt.find_ntlmssp(carrier, 3))["user"] == "erwin"
    assert fmt.find_ntlmssp(b"no signature here", 3) is None


def test_http_authorization_schemes():
    basic = fmt.parse_http_authorization(
        "Basic " + base64.b64encode(b"admin:P@ssw0rd").decode())
    assert (basic["user"], basic["password"]) == ("admin", "P@ssw0rd")

    digest = fmt.parse_http_authorization(
        'Digest username="joe", realm="corp", nonce="abc", uri="/x", '
        'response="deadbeef", qop=auth')
    assert digest["user"] == "joe" and digest["hashcat_mode"] == 11400

    bearer = fmt.parse_http_authorization("Bearer eyJhbGciOi.payload.sig")
    assert bearer["token"].startswith("eyJ")

    assert fmt.parse_http_authorization("") is None
    assert fmt.parse_http_authorization("Weird scheme") is None


def test_form_credentials_from_urlencoded_and_json():
    form = fmt.parse_form_credentials(
        b"user=erwin&password=hunter2&submit=Log+in",
        "application/x-www-form-urlencoded")
    assert (form["user"], form["password"]) == ("erwin", "hunter2")

    js = fmt.parse_form_credentials(b'{"email":"a@b.uz","parol":"maxfiy"}',
                                    "application/json")
    assert (js["user"], js["password"]) == ("a@b.uz", "maxfiy")

    assert fmt.parse_form_credentials(b"nothing interesting here", "") is None


def test_snmp_community_is_read_and_junk_is_refused():
    parsed = fmt.parse_snmp_community(snmp_message("s3cr3t-rw"))
    assert parsed == {"version": "v2c", "community": "s3cr3t-rw"}
    assert fmt.parse_snmp_community(b"\x30\x03not-der") is None
    assert fmt.parse_snmp_community(b"") is None


def test_telnet_option_negotiation_is_stripped():
    raw = b"\xff\xfb\x18\xff\xfd\x03erwin\r\n\xff\xfa\x18\x00x\xff\xf0pw"
    assert _strip_telnet(raw) == "erwin\r\npw"


# ----------------------------------------------------- stateful conversations

@pytest.mark.parametrize("port,exchanges,user,password", [
    (21, [(False, b"220 ready\r\n"), (True, b"USER erwin\r\n"),
          (True, b"PASS Lab2026!\r\n")], "erwin", "Lab2026!"),
    (110, [(True, b"USER mail@lab\r\nPASS s3cret\r\n")], "mail@lab", "s3cret"),
    (143, [(True, b'a1 LOGIN "erwin" "imap-pass"\r\n')], "erwin", "imap-pass"),
    (119, [(True, b"AUTHINFO USER news\r\nAUTHINFO PASS nntppw\r\n")],
     "news", "nntppw"),
    (6379, [(True, b"AUTH default r3dis-pw\r\n")], "default", "r3dis-pw"),
])
def test_cleartext_protocols(port, exchanges, user, password):
    found = converse(port, exchanges)
    assert found, "nothing extracted on port %d" % port
    assert (found[0].user, found[0].password) == (user, password)
    assert found[0].kind == "cleartext"


def test_smtp_sasl_login_spans_several_lines():
    found = converse(587, [
        (True, b"AUTH LOGIN\r\n"), (False, b"334 VXNlcm5hbWU6\r\n"),
        (True, base64.b64encode(b"erwin@lab") + b"\r\n"),
        (False, b"334 UGFzc3dvcmQ6\r\n"),
        (True, base64.b64encode(b"smtp-pw") + b"\r\n")])
    assert (found[0].user, found[0].password) == ("erwin@lab", "smtp-pw")


def test_smtp_sasl_plain():
    payload = base64.b64encode(b"\x00joe\x00plainpw")
    found = converse(25, [(True, b"AUTH PLAIN " + payload + b"\r\n")])
    assert (found[0].user, found[0].password) == ("joe", "plainpw")


def test_ldap_simple_bind():
    dn, password = b"cn=admin,dc=lab,dc=local", b"ldap-pass"
    bind = (b"\x02\x01\x03" + b"\x04" + bytes([len(dn)]) + dn
            + b"\x80" + bytes([len(password)]) + password)
    message = b"\x02\x01\x01" + b"\x60" + bytes([len(bind)]) + bind
    found = converse(389, [(True, b"\x30" + bytes([len(message)]) + message)])
    assert found[0].user == "cn=admin,dc=lab,dc=local"
    assert found[0].password == "ldap-pass"


def test_telnet_is_reassembled_from_single_characters():
    exchanges = [(True, b"\xff\xfb\x18"), (False, b"\r\nlab login: ")]
    exchanges += [(True, bytes([c])) for c in b"erwin\r\n"]
    exchanges += [(False, b"Password: ")]
    exchanges += [(True, bytes([c])) for c in b"tn-secret\r\n"]
    found = converse(23, exchanges)
    assert (found[0].user, found[0].password) == ("erwin", "tn-secret")


def test_socks5_username_password_auth():
    user, password = b"proxyuser", b"proxypw"
    payload = (b"\x01" + bytes([len(user)]) + user
               + bytes([len(password)]) + password)
    found = converse(1080, [(True, payload)])
    assert (found[0].user, found[0].password) == ("proxyuser", "proxypw")


def test_vnc_challenge_response_for_both_rfb_versions():
    challenge, response = bytes(range(16)), bytes(range(100, 116))
    expected = "$vnc$*%s*%s" % (challenge.hex(), response.hex())

    v38 = converse(5900, [(False, b"RFB 003.008\n"), (True, b"RFB 003.008\n"),
                          (False, b"\x01\x02"), (True, b"\x02"),
                          (False, challenge), (True, response)])
    assert v38[0].hash == expected

    v33 = converse(5900, [(False, b"RFB 003.003\n"), (True, b"RFB 003.003\n"),
                          (False, b"\x00\x00\x00\x02" + challenge),
                          (True, response)])
    assert v33[0].hash == expected


def test_mysql_native_auth_pairs_greeting_salt_with_response():
    salt = bytes(range(1, 21))
    body = (b"\x0a" + b"8.0.36-lab\x00" + struct.pack("<I", 99) + salt[:8]
            + b"\x00" + b"\xff\xf7" + b"\x21" + b"\x02\x00" + b"\xff\x81"
            + b"\x15" + b"\x00" * 10 + salt[8:20] + b"\x00")
    greeting = struct.pack("<I", len(body))[:3] + b"\x00" + body

    login = (struct.pack("<I", 0x000A8285) + struct.pack("<I", 1 << 24)
             + b"\x2d" + b"\x00" * 23 + b"root\x00" + bytes([20]) + b"\xAB" * 20)
    auth = struct.pack("<I", len(login))[:3] + b"\x01" + login

    found = converse(3306, [(False, greeting), (True, auth)])
    assert found[0].user == "root"
    assert found[0].hashcat_mode == 11200
    assert found[0].hash.startswith("$mysqlna$%s*" % salt.hex())


def test_postgres_md5_challenge():
    startup_body = b"user\x00erwin\x00database\x00labdb\x00\x00"
    startup = struct.pack("!II", 8 + len(startup_body), 196608) + startup_body
    auth = b"R" + struct.pack("!II", 12, 5) + b"\xde\xad\xbe\xef"
    password = b"p" + struct.pack("!I", 4 + 36) + b"md5" + b"a" * 32 + b"\x00"

    found = converse(5432, [(True, startup), (False, auth), (True, password)])
    assert found[0].user == "erwin"
    assert found[0].hashcat_mode == 11100
    assert "deadbeef" in found[0].hash


def test_mssql_tds7_login_yields_plaintext():
    def obfuscate(text):
        return bytes((((b << 4) | (b >> 4)) & 0xFF) ^ 0xA5
                     for b in text.encode("utf-16-le"))

    fields = [("host", "WS1".encode("utf-16-le")),
              ("user", "sa".encode("utf-16-le")),
              ("pw", obfuscate("MsSql#2026")),
              ("app", "sqlcmd".encode("utf-16-le")),
              ("srv", "SRV".encode("utf-16-le")),
              ("x", b""), ("lib", b""), ("lang", b""),
              ("db", "master".encode("utf-16-le"))]
    body = bytearray(94)
    position, offsets, payload = 94, {}, bytearray()
    for name, value in fields:
        offsets[name] = (position, len(value) // 2)
        payload += value
        position += len(value)
    for name, at in (("host", 38), ("user", 42), ("pw", 46), ("app", 50),
                     ("srv", 54)):
        struct.pack_into("<HH", body, at, *offsets[name])
    struct.pack_into("<HH", body, 66, *offsets["db"])
    full = bytes(body) + bytes(payload)
    packet = b"\x10\x01" + struct.pack(">H", len(full) + 8) + b"\x00" * 4 + full

    found = converse(1433, [(True, packet)])
    assert (found[0].user, found[0].password) == ("sa", "MsSql#2026")
    assert "master" in found[0].context


def test_ntlmssp_over_smb_is_paired_across_directions():
    challenge = bytes.fromhex("aabbccddeeff0011")
    nt = bytes(range(16)) + b"\x01\x01\x00\x00" + b"\xCC" * 48
    found = converse(445, [
        (False, b"\x00\x00\x01\x00\xfeSMB" + b"\x00" * 48
         + ntlm_challenge(challenge)),
        (True, b"\x00\x00\x02\x00\xfeSMB" + b"\x00" * 48
         + ntlm_auth("erwin", "LAB", "KALI", b"\x00" * 24, nt))])
    assert found[0].proto == "SMB"
    assert found[0].user == "LAB\\erwin"
    assert found[0].hashcat_mode == 5600


def test_http_feed_extracts_basic_form_and_cookie():
    class Message:
        def __init__(self, headers, target="/login"):
            self.headers = headers
            self.target = target

    harvester = CredentialHarvester()
    flow = Flow("192.168.1.50", 50000, "93.184.216.34", 80)
    harvester.feed_http(Message({
        "host": "shop.lab",
        "authorization": "Basic " + base64.b64encode(b"admin:letmein").decode(),
    }), flow, Pkt())
    harvester.feed_http(Message({
        "host": "shop.lab",
        "content-type": "application/x-www-form-urlencoded",
    }), flow, Pkt(), body=b"username=erwin&password=Qw3rty!")
    harvester.feed_http(Message({
        "host": "shop.lab",
        "cookie": "theme=dark; PHPSESSID=9f2c1ab77d44e0b81c",
    }), flow, Pkt())

    found = harvester.snapshot()
    assert ("admin", "letmein") in {(c.user, c.password) for c in found}
    assert ("erwin", "Qw3rty!") in {(c.user, c.password) for c in found}
    assert any("PHPSESSID" in c.extra.get("token", "") for c in found)


def test_snmp_datagram():
    harvester = CredentialHarvester()
    harvester.feed_datagram(Pkt(), snmp_message("private"))
    assert harvester.snapshot()[0].password == "private"


def test_the_same_credential_is_only_reported_once():
    harvester = CredentialHarvester()
    for _ in range(4):
        harvester.feed_datagram(Pkt(), snmp_message("private"))
    assert len(harvester.snapshot()) == 1
    assert harvester.suppressed_duplicates == 3


def test_harvesting_can_be_switched_off():
    harvester = CredentialHarvester()
    harvester.enabled = False
    harvester.feed_datagram(Pkt(), snmp_message("private"))
    assert harvester.snapshot() == []


def test_a_conversation_that_is_not_a_login_costs_nothing():
    found = converse(21, [(True, b"x" * 4000), (False, b"y" * 4000)])
    assert found == []


# ---------------------------------------------------- CVS / DC++ / BNC / RADIUS

import hashlib


class Cfg:
    def __init__(self, **kw):
        self._d = kw

    def get(self, key, default=None):
        return self._d.get(key, default)


class RadiusPkt(Pkt):
    dport = 1812
    sport = 50000


def _cvs_scramble(password: str) -> str:
    """Scramble a password the way a CVS pserver client does (table is an
    involution, so the same map descrambles)."""
    return "A" + "".join(chr(fmt._CVS_SHIFTS[ord(c)]) for c in password)


def _radius_encrypt(password: bytes, secret: bytes, authenticator: bytes) -> bytes:
    if len(password) % 16:
        password += b"\x00" * (16 - len(password) % 16)
    out, last = b"", authenticator
    for i in range(0, len(password), 16):
        block = password[i:i + 16]
        digest = hashlib.md5(secret + last).digest()
        enc = bytes(a ^ b for a, b in zip(block, digest))
        out += enc
        last = enc
    return out


def _radius_packet(code, ident, authenticator, avps):
    body = b""
    for atype, value in avps:
        body += bytes([atype, len(value) + 2]) + value
    length = 20 + len(body)
    return bytes([code, ident]) + length.to_bytes(2, "big") + authenticator + body


def test_cvs_shifts_table_is_an_involution():
    # A transcription error in the 256-byte table would break this.
    assert len(fmt._CVS_SHIFTS) == 256
    for b in range(256):
        assert fmt._CVS_SHIFTS[fmt._CVS_SHIFTS[b]] == b


def test_cvs_descramble_roundtrip():
    assert fmt.descramble_cvs(_cvs_scramble("Sekret123!")) == "Sekret123!"
    assert fmt.descramble_cvs("not-A-prefixed") is None


def test_cvs_pserver_login():
    block = ("BEGIN AUTH REQUEST\n/srv/cvsroot\nerwin\n"
             + _cvs_scramble("Passw0rd") + "\nEND AUTH REQUEST\n").encode()
    creds = converse(2401, [(True, block)])
    assert len(creds) == 1
    c = creds[0]
    assert (c.proto, c.user, c.password) == ("CVS", "erwin", "Passw0rd")
    assert "cvsroot" in c.context


def test_dcpp_nmdc_mypass():
    stream = b"$ValidateNick neo|$MyPass tr1nity|"
    creds = converse(411, [(True, stream)])
    assert len(creds) == 1
    c = creds[0]
    assert (c.proto, c.user, c.password) == ("DC++", "neo", "tr1nity")


def test_bnc_pass_user_password():
    creds = converse(6667, [(True, b"PASS erwin:hunter2\r\nNICK e\r\n")])
    bnc = [c for c in creds if c.proto == "BNC"]
    assert len(bnc) == 1
    assert (bnc[0].user, bnc[0].password) == ("erwin", "hunter2")


def test_radius_chap_becomes_hashcat_4800():
    ident = 7
    authenticator = bytes(range(16))
    challenge = bytes(range(16, 32))
    response = b"\xaa" * 16
    pkt = _radius_packet(1, ident, authenticator, [
        (1, b"erwin"),
        (60, challenge),
        (3, bytes([ident]) + response),
    ])
    h = CredentialHarvester()
    h.feed_datagram(RadiusPkt(), pkt)
    creds = h.snapshot()
    assert len(creds) == 1
    c = creds[0]
    assert c.proto == "RADIUS" and c.hashcat_mode == 4800
    assert c.hash == "%s:%s:%s" % (response.hex(), challenge.hex(),
                                   bytes([ident]).hex())


def test_radius_pap_decrypts_with_shared_secret():
    secret = b"testing123"
    authenticator = bytes(range(100, 116))
    enc = _radius_encrypt(b"S3cr3tPAP", secret, authenticator)
    pkt = _radius_packet(1, 3, authenticator, [(1, b"erwin"), (2, enc)])
    h = CredentialHarvester(config=Cfg(radius_secret="testing123"))
    h.feed_datagram(RadiusPkt(), pkt)
    c = h.snapshot()[0]
    assert (c.proto, c.user, c.password) == ("RADIUS", "erwin", "S3cr3tPAP")


def test_radius_pap_without_secret_keeps_user_and_notes_encryption():
    authenticator = bytes(range(16))
    enc = _radius_encrypt(b"whatever", b"x", authenticator)
    pkt = _radius_packet(1, 1, authenticator, [(1, b"erwin"), (2, enc)])
    h = CredentialHarvester()          # no shared secret configured
    h.feed_datagram(RadiusPkt(), pkt)
    c = h.snapshot()[0]
    assert c.user == "erwin" and c.password == ""
    assert "shared secret" in c.context.lower()
    assert c.extra.get("enc_password")
