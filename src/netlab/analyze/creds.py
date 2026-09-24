"""Credential harvesting from observed traffic.

This is the part of NetLab that answers the question Intercepter-NG's
Passwords tab exists to answer: *what did this network just hand to anyone
standing on the path?*

Two kinds of answer come out of it:

* **Cleartext.**  FTP, Telnet, POP3, IMAP, SMTP, LDAP simple bind, Redis,
  IRC, SOCKS5, SNMP communities and HTTP Basic put the password on the wire
  as text.  MSSQL puts it there obfuscated with a fixed transform, which is
  the same thing with extra steps, so it is decoded to plaintext too.
* **Challenge/response.**  NTLMSSP (SMB, HTTP, LDAP, MSSQL, SMTP), MySQL,
  PostgreSQL, VNC, HTTP Digest and Kerberos pre-auth give up a hash that can
  be cracked offline.  These need *both* halves of the exchange, so the
  harvester follows the conversation until it has them and emits the line in
  the format the cracker expects, with the hashcat mode attached.

The store is bounded like every other table in NetLab, and the harvester is
fed from the reassembled byte stream so a login split across segments is
still seen whole.
"""

from __future__ import annotations

import re
import threading
import time
from dataclasses import dataclass, field

from netlab.analyze import credfmt as fmt
from netlab.util.bounded import BoundedLRUDict, BoundedRing

MAX_LINE = 4096
MAX_BUFFER = 16384
MAX_BINARY_PREFIX = 8192

# A conversation is only worth following for as long as a login takes.
CONVERSATION_BUDGET = 262144


PORT_PROTOCOLS = {
    21: "FTP", 23: "Telnet", 25: "SMTP", 88: "Kerberos", 110: "POP3",
    119: "NNTP", 139: "SMB", 445: "SMB", 1521: "Oracle", 3389: "RDP",
    5985: "WinRM", 5986: "WinRM",
    143: "IMAP", 389: "LDAP", 465: "SMTP", 513: "rlogin", 587: "SMTP",
    636: "LDAPS", 993: "IMAPS", 995: "POP3S", 1080: "SOCKS", 1433: "MSSQL",
    3268: "LDAP", 3306: "MySQL", 5432: "PostgreSQL", 5900: "VNC",
    5901: "VNC", 5902: "VNC", 5903: "VNC", 6379: "Redis", 6667: "IRC",
    6697: "IRC", 8021: "FTP", 11211: "memcached",
    2401: "CVS", 411: "NMDC", 412: "NMDC",
}

UDP_PROTOCOLS = {161: "SNMP", 162: "SNMP", 88: "Kerberos", 69: "TFTP",
                 1812: "RADIUS", 1813: "RADIUS", 1645: "RADIUS",
                 1646: "RADIUS"}


@dataclass(slots=True)
class Credential:
    """One thing that was learned. Fields that were not seen stay empty."""

    ts: float = 0.0
    proto: str = ""
    client: str = ""
    server: str = ""
    port: int = 0
    user: str = ""
    password: str = ""
    hash: str = ""
    hash_type: str = ""
    hashcat_mode: int = 0
    john_format: str = ""
    context: str = ""
    source: str = "passive"          # passive | sslstrip | ssl-mitm
    packet_index: int = 0
    extra: dict = field(default_factory=dict)

    @property
    def kind(self) -> str:
        if self.password:
            return "cleartext"
        if self.hash:
            return "hash"
        return "token"

    @property
    def secret(self) -> str:
        return self.password or self.hash or self.extra.get("token", "")

    @property
    def endpoint(self) -> str:
        return "%s:%d" % (self.server, self.port) if self.port else self.server

    def crack_command(self) -> str:
        if not self.hash or not self.hashcat_mode:
            return ""
        return "hashcat -m %d -a 0 hash.txt wordlist.txt" % self.hashcat_mode

    def identity(self) -> tuple:
        return (self.proto, self.client, self.server, self.port, self.user,
                self.password, self.hash[:64])


class _Conversation:
    """Per-flow state: enough of both directions to pair an exchange."""

    __slots__ = ("proto", "buffers", "seen", "bytes", "user", "pending",
                 "challenge", "salt", "done", "last_ts", "prompt")

    def __init__(self, proto: str) -> None:
        self.proto = proto
        self.buffers = [bytearray(), bytearray()]
        self.seen = [0, 0]
        self.bytes = 0
        self.user = ""
        self.pending: dict = {}
        self.challenge: bytes = b""
        self.salt: bytes = b""
        self.done = False
        self.last_ts = 0.0
        self.prompt = ""

    def append(self, index: int, data: bytes) -> bytes:
        buf = self.buffers[index]
        buf.extend(data)
        if len(buf) > MAX_BUFFER:
            del buf[:len(buf) - MAX_BUFFER]
        self.seen[index] += len(data)
        self.bytes += len(data)
        return bytes(buf)

    def lines(self, index: int) -> list[bytes]:
        """Complete CRLF/LF lines from one direction, consumed as taken."""
        buf = self.buffers[index]
        out = []
        while True:
            nl = buf.find(b"\n")
            if nl < 0:
                if len(buf) > MAX_LINE:
                    del buf[:len(buf) - MAX_LINE]
                break
            line = bytes(buf[:nl]).rstrip(b"\r")
            del buf[:nl + 1]
            out.append(line)
            if len(out) > 64:
                break
        return out


class CredentialHarvester:
    """Follows conversations and emits `Credential` records."""

    def __init__(self, config=None, on_credential=None,
                 max_credentials: int = 5000,
                 max_conversations: int = 4000) -> None:
        self.enabled = True
        self.config = config
        self.on_credential = on_credential
        self._lock = threading.RLock()
        self._store = BoundedRing(int(max_credentials))
        self._conversations = BoundedLRUDict(int(max_conversations))
        self._identities: set[tuple] = set()
        self.found = 0
        self.suppressed_duplicates = 0

    # ------------------------------------------------------------- results

    def reset(self) -> None:
        with self._lock:
            self._store.clear()
            self._conversations.clear()
            self._identities.clear()
            self.found = 0
            self.suppressed_duplicates = 0

    def snapshot(self) -> list[Credential]:
        return self._store.snapshot()

    def since(self, marker: int):
        return self._store.since(marker)

    def __len__(self) -> int:
        return len(self._store)

    def emit(self, cred: Credential) -> Credential | None:
        """Record a credential unless the same one was already reported."""
        ident = cred.identity()
        with self._lock:
            if ident in self._identities:
                self.suppressed_duplicates += 1
                return None
            self._identities.add(ident)
            if len(self._identities) > 20000:
                self._identities.clear()
                self._identities.add(ident)
            self._store.append(cred)
            self.found += 1
        if self.on_credential:
            try:
                self.on_credential(cred)
            except Exception:                        # pragma: no cover
                pass
        return cred

    # --------------------------------------------------------------- feeds

    def _conversation(self, key, proto: str) -> _Conversation:
        conv, _created = self._conversations.get_or_create(
            key, lambda: _Conversation(proto))
        return conv

    @staticmethod
    def protocol_for(port_a, port_b) -> str | None:
        for port in (port_b, port_a):
            if port in PORT_PROTOCOLS:
                return PORT_PROTOCOLS[port]
            if port and 5900 <= port <= 5906:
                return "VNC"
        return None

    def feed_stream(self, key, index: int, data: bytes, flow, pkt=None) -> None:
        """One direction of a reassembled TCP stream.

        `index` follows the reassembler's stable direction numbering; which
        side is the client is taken from the flow, so a capture that started
        mid-conversation still lands the right way round.
        """
        if not self.enabled or not data:
            return
        server_port = getattr(flow, "server_port", None)
        client_port = getattr(flow, "client_port", None)
        proto = self.protocol_for(client_port, server_port)

        conv = self._conversation(key, proto or "TCP")
        if conv.done or conv.bytes > CONVERSATION_BUDGET:
            return
        conv.last_ts = getattr(pkt, "ts", 0.0) or time.time()

        client = getattr(flow, "client", "") or ""
        server = getattr(flow, "server", "") or ""
        # Direction 0 of the reassembler is endpoint A of the canonical key,
        # which is not necessarily the client.
        to_server = self._is_client_side(flow, key, index)

        buffered = conv.append(index, data)

        # NTLMSSP rides inside half a dozen different carriers, so it is
        # looked for on every stream rather than only on port 445.
        self._scan_ntlmssp(conv, buffered, data, flow, pkt, client, server,
                           server_port, to_server)

        handler = getattr(self, "_h_" + (proto or "").lower().replace("-", ""),
                          None)
        if handler is None:
            return
        handler(conv, index, to_server, flow, pkt, client, server, server_port)

    @staticmethod
    def _is_client_side(flow, key, index: int) -> bool:
        """True when reassembler direction `index` carries client -> server."""
        try:
            a_ip, a_port = key[1], key[2]
        except (TypeError, IndexError):
            return index == 0
        client_side_is_a = (getattr(flow, "client", None) == a_ip
                            and getattr(flow, "client_port", None) == a_port)
        return (index == 0) == client_side_is_a

    def feed_datagram(self, pkt, payload: bytes) -> None:
        """UDP payloads: SNMP communities and Kerberos pre-auth."""
        if not self.enabled or not payload:
            return
        sport, dport = getattr(pkt, "sport", None), getattr(pkt, "dport", None)
        proto = UDP_PROTOCOLS.get(dport) or UDP_PROTOCOLS.get(sport)
        if proto == "SNMP":
            parsed = fmt.parse_snmp_community(payload)
            if parsed:
                self.emit(Credential(
                    ts=getattr(pkt, "ts", 0.0), proto="SNMP",
                    client=getattr(pkt, "src", "") or "",
                    server=getattr(pkt, "dst", "") or "",
                    port=dport or 161, user="",
                    password=parsed["community"],
                    context="community string (%s)" % parsed["version"],
                    packet_index=getattr(pkt, "index", 0),
                    extra={"snmp_version": parsed["version"]}))
        elif proto == "Kerberos":
            self._emit_kerberos(payload, pkt, getattr(pkt, "src", ""),
                                getattr(pkt, "dst", ""), dport or 88)
        elif proto == "RADIUS":
            self._emit_radius(payload, pkt, getattr(pkt, "src", ""),
                              getattr(pkt, "dst", ""), dport or 1812)

    def _emit_radius(self, payload: bytes, pkt, client, server, port) -> None:
        parsed = fmt.parse_radius(payload)
        if not parsed:
            return
        ts = getattr(pkt, "ts", 0.0)
        index = getattr(pkt, "index", 0)
        user = parsed.get("user", "")
        # CHAP is crackable offline; emit it as a hashcat -m 4800 line.
        chap = parsed.get("chap")
        if chap:
            challenge = parsed.get("chap_challenge") or parsed["authenticator"]
            hashed = fmt.radius_chap_hash(chap, challenge)
            if hashed:
                self.emit(Credential(
                    ts=ts, proto="RADIUS", client=client or "",
                    server=server or "", port=port, user=user,
                    hash=hashed["hash"], hash_type=hashed["hash_type"],
                    hashcat_mode=hashed["hashcat_mode"],
                    john_format=hashed.get("john_format", ""),
                    context="%s CHAP" % parsed["code"],
                    packet_index=index, extra={"nas": parsed.get("nas", "")}))
                return
        # PAP User-Password is secret-encrypted; decrypt if a shared secret is
        # configured, otherwise record the username and that a password rode.
        enc = parsed.get("enc_password") or b""
        if user or enc:
            secret = self._radius_secret()
            password = ""
            context = "%s (User-Name)" % parsed["code"]
            if enc and secret:
                password = fmt.radius_decrypt_password(
                    enc, secret, parsed["authenticator"]) or ""
                if password:
                    context = "%s PAP (decrypted with shared secret)" \
                        % parsed["code"]
            elif enc:
                context = "%s PAP (password encrypted; set shared secret " \
                    "to recover)" % parsed["code"]
            self.emit(Credential(
                ts=ts, proto="RADIUS", client=client or "",
                server=server or "", port=port, user=user, password=password,
                context=context, packet_index=index,
                extra={"nas": parsed.get("nas", ""),
                       "enc_password": enc.hex() if enc and not password else ""}))

    def _radius_secret(self) -> bytes:
        """The RADIUS shared secret, if the operator supplied one."""
        cfg = self.config
        raw = ""
        if cfg is not None:
            getter = getattr(cfg, "get", None)
            raw = getter("radius_secret", "") if getter else ""
        return (raw or "").encode("utf-8")

    def _emit_kerberos(self, payload: bytes, pkt, client, server, port) -> None:
        parsed = fmt.parse_kerberos_asreq(payload)
        if not parsed or not parsed.get("user"):
            return
        cred = Credential(
            ts=getattr(pkt, "ts", 0.0), proto="Kerberos",
            client=client or "", server=server or "", port=port,
            user=parsed["user"],
            context="AS-REQ realm=%s etype=%s" % (parsed.get("realm") or "-",
                                                  parsed.get("etype") or "?"),
            packet_index=getattr(pkt, "index", 0),
            extra={"realm": parsed.get("realm", "")})
        if parsed.get("hash"):
            cred.hash = parsed["hash"]
            cred.hash_type = parsed["hash_type"]
            cred.hashcat_mode = parsed["hashcat_mode"]
            cred.john_format = parsed.get("john_format", "")
        self.emit(cred)

    # ---------------------------------------------------------- HTTP feeds

    def feed_http(self, msg, flow, pkt=None, body: bytes = b"",
                  source: str = "passive", url: str = "") -> None:
        """An HTTP request, from the passive parser or from a proxy."""
        if not self.enabled or msg is None:
            return
        headers = getattr(msg, "headers", {}) or {}
        client = getattr(flow, "client", "") or ""
        server = getattr(flow, "server", "") or ""
        port = getattr(flow, "server_port", 80) or 80
        ts = getattr(pkt, "ts", 0.0) or time.time()
        index = getattr(pkt, "index", 0)
        host = headers.get("host", "") or ""
        target = url or ("http://%s%s" % (host, getattr(msg, "target", "") or ""))

        def base(**kw) -> Credential:
            c = Credential(ts=ts, proto="HTTP", client=client, server=server,
                           port=port, source=source, packet_index=index)
            c.extra["url"] = target
            c.extra["host"] = host
            for k, v in kw.items():
                setattr(c, k, v)
            return c

        auth = headers.get("authorization") or headers.get("proxy-authorization")
        if auth:
            parsed = fmt.parse_http_authorization(auth)
            if parsed:
                if parsed.get("ntlmssp") is not None:
                    self._http_ntlm(parsed["ntlmssp"], flow, base, target)
                elif parsed.get("scheme") == "Bearer":
                    cred = base(user="", context="Bearer token  %s" % target)
                    cred.extra["token"] = parsed["token"]
                    cred.password = ""
                    cred.hash = ""
                    cred.context = "Bearer token"
                    self.emit(cred)
                elif parsed.get("hash"):
                    self.emit(base(user=parsed.get("user", ""),
                                   hash=parsed["hash"],
                                   hash_type=parsed["hash_type"],
                                   hashcat_mode=parsed["hashcat_mode"],
                                   john_format=parsed.get("john_format", ""),
                                   context="%s auth  %s" % (parsed["scheme"],
                                                            target)))
                else:
                    self.emit(base(user=parsed.get("user", ""),
                                   password=parsed.get("password", ""),
                                   context="%s auth  %s" % (parsed["scheme"],
                                                            target)))

        if body:
            form = fmt.parse_form_credentials(
                body, headers.get("content-type", ""))
            if form and (form.get("password") or form.get("user")):
                cred = base(user=form.get("user", ""),
                            password=form.get("password", ""),
                            context="form POST  %s" % target)
                cred.extra["fields"] = form.get("fields", {})
                cred.extra["password_field"] = form.get("password_field", "")
                self.emit(cred)

        cookie = headers.get("cookie")
        if cookie and _session_cookie(cookie):
            cred = base(user="", context="session cookie  %s" % (host or target))
            cred.extra["cookie"] = cookie[:1024]
            cred.password = ""
            cred.hash = ""
            cred.extra["token"] = _session_cookie(cookie)
            cred.context = "session cookie"
            self.emit(cred)

    def _http_ntlm(self, blob: bytes, flow, base, target: str) -> None:
        auth = fmt.parse_ntlm_auth(blob)
        if not auth:
            challenge = fmt.parse_ntlm_challenge(blob)
            if challenge:
                key = getattr(flow, "key", None)
                conv = self._conversation(key, "HTTP")
                conv.challenge = challenge["challenge"]
            return
        key = getattr(flow, "key", None)
        conv = self._conversation(key, "HTTP")
        result = fmt.netntlm_hash(auth, conv.challenge)
        cred = base(user="%s\\%s" % (auth["domain"], auth["user"])
                    if auth["domain"] else auth["user"],
                    context="NTLM over HTTP  %s" % target)
        if result:
            cred.hash = result["hash"]
            cred.hash_type = result["hash_type"]
            cred.hashcat_mode = result["hashcat_mode"]
            cred.john_format = result.get("john_format", "")
        else:
            cred.context += "  (challenge not observed - not crackable)"
        self.emit(cred)

    # -------------------------------------------------------- NTLM on TCP

    def _scan_ntlmssp(self, conv, buffered, data, flow, pkt, client, server,
                      port, to_server) -> None:
        if fmt.NTLMSSP_SIGNATURE not in data and \
                fmt.NTLMSSP_SIGNATURE not in buffered[-len(data) - 64:]:
            return
        window = buffered[-MAX_BUFFER:]
        blob = fmt.find_ntlmssp(window, 2)
        if blob is not None:
            challenge = fmt.parse_ntlm_challenge(blob)
            if challenge:
                conv.challenge = challenge["challenge"]
                conv.pending["ntlm_target"] = challenge.get("target", "")
        blob = fmt.find_ntlmssp(window, 3)
        if blob is None:
            return
        auth = fmt.parse_ntlm_auth(blob)
        if not auth or not auth.get("user"):
            return
        if conv.pending.get("ntlm_emitted") == auth["user"]:
            return
        conv.pending["ntlm_emitted"] = auth["user"]
        result = fmt.netntlm_hash(auth, conv.challenge)
        cred = Credential(
            ts=getattr(pkt, "ts", 0.0), proto=conv.proto or "NTLM",
            client=client, server=server, port=port or 0,
            user="%s\\%s" % (auth["domain"], auth["user"]) if auth["domain"]
            else auth["user"],
            packet_index=getattr(pkt, "index", 0),
            context="NTLMSSP over %s  host=%s" % (conv.proto or "TCP",
                                                  auth.get("host") or "-"),
            extra={"domain": auth.get("domain", ""),
                   "host": auth.get("host", ""),
                   "target": conv.pending.get("ntlm_target", "")})
        if result:
            cred.hash = result["hash"]
            cred.hash_type = result["hash_type"]
            cred.hashcat_mode = result["hashcat_mode"]
            cred.john_format = result.get("john_format", "")
        else:
            cred.context += "  (no challenge seen - not crackable)"
        self.emit(cred)

    # ----------------------------------------------------- text protocols

    def _emit_text(self, conv, flow, pkt, client, server, port, proto,
                   user, password, context) -> None:
        self.emit(Credential(
            ts=getattr(pkt, "ts", 0.0) or conv.last_ts, proto=proto,
            client=client, server=server, port=port or 0, user=user,
            password=password, context=context,
            packet_index=getattr(pkt, "index", 0)))

    def _h_ftp(self, conv, index, to_server, flow, pkt, client, server, port):
        if not to_server:
            conv.lines(index)
            return
        for line in conv.lines(index):
            text = line.decode("latin-1", "replace").strip()
            upper = text.upper()
            if upper.startswith("USER "):
                conv.user = text[5:].strip()
            elif upper.startswith("PASS "):
                self._emit_text(conv, flow, pkt, client, server, port, "FTP",
                                conv.user, text[5:].strip(),
                                "cleartext FTP login")
                conv.done = True
            elif upper.startswith("ACCT "):
                conv.pending["acct"] = text[5:].strip()

    def _h_pop3(self, conv, index, to_server, flow, pkt, client, server, port):
        if not to_server:
            conv.lines(index)
            return
        for line in conv.lines(index):
            text = line.decode("latin-1", "replace").strip()
            upper = text.upper()
            if upper.startswith("USER "):
                conv.user = text[5:].strip()
            elif upper.startswith("PASS "):
                self._emit_text(conv, flow, pkt, client, server, port, "POP3",
                                conv.user, text[5:].strip(),
                                "cleartext POP3 login")
                conv.done = True
            elif upper.startswith("APOP "):
                parts = text.split()
                if len(parts) >= 3:
                    self.emit(Credential(
                        ts=getattr(pkt, "ts", 0.0), proto="POP3",
                        client=client, server=server, port=port or 110,
                        user=parts[1], hash=parts[2],
                        hash_type="APOP MD5 digest", hashcat_mode=0,
                        context="APOP digest (needs the server banner nonce)",
                        packet_index=getattr(pkt, "index", 0)))
                    conv.done = True
            else:
                self._sasl_line(conv, text, flow, pkt, client, server, port,
                                "POP3")

    def _h_imap(self, conv, index, to_server, flow, pkt, client, server, port):
        if not to_server:
            conv.lines(index)
            return
        for line in conv.lines(index):
            text = line.decode("latin-1", "replace").strip()
            m = re.match(r'^\S+\s+LOGIN\s+(\S+)\s+(.+)$', text, re.I)
            if m:
                user = m.group(1).strip('"')
                password = m.group(2).strip().strip('"')
                self._emit_text(conv, flow, pkt, client, server, port, "IMAP",
                                user, password, "cleartext IMAP LOGIN")
                conv.done = True
                continue
            m = re.match(r'^\S+\s+AUTHENTICATE\s+(\S+)\s*(\S*)$', text, re.I)
            if m:
                conv.pending["sasl"] = m.group(1).upper()
                if m.group(2):
                    self._sasl_payload(conv, m.group(2), flow, pkt, client,
                                       server, port, "IMAP")
                continue
            self._sasl_line(conv, text, flow, pkt, client, server, port, "IMAP")

    def _h_smtp(self, conv, index, to_server, flow, pkt, client, server, port):
        if not to_server:
            conv.lines(index)
            return
        for line in conv.lines(index):
            text = line.decode("latin-1", "replace").strip()
            m = re.match(r'^AUTH\s+(\S+)\s*(\S*)$', text, re.I)
            if m:
                conv.pending["sasl"] = m.group(1).upper()
                if m.group(2):
                    self._sasl_payload(conv, m.group(2), flow, pkt, client,
                                       server, port, "SMTP")
                continue
            self._sasl_line(conv, text, flow, pkt, client, server, port, "SMTP")

    def _sasl_line(self, conv, text, flow, pkt, client, server, port, proto):
        """A bare base64 line following an AUTH/AUTHENTICATE command."""
        mech = conv.pending.get("sasl")
        if not mech or not text or " " in text.strip():
            return
        self._sasl_payload(conv, text.strip(), flow, pkt, client, server,
                           port, proto)

    def _sasl_payload(self, conv, payload, flow, pkt, client, server, port,
                      proto) -> None:
        mech = conv.pending.get("sasl", "")
        raw = fmt.b64_decode(payload)
        if raw is None:
            return
        if raw.startswith(fmt.NTLMSSP_SIGNATURE):
            auth = fmt.parse_ntlm_auth(raw)
            challenge = fmt.parse_ntlm_challenge(raw)
            if challenge:
                conv.challenge = challenge["challenge"]
            elif auth:
                self._scan_ntlmssp(conv, raw, raw, flow, pkt, client, server,
                                   port, True)
            return
        if mech == "PLAIN" or raw.count(b"\x00") >= 2:
            parts = raw.split(b"\x00")
            if len(parts) >= 3:
                self._emit_text(conv, flow, pkt, client, server, port, proto,
                                parts[1].decode("utf-8", "replace"),
                                parts[2].decode("utf-8", "replace"),
                                "SASL PLAIN")
                conv.done = True
                return
        # SASL LOGIN sends the username and the password as two separate
        # base64 lines, so the first is held until the second arrives.
        text = raw.decode("utf-8", "replace")
        if True:
            if not conv.user:
                conv.user = text
                conv.pending["sasl_user_seen"] = True
            elif conv.pending.get("sasl_user_seen"):
                self._emit_text(conv, flow, pkt, client, server, port, proto,
                                conv.user, text, "SASL LOGIN")
                conv.done = True

    def _h_ldap(self, conv, index, to_server, flow, pkt, client, server, port):
        if not to_server:
            return
        window = bytes(conv.buffers[index])[-MAX_BINARY_PREFIX:]
        result = _parse_ldap_bind(window)
        if not result:
            return
        if conv.pending.get("ldap_emitted") == result.get("dn"):
            return
        conv.pending["ldap_emitted"] = result.get("dn")
        self._emit_text(conv, flow, pkt, client, server, port, "LDAP",
                        result["dn"], result["password"],
                        "LDAP simple bind (cleartext)")
        conv.done = True

    def _h_redis(self, conv, index, to_server, flow, pkt, client, server, port):
        if not to_server:
            conv.lines(index)
            return
        pending = conv.pending
        for line in conv.lines(index):
            text = line.decode("latin-1", "replace").strip()
            if text.upper().startswith("AUTH "):
                parts = text.split(None, 2)
                if len(parts) == 3:
                    self._emit_text(conv, flow, pkt, client, server, port,
                                    "Redis", parts[1], parts[2], "Redis AUTH")
                elif len(parts) == 2:
                    self._emit_text(conv, flow, pkt, client, server, port,
                                    "Redis", "", parts[1], "Redis AUTH")
                conv.done = True
            elif text.upper() == "AUTH":
                pending["redis_auth"] = []
            elif "redis_auth" in pending and not text.startswith(("*", "$")):
                pending["redis_auth"].append(text)
                if len(pending["redis_auth"]) >= 2:
                    user, password = pending["redis_auth"][:2]
                    self._emit_text(conv, flow, pkt, client, server, port,
                                    "Redis", user, password,
                                    "Redis AUTH (RESP)")
                    conv.done = True
                elif len(pending["redis_auth"]) == 1 and conv.seen[index] > 40:
                    pass

    def _h_irc(self, conv, index, to_server, flow, pkt, client, server, port):
        if not to_server:
            conv.lines(index)
            return
        for line in conv.lines(index):
            text = line.decode("latin-1", "replace").strip()
            upper = text.upper()
            if upper.startswith("PASS "):
                value = text[5:].strip().lstrip(":")
                # A BNC (ZNC/psyBNC) login carries user:password, sometimes
                # user/network:password, in the single PASS line.
                if ":" in value:
                    bnc_user, bnc_pass = value.split(":", 1)
                    self._emit_text(conv, flow, pkt, client, server, port,
                                    "BNC", bnc_user.split("/", 1)[0], bnc_pass,
                                    "IRC bouncer PASS user:password")
                else:
                    conv.pending["irc_pass"] = value
            elif upper.startswith("NICK "):
                conv.user = text[5:].strip()
            elif upper.startswith("OPER "):
                parts = text.split()
                if len(parts) >= 3:
                    self._emit_text(conv, flow, pkt, client, server, port,
                                    "IRC", parts[1], parts[2], "IRC OPER")
            if conv.pending.get("irc_pass") and conv.user:
                self._emit_text(conv, flow, pkt, client, server, port, "IRC",
                                conv.user, conv.pending.pop("irc_pass"),
                                "IRC PASS/NICK")

    def _h_nntp(self, conv, index, to_server, flow, pkt, client, server, port):
        if not to_server:
            conv.lines(index)
            return
        for line in conv.lines(index):
            text = line.decode("latin-1", "replace").strip()
            if text.upper().startswith("AUTHINFO USER "):
                conv.user = text[14:].strip()
            elif text.upper().startswith("AUTHINFO PASS "):
                self._emit_text(conv, flow, pkt, client, server, port, "NNTP",
                                conv.user, text[14:].strip(), "NNTP AUTHINFO")
                conv.done = True

    def _h_cvs(self, conv, index, to_server, flow, pkt, client, server, port):
        """CVS pserver auth: a BEGIN AUTH REQUEST block whose password line
        is the byte 'A' followed by the reversibly scrambled password."""
        if not to_server:
            conv.lines(index)
            return
        for line in conv.lines(index):
            text = line.decode("latin-1", "replace")
            stripped = text.strip()
            if stripped in ("BEGIN AUTH REQUEST", "BEGIN VERIFICATION REQUEST"):
                conv.pending["cvs"] = []
            elif "cvs" in conv.pending:
                if stripped in ("END AUTH REQUEST", "END VERIFICATION REQUEST"):
                    fields = conv.pending.pop("cvs")
                    # repository, username, scrambled password
                    if len(fields) >= 3:
                        password = fmt.descramble_cvs(fields[2])
                        if password is not None:
                            self._emit_text(conv, flow, pkt, client, server,
                                            port, "CVS", fields[1], password,
                                            "pserver repo=%s" % fields[0])
                    conv.done = True
                else:
                    conv.pending["cvs"].append(stripped)
                    if len(conv.pending["cvs"]) > 8:
                        conv.pending.pop("cvs")

    def _h_nmdc(self, conv, index, to_server, flow, pkt, client, server, port):
        """Direct Connect (NMDC): $ValidateNick names the user, $MyPass sends
        the password in cleartext. Messages are '|'-terminated, not newline."""
        if not to_server:
            conv.lines(index)
            return
        buf = conv.buffers[index]
        blob = bytes(buf)
        cut = blob.rfind(b"|")
        if cut < 0:
            return
        del buf[:cut + 1]
        for raw in blob[:cut].split(b"|"):
            msg = raw.decode("latin-1", "replace").strip()
            if msg.startswith("$ValidateNick "):
                conv.user = msg[len("$ValidateNick "):].strip()
            elif msg.startswith("$MyPass "):
                self._emit_text(conv, flow, pkt, client, server, port,
                                "DC++", conv.user, msg[len("$MyPass "):].strip(),
                                "NMDC $MyPass")
                conv.done = True

    def _h_telnet(self, conv, index, to_server, flow, pkt, client, server, port):
        """Telnet is typed one character at a time, echoed by the server.

        The client side is therefore reassembled by hand: option negotiation
        is stripped, the server's prompts say which field is being typed, and
        the characters the client sends between them are the value.
        """
        data = bytes(conv.buffers[index])
        conv.buffers[index] = bytearray()
        text = _strip_telnet(data)
        if not text:
            return
        if not to_server:
            lower = text.lower()
            if "password" in lower or "parol" in lower:
                conv.prompt = "password"
            elif "login" in lower or "username" in lower:
                conv.prompt = "user"
            return
        buf = conv.pending.setdefault("typed", "")
        for ch in text:
            if ch in "\r\n":
                value = buf.strip()
                buf = ""
                if not value:
                    continue
                if conv.prompt == "password":
                    self._emit_text(conv, flow, pkt, client, server, port,
                                    "Telnet", conv.user, value,
                                    "cleartext Telnet login")
                    conv.done = True
                elif conv.prompt == "user" or not conv.user:
                    conv.user = value
            elif ch in "\x7f\x08":
                buf = buf[:-1]
            elif ch.isprintable():
                buf += ch
        conv.pending["typed"] = buf[:256]

    def _h_socks(self, conv, index, to_server, flow, pkt, client, server, port):
        if not to_server:
            return
        data = bytes(conv.buffers[index])[:512]
        if len(data) < 5 or data[0] != 0x01:
            return
        ulen = data[1]
        if len(data) < 2 + ulen + 1:
            return
        user = data[2:2 + ulen]
        plen = data[2 + ulen]
        if len(data) < 3 + ulen + plen:
            return
        password = data[3 + ulen:3 + ulen + plen]
        if not user.isascii():
            return
        self._emit_text(conv, flow, pkt, client, server, port, "SOCKS5",
                        user.decode("latin-1"), password.decode("latin-1"),
                        "SOCKS5 username/password auth")
        conv.done = True

    def _h_rlogin(self, conv, index, to_server, flow, pkt, client, server, port):
        if not to_server:
            return
        data = bytes(conv.buffers[index])[:512]
        parts = data.split(b"\x00")
        if len(parts) >= 3 and parts[0] == b"":
            self._emit_text(conv, flow, pkt, client, server, port, "rlogin",
                            parts[1].decode("latin-1", "replace"),
                            parts[2].decode("latin-1", "replace"),
                            "rlogin local/remote user (trusted-host auth)")
            conv.done = True

    # --------------------------------------------------- binary protocols

    def _h_mssql(self, conv, index, to_server, flow, pkt, client, server, port):
        if not to_server:
            return
        data = bytes(conv.buffers[index])[:MAX_BINARY_PREFIX]
        login = fmt.parse_tds7_login(data)
        if not login or conv.pending.get("mssql_emitted"):
            return
        conv.pending["mssql_emitted"] = True
        self.emit(Credential(
            ts=getattr(pkt, "ts", 0.0), proto="MSSQL", client=client,
            server=server, port=port or 1433, user=login["user"],
            password=login["password"],
            context="TDS7 login  db=%s app=%s (password obfuscation undone)"
                    % (login.get("database") or "-", login.get("app") or "-"),
            packet_index=getattr(pkt, "index", 0),
            extra={k: v for k, v in login.items()
                   if k in ("host", "app", "server", "database")}))
        conv.done = True

    def _h_mysql(self, conv, index, to_server, flow, pkt, client, server, port):
        data = bytes(conv.buffers[index])[:MAX_BINARY_PREFIX]
        if not to_server:
            if not conv.salt:
                salt = fmt.parse_mysql_greeting(data)
                if salt:
                    conv.salt = salt
            return
        if conv.pending.get("mysql_emitted"):
            return
        auth = fmt.parse_mysql_auth(data)
        if not auth:
            return
        conv.pending["mysql_emitted"] = True
        cred = Credential(
            ts=getattr(pkt, "ts", 0.0), proto="MySQL", client=client,
            server=server, port=port or 3306, user=auth["user"],
            packet_index=getattr(pkt, "index", 0))
        result = fmt.mysql_hash(auth["user"], conv.salt, auth["response"])
        if result:
            cred.hash = result["hash"]
            cred.hash_type = result["hash_type"]
            cred.hashcat_mode = result["hashcat_mode"]
            cred.john_format = result.get("john_format", "")
            cred.context = "MySQL native auth"
        elif not auth["response"]:
            cred.password = ""
            cred.context = "MySQL login with an empty password"
        else:
            cred.context = "MySQL auth (server greeting not observed)"
        self.emit(cred)
        conv.done = True

    def _h_postgresql(self, conv, index, to_server, flow, pkt, client, server,
                      port):
        data = bytes(conv.buffers[index])[:MAX_BINARY_PREFIX]
        if not to_server:
            # AuthenticationMD5Password: 'R', len=12, method=5, 4-byte salt.
            pos = data.find(b"R")
            if pos >= 0 and len(data) >= pos + 13:
                import struct as _s
                try:
                    length, method = _s.unpack_from("!II", data, pos + 1)
                except _s.error:
                    return
                if length == 12 and method == 5:
                    conv.salt = data[pos + 9:pos + 13]
            return
        if not conv.user:
            startup = fmt.parse_postgres_startup(data)
            if startup:
                conv.user = startup.get("user", "")
                conv.pending["database"] = startup.get("database", "")
        pos = data.find(b"p")
        if pos < 0 or conv.pending.get("pg_emitted"):
            return
        import struct as _s
        try:
            length = _s.unpack_from("!I", data, pos + 1)[0]
        except _s.error:
            return
        if not 5 <= length <= 1024 or len(data) < pos + 1 + length:
            return
        payload = data[pos + 5:pos + 1 + length]
        conv.pending["pg_emitted"] = True
        cred = Credential(
            ts=getattr(pkt, "ts", 0.0), proto="PostgreSQL", client=client,
            server=server, port=port or 5432, user=conv.user,
            packet_index=getattr(pkt, "index", 0),
            extra={"database": conv.pending.get("database", "")})
        result = fmt.postgres_md5_hash(conv.user, conv.salt, payload)
        if result:
            cred.hash = result["hash"]
            cred.hash_type = result["hash_type"]
            cred.hashcat_mode = result["hashcat_mode"]
            cred.john_format = result.get("john_format", "")
            cred.context = "PostgreSQL md5 challenge"
        else:
            cred.password = payload.rstrip(b"\x00").decode("latin-1", "replace")
            cred.context = "PostgreSQL cleartext password"
        self.emit(cred)
        conv.done = True

    def _h_vnc(self, conv, index, to_server, flow, pkt, client, server, port):
        """RFB: the server sends 16 random bytes, the client DES-encrypts them.

        Both sides open with a 12-byte version string.  From 3.7 the server
        then offers a list of security types and the client picks one, while
        3.3 lets the server dictate a single 4-byte type; the challenge
        follows either way, so the handshake is walked rather than guessed at.
        """
        data = bytes(conv.buffers[index])
        pos = data.find(b"RFB ")
        if pos < 0 or len(data) < pos + 13:
            return
        rest = data[pos + 12:]

        if not to_server:
            if conv.challenge:
                return
            if rest[:3] == b"\x00\x00\x00":           # RFB 3.3 security type
                offset = 4
                conv.pending["vnc_v33"] = True
            else:                                      # 3.7+ type list
                offset = 1 + rest[0]
                conv.pending["vnc_v33"] = False
            if len(rest) >= offset + 16:
                conv.challenge = rest[offset:offset + 16]
            return

        if not conv.challenge or conv.pending.get("vnc_emitted"):
            return
        # 3.3 clients answer the challenge directly; 3.7+ clients first send
        # the one-byte security type they chose.
        offset = 0 if conv.pending.get("vnc_v33") else 1
        response = rest[offset:offset + 16]
        if len(response) < 16:
            return
        result = fmt.vnc_hash(conv.challenge, response)
        if not result:
            return
        conv.pending["vnc_emitted"] = True
        self.emit(Credential(
            ts=getattr(pkt, "ts", 0.0), proto="VNC", client=client,
            server=server, port=port or 5900,
            hash=result["hash"], hash_type=result["hash_type"],
            john_format=result.get("john_format", ""),
            context="VNC authentication challenge/response",
            packet_index=getattr(pkt, "index", 0)))
        conv.done = True


# ----------------------------------------------------------------- helpers

_TELNET_IAC = 255


def _strip_telnet(data: bytes) -> str:
    """Remove IAC option negotiation, leaving what was actually typed."""
    out = bytearray()
    i = 0
    n = len(data)
    while i < n:
        byte = data[i]
        if byte == _TELNET_IAC:
            if i + 1 >= n:
                break
            cmd = data[i + 1]
            if cmd == 250:                       # SB ... SE
                end = data.find(b"\xff\xf0", i + 2)
                i = (end + 2) if end >= 0 else n
                continue
            if cmd in (251, 252, 253, 254):      # WILL/WONT/DO/DONT + option
                i += 3
                continue
            i += 2
            continue
        if byte == 0:
            i += 1
            continue
        out.append(byte)
        i += 1
    return out.decode("latin-1", "replace")


def _parse_ldap_bind(data: bytes) -> dict | None:
    """Name and password from an LDAP simple bind (BER, context tag 0)."""
    if len(data) < 14 or data[0] != 0x30:
        return None
    pos = data.find(b"\x60")                     # [APPLICATION 0] BindRequest
    if pos < 0 or pos + 6 > len(data):
        return None
    i = pos + 1
    # Length of the BindRequest.
    if data[i] & 0x80:
        n = data[i] & 0x7F
        if n == 0 or i + 1 + n > len(data):
            return None
        i += 1 + n
    else:
        i += 1
    if i + 3 > len(data) or data[i] != 0x02:     # version INTEGER
        return None
    i += 2 + data[i + 1]
    if i >= len(data) or data[i] != 0x04:        # name OCTET STRING
        return None
    name_len = data[i + 1]
    if name_len & 0x80 or i + 2 + name_len > len(data):
        return None
    dn = data[i + 2:i + 2 + name_len].decode("utf-8", "replace")
    i += 2 + name_len
    if i >= len(data) or data[i] != 0x80:        # [0] simple authentication
        return None
    pw_len = data[i + 1]
    if pw_len & 0x80 or i + 2 + pw_len > len(data):
        return None
    password = data[i + 2:i + 2 + pw_len].decode("utf-8", "replace")
    if not dn and not password:
        return None
    return {"dn": dn, "password": password}


_SESSION_COOKIE = re.compile(
    r"(?:^|;\s*)((?:[A-Za-z0-9_-]*(?:sess|sid|auth|token|login|jwt|remember)"
    r"[A-Za-z0-9_-]*))=([^;]{8,})", re.I)


def _session_cookie(header: str) -> str:
    m = _SESSION_COOKIE.search(header or "")
    return "%s=%s" % (m.group(1), m.group(2)[:256]) if m else ""
