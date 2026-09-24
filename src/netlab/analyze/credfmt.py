"""Pure decoders for the credential material that appears on a wire.

Everything here is a function from bytes to a result, with no state and no
I/O, so each one is directly testable against a captured sample.  The stateful
part -- following a conversation until both halves of a challenge/response
have been seen -- lives in `netlab.analyze.creds`.

Hashes are emitted in the format the usual cracker expects, and the hashcat
mode is carried alongside so the operator does not have to remember it.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import struct

NTLMSSP_SIGNATURE = b"NTLMSSP\x00"
NEGOTIATE_UNICODE = 0x00000001


# --------------------------------------------------------------------- misc

def b64_decode(text) -> bytes | None:
    """Decode base64 that may be missing its padding. None if it is not b64."""
    if isinstance(text, str):
        text = text.encode("ascii", "ignore")
    text = bytes(text).strip()
    if not text:
        return None
    pad = (-len(text)) % 4
    try:
        return base64.b64decode(text + b"=" * pad, validate=False)
    except (binascii.Error, ValueError):
        return None


def printable(data: bytes, limit: int = 256) -> str:
    """A safe one-line rendering of bytes that may not be text."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = data.decode("latin-1", "replace")
    text = "".join(ch if ch.isprintable() else "." for ch in text)
    return text[:limit]


def _utf16_or_ascii(raw: bytes, unicode_flag: bool) -> str:
    if unicode_flag:
        try:
            return raw.decode("utf-16-le")
        except UnicodeDecodeError:
            pass
    return raw.decode("latin-1", "replace")


# ------------------------------------------------------------------- NTLMSSP

def find_ntlmssp(data: bytes, want_type: int | None = None) -> bytes | None:
    """Locate an NTLMSSP blob inside any carrier (SMB, HTTP, LDAP, TDS)."""
    start = 0
    while True:
        idx = data.find(NTLMSSP_SIGNATURE, start)
        if idx < 0:
            return None
        if len(data) >= idx + 12:
            msg_type = struct.unpack_from("<I", data, idx + 8)[0]
            if want_type is None or msg_type == want_type:
                return data[idx:]
        start = idx + 1


def ntlmssp_type(blob: bytes) -> int | None:
    if len(blob) < 12 or not blob.startswith(NTLMSSP_SIGNATURE):
        return None
    return struct.unpack_from("<I", blob, 8)[0]


def parse_ntlm_challenge(blob: bytes) -> dict | None:
    """The 8-byte server challenge from an NTLMSSP CHALLENGE (type 2)."""
    if ntlmssp_type(blob) != 2 or len(blob) < 32:
        return None
    challenge = blob[24:32]
    target = ""
    try:
        t_len, _t_max, t_off = struct.unpack_from("<HHI", blob, 12)
        flags = struct.unpack_from("<I", blob, 20)[0]
        if t_len and t_off + t_len <= len(blob):
            target = _utf16_or_ascii(blob[t_off:t_off + t_len],
                                     bool(flags & NEGOTIATE_UNICODE))
    except struct.error:
        flags = 0
    return {"challenge": challenge, "target": target, "flags": flags}


def _field(blob: bytes, offset: int) -> bytes:
    """Read one NTLM (len, maxlen, offset) security buffer."""
    length, _maxlen, off = struct.unpack_from("<HHI", blob, offset)
    if length == 0 or off + length > len(blob):
        return b""
    return blob[off:off + length]


def parse_ntlm_auth(blob: bytes) -> dict | None:
    """User, domain, host and both responses from an AUTHENTICATE (type 3)."""
    if ntlmssp_type(blob) != 3 or len(blob) < 52:
        return None
    try:
        lm = _field(blob, 12)
        nt = _field(blob, 20)
        domain_raw = _field(blob, 28)
        user_raw = _field(blob, 36)
        host_raw = _field(blob, 44)
        flags = struct.unpack_from("<I", blob, 60)[0] if len(blob) >= 64 else 0
    except struct.error:
        return None
    unicode_flag = bool(flags & NEGOTIATE_UNICODE) or b"\x00" in user_raw[1:2]
    return {
        "user": _utf16_or_ascii(user_raw, unicode_flag),
        "domain": _utf16_or_ascii(domain_raw, unicode_flag),
        "host": _utf16_or_ascii(host_raw, unicode_flag),
        "lm": lm,
        "nt": nt,
        "flags": flags,
    }


def netntlm_hash(auth: dict, challenge: bytes) -> dict | None:
    """Build the crackable line for a paired NTLMSSP challenge/response.

    NTLMv2 responses carry a blob after the 16-byte proof string; v1 responses
    are a bare 24 bytes.  The two go to different hashcat modes, and a
    response with no challenge to pair against is not crackable at all, so it
    is reported without a hash rather than with a wrong one.
    """
    if not auth or not challenge or len(challenge) != 8:
        return None
    user = auth.get("user") or ""
    domain = auth.get("domain") or ""
    nt = auth.get("nt") or b""
    lm = auth.get("lm") or b""
    chal = challenge.hex()

    if len(nt) > 24:
        proof = nt[:16].hex()
        blob = nt[16:].hex()
        return {
            "hash": "%s::%s:%s:%s:%s" % (user, domain, chal, proof, blob),
            "hash_type": "NetNTLMv2",
            "hashcat_mode": 5600,
            "john_format": "netntlmv2",
        }
    if len(nt) == 24:
        return {
            "hash": "%s::%s:%s:%s:%s" % (user, domain, lm.hex(), nt.hex(), chal),
            "hash_type": "NetNTLMv1",
            "hashcat_mode": 5500,
            "john_format": "netntlm",
        }
    if len(lm) == 24:
        return {
            "hash": "%s::%s:%s:%s:%s" % (user, domain, lm.hex(), lm.hex(), chal),
            "hash_type": "NetNTLMv1 (LM only)",
            "hashcat_mode": 5500,
            "john_format": "netntlm",
        }
    return None


# --------------------------------------------------------------------- MSSQL

def decode_mssql_password(raw: bytes) -> str:
    """Undo the TDS7 login password obfuscation.

    It is not encryption: each byte has its nibbles swapped and is XORed with
    0xA5, and the result is UTF-16LE.  Anyone on the path reads the password.
    """
    out = bytearray()
    for byte in raw:
        x = byte ^ 0xA5
        out.append(((x >> 4) | (x << 4)) & 0xFF)
    try:
        return bytes(out).decode("utf-16-le").rstrip("\x00")
    except UnicodeDecodeError:
        return bytes(out).decode("latin-1", "replace").rstrip("\x00")


def parse_tds7_login(data: bytes) -> dict | None:
    """Username, password and client details from a TDS7 LOGIN7 packet."""
    if len(data) < 8 or data[0] != 0x10:            # TDS packet type LOGIN7
        return None
    body = data[8:]
    if len(body) < 90:
        return None
    try:
        def field(off: int) -> bytes:
            pos, length = struct.unpack_from("<HH", body, off)
            if length == 0 or pos + length * 2 > len(body):
                return b""
            return body[pos:pos + length * 2]

        hostname = field(38).decode("utf-16-le", "replace")
        username = field(42).decode("utf-16-le", "replace")
        password_raw = field(46)
        appname = field(50).decode("utf-16-le", "replace")
        server = field(54).decode("utf-16-le", "replace")
        database = field(66).decode("utf-16-le", "replace")
    except (struct.error, UnicodeDecodeError):
        return None
    if not username and not password_raw:
        return None
    return {"user": username, "password": decode_mssql_password(password_raw),
            "host": hostname, "app": appname, "server": server,
            "database": database}


# --------------------------------------------------------------------- MySQL

def parse_mysql_greeting(data: bytes) -> bytes | None:
    """The 20-byte scramble from a MySQL server greeting, in two pieces."""
    if len(data) < 5:
        return None
    payload_len = int.from_bytes(data[0:3], "little")
    if payload_len + 4 > len(data) or data[4] != 10:        # protocol v10
        return None
    body = data[5:4 + payload_len]
    end = body.find(b"\x00")                                # server version
    if end < 0 or len(body) < end + 1 + 4 + 8:
        return None
    pos = end + 1 + 4                                       # skip thread id
    salt1 = body[pos:pos + 8]
    pos += 8 + 1                                            # filler
    if len(body) < pos + 2 + 1 + 2 + 2 + 1 + 10:
        return salt1
    pos += 2 + 1 + 2 + 2 + 1 + 10                           # caps, charset...
    salt2 = body[pos:pos + 12]
    salt = salt1 + salt2
    return salt.rstrip(b"\x00") or salt1


def parse_mysql_auth(data: bytes) -> dict | None:
    """Username and the 20-byte SHA1 auth response from a login packet."""
    if len(data) < 40:
        return None
    payload_len = int.from_bytes(data[0:3], "little")
    if payload_len + 4 > len(data) + 4:
        return None
    body = data[4:]
    if len(body) < 36:
        return None
    pos = 4 + 4 + 1 + 23                                    # caps, max, cs, pad
    if len(body) <= pos:
        return None
    end = body.find(b"\x00", pos)
    if end < 0:
        return None
    user = body[pos:end].decode("latin-1", "replace")
    if not user or not user.isprintable():
        return None
    pos = end + 1
    if pos >= len(body):
        return None
    resp_len = body[pos]
    response = body[pos + 1:pos + 1 + resp_len]
    return {"user": user, "response": response}


def mysql_hash(user: str, salt: bytes, response: bytes) -> dict | None:
    if not salt or len(response) != 20:
        return None
    return {"hash": "$mysqlna$%s*%s" % (salt.hex(), response.hex()),
            "hash_type": "MySQL native (CHALLENGE)",
            "hashcat_mode": 11200, "john_format": "mysqlna"}


# ----------------------------------------------------------------- PostgreSQL

def parse_postgres_startup(data: bytes) -> dict | None:
    """user/database from a PostgreSQL StartupMessage."""
    if len(data) < 9:
        return None
    length = struct.unpack_from("!I", data, 0)[0]
    if length > len(data) or length < 9:
        return None
    if struct.unpack_from("!I", data, 4)[0] != 196608:      # protocol 3.0
        return None
    parts = data[8:length].split(b"\x00")
    fields = {}
    for i in range(0, len(parts) - 1, 2):
        key = parts[i].decode("latin-1", "replace")
        if not key:
            break
        fields[key] = parts[i + 1].decode("latin-1", "replace")
    return fields or None


def postgres_md5_hash(user: str, salt: bytes, response: bytes) -> dict | None:
    """`md5<hex>` from a PasswordMessage, paired with the 4-byte salt."""
    text = response.rstrip(b"\x00").decode("latin-1", "replace")
    if not text.startswith("md5") or len(salt) != 4:
        return None
    return {"hash": "$postgres$%s*%s*%s" % (user, salt.hex(), text[3:]),
            "hash_type": "PostgreSQL MD5 challenge",
            "hashcat_mode": 11100, "john_format": "postgres"}


# ----------------------------------------------------------------------- VNC

def vnc_hash(challenge: bytes, response: bytes) -> dict | None:
    if len(challenge) != 16 or len(response) != 16:
        return None
    return {"hash": "$vnc$*%s*%s" % (challenge.hex(), response.hex()),
            "hash_type": "VNC challenge/response (DES)",
            "hashcat_mode": 0, "john_format": "vnc"}


# ------------------------------------------------------------------ Kerberos

def _der_walk(data: bytes, offset: int = 0, end: int | None = None,
              depth: int = 0, limit: int = 40):
    """Yield (tag, header_len, length, value_offset) for one DER level."""
    end = len(data) if end is None else end
    count = 0
    while offset < end and count < limit:
        count += 1
        tag = data[offset]
        if offset + 1 >= end:
            return
        first = data[offset + 1]
        if first & 0x80:
            n = first & 0x7F
            if n == 0 or offset + 2 + n > end:
                return
            length = int.from_bytes(data[offset + 2:offset + 2 + n], "big")
            header = 2 + n
        else:
            length = first
            header = 2
        value = offset + header
        if value + length > end:
            return
        yield tag, header, length, value
        offset = value + length


def _der_find_ints_and_octets(data: bytes, offset: int, end: int,
                              out: list, depth: int = 0) -> None:
    if depth > 8:
        return
    for tag, _hdr, length, value in _der_walk(data, offset, end, depth):
        constructed = bool(tag & 0x20)
        if constructed:
            _der_find_ints_and_octets(data, value, value + length, out,
                                      depth + 1)
        else:
            out.append((tag, data[value:value + length]))


def parse_kerberos_asreq(data: bytes) -> dict | None:
    """Pre-auth timestamp, principal and realm from an AS-REQ.

    Only the etype 23 (RC4-HMAC) pre-auth blob is crackable offline, so that
    is the one turned into a hash; other etypes are reported as observed.
    """
    idx = data.find(b"\x6a")                     # [APPLICATION 10] AS-REQ
    if idx < 0 or len(data) - idx < 32:
        return None
    body = data[idx:]
    strings: list[str] = []
    octets: list[bytes] = []
    found: list[tuple[int, bytes]] = []
    _der_find_ints_and_octets(body, 0, len(body), found)
    etype = None
    for tag, value in found:
        if tag == 0x1B and 0 < len(value) < 128:              # GeneralString
            try:
                strings.append(value.decode("ascii"))
            except UnicodeDecodeError:
                continue
        elif tag == 0x04 and len(value) >= 32:                # OCTET STRING
            octets.append(value)
        elif tag == 0x02 and len(value) == 1 and value[0] in (23, 17, 18):
            if etype is None:
                etype = value[0]
    if not strings:
        return None
    user = strings[0] if strings else ""
    realm = ""
    for s in strings:
        if s.isupper() and "." in s:
            realm = s
            break
    if not realm and len(strings) > 1:
        realm = strings[1]
    result = {"user": user, "realm": realm, "etype": etype}
    if etype == 23 and octets:
        blob = max(octets, key=len)
        if len(blob) >= 52:
            result["hash"] = "$krb5pa$23$%s$%s$%s" % (user, realm, blob.hex())
            result["hash_type"] = "Kerberos 5 AS-REQ pre-auth (etype 23)"
            result["hashcat_mode"] = 7500
            result["john_format"] = "krb5pa-md5"
    return result


# --------------------------------------------------------------------- SNMP

def parse_snmp_community(data: bytes) -> dict | None:
    """Version and community string from an SNMP v1/v2c message."""
    if len(data) < 8 or data[0] != 0x30:
        return None
    levels = list(_der_walk(data, 0, len(data)))
    if not levels:
        return None
    _tag, _hdr, length, value = levels[0]
    inner = list(_der_walk(data, value, value + length))
    if len(inner) < 2:
        return None
    ver_tag, _h, ver_len, ver_off = inner[0]
    com_tag, _h2, com_len, com_off = inner[1]
    if ver_tag != 0x02 or com_tag != 0x04:
        return None
    version = int.from_bytes(data[ver_off:ver_off + ver_len], "big")
    if version not in (0, 1, 3):
        return None
    community = data[com_off:com_off + com_len]
    try:
        text = community.decode("ascii")
    except UnicodeDecodeError:
        return None
    if not text or not text.isprintable():
        return None
    return {"version": {0: "v1", 1: "v2c", 3: "v3"}.get(version, str(version)),
            "community": text}


# ---------------------------------------------------------------- HTTP auth

def parse_http_authorization(value: str) -> dict | None:
    """Split an Authorization header into something crackable or usable."""
    if not value:
        return None
    parts = value.split(None, 1)
    scheme = parts[0].lower()
    payload = parts[1].strip() if len(parts) > 1 else ""

    if scheme == "basic":
        raw = b64_decode(payload)
        if raw is None:
            return None
        text = raw.decode("utf-8", "replace")
        user, _, password = text.partition(":")
        return {"scheme": "Basic", "user": user, "password": password}

    if scheme == "digest":
        fields = {}
        for chunk in payload.split(","):
            key, _, val = chunk.strip().partition("=")
            fields[key.strip().lower()] = val.strip().strip('"')
        user = fields.get("username", "")
        realm = fields.get("realm", "")
        nonce = fields.get("nonce", "")
        uri = fields.get("uri", "")
        response = fields.get("response", "")
        if not (user and response):
            return None
        out = {"scheme": "Digest", "user": user, "realm": realm,
               "context": "uri=%s qop=%s" % (uri, fields.get("qop", "-"))}
        out.update({
            "hash": "$sip$**%s*%s*%s*%s*%s*%s*%s*%s*%s" % (
                realm, user, realm, fields.get("method", "GET"), "", uri,
                nonce, fields.get("cnonce", ""), response),
            "hash_type": "HTTP Digest",
            "hashcat_mode": 11400, "john_format": "hdaa"})
        out["digest_fields"] = fields
        return out

    if scheme in ("ntlm", "negotiate"):
        raw = b64_decode(payload)
        if raw is None:
            return None
        return {"scheme": scheme.upper(), "ntlmssp": raw}

    if scheme == "bearer":
        return {"scheme": "Bearer", "token": payload}

    return None


PASSWORD_FIELDS = ("pass", "pwd", "passwd", "password", "passwort", "senha",
                   "contrasena", "secret", "pin", "token", "auth", "apikey",
                   "api_key", "key", "otp", "code", "parol")
USERNAME_FIELDS = ("user", "username", "usr", "login", "email", "mail",
                   "uid", "userid", "user_id", "account", "name", "nick",
                   "phone", "tel", "logon", "signin")


def _looks_like(name: str, candidates) -> bool:
    low = name.lower()
    return any(c in low for c in candidates)


def parse_form_credentials(body: bytes, content_type: str = "") -> dict | None:
    """Username/password pairs out of a submitted form or JSON body."""
    if not body or len(body) > 262144:
        return None
    ctype = (content_type or "").lower()
    fields: dict[str, str] = {}

    if "json" in ctype or body.lstrip()[:1] in (b"{", b"["):
        import json
        try:
            parsed = json.loads(body.decode("utf-8", "replace"))
        except ValueError:
            parsed = None
        if isinstance(parsed, dict):
            for key, value in parsed.items():
                if isinstance(value, (str, int, float)):
                    fields[str(key)] = str(value)
                elif isinstance(value, dict):
                    for k2, v2 in value.items():
                        if isinstance(v2, (str, int, float)):
                            fields["%s.%s" % (key, k2)] = str(v2)
    if not fields:
        from urllib.parse import parse_qsl
        try:
            text = body.decode("utf-8", "replace")
        except Exception:                                   # pragma: no cover
            return None
        if "=" not in text:
            return None
        for key, value in parse_qsl(text, keep_blank_values=True):
            fields[key] = value

    if not fields:
        return None
    user = password = ""
    user_field = pass_field = ""
    for key, value in fields.items():
        if not password and _looks_like(key, PASSWORD_FIELDS) and value:
            password, pass_field = value, key
        elif not user and _looks_like(key, USERNAME_FIELDS) and value:
            user, user_field = value, key
    if not password and not user:
        return None
    return {"user": user, "password": password,
            "user_field": user_field, "password_field": pass_field,
            "fields": {k: v for k, v in list(fields.items())[:24]}}


# ------------------------------------------------------------- CVS pserver

# The fixed substitution table from CVS `src/scramble.c`, reproduced here
# byte-for-byte (via git-cvsserver, which carries the same table). It is an
# involution, so the same map both scrambles and descrambles. A pserver
# client sends the password as the byte 'A' followed by the scrambled bytes.
_CVS_SHIFTS = bytes((
    0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
    16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
    114,120, 53, 79, 96,109, 72,108, 70, 64, 76, 67,116, 74, 68, 87,
    111, 52, 75,119, 49, 34, 82, 81, 95, 65,112, 86,118,110,122,105,
    41, 57, 83, 43, 46,102, 40, 89, 38,103, 45, 50, 42,123, 91, 35,
    125, 55, 54, 66,124,126, 59, 47, 92, 71,115, 78, 88,107,106, 56,
    36,121,117,104,101,100, 69, 73, 99, 63, 94, 93, 39, 37, 61, 48,
    58,113, 32, 90, 44, 98, 60, 51, 33, 97, 62, 77, 84, 80, 85,223,
    225,216,187,166,229,189,222,188,141,249,148,200,184,136,248,190,
    199,170,181,204,138,232,218,183,255,234,220,247,213,203,226,193,
    174,172,228,252,217,201,131,230,197,211,145,238,161,179,160,212,
    207,221,254,173,202,146,224,151,140,196,205,130,135,133,143,246,
    192,159,244,239,185,168,215,144,139,165,180,157,147,186,214,176,
    227,231,219,169,175,156,206,198,129,164,150,210,154,177,134,127,
    182,128,158,208,162,132,167,209,149,241,153,251,237,236,171,195,
    243,233,253,240,194,250,191,155,142,137,245,235,163,242,178,152,
))


def descramble_cvs(scrambled: str) -> str | None:
    """Recover a CVS pserver password from its scrambled `A...` form."""
    if not scrambled or scrambled[0] != "A":
        return None
    try:
        raw = scrambled[1:].encode("latin-1")
    except (UnicodeEncodeError, AttributeError):
        return None
    if not raw:
        return None
    return "".join(chr(_CVS_SHIFTS[b]) for b in raw)


# ------------------------------------------------------------------- RADIUS

# RADIUS codes and attribute types we read (RFC 2865/2866).
_RADIUS_CODES = {1: "Access-Request", 4: "Accounting-Request",
                 2: "Access-Accept", 3: "Access-Reject", 11: "Access-Challenge"}
_RA_USER_NAME = 1
_RA_USER_PASSWORD = 2
_RA_CHAP_PASSWORD = 3
_RA_NAS_IP = 4
_RA_CHAP_CHALLENGE = 60


def parse_radius(data: bytes) -> dict | None:
    """Fields out of a RADIUS packet: username and the password material.

    The User-Password attribute is encrypted with the shared secret and the
    Request Authenticator (RFC 2865 §5.2); without the secret only its
    presence is reported. CHAP-Password is a crackable MD5 and is returned
    with the challenge so it can be emitted as a hashcat -m 4800 line.
    """
    if len(data) < 20:
        return None
    code = data[0]
    if code not in _RADIUS_CODES:
        return None
    length = int.from_bytes(data[2:4], "big")
    if length < 20 or length > len(data):
        return None
    authenticator = data[4:20]
    out = {"code": _RADIUS_CODES[code], "identifier": data[1],
           "authenticator": authenticator, "user": "", "nas": "",
           "enc_password": b"", "chap": None, "chap_challenge": b""}
    off = 20
    while off + 2 <= length:
        atype = data[off]
        alen = data[off + 1]
        if alen < 2 or off + alen > length:
            break
        value = data[off + 2:off + alen]
        if atype == _RA_USER_NAME:
            out["user"] = value.decode("utf-8", "replace")
        elif atype == _RA_USER_PASSWORD:
            out["enc_password"] = value
        elif atype == _RA_CHAP_PASSWORD and len(value) == 17:
            out["chap"] = {"id": value[0], "response": value[1:]}
        elif atype == _RA_CHAP_CHALLENGE:
            out["chap_challenge"] = value
        elif atype == _RA_NAS_IP and len(value) == 4:
            out["nas"] = ".".join(str(b) for b in value)
        off += alen
    if not out["user"] and not out["enc_password"] and not out["chap"]:
        return None
    return out


def radius_decrypt_password(enc: bytes, secret: bytes,
                            authenticator: bytes) -> str | None:
    """RFC 2865 User-Password decryption, given the shared secret."""
    if not enc or len(enc) % 16 != 0 or len(authenticator) != 16:
        return None
    out = bytearray()
    last = authenticator
    for i in range(0, len(enc), 16):
        block = enc[i:i + 16]
        digest = hashlib.md5(secret + last).digest()
        out.extend(a ^ b for a, b in zip(block, digest))
        last = block
    return out.rstrip(b"\x00").decode("utf-8", "replace")


def radius_chap_hash(chap: dict, challenge: bytes) -> dict | None:
    """A RADIUS CHAP-Password as a hashcat -m 4800 line: response:challenge:id."""
    if not chap or not challenge:
        return None
    line = "%s:%s:%s" % (chap["response"].hex(), challenge.hex(),
                         bytes([chap["id"]]).hex())
    return {"hash": line, "hash_type": "RADIUS CHAP (MD5)",
            "hashcat_mode": 4800, "john_format": ""}
