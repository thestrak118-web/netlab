"""Passive Wi-Fi monitor sniff: mode switch, capture, decrypt, orchestration.

No radio is touched -- the privileged and capture steps are stubbed. The live
`iw` sequence itself was verified by hand on iwlwifi; here we lock down the
logic: managed mode is always restored, decrypt runs only with a handshake, and
the helper remembers the monitor interface so shutdown puts the radio back.
"""
import threading
from pathlib import Path

import pytest

from netlab.capture import wifidecrypt, wifimon
from netlab.intercept import netcfg


# --------------------------------------------------------------- wifidecrypt

def test_decrypt_returns_the_dec_file(tmp_path, monkeypatch):
    src = tmp_path / "cap.pcap"
    src.write_bytes(b"\0")
    dec = tmp_path / "cap-dec.pcap"
    monkeypatch.setattr(wifidecrypt.shutil, "which", lambda n: "/usr/bin/airdecap-ng")

    def fake_run(argv, timeout=120):
        assert "-e" in argv and "Zohidjon" in argv and "-p" in argv
        dec.write_bytes(b"\0")                       # airdecap writes -dec
        class R: returncode = 0; stdout = "decrypted WPA packets 12"; stderr = ""
        return R()
    monkeypatch.setattr(wifidecrypt, "_run", fake_run)
    out = wifidecrypt.decrypt(src, "Zohidjon", "secretpass")
    assert Path(out) == dec


def test_decrypt_without_handshake_output_raises(tmp_path, monkeypatch):
    src = tmp_path / "cap.pcap"
    src.write_bytes(b"\0")
    monkeypatch.setattr(wifidecrypt.shutil, "which", lambda n: "/usr/bin/airdecap-ng")
    class R: returncode = 0; stdout = ""; stderr = ""
    monkeypatch.setattr(wifidecrypt, "_run", lambda *a, **k: R())   # no -dec file
    with pytest.raises(wifidecrypt.WifiDecryptError):
        wifidecrypt.decrypt(src, "Zohidjon", "x")


def test_decrypt_missing_tool_raises(tmp_path, monkeypatch):
    monkeypatch.setattr(wifidecrypt.shutil, "which", lambda n: None)
    with pytest.raises(wifidecrypt.WifiDecryptError):
        wifidecrypt.decrypt(tmp_path / "c.pcap", "Zohidjon", "x")


def test_decrypted_packet_count_parses_report():
    assert wifidecrypt.decrypted_packet_count(
        "Number of decrypted WPA  packets     42") == 42
    assert wifidecrypt.decrypted_packet_count("nothing here") == 0


# ------------------------------------------------------------------ netcfg

def test_monitor_start_verifies_mode_and_channel(monkeypatch):
    calls = []
    def fake_run(argv, timeout=8.0):
        calls.append(argv)
        out = "type monitor\nchannel 1" if argv[:3] == ["iw", "dev", "wlan0"] and "info" in argv else ""
        return (0, out, "")
    monkeypatch.setattr(netcfg, "_run", fake_run)
    res = netcfg.monitor_start("wlan0", 1)
    assert res == {"interface": "wlan0", "mode": "monitor", "channel": "1"}
    assert any("set" in c and "monitor" in c for c in calls)


def test_monitor_start_raises_if_not_monitor(monkeypatch):
    monkeypatch.setattr(netcfg, "_run", lambda argv, timeout=8.0: (0, "type managed", ""))
    with pytest.raises(netcfg.NetcfgError):
        netcfg.monitor_start("wlan0", 1)


def test_monitor_stop_restores_managed(monkeypatch):
    calls = []
    monkeypatch.setattr(netcfg, "_run", lambda argv, timeout=8.0: (calls.append(argv), (0, "", ""))[1])
    res = netcfg.monitor_stop("wlan0", "Zohidjon")
    assert res["mode"] == "managed"
    assert any("managed" in c for c in calls) and any("connection" in c for c in calls)


# ------------------------------------------------------------------ orchestrator

def test_run_sniff_restores_even_when_capture_fails(monkeypatch):
    events = []
    def cap(iface, out, seconds):
        events.append(("capture", iface))
        raise wifimon.WifiMonError("boom")
    with pytest.raises(wifimon.WifiMonError):
        wifimon.run_sniff("wlan0", 1, "Zohidjon", "p", seconds=1,
                          enter=lambda i, c: events.append(("enter", i)),
                          leave=lambda i: events.append(("leave", i)),
                          capture=cap)
    # leave() ran despite the capture error -> radio restored.
    assert ("enter", "wlan0") in events and ("leave", "wlan0") in events


def test_run_sniff_decrypts_only_with_a_handshake(tmp_path, monkeypatch):
    raw = tmp_path / "wifimon.pcap"
    def cap(iface, out, seconds):
        Path(out).write_bytes(b"\0"); return Path(out)
    monkeypatch.setattr(wifidecrypt, "inspect",
                        lambda p: {"frames": 5, "data_frames": 3, "clients": ["aa"],
                                   "handshake_macs": ["aa:bb:cc:dd:ee:ff"], "eapol_frames": 4})
    monkeypatch.setattr(wifidecrypt, "decrypt", lambda p, e, pw: str(tmp_path / "dec.pcap"))
    res = wifimon.run_sniff("wlan0", 1, "Zohidjon", "p", seconds=1, workdir=tmp_path,
                            enter=lambda i, c: None, leave=lambda i: None, capture=cap)
    assert res["decrypted"] == str(tmp_path / "dec.pcap")
    assert res["summary"]["handshake_macs"] == ["aa:bb:cc:dd:ee:ff"]


def test_run_sniff_no_handshake_no_decrypt(tmp_path, monkeypatch):
    def cap(iface, out, seconds):
        Path(out).write_bytes(b"\0"); return Path(out)
    monkeypatch.setattr(wifidecrypt, "inspect",
                        lambda p: {"frames": 5, "data_frames": 3, "clients": ["aa"],
                                   "handshake_macs": [], "eapol_frames": 0})
    called = []
    monkeypatch.setattr(wifidecrypt, "decrypt", lambda *a: called.append(1))
    res = wifimon.run_sniff("wlan0", 1, "Zohidjon", "p", seconds=1, workdir=tmp_path,
                            enter=lambda i, c: None, leave=lambda i: None, capture=cap)
    assert res["decrypted"] is None and called == []


# ------------------------------------------------------------------ helper

def test_helper_wifi_commands_track_and_restore(monkeypatch):
    from netlab.priv.helper import Helper
    import io
    h = Helper(stdin=io.BytesIO(), stdout=io.BytesIO())
    monkeypatch.setattr(netcfg, "monitor_start",
                        lambda iface, ch="": {"interface": iface, "mode": "monitor", "channel": str(ch)})
    stops = []
    monkeypatch.setattr(netcfg, "monitor_stop",
                        lambda iface, rc="": stops.append((iface, rc)) or {"interface": iface, "mode": "managed"})
    h.cmd_wifi_monitor("wlan0", 1, reconnect="Zohidjon")
    assert h._monitor_iface == "wlan0" and h._monitor_reconnect == "Zohidjon"
    # A dropped pipe / shutdown must put the radio back.
    h.shutdown("stdin closed")
    assert stops == [("wlan0", "Zohidjon")] and h._monitor_iface == ""


# ------------------------------------------------------------ station filter

def test_real_stations_drops_one_off_bad_fcs_noise():
    # A real station sends many frames; monitor-mode corruption yields garbled
    # source MACs that appear once or twice. Frequency floor keeps only real.
    rows = (["aa:bb:cc:dd:ee:ff"] * 40 + ["11:22:33:44:55:66"] * 8
            + ["de:ad:be:ef:00:01"]        # one-off corruption
            + ["de:ad:be:ef:00:02"]        # one-off corruption
            + ["ff:ff:ff:ff:ff:ff"] * 3)   # broadcast ignored
    assert wifidecrypt.real_stations(rows, min_frames=5) == [
        "11:22:33:44:55:66", "aa:bb:cc:dd:ee:ff"]
    assert wifidecrypt.real_stations([], min_frames=5) == []
