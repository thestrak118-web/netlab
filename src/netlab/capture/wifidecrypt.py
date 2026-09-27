"""Passive Wi-Fi decryption for monitor-mode captures.

As a normal (managed) station you never see another client's unicast traffic:
the access point delivers each client only its own frames. In MONITOR mode the
radio hands up every 802.11 frame on the channel -- including other clients' --
but they are WPA/WPA2 encrypted. Given the network passphrase and a captured
4-way handshake for a client, `airdecap-ng` derives that client's transient key
and writes out its plaintext IP traffic, which NetLab's ordinary decoders then
read like any other pcap.

Hard limits, stated honestly:
  * A client only decrypts if its 4-way handshake (EAPOL) is in the capture --
    caught when it (re)connects. Already-connected clients contribute encrypted
    data with no key until they roam/reconnect.
  * WPA3 (SAE) has per-session forward secrecy and cannot be decrypted from the
    passphrase. An open network needs no key (`-e` alone).
  * Monitor mode is one channel at a time and takes the radio off the network.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path


class WifiDecryptError(RuntimeError):
    pass


def _run(argv, timeout=120):
    try:
        return subprocess.run(argv, capture_output=True, text=True,
                              timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise WifiDecryptError(str(exc)) from exc


_BROADCAST = "ff:ff:ff:ff:ff:ff"


def _tally(values):
    """Count clean MAC strings, returning (dominant, {mac: count})."""
    counts = {}
    for v in values:
        v = (v or "").strip().lower()
        if v and v != _BROADCAST:
            counts[v] = counts.get(v, 0) + 1
    return (max(counts, key=counts.get) if counts else ""), counts


def real_stations(sa_rows, min_frames=3):
    """Recurring source MACs only. Monitor mode captures many corrupted frames
    (no FCS to reject them here) whose garbled source address appears once or
    twice; a real associated station sends many frames, so a frequency floor
    drops the noise. Returns sorted MACs meeting the floor."""
    _dom, counts = _tally(sa_rows)
    return sorted(m for m, n in counts.items() if n >= min_frames)


def inspect(pcap, tshark=None, min_frames=5) -> dict:
    """Summarise a monitor capture: total frames, the AP's BSSID, the encrypted
    data-frame count, the REAL client MACs (frequency-filtered per the AP's
    BSSID, so bad-FCS garbage does not show up as hundreds of phantom stations),
    and which clients have a usable 4-way handshake (so the caller can say who
    is decryptable before running airdecap)."""
    exe = tshark or shutil.which("tshark")
    if not exe:
        raise WifiDecryptError("tshark is required to inspect a capture")
    path = str(pcap)

    def field(display_filter, fields):
        argv = [exe, "-r", path]
        if display_filter:
            argv += ["-Y", display_filter]
        argv += ["-T", "fields"]
        for f in fields:
            argv += ["-e", f]
        return [ln for ln in _run(argv).stdout.splitlines() if ln.strip()]

    total = len(field("wlan", ["frame.number"]))
    # The AP is the dominant BSSID across data and beacon frames; corrupted
    # frames scatter across bogus BSSIDs that never dominate.
    ap, _ = _tally(field("wlan.fc.type==2 || wlan.fc.type_subtype==0x08",
                         ["wlan.bssid"]))
    scope = " && wlan.bssid==%s" % ap if ap else ""
    data_rows = field("wlan.fc.type==2" + scope, ["wlan.sa"])
    clients = real_stations(data_rows, min_frames)
    handshake = set()
    for line in field("eapol" + scope, ["wlan.sa", "wlan.da"]):
        for mac in line.split("\t"):
            mac = (mac or "").strip().lower()
            if mac and mac not in (_BROADCAST, "", ap):
                handshake.add(mac)
    return {
        "frames": total,
        "data_frames": len(data_rows),
        "bssid": ap,
        "clients": clients,
        "handshake_macs": sorted(handshake),
        "eapol_frames": len(field("eapol", ["frame.number"])),
    }


def decrypt(pcap, essid, passphrase="", out=None) -> Path:
    """Decrypt a monitor capture with airdecap-ng and return the path to the
    plaintext pcap. `passphrase` empty means an open network. Raises if
    airdecap-ng is missing or produced no output (usually: no handshake, wrong
    passphrase, or WPA3)."""
    exe = shutil.which("airdecap-ng")
    if not exe:
        raise WifiDecryptError(
            "airdecap-ng is not installed (apt install aircrack-ng)")
    src = Path(pcap)
    if not src.is_file():
        raise WifiDecryptError("capture not found: %s" % src)
    if not essid:
        raise WifiDecryptError("the network SSID is required")

    argv = [exe, "-e", essid]
    if passphrase:
        argv += ["-p", passphrase]
    argv.append(str(src))
    res = _run(argv)
    if res.returncode != 0:
        raise WifiDecryptError(
            (res.stderr or res.stdout or "airdecap-ng failed").strip())

    # airdecap-ng writes "<stem>-dec<suffix>" next to the input.
    produced = src.with_name(src.stem + "-dec" + src.suffix)
    if not produced.is_file():
        raise WifiDecryptError(
            "airdecap-ng wrote no decrypted file -- no captured handshake, a "
            "wrong passphrase, or a WPA3/OWE network that cannot be decrypted "
            "passively")
    if out:
        produced = produced.replace(Path(out))
    return Path(produced)


def decrypted_packet_count(airdecap_stdout: str) -> int:
    """Pull 'Number of decrypted WPA  packets' out of airdecap-ng's report."""
    import re
    m = re.search(r"decrypted\s+\w*\s*packets\s+(\d+)", airdecap_stdout, re.I)
    return int(m.group(1)) if m else 0
