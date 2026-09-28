"""Orchestrate a passive Wi-Fi monitor sniff, end to end.

    monitor mode  ->  capture 802.11  ->  restore managed  ->  decrypt  ->  pcap

The privileged mode switch goes through the helper (`wifi_monitor` /
`wifi_managed`); the capture is an ordinary dumpcap the unprivileged side already
runs; decryption is airdecap-ng (see `wifidecrypt`). Recovery is attempted even
after a partial start, and failures are reported. The helper independently
attempts recovery on a dropped pipe.

The steps are injected so the flow is unit-testable without a radio: `enter`
and `leave` call the helper, `capture` writes a pcap. On real hardware the GUI
supplies dumpcap for `capture` and the helper client for `enter`/`leave`.
"""
from __future__ import annotations

import shutil
import subprocess
import time
from pathlib import Path

from netlab.capture import wifidecrypt


class WifiMonError(RuntimeError):
    pass


def dumpcap_capture(interface: str, out_pcap, seconds: int = 20,
                    exe: str = "", cancel=None) -> Path:
    """Capture raw 802.11 on `interface` for `seconds` (dumpcap uses cap_net_raw,
    no root). Returns the pcap path. `cancel` (an Event) ends it early."""
    tool = exe or shutil.which("dumpcap") or shutil.which("tcpdump")
    if not tool:
        raise WifiMonError("dumpcap or tcpdump is required to capture")
    out = str(out_pcap)
    if tool.endswith("dumpcap"):
        argv = [tool, "-i", interface, "-w", out,
                "-a", "duration:%d" % max(1, seconds)]
    else:                                            # tcpdump fallback
        argv = [tool, "-i", interface, "-w", out]
    proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    deadline = time.monotonic() + max(1, seconds) + 5
    while proc.poll() is None:
        if (cancel is not None and cancel.is_set()) or time.monotonic() > deadline:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
            break
        time.sleep(0.2)
    if not Path(out).is_file():
        err = (proc.stderr.read().decode("utf-8", "replace") if proc.stderr else "")
        raise WifiMonError(err.strip() or "capture produced no file")
    return Path(out)


def run_sniff(interface: str, channel, essid: str, passphrase: str = "",
              seconds: int = 20, workdir=None, *,
              enter, leave, capture=dumpcap_capture, reconnect: str = "") -> dict:
    """Run the whole passive-sniff flow and return a result dict:

        {raw, decrypted, summary}

    `raw` is the monitor capture, `decrypted` the plaintext pcap (None if no
    client handshake was caught), `summary` the `wifidecrypt.inspect` counts.
    `enter(interface, channel)` and `leave(interface)` drive the helper. Managed
    mode recovery is attempted even on error, with failures reported.
    """
    work = Path(workdir) if workdir else Path(".")
    raw = work / "wifimon.pcap"
    try:
        enter(interface, channel)
        capture(interface, raw, seconds)
    except BaseException as exc:
        # Enter can fail after changing the radio. Always attempt recovery.
        try:
            leave(interface)
        except Exception as restore_exc:
            raise WifiMonError("%s; Wi-Fi restore failed: %s" %
                               (exc, restore_exc)) from exc
        raise
    else:
        leave(interface)  # A restore error must not be reported as success.
    summary = wifidecrypt.inspect(raw)
    decrypted = None
    if summary["handshake_macs"]:
        try:
            decrypted = str(wifidecrypt.decrypt(raw, essid, passphrase))
        except wifidecrypt.WifiDecryptError:
            decrypted = None
    return {"raw": str(raw), "decrypted": decrypted, "summary": summary}


def main(argv=None) -> int:
    """`netlab-wifisniff`: run a passive monitor sniff as root and write a
    plaintext pcap NetLab can open. Monitor mode needs root, so use sudo."""
    import argparse
    import os
    from netlab.intercept import netcfg

    ap = argparse.ArgumentParser(
        prog="netlab-wifisniff",
        description="Passive Wi-Fi monitor sniff of OTHER stations + WPA2 decrypt")
    ap.add_argument("-i", "--interface", default="wlan0")
    ap.add_argument("-c", "--channel", default="", help="lock to this channel")
    ap.add_argument("-e", "--essid", default="", help="network SSID (for decrypt)")
    ap.add_argument("-p", "--passphrase", default="", help="WPA passphrase")
    ap.add_argument("-t", "--seconds", type=int, default=20)
    ap.add_argument("-r", "--reconnect", default="", help="nmcli connection to restore")
    ap.add_argument("-o", "--outdir", default="/tmp/netlab-wifisniff")
    args = ap.parse_args(argv)

    if os.geteuid() != 0:
        print("Monitor mode needs root — run with sudo.", file=__import__("sys").stderr)
        return 2
    work = Path(args.outdir)
    work.mkdir(parents=True, exist_ok=True)
    print("→ %s: monitor mode (ch %s), capturing %ss…"
          % (args.interface, args.channel or "current", args.seconds))
    try:
        result = run_sniff(
            args.interface, args.channel, args.essid, args.passphrase,
            seconds=args.seconds, workdir=work,
            enter=lambda iface, ch: netcfg.monitor_start(iface, ch),
            leave=lambda iface: netcfg.monitor_stop(iface, args.reconnect),
            reconnect=args.reconnect)
    except Exception as exc:
        try:
            netcfg.monitor_stop(args.interface, args.reconnect)
        except Exception:
            pass
        print("error: %s" % exc, file=__import__("sys").stderr)
        return 1

    s = result["summary"]
    print("\n── captured ──────────────────────────────")
    print("  frames                : %d" % s["frames"])
    print("  access point (BSSID)  : %s" % (s.get("bssid") or "unknown"))
    print("  encrypted data frames : %d" % s["data_frames"])
    print("  real stations         : %d" % len(s["clients"]))
    for mac in s["clients"]:
        print("       %s" % mac)
    print("  handshakes for        : %s"
          % (", ".join(s["handshake_macs"]) or "none (no client reconnected)"))
    print("  raw capture           : %s" % result["raw"])
    if result["decrypted"]:
        print("\n✔ DECRYPTED pcap: %s" % result["decrypted"])
        print("  Open it in NetLab (File → Open capture) to read those stations'")
        print("  sites, DNS and cleartext logins — like your own device.")
    elif not s["handshake_macs"]:
        print("\n⚠ No handshake captured — re-run while a target device RECONNECTS "
              "(toggle its Wi-Fi), or use a longer -t.")
    else:
        print("\n⚠ Handshake present but decrypt failed — wrong passphrase or WPA3.")
    return 0
