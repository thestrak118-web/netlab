# NetLab on Windows

NetLab is a Linux network-analysis and interception tool. Its **live** side —
packet capture, device discovery, MITM (ARP/DNS/SSL-strip), the Wi-Fi monitor
sniff and credential harvesting — is built on Linux-only facilities (`iw`,
`nftables`, `AF_PACKET`, `dumpcap`, `pkexec`, monitor mode). **None of that runs
on Windows**, and no repackaging changes that: it would need a rewrite against
Npcap and the Windows APIs.

What the Windows build **does** give you is NetLab as an **offline analyser**:

- Open a `.pcap` / `.pcapng` (**File → Open capture**).
- Every decoder (HTTP, DNS, TLS/SNI, QUIC, 30+ protocols), stream reassembly.
- The device and topology projections, and the credential parsers, over that file.

Live capture, Scan, MITM/Kuzat and the Wi-Fi sniff are shown as unavailable.

## Getting the .exe

A real Windows build is produced by GitHub Actions on a Windows runner (see
`.github/workflows/build-windows.yml`) — PyInstaller can only target the OS it
runs on, so it is not built from Linux.

- **Automatic:** push a `v*` tag; the exe is attached to that GitHub release.
- **On demand:** Actions tab → *build-windows* → *Run workflow*; download the
  `netlab-windows-exe` artifact when it finishes.

## Building it yourself on a Windows machine

```bat
py -m pip install PySide6 cryptography pyinstaller pillow
pyinstaller --onefile --windowed --name netlab --paths src ^
  --collect-all PySide6 --collect-submodules netlab ^
  --add-data "src/netlab/gui/icons;netlab/gui/icons" ^
  windows/netlab-launcher.py
```

The single `dist\netlab.exe` is self-contained (bundles Python and Qt).
