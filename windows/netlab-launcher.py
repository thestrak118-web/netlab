"""PyInstaller entry point for the Windows build of NetLab.

On Windows NetLab runs as an OFFLINE analyser: open a .pcap/.pcapng (File ->
Open capture) and use every decoder, the device/topology views and the
credential parsers. Live capture, discovery, MITM and the Wi-Fi monitor sniff
are Linux-only (they need iw, nftables, AF_PACKET, dumpcap and pkexec) and
report that they are unavailable rather than pretending to work.
"""
import sys

from netlab.app import main

if __name__ == "__main__":
    sys.exit(main())
