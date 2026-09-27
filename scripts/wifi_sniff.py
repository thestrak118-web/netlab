#!/usr/bin/env python3
"""Dev wrapper for `netlab-wifisniff` — see netlab.capture.wifimon:main.

    sudo python3 scripts/wifi_sniff.py -i wlan0 -c 1 -e "SSID" -p "pass" -t 25
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from netlab.capture.wifimon import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
