"""Configuration and on-disk locations.

Defaults ship in /etc/netlab/netlab.conf (installed by the .deb) and are
overlaid by the per-user file in ~/.config/netlab/config.json.
"""

from __future__ import annotations

import copy
import json
import os
import threading
from pathlib import Path
from typing import Any

SYSTEM_CONFIG = Path("/etc/netlab/netlab.conf")

DEFAULTS: dict[str, Any] = {
    # capture
    "interface": "",
    "bpf_filter": "",
    "snaplen": 262144,
    "promiscuous": True,
    "capture_format": "pcapng",          # "pcap" or "pcapng"
    "capture_dir": "",                    # empty -> XDG data dir/captures
    "max_pcap_mb": 512,                   # dumpcap autostop filesize
    "retention_days": 14,                 # capture file retention
    "retention_max_files": 100,

    # bounds (these keep memory flat at high packet rates)
    "queue_packets": 200000,              # capture -> analysis bounded queue
    "live_rows": 100000,                  # rows retained in Live Traffic
    "max_flows": 100000,
    "max_hosts": 50000,
    "max_dns_events": 50000,
    "max_http_events": 50000,
    "max_tls_events": 50000,
    "gui_refresh_ms": 500,

    # TCP reassembly (Phase 2). Only out-of-order segments occupy memory,
    # so these caps bound the pathological case, not normal traffic.
    "tcp_reassembly": True,
    "max_streams": 20000,               # concurrently tracked TCP streams
    "reasm_dir_buffer_kb": 256,         # out-of-order buffer per direction
    "reasm_max_segments": 256,          # out-of-order segments per direction
    "reasm_total_buffer_mb": 64,        # global out-of-order ceiling
    "flow_idle_timeout": 120,           # seconds before a stream is retired
    "http_header_limit": 65536,         # max header block held while parsing
    "tls_handshake_limit": 32768,       # max handshake bytes held per stream

    # credential harvesting (Intercepter mode). Off by default: it reads
    # what protocols were trying to keep private, so it is opted into.
    "harvest_credentials": False,
    "max_credentials": 5000,

    # active interception
    "intercept_enabled": False,
    "mitm_poison_interval": 2.0,
    "mitm_http_port": 18080,
    "mitm_tls_port": 18443,
    "mitm_dns_port": 15353,
    "mitm_upstream_dns": "",
    "mitm_sslstrip": True,
    "mitm_ssl_mitm": False,
    "mitm_dns_spoof": False,
    "mitm_dhcp": False,
    "mitm_cookie_killer": False,
    "mitm_carve_files": False,
    "mitm_ntlm_relay": False,
    "relay_target": "",                  # SMB server the NTLM relay targets
    "mitm_verify_upstream": False,
    "changer_rules": [],
    "dns_spoof_rules": [],
    "engagement_name": "",
    "engagement_targets": "",
    "radius_secret": "",                 # to decrypt RADIUS PAP passwords

    # nmap
    "nmap_path": "nmap",
    "nmap_use_pkexec": False,

    # ui
    "auto_scroll": True,
    "resolve_dns_names": True,            # only from observed DNS traffic
    "nav_collapsed_groups": [],           # folded sidebar sections (by id)
}


def real_user() -> tuple[int, int, Path]:
    """The person running NetLab, as (uid, gid, home).

    Under `sudo netlab` the process is root, but its config, captures and
    engagements belong to the operator, not to root -- so they must land in the
    operator's home and be owned by them. This resolves that identity from
    SUDO_UID/PKEXEC_UID; without them it is just the current user.
    """
    if os.geteuid() == 0:
        for var in ("SUDO_UID", "PKEXEC_UID"):
            value = os.environ.get(var)
            if value and value.isdigit():
                try:
                    import pwd
                    info = pwd.getpwuid(int(value))
                    return info.pw_uid, info.pw_gid, Path(info.pw_dir)
                except (KeyError, OSError):
                    pass
    return os.getuid(), os.getgid(), Path.home()


def _own(path: Path) -> None:
    """Give `path` back to the real user when NetLab created it as root, so a
    later unprivileged run can still read and write it."""
    if os.geteuid() != 0:
        return
    uid, gid, _home = real_user()
    if uid == 0:
        return
    try:
        os.chown(path, uid, gid)
    except OSError:
        pass


def xdg(var: str, fallback: str) -> Path:
    v = os.environ.get(var)
    if v:
        return Path(v)
    return real_user()[2] / fallback


def config_dir() -> Path:
    return xdg("XDG_CONFIG_HOME", ".config") / "netlab"


def data_dir() -> Path:
    return xdg("XDG_DATA_HOME", ".local/share") / "netlab"


def config_path() -> Path:
    return config_dir() / "config.json"


def default_capture_dir() -> Path:
    return data_dir() / "captures"


class Config:
    """Thread-safe settings store with JSON persistence."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._data = copy.deepcopy(DEFAULTS)
        self.load()

    def load(self) -> None:
        merged = copy.deepcopy(DEFAULTS)
        for path in (SYSTEM_CONFIG, config_path()):
            try:
                if path.is_file():
                    loaded = json.loads(path.read_text(encoding="utf-8"))
                    if isinstance(loaded, dict):
                        for k, v in loaded.items():
                            if k in merged:
                                merged[k] = v
            except (OSError, ValueError):
                # A broken config file must never stop the application.
                continue
        with self._lock:
            self._data = merged

    def save(self) -> tuple[bool, str]:
        try:
            d = config_dir()
            existed = d.exists()
            d.mkdir(parents=True, exist_ok=True)
            if not existed:
                _own(d)
            with self._lock:
                payload = json.dumps(self._data, indent=2, sort_keys=True)
            tmp = config_path().with_suffix(".json.tmp")
            tmp.write_text(payload + "\n", encoding="utf-8")
            tmp.replace(config_path())
            _own(config_path())
            return True, str(config_path())
        except OSError as exc:
            return False, str(exc)

    def get(self, key: str, default: Any = None) -> Any:
        with self._lock:
            return self._data.get(key, DEFAULTS.get(key, default))

    def set(self, key: str, value: Any) -> None:
        with self._lock:
            self._data[key] = value

    def update(self, mapping: dict[str, Any]) -> None:
        with self._lock:
            self._data.update(mapping)

    def as_dict(self) -> dict[str, Any]:
        with self._lock:
            return copy.deepcopy(self._data)

    def capture_dir(self) -> Path:
        raw = str(self.get("capture_dir") or "").strip()
        return Path(raw).expanduser() if raw else default_capture_dir()

    def ensure_capture_dir(self) -> Path:
        d = self.capture_dir()
        existed = d.exists()
        d.mkdir(parents=True, exist_ok=True)
        if not existed:
            _own(d)
            _own(d.parent)
        return d


CONFIG = Config()
