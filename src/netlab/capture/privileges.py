"""Capture privilege diagnosis.

NetLab is designed to run as a normal desktop user.  Capture privileges live
in dumpcap, which on Debian/Kali carries cap_net_raw+cap_net_admin and is
executable by the `wireshark` group.  Running the whole GUI as root is
supported but is not recommended and is reported as such.
"""

from __future__ import annotations

try:
    import grp                              # POSIX only; absent on Windows
except ImportError:
    grp = None
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

CAPTURE_GROUP = "wireshark"


@dataclass(slots=True)
class PrivilegeReport:
    can_capture: bool = False
    running_as_root: bool = False
    dumpcap: str | None = None
    has_capabilities: bool = False
    capabilities: str = ""
    group_owner: str | None = None
    user_in_group: bool = False
    executable: bool = False
    summary: str = ""
    details: list[str] = field(default_factory=list)
    remediation: list[str] = field(default_factory=list)


def _read_capabilities(path: str) -> str:
    """Return the file capability string for `path`, e.g.
    "cap_net_admin,cap_net_raw=eip", or "" if it has none."""
    getcap = shutil.which("getcap")
    if getcap:
        try:
            proc = subprocess.run([getcap, path], capture_output=True,
                                  text=True, timeout=5)
            out = (proc.stdout or "").strip()
            if proc.returncode == 0 and out:
                # getcap prints "<path> <caps>"; strip the path, keep the caps.
                if out.startswith(path):
                    out = out[len(path):].strip()
                if out.startswith("="):
                    out = out[1:].strip()
                return out
        except (subprocess.TimeoutExpired, OSError):
            pass
    # Fall back to the raw xattr so a missing libcap-ng-utils is not fatal.
    try:
        blob = os.getxattr(path, "security.capability")
    except OSError:
        return ""
    return "cap_net_raw (from security.capability xattr)" if blob else ""


def check() -> PrivilegeReport:
    rep = PrivilegeReport()
    # Windows has no root uid; treat it as not-root (its capture path is Npcap,
    # not this one, and the offline build never captures live anyway).
    rep.running_as_root = hasattr(os, "geteuid") and os.geteuid() == 0

    exe = shutil.which("dumpcap")
    rep.dumpcap = exe
    if not exe:
        rep.summary = "dumpcap is not installed"
        rep.details.append(
            "NetLab captures through dumpcap and cannot capture without it.")
        rep.remediation.append("sudo apt install wireshark-common")
        return rep

    path = Path(exe)
    rep.executable = os.access(exe, os.X_OK)
    rep.capabilities = _read_capabilities(exe)
    rep.has_capabilities = "cap_net_raw" in rep.capabilities

    try:
        st = path.stat()
        rep.group_owner = grp.getgrgid(st.st_gid).gr_name if grp else None
    except (OSError, KeyError, AttributeError):
        rep.group_owner = None

    try:
        getgroups = getattr(os, "getgroups", None)
        user_groups = ({grp.getgrgid(g).gr_name for g in getgroups()}
                       if grp and getgroups else set())
    except (OSError, KeyError, AttributeError):
        user_groups = set()
    rep.user_in_group = bool(rep.group_owner and rep.group_owner in user_groups)

    if rep.running_as_root:
        rep.can_capture = True
        rep.summary = "Running as root - capture is available"
        rep.details.append(
            "NetLab is running as root. This works, but running the GUI as an "
            "unprivileged user in the '%s' group is the safer configuration."
            % CAPTURE_GROUP)
        return rep

    if rep.has_capabilities and rep.executable:
        rep.can_capture = True
        rep.summary = "Capture available as %s (no root required)" % (
            os.environ.get("USER") or "this user")
        rep.details.append("dumpcap: %s" % exe)
        rep.details.append("capabilities: %s" % (rep.capabilities or "none"))
        if rep.group_owner:
            rep.details.append("group: %s (member: %s)" % (
                rep.group_owner, "yes" if rep.user_in_group else "no"))
        return rep

    rep.can_capture = False
    if not rep.has_capabilities:
        rep.summary = "dumpcap has no capture capabilities"
        rep.details.append(
            "dumpcap is missing cap_net_raw, so it cannot open an interface.")
        rep.remediation.append("sudo dpkg-reconfigure wireshark-common")
        rep.remediation.append(
            "sudo setcap cap_net_raw,cap_net_admin+eip %s" % exe)
    elif not rep.executable:
        rep.summary = "dumpcap is not executable by this user"
        rep.details.append(
            "dumpcap is owned by group '%s' and this user is not a member."
            % (rep.group_owner or "?"))
        rep.remediation.append(
            "sudo usermod -aG %s $USER   # then log out and back in"
            % (rep.group_owner or CAPTURE_GROUP))
    return rep


def remediation_text(rep: PrivilegeReport) -> str:
    lines = [rep.summary, ""]
    lines.extend(rep.details)
    if rep.remediation:
        lines.append("")
        lines.append("To fix this, run:")
        lines.extend("    " + r for r in rep.remediation)
    return "\n".join(lines)
