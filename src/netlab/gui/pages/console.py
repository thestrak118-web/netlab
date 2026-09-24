"""KONSOL: a single scrolling, terminal-style feed of the live session.

Every other page shows one slice of the engagement in a table.  This page
shows the whole thing as one narrative, the way a console tool does: capture
started, the gateway and its MAC, a line per target as poisoning begins, and
then the credentials and hits streaming in underneath.

It is a *view*, not a source.  Each line is a formatted real event -- the same
events the tables consume, routed here as well -- so nothing on this page is
invented.  An event whose fields were not observed simply prints what was.
"""

from __future__ import annotations

import time

from PySide6.QtGui import QColor, QFont, QTextCharFormat, QTextCursor
from PySide6.QtWidgets import (QFileDialog, QHBoxLayout, QLabel, QPlainTextEdit,
                               QPushButton, QVBoxLayout, QWidget)

from netlab import __version__

# class -> colour.  One green for status, brighter for the credential header,
# yellow for the values that matter, teal for a module hit, orange/red for
# trouble.  Kept close to the black-on-green console aesthetic.
_COLOURS = {
    "status": "#32d296",
    "gw": "#32d296",
    "host": "#8fe3c4",
    "poison": "#32d296",
    "hit": "#3bd0e0",
    "credhdr": "#eafff5",
    "cred": "#9fb4c8",
    "credval": "#ffd166",
    "warn": "#f2a65a",
    "err": "#ff6b6b",
    "dim": "#5b6b7a",
}

_BANNER = r"""
  _   _      _   _          _
 | \ | | ___| |_| |    __ _| |__
 |  \| |/ _ \ __| |   / _` | '_ \
 | |\  |  __/ |_| |__| (_| | |_) |
 |_| \_|\___|\__|_____\__,_|_.__/
"""


class ConsolePage(QWidget):
    """Live session log, rendered as a monospace console."""

    MAX_BLOCKS = 6000

    def __init__(self) -> None:
        super().__init__()
        self._armed_noted = False
        self._seen_strip: set[str] = set()
        self._seen_spoof: set[str] = set()

        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(6)

        bar = QHBoxLayout()
        title = QLabel("KONSOL — jonli seans oqimi")
        title.setObjectName("PageHint")
        bar.addWidget(title)
        bar.addStretch(1)
        self.clear_btn = QPushButton("Tozalash")
        self.clear_btn.clicked.connect(self.reset)
        self.save_btn = QPushButton("Saqlash…")
        self.save_btn.clicked.connect(self._save)
        bar.addWidget(self.clear_btn)
        bar.addWidget(self.save_btn)
        lay.addLayout(bar)

        self.view = QPlainTextEdit()
        self.view.setReadOnly(True)
        self.view.setObjectName("Console")
        self.view.setMaximumBlockCount(self.MAX_BLOCKS)
        font = QFont("DejaVu Sans Mono", 10)
        font.setStyleHint(QFont.StyleHint.Monospace)
        self.view.setFont(font)
        self.view.setStyleSheet(
            "QPlainTextEdit#Console{background:#0a0d11;color:#32d296;"
            "border:1px solid #1c2530;border-radius:6px;padding:8px;}")
        lay.addWidget(self.view, 1)

        self._banner()

    # ------------------------------------------------------------- writing

    def _banner(self) -> None:
        for row in _BANNER.strip("\n").splitlines():
            self._line(row, "status")
        self._line("NetLab %s  —  network analysis & interception workbench"
                   % __version__, "dim")
        self._line("The passive half observes; the active half only transmits "
                   "inside an armed engagement.", "dim")
        self._rule()

    def _rule(self) -> None:
        self._line("─" * 56, "dim", stamp=False)

    def _blank(self) -> None:
        self._line("", "dim", stamp=False)

    def _fmt(self, cls: str) -> QTextCharFormat:
        fmt = QTextCharFormat()
        fmt.setForeground(QColor(_COLOURS.get(cls, _COLOURS["status"])))
        return fmt

    def _line(self, text: str, cls: str = "status", stamp: bool = True) -> None:
        # A console preserves its columns, so lines go in as plain text with a
        # per-run colour format rather than HTML, whose whitespace collapses.
        sb = self.view.verticalScrollBar()
        near_bottom = sb.value() >= sb.maximum() - 4
        cursor = self.view.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        if not self.view.document().isEmpty():
            cursor.insertText("\n")
        if stamp:
            cursor.insertText(time.strftime("%H:%M:%S "), self._fmt("dim"))
        cursor.insertText(text, self._fmt(cls))
        if near_bottom:
            sb.setValue(sb.maximum())

    # -------------------------------------------------------------- inputs

    def capture_started(self, iface: str, ip: str = "", bpf: str = "") -> None:
        self._line("Starting capturing on %s%s"
                   % (iface or "?", "  [%s]" % ip if ip else ""), "status")
        self._line("Pcap filter: [%s]" % (bpf or "OK"), "status")

    def capture_stopped(self, reason: str = "") -> None:
        self._line("Capture stopped%s"
                   % ("  (%s)" % reason if reason else ""), "dim")

    def note_armed(self, data: dict) -> None:
        if self._armed_noted:
            return
        self._armed_noted = True
        data = data or {}
        eng = data.get("engagement") or {}
        iface = data.get("interface")
        ifname = (eng.get("interface")
                  or (iface.get("name") if isinstance(iface, dict) else "")
                  or "?")
        local_ip = iface.get("ipv4") if isinstance(iface, dict) else ""
        modules = data.get("modules") or []
        self._rule()
        self._line("Interception armed on %s%s"
                   % (ifname, "  [%s]" % local_ip if local_ip else ""),
                   "credhdr")
        if modules:
            self._line("Modules: %s" % ", ".join(modules), "status")
        gw = data.get("gateway", "")
        if gw:
            self._line("Gateway: %-15s : [%s]"
                       % (gw, data.get("gateway_mac") or "?"), "gw")
        for ip, mac in (data.get("targets") or {}).items():
            self._line("Starting poisoning %-15s : [%s]" % (ip, mac or "?"),
                       "poison")

    def note_disarmed(self) -> None:
        self._armed_noted = False
        self._seen_strip.clear()
        self._seen_spoof.clear()
        self._line("Interception disarmed — network restored", "status")
        self._rule()

    def feed(self, name: str, data: dict) -> None:
        """Format one live event as a console line (or a few)."""
        data = data or {}
        if name == "armed":
            self.note_armed(data)
        elif name == "disarmed":
            self.note_disarmed()
        elif name == "credential":
            self._credential(data)
        elif name == "scan.host":
            ip = data.get("ip", "")
            host = data.get("name") or data.get("hostname") or ""
            self._line("Host   %-15s : [%s]%s"
                       % (ip, data.get("mac") or "?",
                          "  " + host if host else ""), "host")
        elif name == "strip.host":
            host = data.get("host", "")
            if host and host not in self._seen_strip:
                self._seen_strip.add(host)
                self._line("SSL strip   %s" % host, "hit")
        elif name == "dns.spoofed":
            key = "%s->%s" % (data.get("name", ""), data.get("address", ""))
            if key not in self._seen_spoof:
                self._seen_spoof.add(key)
                self._line("DNS spoof   %s -> %s"
                           % (data.get("name", ""), data.get("address", "")),
                           "hit")
        elif name == "dhcp.lease":
            self._line("DHCP lease  %s -> %s"
                       % (data.get("mac", ""), data.get("ip", "")), "hit")
        elif name == "cookie.killed":
            self._line("Cookie kill %s" % data.get("host", ""), "hit")
        elif name == "file.carved":
            self._line("File carved %s"
                       % (data.get("name") or data.get("path", "")), "hit")
        elif name == "changer.hit":
            self._line("Rewrote     %s" % data.get("host", ""), "hit")
        elif name == "promisc.found":
            self._line("Promiscuous host %s  (confidence %s)"
                       % (data.get("ip", ""), data.get("confidence", "?")),
                       "warn")
        elif name == "relay.success":
            self._line("NTLM relay  authenticated %s -> %s"
                       % (data.get("client", ""), data.get("target", "")),
                       "credhdr")
        elif name == "relay.rejected":
            self._line("NTLM relay  rejected (%s)"
                       % (data.get("reason") or "signing/MIC required"), "warn")
        elif name in ("log.warn", "log.error"):
            self._line(data.get("message", ""),
                       "err" if name == "log.error" else "warn")

    def _credential(self, d: dict) -> None:
        proto = (d.get("proto") or "HTTP").upper()
        header = ("HTTP Authorization intercepted" if proto == "HTTP"
                  else "%s credential intercepted" % proto)
        self._blank()
        self._line(header, "credhdr")
        server = d.get("server", "")
        port = d.get("port") or ""
        if server:
            self._line("%s%s" % (server, ":%s" % port if port else ""), "cred")
        ctx = d.get("context") or d.get("host")
        if ctx:
            self._line("Host: %s" % ctx, "cred")
        if d.get("user"):
            self._line("Username=%s" % d["user"], "credval")
        if d.get("password"):
            self._line("Password=%s" % d["password"], "credval")
        if d.get("hash"):
            digest = str(d["hash"])
            if len(digest) > 80:
                digest = digest[:80] + "…"
            self._line("Hash(%s)=%s" % (d.get("hash_type") or "?", digest),
                       "credval")

    # -------------------------------------------------------------- actions

    def reset(self) -> None:
        self.view.clear()
        self._armed_noted = False
        self._seen_strip.clear()
        self._seen_spoof.clear()
        self._banner()

    def _save(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self, "Konsol oqimini saqlash",
            "netlab-console-%s.log" % time.strftime("%Y%m%d-%H%M%S"),
            "Log (*.log *.txt)")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(self.view.toPlainText())
        except OSError:
            pass
