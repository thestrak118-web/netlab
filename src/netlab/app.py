"""NetLab application entry point."""

from __future__ import annotations

import argparse
import os
import signal
import sys
from pathlib import Path

from netlab import __version__

# PNG first: rendering an .svg through QIcon needs the Qt SVG image plugin
# (python3-pyside6.qtsvg), which is only a Recommends. The desktop entry still
# uses the SVG, because the desktop environment renders that one, not Qt.
ICON_SEARCH = [
    "/usr/share/icons/hicolor/128x128/apps/netlab.png",
    "/usr/share/icons/hicolor/256x256/apps/netlab.png",
    "/usr/share/pixmaps/netlab.png",
    "/usr/share/icons/hicolor/scalable/apps/netlab.svg",
]


def _find_icon() -> str | None:
    assets = Path(__file__).resolve().parents[2] / "assets"
    for name in ("netlab-128.png", "netlab.png", "netlab.svg"):
        local = assets / name
        if local.is_file():
            return str(local)
    for candidate in ICON_SEARCH:
        if Path(candidate).is_file():
            return candidate
    return None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netlab",
        description="NetLab - network analysis and interception workbench for Kali Linux.",
        epilog="NetLab captures through dumpcap. Active interception requires "
               "an authorised engagement; passive capture does not decrypt TLS.")
    parser.add_argument("--version", action="version",
                        version="NetLab %s" % __version__)
    parser.add_argument("-i", "--interface", metavar="IFACE",
                        help="preselect this capture interface")
    parser.add_argument("-f", "--filter", metavar="BPF", dest="bpf",
                        help="preload this BPF capture filter")
    parser.add_argument("-r", "--read", metavar="FILE",
                        help="open a pcap/pcapng file on startup")
    parser.add_argument("--start", action="store_true",
                        help="start capturing immediately on the chosen interface")
    parser.add_argument("--check", action="store_true",
                        help="report capture privileges and exit")
    return parser


def run_check() -> int:
    from netlab.capture.interfaces import InterfaceError, list_interfaces
    from netlab.capture.privileges import check, remediation_text

    report = check()
    print(remediation_text(report))
    print()
    try:
        interfaces = list_interfaces(include_pseudo=False)
    except InterfaceError as exc:
        print("Interfaces: unavailable (%s)" % exc)
        return 1
    print("Capture interfaces (%d):" % len(interfaces))
    for iface in interfaces:
        print("  %-18s %-10s %-6s %s" % (
            iface.name, iface.kind, "up" if iface.is_up else "down",
            ", ".join(iface.addresses) or "-"))
    return 0 if report.can_capture else 1


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.check:
        return run_check()

    # Ctrl+C in a terminal should close the GUI rather than be swallowed by Qt.
    signal.signal(signal.SIGINT, signal.SIG_DFL)

    if not os.environ.get("DISPLAY") and not os.environ.get("WAYLAND_DISPLAY") \
            and not os.environ.get("QT_QPA_PLATFORM"):
        sys.stderr.write(
            "netlab: no graphical display was found.\n"
            "NetLab is a GUI application. Start it from a desktop session, or "
            "run 'netlab --check' to verify capture privileges from a "
            "terminal.\n")
        return 2

    from PySide6.QtGui import QIcon
    from PySide6.QtWidgets import QApplication

    from netlab.config import CONFIG
    from netlab.gui import theme
    from netlab.gui.main_window import MainWindow

    QApplication.setApplicationName("NetLab")
    QApplication.setApplicationDisplayName("NetLab")
    QApplication.setOrganizationName("NetLab")
    QApplication.setDesktopFileName("netlab")

    app = QApplication(sys.argv[:1])
    app.setStyleSheet(theme.STYLESHEET)
    icon = _find_icon()
    if icon:
        app.setWindowIcon(QIcon(icon))

    if args.interface:
        CONFIG.set("interface", args.interface)
    if args.bpf:
        CONFIG.set("bpf_filter", args.bpf)

    window = MainWindow()
    window.show()

    if args.read:
        path = Path(args.read).expanduser()
        if not path.is_file():
            sys.stderr.write("netlab: no such capture file: %s\n" % path)
        else:
            window.open_capture_file(str(path))
    elif args.start:
        window.start_capture()

    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
