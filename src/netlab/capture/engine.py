"""Live capture supervision and offline capture import.

dumpcap owns the write to disk and NetLab tails the file it is producing.
That is the same split Wireshark uses, and it matters: if the GUI or the
analysis thread falls behind, dumpcap keeps writing at full speed, so the
capture on disk stays complete even when the on-screen view cannot keep up.
Anything NetLab itself has to drop is counted and shown.
"""

from __future__ import annotations

import os
import re
import signal
import subprocess
import threading
import time
from functools import lru_cache
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import QObject, Signal

from netlab.capture.interfaces import dumpcap_path
from netlab.capture.pcapio import (CaptureFormatError, StreamingCaptureParser)


def _drop_to_operator():
    """When NetLab runs as root (the root launcher, so MITM needs no per-action
    pkexec) dumpcap must NOT run as root: a root-run dumpcap drops its own
    privileges and then cannot open the operator's capture file ("Permission
    denied"). Return a preexec_fn that switches the child to the operator --
    their uid/gid and full group list, so the wireshark group is kept and
    dumpcap's file capabilities still apply. None when already unprivileged or
    there is no operator to drop to (so a plain root shell is unaffected)."""
    if getattr(os, "geteuid", lambda: 0)() != 0:
        return None
    try:
        import pwd
        from netlab.config import real_user
        uid, gid, _home = real_user()
        if uid == 0:
            return None
        groups = os.getgrouplist(pwd.getpwuid(uid).pw_name, gid)
    except Exception:
        return None

    def _preexec():
        os.setgroups(groups)
        os.setgid(gid)
        os.setuid(uid)

    return _preexec

READ_CHUNK = 1 << 18
FILE_WAIT_TIMEOUT = 10.0

@lru_cache(maxsize=4)
def supports_format_flag(exe: str) -> bool:
    """True if this dumpcap takes `-F pcap|pcapng`.

    Wireshark 4.2+ deprecated the old `-P` / `-n` format switches in favour
    of `-F`; older builds only understand the deprecated pair, so probe once
    and cache the answer rather than emitting a warning on every capture.
    """
    try:
        proc = subprocess.run([exe, "-h"], capture_output=True, text=True,
                              timeout=5)
    except (subprocess.TimeoutExpired, OSError):
        return False
    text = (proc.stdout or "") + (proc.stderr or "")
    return bool(re.search(r"^\s+-F\s", text, re.MULTILINE))


_PERMISSION_HINTS = (
    "you don't have permission",
    "permission denied",
    "are you a member",
    "operation not permitted",
)


@dataclass
class CaptureSession:
    interface: str
    bpf_filter: str = ""
    fmt: str = "pcapng"                 # "pcap" or "pcapng"
    snaplen: int = 262144
    promiscuous: bool = True
    output_path: Path | None = None
    max_mb: int = 512
    started_at: float = field(default_factory=time.time)

    def build_argv(self, exe: str) -> list[str]:
        argv = [exe, "-i", self.interface, "-w", str(self.output_path), "-q"]
        fmt = "pcap" if self.fmt == "pcap" else "pcapng"
        if supports_format_flag(exe):
            argv += ["-F", fmt]
        elif fmt == "pcap":
            argv.append("-P")
        if self.bpf_filter.strip():
            argv += ["-f", self.bpf_filter.strip()]
        if self.snaplen and self.snaplen > 0:
            argv += ["-s", str(int(self.snaplen))]
        if not self.promiscuous:
            argv.append("-p")
        if self.max_mb and self.max_mb > 0:
            # dumpcap takes the autostop file size in kB.
            argv += ["-a", "filesize:%d" % (int(self.max_mb) * 1024)]
        return argv


def default_capture_name(interface: str, fmt: str) -> str:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", interface)
    return "netlab-%s-%s.%s" % (safe, stamp, "pcap" if fmt == "pcap" else "pcapng")


class CaptureEngine(QObject):
    """Supervises one dumpcap process and feeds packets into a bounded queue."""

    started = Signal(str)          # output path
    stopped = Signal(str)          # human-readable reason
    failed = Signal(str)           # fatal error message
    status = Signal(str)           # informational line
    stats_changed = Signal()

    def __init__(self, queue, parent=None) -> None:
        super().__init__(parent)
        self._queue = queue
        self._proc: subprocess.Popen | None = None
        self._session: CaptureSession | None = None
        self._reader: threading.Thread | None = None
        self._stderr_thread: threading.Thread | None = None
        self._watcher: threading.Thread | None = None
        self._stop_evt = threading.Event()
        self._lock = threading.Lock()
        self._stderr_lines: list[str] = []
        self._packets_read = 0
        self._bytes_on_disk = 0
        self._parser_error: str | None = None
        self._stopping = False

    # ------------------------------------------------------------ properties

    @property
    def is_running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    @property
    def session(self) -> CaptureSession | None:
        return self._session

    @property
    def output_path(self) -> Path | None:
        return self._session.output_path if self._session else None

    @property
    def packets_read(self) -> int:
        with self._lock:
            return self._packets_read

    @property
    def bytes_on_disk(self) -> int:
        with self._lock:
            return self._bytes_on_disk

    def stderr_text(self) -> str:
        with self._lock:
            return "\n".join(self._stderr_lines[-40:])

    # --------------------------------------------------------------- control

    def start(self, session: CaptureSession) -> bool:
        if self.is_running:
            self.failed.emit("A capture is already running.")
            return False

        exe = dumpcap_path()
        if not exe:
            self.failed.emit(
                "dumpcap was not found on PATH.\n\n"
                "Install it with:  sudo apt install wireshark-common")
            return False

        if session.output_path is None:
            self.failed.emit("No capture output path was set.")
            return False
        try:
            session.output_path.parent.mkdir(parents=True, exist_ok=True)
            if getattr(os, "geteuid", lambda: 0)() == 0:
                # Created as root -> give it to the operator so the dropped
                # dumpcap (and a later unprivileged run) can write there.
                from netlab.config import _own
                _own(session.output_path.parent)
        except OSError as exc:
            self.failed.emit("Cannot create the capture directory:\n%s" % exc)
            return False

        with self._lock:
            self._stderr_lines = []
            self._packets_read = 0
            self._bytes_on_disk = 0
            self._parser_error = None
        self._stop_evt.clear()
        self._stopping = False
        self._session = session

        argv = session.build_argv(exe)
        try:
            self._proc = subprocess.Popen(
                argv, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                text=True, bufsize=1, start_new_session=True,
                preexec_fn=_drop_to_operator())
        except OSError as exc:
            self._proc = None
            self.failed.emit("Could not start dumpcap:\n%s" % exc)
            return False

        self._stderr_thread = threading.Thread(
            target=self._drain_stderr, name="netlab-dumpcap-stderr", daemon=True)
        self._stderr_thread.start()
        self._reader = threading.Thread(
            target=self._tail_file, name="netlab-capture-reader", daemon=True)
        self._reader.start()
        self._watcher = threading.Thread(
            target=self._watch_process, name="netlab-capture-watch", daemon=True)
        self._watcher.start()

        self.started.emit(str(session.output_path))
        self.status.emit("Capturing on %s -> %s" % (
            session.interface, session.output_path.name))
        return True

    def stop(self, timeout: float = 5.0) -> None:
        proc = self._proc
        if proc is None:
            return
        self._stopping = True
        if proc.poll() is None:
            try:
                # SIGINT makes dumpcap flush and close the file cleanly.
                proc.send_signal(signal.SIGINT)
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                try:
                    proc.terminate()
                    proc.wait(timeout=2.0)
                except (subprocess.TimeoutExpired, OSError):
                    try:
                        proc.kill()
                    except OSError:
                        pass
            except OSError:
                pass
        # Let the reader drain whatever dumpcap flushed on its way out.
        time.sleep(0.35)
        self._stop_evt.set()
        if self._reader:
            self._reader.join(timeout=3.0)

    # --------------------------------------------------------------- threads

    def _drain_stderr(self) -> None:
        proc = self._proc
        if proc is None or proc.stderr is None:
            return
        try:
            for line in proc.stderr:
                line = line.rstrip("\n")
                if not line:
                    continue
                with self._lock:
                    self._stderr_lines.append(line)
                low = line.lower()
                if low.startswith("dumpcap:") or "error" in low:
                    self.status.emit(line)
        except (OSError, ValueError):
            pass

    def _tail_file(self) -> None:
        path = self._session.output_path if self._session else None
        if path is None:
            return

        deadline = time.monotonic() + FILE_WAIT_TIMEOUT
        while not path.exists():
            if self._stop_evt.is_set():
                return
            if self._proc is not None and self._proc.poll() is not None:
                return          # dumpcap died before creating the file
            if time.monotonic() > deadline:
                self.failed.emit(
                    "dumpcap did not create the capture file within %.0f s."
                    % FILE_WAIT_TIMEOUT)
                return
            time.sleep(0.05)

        parser = StreamingCaptureParser()
        try:
            fh = open(path, "rb")
        except OSError as exc:
            self.failed.emit("Cannot read the capture file:\n%s" % exc)
            return

        try:
            while True:
                chunk = fh.read(READ_CHUNK)
                if chunk:
                    try:
                        packets = parser.feed(chunk)
                    except CaptureFormatError as exc:
                        with self._lock:
                            self._parser_error = str(exc)
                        self.failed.emit("Capture stream is unreadable: %s" % exc)
                        return
                    if packets:
                        for pkt in packets:
                            self._queue.put(pkt)
                        with self._lock:
                            self._packets_read += len(packets)
                    continue

                try:
                    with self._lock:
                        self._bytes_on_disk = path.stat().st_size
                except OSError:
                    pass

                proc_done = self._proc is None or self._proc.poll() is not None
                if self._stop_evt.is_set() or proc_done:
                    # One final drain so the last flush is not lost.
                    tail = fh.read()
                    if tail:
                        try:
                            packets = parser.feed(tail)
                        except CaptureFormatError:
                            packets = []
                        for pkt in packets:
                            self._queue.put(pkt)
                        with self._lock:
                            self._packets_read += len(packets)
                    if self._stop_evt.is_set():
                        break
                    if proc_done:
                        break
                time.sleep(0.05)
        finally:
            try:
                fh.close()
            except OSError:
                pass

    def _watch_process(self) -> None:
        proc = self._proc
        if proc is None:
            return
        rc = proc.wait()
        if self._stderr_thread:
            self._stderr_thread.join(timeout=1.0)
        time.sleep(0.4)          # let the reader finish its final drain
        self._stop_evt.set()
        if self._reader:
            self._reader.join(timeout=3.0)

        try:
            if self._session and self._session.output_path.exists():
                with self._lock:
                    self._bytes_on_disk = self._session.output_path.stat().st_size
        except OSError:
            pass

        err = self.stderr_text()
        if self._stopping or rc == 0:
            reason = "Capture stopped."
            if "file size limit" in err.lower() or "autostop" in err.lower():
                reason = "Capture stopped: the configured maximum file size was reached."
            self.stopped.emit(reason)
        else:
            self.failed.emit(self._explain_failure(rc, err))
        self.stats_changed.emit()

    def _explain_failure(self, rc: int, err: str) -> str:
        low = err.lower()
        lines = [l for l in err.splitlines() if l.strip()]
        detail = "\n".join(lines[-6:]) if lines else "(no output from dumpcap)"
        iface = self._session.interface if self._session else "the interface"

        if any(h in low for h in _PERMISSION_HINTS):
            return ("Permission denied opening %s.\n\n%s\n\n"
                    "Fix it with:\n"
                    "    sudo dpkg-reconfigure wireshark-common\n"
                    "    sudo usermod -aG wireshark $USER\n"
                    "then log out and back in." % (iface, detail))
        if "no such device" in low or "not found" in low or "no such" in low:
            return ("Interface %s is no longer available.\n\n%s\n\n"
                    "It may have been unplugged, renamed, or brought down. "
                    "Refresh the Interfaces page and pick another one."
                    % (iface, detail))
        if "invalid capture filter" in low or "isn't a valid capture filter" in low:
            return ("The capture filter was rejected by libpcap.\n\n%s" % detail)
        if "is not up" in low:
            return ("Interface %s is down.\n\n%s\n\n"
                    "Bring it up with:  sudo ip link set %s up"
                    % (iface, detail, iface))
        return ("dumpcap exited with status %d.\n\n%s" % (rc, detail))


class FileImporter(QObject):
    """Reads an existing pcap/pcapng file into the analysis queue."""

    progress = Signal(int, int)        # bytes read, total bytes
    finished = Signal(int, str, bool)  # packet count, path, truncated
    failed = Signal(str)

    def __init__(self, queue, parent=None) -> None:
        super().__init__(parent)
        self._queue = queue
        self._thread: threading.Thread | None = None
        self._cancel = threading.Event()

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def cancel(self) -> None:
        self._cancel.set()

    def start(self, path: str | Path) -> bool:
        if self.is_running:
            self.failed.emit("An import is already in progress.")
            return False
        self._cancel.clear()
        self._thread = threading.Thread(target=self._run, args=(Path(path),),
                                        name="netlab-import", daemon=True)
        self._thread.start()
        return True

    def _run(self, path: Path) -> None:
        try:
            total = path.stat().st_size
        except OSError as exc:
            self.failed.emit("Cannot open %s:\n%s" % (path, exc))
            return

        parser = StreamingCaptureParser()
        count = 0
        read = 0
        try:
            with open(path, "rb") as fh:
                while not self._cancel.is_set():
                    chunk = fh.read(READ_CHUNK)
                    if not chunk:
                        break
                    read += len(chunk)
                    try:
                        packets = parser.feed(chunk)
                    except CaptureFormatError as exc:
                        self.failed.emit(
                            "%s is not a readable capture file:\n%s"
                            % (path.name, exc))
                        return
                    for pkt in packets:
                        # Back-pressure: an import must not out-run analysis
                        # and start dropping packets from a finite file.
                        while not self._queue.put(pkt):
                            if self._cancel.is_set():
                                return
                            time.sleep(0.01)
                    count += len(packets)
                    self.progress.emit(read, total)
        except OSError as exc:
            self.failed.emit("Error reading %s:\n%s" % (path.name, exc))
            return

        if self._cancel.is_set():
            self.failed.emit("Import cancelled.")
            return
        if parser.fmt is None:
            self.failed.emit("%s is empty or not a capture file." % path.name)
            return
        # Bytes left in the parser at end of file are a record the capture was
        # cut off in the middle of -- the file is truncated. The complete
        # packets before the cut were still delivered.
        truncated = parser.pending_bytes() > 0
        self.finished.emit(count, str(path), truncated)
