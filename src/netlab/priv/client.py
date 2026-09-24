"""The GUI's end of the helper pipe.

The window never opens a raw socket, never writes a sysctl and never shells
out to nft.  It starts one privileged helper through pkexec, talks to it over
that process's stdin and stdout, and turns what comes back into Qt signals.

Two consequences are deliberate.  The password prompt happens once, at the
moment the operator asks for something privileged, not at application start.
And when this process dies for any reason the pipe closes, which the helper
treats as its cue to restore the network -- so a crashed GUI cannot leave a
subnet poisoned.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import sys
import threading
from pathlib import Path

from PySide6.QtCore import QObject, Signal

from netlab.priv import protocol

log = logging.getLogger("netlab.helper.client")

PKEXEC = "pkexec"
HELPER_NAME = "netlab-helper"


def helper_command() -> list[str] | None:
    """How to start the helper, privileged, on this installation."""
    installed = shutil.which(HELPER_NAME)
    if installed:
        return [installed]
    # An uninstalled checkout: run the module file by absolute path, which is
    # what pkexec needs anyway.
    script = Path(__file__).resolve().parent / "helper.py"
    if script.is_file():
        return [sys.executable, str(script)]
    return None


def launch_command() -> tuple[list[str] | None, str]:
    base = helper_command()
    if base is None:
        return None, "the NetLab helper is not installed"
    if os.geteuid() == 0:
        return base, "already root"
    if not shutil.which(PKEXEC):
        return None, ("pkexec is not installed, so NetLab cannot raise "
                      "privileges; install policykit-1 or run netlab as root")
    return [PKEXEC] + base, "pkexec"


class HelperClient(QObject):
    """Starts, drives and supervises one privileged helper process."""

    ready = Signal(dict)                 # helper hello
    event = Signal(str, dict)            # unsolicited event
    replied = Signal(int, bool, object)  # request id, ok, result or error
    closed = Signal(str)                 # reason
    failed = Signal(str)                 # could not start

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.process: subprocess.Popen | None = None
        self.info: dict = {}
        self._id = 0
        self._lock = threading.Lock()
        self._pending: dict[int, object] = {}
        self._reader: threading.Thread | None = None
        self._stderr: threading.Thread | None = None
        self._stderr_tail: list[str] = []
        self._closing = False

    # ----------------------------------------------------------- lifecycle

    @property
    def running(self) -> bool:
        return bool(self.process and self.process.poll() is None)

    def start(self) -> bool:
        if self.running:
            return True
        argv, how = launch_command()
        if argv is None:
            self.failed.emit(how)
            return False
        self._closing = False
        self._stderr_tail = []
        try:
            self.process = subprocess.Popen(
                argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, bufsize=0, close_fds=True)
        except OSError as exc:
            self.failed.emit("cannot start the NetLab helper: %s" % exc)
            return False
        log.debug("helper started via %s: %s", how, argv)
        self._reader = threading.Thread(target=self._read, name="helper-read",
                                        daemon=True)
        self._reader.start()
        self._stderr = threading.Thread(target=self._read_stderr,
                                        name="helper-err", daemon=True)
        self._stderr.start()
        return True

    def stop(self, timeout: float = 6.0) -> None:
        """Ask the helper to disarm and exit, then make sure it did."""
        self._closing = True
        process, self.process = self.process, None
        if process is None:
            return
        try:
            if process.poll() is None and process.stdin:
                process.stdin.write(protocol.encode(
                    protocol.request(self._next_id(), "shutdown")))
                process.stdin.flush()
                process.stdin.close()
        except (OSError, ValueError):
            pass
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            log.warning("helper did not exit; terminating")
            process.terminate()
            try:
                process.wait(timeout=3.0)
            except subprocess.TimeoutExpired:    # pragma: no cover
                process.kill()

    # --------------------------------------------------------------- calls

    def _next_id(self) -> int:
        with self._lock:
            self._id += 1
            return self._id

    def call(self, command: str, **args) -> int:
        """Send a command; the answer arrives on `replied`. Returns its id."""
        if not self.running:
            raise protocol.HelperError("the NetLab helper is not running",
                                       "not-running")
        req_id = self._next_id()
        payload = protocol.encode(protocol.request(req_id, command, **args))
        process = self.process
        try:
            with self._lock:
                process.stdin.write(payload)
                process.stdin.flush()
        except (OSError, ValueError) as exc:
            raise protocol.HelperError(
                "the helper pipe closed: %s" % exc, "closed") from exc
        return req_id

    def call_sync(self, command: str, timeout: float = 30.0, **args):
        """Send a command and wait for its answer. Raises on failure."""
        done = threading.Event()
        box: dict = {}

        def capture(req_id: int, ok: bool, payload) -> None:
            if req_id != wanted:
                return
            box["ok"], box["payload"] = ok, payload
            done.set()

        self.replied.connect(capture)
        try:
            wanted = self.call(command, **args)
            if not done.wait(timeout):
                raise protocol.HelperError(
                    "the helper did not answer '%s' within %gs"
                    % (command, timeout), "timeout")
        finally:
            try:
                self.replied.disconnect(capture)
            except (RuntimeError, TypeError):    # pragma: no cover
                pass
        if not box.get("ok"):
            raise protocol.HelperError(str(box.get("payload")
                                           or "the helper refused"), "refused")
        return box.get("payload")

    # --------------------------------------------------------------- reads

    def _read(self) -> None:
        process = self.process
        if process is None or process.stdout is None:
            return
        for raw in process.stdout:
            try:
                message = protocol.decode(raw)
            except protocol.ProtocolError:
                continue
            if "event" in message:
                name = str(message.get("event"))
                data = message.get("data") or {}
                if name == "ready":
                    self.info = data
                    self.ready.emit(data)
                self.event.emit(name, data)
                continue
            req_id = int(message.get("id", 0))
            if message.get("ok"):
                self.replied.emit(req_id, True, message.get("result"))
            else:
                self.replied.emit(req_id, False, message.get("error", ""))
        code = process.poll()
        reason = self._exit_reason(code)
        if not self._closing:
            self.closed.emit(reason)

    def _read_stderr(self) -> None:
        process = self.process
        if process is None or process.stderr is None:
            return
        for line in process.stderr:
            text = line.decode("utf-8", "replace").rstrip()
            if not text:
                continue
            self._stderr_tail = (self._stderr_tail + [text])[-20:]
            log.debug("helper stderr: %s", text)

    def _exit_reason(self, code) -> str:
        if code == 126 or code == 127:
            return ("the privilege prompt was dismissed, or pkexec refused "
                    "to start the helper")
        tail = " / ".join(self._stderr_tail[-3:])
        if code:
            return "the helper exited with status %s%s" % (
                code, (": " + tail) if tail else "")
        return "the helper exited"
