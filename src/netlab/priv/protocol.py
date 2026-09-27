"""The line protocol between the NetLab GUI and its privileged helper.

One JSON object per line, in both directions.  Requests carry an `id` and
come back as a reply with the same `id`; anything with an `event` key is
unsolicited and may arrive at any time, including in the middle of a slow
command, because a scan that is finding hosts should show them as it goes.

Keeping this to stdin/stdout rather than a socket is deliberate: there is no
path to guess, no permissions to get wrong, and when the GUI dies the pipe
closes, which is the helper's signal to put the network back and exit.
"""

from __future__ import annotations

import json

PROTOCOL_VERSION = 1
MAX_LINE = 8 * 1024 * 1024


class ProtocolError(Exception):
    pass


class HelperError(Exception):
    """The helper refused or failed a command."""

    def __init__(self, message: str, kind: str = "error") -> None:
        super().__init__(message)
        self.kind = kind


def encode(obj: dict) -> bytes:
    line = json.dumps(obj, default=_fallback, separators=(",", ":"))
    if len(line) > MAX_LINE:
        line = json.dumps({"event": "log", "data": {
            "level": "error",
            "message": "a message of %d bytes was too large to send" % len(line)
        }})
    return line.encode("utf-8") + b"\n"


def decode(line) -> dict:
    if isinstance(line, bytes):
        line = line.decode("utf-8", "replace")
    line = line.strip()
    if not line:
        raise ProtocolError("empty line")
    try:
        obj = json.loads(line)
    except ValueError as exc:
        raise ProtocolError("not JSON: %s" % exc) from exc
    if not isinstance(obj, dict):
        raise ProtocolError("expected an object")
    return obj


def _fallback(obj):
    if isinstance(obj, (bytes, bytearray)):
        return obj.hex()
    if isinstance(obj, set):
        return sorted(obj)
    return str(obj)


def request(req_id: int, command: str, **args) -> dict:
    return {"id": req_id, "cmd": command, "args": args}


def reply(req_id: int, result) -> dict:
    return {"id": req_id, "ok": True, "result": result}


def failure(req_id: int, message: str, kind: str = "error") -> dict:
    return {"id": req_id, "ok": False, "error": message, "kind": kind}


def event(name: str, data: dict) -> dict:
    return {"event": name, "data": data}


# Commands the helper accepts.  Anything else is refused by name, so a
# malformed or hostile line cannot reach an arbitrary attribute.
COMMANDS = (
    "hello", "interfaces", "iface", "gateway", "arp_scan", "resolve",
    "arm", "disarm", "status", "add_target", "remove_target",
    "changer_rules", "dns_rules", "promisc_scan", "ca_info", "credentials",
    "files", "wifi_monitor", "wifi_managed", "shutdown",
)
