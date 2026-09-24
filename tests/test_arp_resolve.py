"""resolve_many(): one ARP sweep for a list of hosts, not a resolve apiece.

The frame building and parsing are covered in test_intercept; here we drive
the batching logic over a fake socket, so no real network is touched: every
request is recorded and the replies are handed back through drain().
"""

import netlab.intercept.arp as arp
from netlab.intercept.arp import ARPOP_REPLY, ARPOP_REQUEST, resolve_many


class FakeArpSocket:
    replies: list = []

    def __init__(self, interface, local_mac, local_ip):
        self.requested: list = []
        self._served = False

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def request(self, ip):
        self.requested.append(ip)

    def drain(self, timeout):
        if self._served:
            return []
        self._served = True
        return list(FakeArpSocket.replies)


def _reply(spa, sha):
    # (oper, sha, spa, tha, tpa) -- the shape scan()/resolve_many() unpack.
    return (ARPOP_REPLY, sha, spa, "00:00:00:00:00:00", "0.0.0.0")


def test_empty_list_opens_no_socket(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("a socket was opened for an empty resolve")
    monkeypatch.setattr(arp, "ArpSocket", boom)
    assert resolve_many("eth0", "aa:bb:cc:dd:ee:ff", "10.0.0.2", []) == {}


def test_only_wanted_replies_are_kept(monkeypatch):
    FakeArpSocket.replies = [
        _reply("10.0.0.5", "11:11:11:11:11:11"),
        _reply("10.0.0.6", "22:22:22:22:22:22"),
        _reply("10.0.0.99", "99:99:99:99:99:99"),      # never asked for
        (ARPOP_REQUEST, "33:33:33:33:33:33", "10.0.0.7", "x", "y"),  # not a reply
    ]
    monkeypatch.setattr(arp, "ArpSocket", FakeArpSocket)
    out = resolve_many("eth0", "aa:bb:cc:dd:ee:ff", "10.0.0.2",
                       ["10.0.0.5", "10.0.0.6", "10.0.0.7"], timeout=0.5)
    assert out == {"10.0.0.5": "11:11:11:11:11:11",
                   "10.0.0.6": "22:22:22:22:22:22"}


def test_local_ip_and_duplicates_are_dropped(monkeypatch):
    seen = {}

    class Recorder(FakeArpSocket):
        def __init__(self, *a):
            super().__init__(*a)
            seen["sock"] = self

    Recorder.replies = [_reply("10.0.0.5", "11:11:11:11:11:11")]
    monkeypatch.setattr(arp, "ArpSocket", Recorder)
    resolve_many("eth0", "aa:bb:cc:dd:ee:ff", "10.0.0.2",
                 ["10.0.0.5", "10.0.0.5", "10.0.0.2"], timeout=0.5)
    # local_ip (10.0.0.2) is skipped and the duplicate collapses.
    assert seen["sock"].requested == ["10.0.0.5"]
