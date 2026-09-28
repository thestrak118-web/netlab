"""When NetLab runs as root (root launcher, for MITM), dumpcap must drop to the
operator or it cannot write the capture file. _drop_to_operator() builds that
preexec, or returns None when it must not drop (unprivileged, or no operator)."""
import os
import pytest
from netlab.capture import engine


def test_no_drop_when_unprivileged(monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 1000, raising=False)
    assert engine._drop_to_operator() is None


def test_no_drop_when_root_shell_has_no_operator(monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr("netlab.config.real_user", lambda: (0, 0, __import__("pathlib").Path("/root")))
    assert engine._drop_to_operator() is None


def test_drops_to_operator_uid_gid_and_groups_when_root(monkeypatch):
    from pathlib import Path
    monkeypatch.setattr(os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr("netlab.config.real_user", lambda: (1000, 1000, Path("/home/op")))
    monkeypatch.setattr(os, "getgrouplist", lambda name, gid: [1000, 108], raising=False)
    calls = {}
    monkeypatch.setattr(os, "setgroups", lambda g: calls.__setitem__("groups", g), raising=False)
    monkeypatch.setattr(os, "setgid", lambda g: calls.__setitem__("gid", g), raising=False)
    monkeypatch.setattr(os, "setuid", lambda u: calls.__setitem__("uid", u), raising=False)
    pre = engine._drop_to_operator()
    assert callable(pre)
    pre()
    assert calls == {"groups": [1000, 108], "gid": 1000, "uid": 1000}  # wireshark (108) kept
