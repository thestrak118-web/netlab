"""NetLab must still IMPORT on Windows (no uid model, no pwd/grp/fcntl), so the
PyInstaller build launches as an offline analyser. The live/privileged features
are Linux-only and refuse at runtime; here we only guard import-time breakage.
"""
import builtins
import importlib
import os

import pytest


@pytest.fixture
def windows_like(monkeypatch):
    """Simulate a Windows interpreter: hide the POSIX-only os.* uid calls and
    make pwd/grp/fcntl/termios/resource unimportable."""
    for name in ("geteuid", "getuid", "getgid", "getgroups", "getegid", "chown"):
        monkeypatch.delattr(os, name, raising=False)
    real_import = builtins.__import__

    def guard(name, *a, **k):
        if name in ("pwd", "grp", "fcntl", "termios", "resource"):
            raise ImportError("no %s on Windows" % name)
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", guard)
    yield


def test_config_imports_and_resolves_home_without_uids(windows_like):
    import netlab.config as cfg
    importlib.reload(cfg)
    # config_dir must not blow up without geteuid/pwd (it did before the guard).
    assert cfg.config_dir().name == "netlab"
    uid, gid, home = cfg.real_user()
    assert uid == 0 and gid == 0 and home == cfg.Path.home()


def test_privileges_check_imports_and_runs_without_grp(windows_like):
    import netlab.capture.privileges as priv
    importlib.reload(priv)
    rep = priv.check()                     # must not raise on a uid-less OS
    assert rep.running_as_root is False


def test_app_module_imports_on_windows(windows_like):
    # The GUI entry chain (pages, capture, intercept) must import so PyInstaller
    # can bundle it and the exe can launch.
    import netlab.app as app
    importlib.reload(app)
    assert hasattr(app, "main")
