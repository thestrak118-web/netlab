"""Shared test setup.

The HTTP parser's "retain credential values" switch is a module-level global
(`netlab.analyze.http.set_retain_sensitive`). One test turning harvesting on --
or a persisted config that has it on -- must not leak into another test's
privacy assertion, so it is reset to the redacted default before every test.
A test that needs it on turns it on itself.
"""

import pytest


@pytest.fixture(autouse=True)
def _isolate_config(tmp_path_factory, monkeypatch):
    """Never let a test touch the operator's real ~/.config/netlab/config.json.

    Tests set throwaway values (e.g. a tmp capture_dir); a code path that then
    calls CONFIG.save() would persist that garbage to the real file -- which is
    exactly how a pytest tmp dir once ended up as the live capture directory.
    Redirect saves to a tmp dir and snapshot/restore the in-memory singleton so
    nothing leaks between tests or onto disk."""
    from netlab import config as cfgmod
    d = tmp_path_factory.mktemp("netlab-config-iso")
    # Redirect only the SAVE target (config_path), not config_dir/xdg logic,
    # so tests that assert on config_dir()/XDG still see the real thing.
    monkeypatch.setattr(cfgmod, "config_path", lambda: d / "config.json")
    try:
        snapshot = dict(cfgmod.CONFIG._data)
    except Exception:
        snapshot = None
    yield
    if snapshot is not None:
        with cfgmod.CONFIG._lock:
            cfgmod.CONFIG._data.clear()
            cfgmod.CONFIG._data.update(snapshot)


@pytest.fixture(autouse=True)
def _reset_retain_sensitive():
    try:
        from netlab.analyze import http as httpmod
        httpmod.set_retain_sensitive(False)
    except Exception:
        pass
    yield
    try:
        from netlab.analyze import http as httpmod
        httpmod.set_retain_sensitive(False)
    except Exception:
        pass
