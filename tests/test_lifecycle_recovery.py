"""Lifecycle regression tests: no real interfaces or kernel state are changed."""

import io
import threading
from unittest.mock import Mock

import pytest

from netlab.capture import wifimon
from netlab.intercept import netcfg
from netlab.intercept.session import InterceptError, InterceptSession
from netlab.priv import helper as helpermod
from tests.test_helper import AUTHORISED


@pytest.mark.parametrize("stop_method", ["cmd_disarm", "shutdown"])
def test_stop_waits_for_inflight_arm(monkeypatch, stop_method):
    entered, release, stopping, stopped = (threading.Event() for _ in range(4))
    sessions, errors = [], []

    class Session:
        def __init__(self, *args, **kwargs):
            self.armed = False
            sessions.append(self)

        def arm(self):
            entered.set()
            assert release.wait(3)
            self.armed = True
            return {"armed": True}

        def disarm(self):
            self.armed = False
            return {"armed": False}

    monkeypatch.setattr(helpermod, "InterceptSession", Session)
    helper = helpermod.Helper(stdin=io.BytesIO(), stdout=io.BytesIO())

    def arm():
        try:
            helper.cmd_arm(AUTHORISED)
        except Exception as exc:
            errors.append(exc)

    def stop():
        stopping.set()
        try:
            getattr(helper, stop_method)()
        except Exception as exc:
            errors.append(exc)
        finally:
            stopped.set()

    starter = threading.Thread(target=arm)
    stopper = threading.Thread(target=stop)
    starter.start()
    try:
        assert entered.wait(2)
        stopper.start()
        assert stopping.wait(2)
        assert not stopped.wait(0.1), "stop returned before arm finished"
    finally:
        release.set()
        starter.join(3)
        if stopper.ident is not None:
            stopper.join(3)
    assert not starter.is_alive() and not stopper.is_alive()
    assert not errors
    assert helper.session is None
    assert not sessions[0].armed
    if stop_method == "shutdown":
        with pytest.raises(InterceptError, match="shutting down"):
            helper.cmd_arm(AUTHORISED)


def test_failed_disarm_is_retained_for_retry():
    helper = helpermod.Helper(stdin=io.BytesIO(), stdout=io.BytesIO())
    session = Mock()
    session.disarm.side_effect = [{"errors": ["restore failed"]}, {"errors": []}]
    helper.session = session
    assert helper.cmd_disarm()["errors"]
    assert helper.session is session
    assert not helper.cmd_disarm()["errors"]
    assert helper.session is None


def test_forwarding_failure_rolls_back_partial_changes(monkeypatch):
    values = {"net.ipv4.ip_forward": "0", "net.ipv6.conf.all.forwarding": "0"}
    original = dict(values)
    monkeypatch.setattr(netcfg, "_sysctl_read", values.get)

    def write(key, value):
        if key.startswith("net.ipv6."):
            return False
        values[key] = value
        return True

    monkeypatch.setattr(netcfg, "_sysctl_write", write)
    kernel = netcfg.KernelState()
    with pytest.raises(netcfg.NetcfgError, match="cannot apply"):
        kernel.enable_forwarding()
    assert not kernel.applied
    kernel.restore()
    assert values == original


def test_forwarding_requires_readback_and_required_keys(monkeypatch):
    monkeypatch.setattr(netcfg, "_sysctl_read", lambda key: "0")
    monkeypatch.setattr(netcfg, "_sysctl_write", lambda *args: True)
    with pytest.raises(netcfg.NetcfgError, match="cannot apply"):
        netcfg.KernelState().enable_forwarding()
    monkeypatch.setattr(netcfg, "_sysctl_read", lambda key: None)
    with pytest.raises(netcfg.NetcfgError, match="cannot read"):
        netcfg.KernelState().enable_forwarding()


def test_session_retains_failed_kernel_restore_for_retry(monkeypatch):
    values = {"net.ipv4.ip_forward": "1"}
    monkeypatch.setattr(netcfg, "_sysctl_read", values.get)
    monkeypatch.setattr(netcfg, "_sysctl_write", lambda *args: False)
    kernel = netcfg.KernelState()
    kernel._saved = {"net.ipv4.ip_forward": "0"}
    # Exercise the real teardown without creating an engagement or touching disk.
    session = InterceptSession.__new__(InterceptSession)
    for name in ("poisoner", "redirects", "dhcp", "dns", "http_proxy", "tls_proxy", "relay"):
        setattr(session, name, None)
    session.kernel = kernel
    report = session._teardown()
    assert report["errors"] and not report["forwarding_restored"]
    assert session.kernel is kernel and not session._teardown_done
    assert kernel._saved == {"net.ipv4.ip_forward": "0"}

    def write(key, value):
        values[key] = value
        return True

    monkeypatch.setattr(netcfg, "_sysctl_write", write)
    report = session._teardown()
    assert not report["errors"] and report["forwarding_restored"]
    assert session.kernel is None and session._teardown_done
    assert values["net.ipv4.ip_forward"] == "0"


def test_monitor_restore_attempts_all_steps_and_reports_errors(monkeypatch):
    calls = []

    def fail(argv, timeout=8):
        calls.append(argv)
        if argv[0] == "iw":
            raise netcfg.NetcfgError("iw unavailable")
        return 1, "", "denied"

    monkeypatch.setattr(netcfg, "_run", fail)
    with pytest.raises(netcfg.NetcfgError, match="restore incomplete"):
        netcfg.monitor_stop("dummy")
    assert len(calls) == 5
    assert calls[-1] == ["nmcli", "device", "connect", "dummy"]


def test_sniff_restores_after_partial_enter_failure():
    leave = Mock()
    with pytest.raises(RuntimeError, match="partial start"):
        wifimon.run_sniff("dummy", 1, "test",
                          enter=Mock(side_effect=RuntimeError("partial start")),
                          leave=leave)
    leave.assert_called_once_with("dummy")


@pytest.mark.parametrize("capture_fails", [True, False])
def test_sniff_never_hides_restore_failure(capture_fails):
    capture = Mock(side_effect=RuntimeError("capture failed") if capture_fails else None)
    with pytest.raises((wifimon.WifiMonError, netcfg.NetcfgError), match="restore failed"):
        wifimon.run_sniff("dummy", 1, "test", enter=Mock(), capture=capture,
                          leave=Mock(side_effect=netcfg.NetcfgError("restore failed")))


def test_helper_retries_failed_monitor_rollback_on_shutdown(monkeypatch):
    helper = helpermod.Helper(stdin=io.BytesIO(), stdout=io.BytesIO())
    monkeypatch.setattr(netcfg, "monitor_start", Mock(side_effect=RuntimeError("partial start")))
    restore = Mock(side_effect=[netcfg.NetcfgError("restore failed"), {"mode": "managed"}])
    monkeypatch.setattr(netcfg, "monitor_stop", restore)
    with pytest.raises(netcfg.NetcfgError, match="restore failed"):
        helper.cmd_wifi_monitor("dummy", reconnect="test")
    assert helper._monitor_iface == "dummy"
    assert not helper.shutdown().get("errors")
    assert helper._monitor_iface == ""
    assert restore.call_count == 2
    with pytest.raises(InterceptError, match="shutting down"):
        helper.cmd_wifi_monitor("dummy")


def test_recovery_ui_keeps_retry_available_and_blocks_next_watch():
    from tests.qtapp import get_app
    from netlab.gui.main_window import MainWindow
    from netlab.gui.pages.mitmpage import MitmPage
    from netlab.config import Config
    get_app()
    page = MitmPage(Config())
    window = Mock()
    window.mitm_page = page
    window._pending_watch_ip = "10.0.0.8"
    report = {"errors": ["sysctl restore failed"], "cleanup_pending": True}
    MainWindow._helper_event(window, "disarmed", report)
    assert window._armed
    assert page.disarm_button.isEnabled()
    assert not page.arm_button.isEnabled()
    assert page.cards["state"]._value.text() == "Recovery needed"
    window._start_watch.assert_not_called()
    MainWindow._helper_event(window, "disarmed", {"errors": []})
    assert not window._armed
    assert page.arm_button.isEnabled()
    assert not page.disarm_button.isEnabled()
    page.deleteLater()


def test_failed_redirect_cleanup_can_be_retried():
    session = InterceptSession.__new__(InterceptSession)
    for name in ("poisoner", "kernel", "dhcp", "dns", "http_proxy", "tls_proxy", "relay"):
        setattr(session, name, None)
    redirects = Mock()
    redirects.destroy.side_effect = [False, True]
    session.redirects = redirects
    assert session._teardown()["cleanup_pending"]
    assert session.redirects is redirects
    assert not session._teardown()["cleanup_pending"]
    assert session.redirects is None


def test_release_versions_match():
    from pathlib import Path
    import tomllib
    from netlab import __version__
    root = Path(__file__).resolve().parents[1]
    project = tomllib.loads((root / "pyproject.toml").read_text())["project"]
    assert project["version"] == __version__
    assert (root / "debian/changelog").read_text().startswith("netlab (%s)" % __version__)
