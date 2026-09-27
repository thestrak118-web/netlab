"""Auto-watch: selecting a device starts watching it, but only on a real change.

_selected() also runs on every refresh tick for the row that stays selected, so
the trigger must fire on an identity change, never on a refresh of the same
device, and never for this machine.
"""
from types import SimpleNamespace

import pytest

from netlab.gui.pages.devices import DevicesPage


@pytest.fixture(scope="module")
def app():
    from PySide6.QtWidgets import QApplication
    return QApplication.instance() or QApplication([])


def dev(ip, identity=None, device_type="Smartphone"):
    return SimpleNamespace(ip=ip, identity=identity or ip,
                           device_type=device_type)


def test_auto_watch_off_never_fires(app):
    page = DevicesPage()
    fired = []
    page.auto_watch_requested.connect(fired.append)
    page._selected(dev("10.0.0.5"))
    page._auto_watch_fire()
    assert fired == []


def test_auto_watch_fires_once_per_device_change(app):
    page = DevicesPage()
    page.set_auto_watch(True)
    fired = []
    page.auto_watch_requested.connect(fired.append)

    page._selected(dev("10.0.0.5"))
    page._auto_watch_fire()                       # debounce timer would call this
    assert fired == ["10.0.0.5"]

    # A refresh re-selects the same row -> no second arm.
    page._selected(dev("10.0.0.5"))
    page._auto_watch_fire()
    assert fired == ["10.0.0.5"]

    # A different device moves the watch.
    page._selected(dev("10.0.0.9"))
    page._auto_watch_fire()
    assert fired == ["10.0.0.5", "10.0.0.9"]


def test_auto_watch_skips_this_device(app):
    page = DevicesPage()
    page.set_auto_watch(True)
    fired = []
    page.auto_watch_requested.connect(fired.append)
    page._selected(dev("10.0.0.2", device_type="This Device"))
    page._auto_watch_fire()
    assert fired == []


def test_toggle_persists_and_resets_tracking(app):
    page = DevicesPage()
    toggles = []
    page.auto_watch_toggled.connect(toggles.append)
    page.auto_watch_btn.setChecked(True)          # user click emits the signal
    assert toggles == [True]
    # set_auto_watch reflects a stored value WITHOUT re-emitting (no loop).
    toggles.clear()
    page.set_auto_watch(False)
    assert toggles == [] and page.auto_watch_btn.isChecked() is False
