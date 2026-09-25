"""Visible live state, evidence details and icons, without fabricated identities."""
from dataclasses import replace
from PySide6.QtCore import Qt
import pytest
from netlab.analyze.engine import Stats
from netlab.gui.pages.devices import DevicesPage
from netlab.gui.pages.hosts import HostsPage
from netlab.gui.device_icons import icon_name, device_icon
from tests.test_phase3 import app, engine
from tests.test_local_devices import configured, V6
from tests.test_engine import CLIENT


@pytest.mark.parametrize('page_type',[DevicesPage,HostsPage])
def test_details_open_automatically_and_live_snapshots_update(app,engine,page_type):
    configured(engine)
    page=page_type();page.engine=engine
    devices=engine.device_view(1700000001)[0]
    page.refresh(devices)
    own=engine.resolve_device(CLIENT,1700000001)
    assert page.selected_identity==own.identity
    assert V6 in page.detail.text.toPlainText()
    assert V6 in page.model.cell(page.model.object_at(0),0)
    assert 'Local evidence' in page.detail.text.toPlainText()
    assert not page.splitter.childrenCollapsible()
    assert page.monitor_button.isEnabled()
    refreshed=tuple(replace(d,packets=d.packets+7,packets_sec=4.2,bytes_sec=500) if d.identity==own.identity else d for d in devices)
    revision=page.revisions
    page.refresh(refreshed)
    assert page.revisions==revision+1
    assert page.selected_identity==own.identity
    d=page.model.object_at(0)
    assert page.model.cell(d,6)==str(own.packets+7)
    assert page.model.cell(d,13)=='4.2'
    assert '4.2' in page.detail.text.toPlainText()
    # The host list keeps only the readable columns visible; Bytes(7),
    # Connections(8) and the per-second rates(13,14) are hidden as detail.
    assert all(not page.table.isColumnHidden(c) for c in (0, 1, 6, 9, 12))
    assert all(page.table.isColumnHidden(c) for c in (7, 8, 13, 14))
    page.close()


def test_capture_state_is_not_faked_by_ui_refresh(app):
    page=HostsPage();stats=Stats(total_packets=77,packets_per_sec=3.5,bytes_per_sec=400)
    page.set_capture_status('live',True,'wlan0',stats,500)
    assert 'LIVE' in page.live_status.text() and 'wlan0' in page.live_status.text()
    assert '3.5' in page.live_status.text()            # live rate reflects real state
    page.set_capture_status('idle',False,'wlan0',stats,500)
    assert 'LIVE' not in page.live_status.text() and 'Stopped' in page.live_status.text()
    page.set_capture_status('offline',False,'wlan0',stats,500)
    assert 'Offline file' in page.live_status.text() and 'LIVE' not in page.live_status.text()
    page.close()


@pytest.mark.parametrize('kind,asset', [('Computer','computer'),('Laptop','laptop'),('Smartphone','smartphone'),('Tablet','tablet'),('Router','router'),('Server','server'),('Printer','printer'),('IoT','iot'),('Unknown','unknown')])
def test_supported_type_icons_render_without_vendor_guess(app,kind,asset):
    assert icon_name(kind)==asset
    assert not device_icon(kind).pixmap(32,32).isNull()
    assert icon_name('Netgear')=='unknown'


def test_unknown_type_explains_missing_classification(app,engine):
    configured(engine);page=HostsPage();page.engine=engine
    page.refresh(engine.device_view()[0]);assert page.select_device('10.0.0.53')
    text=page.detail.text.toPlainText()
    assert 'no verified phone/computer/printer identity' in text
    assert 'A MAC or OUI vendor alone does not establish device type' in text
    page.refresh(())
    assert page.selected_identity is None and not page.monitor_button.isEnabled()
    page.close()
