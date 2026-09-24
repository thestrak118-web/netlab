"""Selected-device monitor contracts, using real analyzer fixtures and Qt widgets."""
import dataclasses
import threading
import time
from pathlib import Path
from unittest.mock import patch
import pytest
from PySide6.QtCore import Qt, QEvent, QPointF
from PySide6.QtGui import QMouseEvent
from PySide6.QtWidgets import QStyleOptionViewItem
from netlab.analyze.monitor import MonitorRegistry, MonitorState, snapshot_for_device
from netlab.analyze.devices import NetworkContext
from netlab.gui.pages.monitor import MonitorPage
from netlab.gui.main_window import MainWindow
from netlab.config import CONFIG
from netlab.capture.pcapio import iter_capture_file
from netlab.analyze.decode import decode
from tests.test_phase3 import app, engine as offline_engine, context
from tests.test_engine import CLIENT, SERVER, build_capture
from tests.helpers import pcapng_file


@pytest.fixture
def engine(offline_engine):
    # Monitoring now requires real local evidence, rather than any seen endpoint.
    offline_engine.hosts.apply_context(context())
    return offline_engine


@pytest.fixture
def monitor(app, engine):
    page = MonitorPage(engine, lambda: None, lambda: True)
    yield page
    page.stop()
    end = time.monotonic()+3
    while page._busy and time.monotonic()<end:
        app.processEvents(); time.sleep(.01)
    page.close()


def wait(app, predicate, timeout=3):
    end=time.monotonic()+timeout
    while time.monotonic()<end:
        app.processEvents()
        if predicate(): return
        time.sleep(.01)
    assert predicate(), 'Qt result did not arrive'


def test_registry_multiple_ready_but_single_selection():
    r=MonitorRegistry(2)
    r.subscribe(CLIENT); r.subscribe(SERVER)
    with pytest.raises(ValueError): r.subscribe('10.0.0.53')
    r.select_one('2001:0db8::1')
    assert list(r.subscriptions)==['2001:db8::1']
    r.clear()
    assert not r.subscriptions


def test_ipv4_exact_filter_direction_and_counters(engine):
    s=snapshot_for_device(engine,CLIENT,1700000000.2)
    assert len(s.activity)==10
    assert all(CLIENT in (r.src,r.dst) for r in s.activity)
    assert {r.direction for r in s.activity}=={'IN','OUT'}
    assert all(r.direction==('OUT' if r.src==CLIENT else 'IN') for r in s.activity)
    assert s.device.packets==10 and s.device.bytes>0
    assert s.device.packets_sec>0 and s.device.bytes_sec>0
    assert not snapshot_for_device(engine,'10.0.0.1').activity
    with pytest.raises(ValueError): snapshot_for_device(engine,SERVER)


def test_ipv6_identity_and_direction(engine):
    from netlab.analyze.engine import PacketRow
    for i,(src,dst) in enumerate([('2001:db8::1','2001:db8::2'),('2001:db8::2','2001:db8::1'),('2001:db8::10','2001:db8::2')]):
        engine.live.append(PacketRow(100+i,1,src,dst,'UDP',123,53,100,'',0,1))
    engine.hosts.apply_context(NetworkContext(interface='wlan0',addresses=(('2001:db8::1','00:11:22:33:44:55',64),)))
    s=snapshot_for_device(engine,'2001:0db8::1',now=2)
    assert s.ip=='2001:db8::1'
    assert [r.direction for r in s.activity]==['OUT','IN']
    assert all(r.destination=='2001:db8::2' for r in s.activity)


def test_dns_http_tls_correlations_and_connection_ids(engine):
    s=snapshot_for_device(engine,CLIENT,1700000000.2)
    assert s.dns and any(SERVER in e.resolved_ips for e in s.dns)
    assert s.http[0].host=='example.test'
    assert s.tls[0].sni=='example.test'
    assert s.counts['dns']==2 and s.counts['http']==1 and s.counts['tls']==1
    assert all(CLIENT in (f.client,f.server) for f in s.connections)
    assert s.http[0].flow_key in s.tls_bytes
    assert s.tls[0].flow_key in s.tls_bytes
    assert all(f.key==engine.flows.get(f.key).key for f in s.connections)
    assert s.http[0].req_has_auth
    assert not any('secret' in str(v).lower() for v in dataclasses.asdict(s.http[0]).values())


def test_snapshot_limits_and_detached_protocol_rows(engine):
    s=snapshot_for_device(engine,CLIENT,1700000000.2,row_limit=1)
    assert len(s.activity)==len(s.dns)==len(s.connections)==1
    assert s.omitted['activity']==9
    old=s.http[0].status
    engine.http_txns.snapshot()[0].status=418
    assert s.http[0].status==old


def test_monitor_select_pause_resume_stop(app,monitor,engine):
    monitor.select_device(CLIENT)
    wait(app,lambda:monitor.snapshot is not None)
    assert monitor.state==MonitorState.MONITORING
    assert monitor.models['Activity'].rowCount()==10
    monitor.buttons['Pause'].click()
    frozen=monitor.snapshot
    engine.hosts.get(CLIENT).pkts_sent+=5
    monitor.refresh(); app.processEvents()
    assert monitor.snapshot is frozen
    monitor.buttons['Resume'].click()
    wait(app,lambda:monitor.snapshot is not frozen)
    assert monitor.snapshot.device.packets==15
    monitor.buttons['Stop Monitoring'].click()
    assert monitor.state==MonitorState.STOPPED
    assert not monitor.registry.subscriptions
    assert monitor.models['Activity'].rowCount()==0
    monitor.buttons['Monitor'].click()
    wait(app,lambda:monitor.snapshot is not None)
    assert monitor.state==MonitorState.MONITORING


def test_pause_rejects_inflight_snapshot(app,monitor,engine):
    monitor.select_device(CLIENT)
    generation=monitor.subscription.generation
    monitor.pause()
    monitor._received(generation,snapshot_for_device(engine,CLIENT),'')
    assert monitor.snapshot is None
    assert monitor.models['Activity'].rowCount()==0


def test_switch_device_rejects_old_snapshot(app,monitor,engine):
    monitor.select_device(CLIENT)
    old=monitor.subscription.generation
    monitor.select_device('10.0.0.53')
    monitor._received(old,snapshot_for_device(engine,CLIENT),'')
    assert monitor.snapshot is None
    assert list(monitor.registry.subscriptions)==[engine.resolve_device('10.0.0.53').identity]
    wait(app,lambda:not monitor._busy)
    monitor.refresh()
    wait(app,lambda:monitor.snapshot is not None)
    assert monitor.snapshot.ip=='10.0.0.53'
    assert all('10.0.0.53' in (r.src,r.dst) for r in monitor.snapshot.activity)


def test_inactive_unknown_and_disappearing(engine,monitor):
    s=snapshot_for_device(engine,CLIENT,1700000031)
    assert s.device.status=='Inactive'
    monitor.selected_ip=CLIENT
    monitor.selected_id=s.identity
    monitor.apply_snapshot(s)
    assert '○ Inactive' in monitor.identity.text()
    engine.hosts.clear()
    monitor.apply_snapshot(snapshot_for_device(engine,CLIENT,previous=s.device))
    assert 'No longer retained' in monitor.identity.text()
    with pytest.raises(ValueError): snapshot_for_device(engine,'192.0.2.222')


def test_mac_changes_do_not_merge_ip_identities(engine):
    hosts=engine.hosts
    first=NetworkContext(addresses=((CLIENT,'00:11:22:33:44:55',24),),ts=1700000000)
    hosts.apply_context(first)
    old=snapshot_for_device(engine,CLIENT,1700000001)
    hosts.apply_context(dataclasses.replace(first,addresses=((CLIENT,'00:11:22:33:44:66',24),),neighbors=(('10.0.0.11','00:11:22:33:44:55'),)))
    new=snapshot_for_device(engine,CLIENT,1700000001)
    assert new.device.ip==old.device.ip==CLIENT
    assert new.device.packets==old.device.packets
    assert '00:11:22:33:44:66' in new.device.mac
    other=snapshot_for_device(engine,'10.0.0.11')
    assert not other.activity and other.device.packets==0


def test_snapshot_runs_off_gui_thread(app,monitor):
    from netlab.gui.pages import monitor as module
    original=module.snapshot_for_device
    threads=[]
    def collect(*args,**kwargs):
        threads.append(threading.get_ident())
        return original(*args,**kwargs)
    with patch.object(module,'snapshot_for_device',collect):
        monitor.select_device(CLIENT)
        wait(app,lambda:monitor.snapshot is not None)
    assert threads and all(t!=threading.get_ident() for t in threads)


def test_selected_pcap_export_preserves_original_bytes(app,engine,tmp_path):
    source=tmp_path/'source.pcapng'; source.write_bytes(pcapng_file(build_capture()))
    target=tmp_path/'selected.pcapng'
    page=MonitorPage(engine,lambda:source,lambda:True)
    page.select_device('10.0.0.53')
    wait(app,lambda:page.snapshot is not None)
    with patch('netlab.gui.pages.monitor.QFileDialog.getSaveFileName',return_value=(str(target),'')):
        page.buttons['Export Device Traffic'].click()
    wait(app,lambda:target.exists() and not page._export_busy)
    actual=list(iter_capture_file(target))
    expected=[]
    for raw in iter_capture_file(source):
        p=decode(raw.data,raw.linktype,raw.ts,raw.wirelen)
        if '10.0.0.53' in (p.src,p.dst):expected.append(raw.data)
    assert actual and [r.data for r in actual]==expected
    page.stop();page.close()


def test_devices_monitor_button_and_connection_navigation(app,engine,tmp_path):
    CONFIG.set('capture_dir',str(tmp_path))
    w=MainWindow(); w.timer.stop();w.analysis.stop()
    w.analysis=engine;w.monitor_page.engine=engine;w.devices_page.engine=engine
    w.connections_page.set_engine(engine)
    w._open_device(CLIENT)
    page=w.devices_page
    row=next(i for i in range(page.model.rowCount()) if page.model.object_at(i).ip==CLIENT)
    index=page.model.index(row,12)
    option=QStyleOptionViewItem(); option.rect=page.table.visualRect(index)
    pos=QPointF(option.rect.center())
    event=QMouseEvent(QEvent.Type.MouseButtonRelease,pos,pos,Qt.MouseButton.LeftButton,Qt.MouseButton.LeftButton,Qt.KeyboardModifier.NoModifier)
    assert page.monitor_delegate.editorEvent(event,page.model,option,index)
    wait(app,lambda:w.monitor_page.snapshot is not None)
    assert w.stack.currentWidget() is w.monitor_page
    assert CLIENT in w.monitor_indicator.text()
    assert not w.monitor_status_icon.pixmap().isNull()
    # Old fixture is inactive by wall clock; inspect its active-at-capture snapshot.
    w.monitor_page.apply_snapshot(snapshot_for_device(engine,CLIENT,1700000000.2))
    index=w.monitor_page.models['Connections'].index(0,0)
    w.monitor_page.tables['Connections'].clicked.emit(index)
    assert w.stack.currentWidget() is w.connections_page
    with patch.object(w.capture,'stop') as stop:
        w.monitor_page.stop()
        stop.assert_not_called()
    assert w.monitor_indicator.text()==''
    with patch.object(w.config,'save'):w.close()


def test_live_counters_follow_existing_ingestion(engine,tmp_path):
    before=snapshot_for_device(engine,CLIENT,1700000001)
    path=tmp_path/'more.pcapng';path.write_bytes(pcapng_file(build_capture()))
    engine.ingest_batch(list(iter_capture_file(path)))
    after=snapshot_for_device(engine,CLIENT,1700000001)
    assert after.device.packets==before.device.packets*2
    assert after.device.bytes==before.device.bytes*2
    assert len(after.activity)==len(before.activity)*2


def test_source_reset_cancels_monitor_and_stale_result(app,monitor,engine):
    monitor.select_device(CLIENT)
    old=monitor.subscription.generation
    monitor.reset()
    monitor._received(old,snapshot_for_device(engine,CLIENT),'')
    assert monitor.selected_ip is None and monitor.snapshot is None
    assert not monitor.registry.subscriptions


def test_closing_gui_does_not_give_widget_ownership_to_worker(app,engine):
    import weakref
    import gc
    from netlab.gui.pages import monitor as module
    entered=threading.Event();release=threading.Event();finished=threading.Event()
    original=module.snapshot_for_device
    def slow(*args,**kwargs):
        entered.set()
        release.wait(3)
        try:return original(*args,**kwargs)
        finally:finished.set()
    with patch.object(module,'snapshot_for_device',slow):
        page=MonitorPage(engine,lambda:None,lambda:False)
        ref=weakref.ref(page)
        page.select_device(CLIENT)
        assert entered.wait(1)
        page.close()
        del page
        gc.collect()
        assert ref() is None, 'worker must not keep the GUI alive or destroy it later'
        release.set()
        assert finished.wait(2)
