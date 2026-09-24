#!/usr/bin/python3
"""Real GUI/discovery acceptance, using the installed or selected source build."""
import dataclasses
import json
from pathlib import Path
import sys
import time
from PySide6.QtWidgets import QApplication
from netlab.config import CONFIG
from netlab.gui import theme
from netlab.gui.main_window import MainWindow
import netlab

out=Path(sys.argv[1]);out.mkdir(parents=True,exist_ok=True)
original_config=CONFIG.as_dict()
if '/validation/discovery-release/' in str(original_config.get('capture_dir','')):
 original_config['capture_dir']=''
CONFIG.set('capture_dir',str(out));CONFIG.set('bpf_filter','')
app=QApplication([]);app.setStyleSheet(theme.STYLESHEET)
w=MainWindow();w.resize(1820,1050);w.show()
errors=[];messages=[];stops=[]
w.capture.stopped.connect(stops.append)
w.capture.failed.connect(errors.append)
w.discovery.failed.connect(errors.append)
w.discovery.finished.connect(messages.append)
result={'version':netlab.__version__,'module':netlab.__file__,'platform':app.platformName()}
beats=[]
from PySide6.QtCore import QTimer
heartbeat=QTimer();heartbeat.timeout.connect(lambda:beats.append(time.monotonic()));heartbeat.start(100)
def pump(): app.processEvents();time.sleep(.01)
def wait(predicate,seconds=40):
 end=time.monotonic()+seconds
 while time.monotonic()<end:
  pump()
  if errors: raise RuntimeError(errors)
  if predicate(): return
 raise TimeoutError('Acceptance condition timed out')
try:
 idx=w.iface_combo.findData('wlan0');assert idx>=0
 w.iface_combo.setCurrentIndex(idx);w.bpf_edit.setText('');w.start_btn.click()
 wait(lambda:w.capture.is_running and bool(w.analysis.hosts.context.addresses))
 w._goto('Devices');wait(lambda:w.devices_page.model.rowCount()>0)
 before=w.analysis.stats().total_packets
 w.devices_page.discover_button.click()
 wait(lambda:bool(messages),480)
 wait(lambda:not w.discovery.is_running)
 wait(lambda:w.analysis.stats().total_packets>before)
 devices=w.analysis.device_view()[0]
 result['devices']=[dataclasses.asdict(d) for d in devices]
 result['discovery_messages']=messages
 result['discovery_reports']=str(w.discovery.report_dir)
 result['capture_continued']=w.capture.is_running
 result['packet_counts']=[before,w.analysis.stats().total_packets]
 result['heartbeat_count']=len(beats)
 result['max_gui_heartbeat_gap']=max((b-a for a,b in zip(beats,beats[1:])),default=0)
 assert any(d.model!='Unknown' for d in devices),'No actual advertised model received'
 assert all(d.monitor_eligible for d in devices)
 assert len(devices)<40, 'ARP probe targets incorrectly became devices'
 result['device_count']=len(devices)
 own=[d for d in devices if d.device_type=='This Device'];assert len(own)==1
 result['own_addresses']=own[0].addresses
 w.devices_page.refresh(devices)
 named=next(d for d in devices if d.model!='Unknown' and d.device_type!='Gateway') if any(d.model!='Unknown' and d.device_type!='Gateway' for d in devices) else next(d for d in devices if d.model!='Unknown')
 w._goto('Devices')
 w.devices_page.select_device(named.ip)
 assert named.model in w.devices_page.detail.text.toPlainText()
 w.devices_page.table.scrollToTop()
 pump()
 w._goto('Devices')
 assert w.stack.currentWidget() is w.devices_page
 assert w.grab().save(str(out/'devices-discovered.png'))
 w.devices_page.monitor_button.click();wait(lambda:w.stack.currentWidget() is w.monitor_page)
 assert w.capture.is_running
 result['monitor_opened']=True
 assert w.grab().save(str(out/'selected-device.png'))
 w._goto('Topology');pump();assert w.grab().save(str(out/'topology.png'))
 result['capture_path']=str(w._source_path)
 result['success']=True
finally:
 w.discovery.cancel()
 if w.capture.is_running:
  w.stop_capture()
  end=time.monotonic()+8
  while w.capture.is_running and time.monotonic()<end:pump()
 result['errors']=errors
 result['capture_stop_events']=stops
 result['capture_stderr']=w.capture.stderr_text()
 (out/'acceptance.json').write_text(json.dumps(result,indent=2,default=str))
 CONFIG.update(original_config)
 w.close();app.processEvents()
 print(json.dumps({k:v for k,v in result.items() if k!='devices'},indent=2))
