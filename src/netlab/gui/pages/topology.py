"""Separated LAN identities and Internet endpoint groups; no fabricated physical map."""
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QPen, QBrush, QPainter, QIcon
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QGraphicsScene, QGraphicsView, QGraphicsRectItem, QGraphicsSimpleTextItem,
    QGraphicsPixmapItem, QTableWidget, QTableWidgetItem, QSplitter)
from netlab.gui.device_icons import device_icon, ICON_DIR
from netlab.util.format import human_bytes


class DeviceNode(QGraphicsRectItem):
    def __init__(self, ip, callback):
        super().__init__(0,0,260,92)
        self.ip=ip;self.callback=callback
        self.setBrush(QBrush(QColor('#172a38')))
        self.setPen(QPen(QColor('#385769')))
        self.setZValue(1)
    def mousePressEvent(self,event):
        self.callback(self.ip)
        super().mousePressEvent(event)


class TopologyPage(QWidget):
    device_selected=Signal(str)
    remote_action=Signal(str,str)

    def __init__(self):
        super().__init__()
        layout=QVBoxLayout(self)
        title=QLabel('Network Topology');title.setObjectName('PageTitle');layout.addWidget(title)
        hint=QLabel('LOCAL DEVICES and INTERNET / REMOTE DESTINATIONS are separate groups.\n'
                    'Dashed lines: verified default routes. Observed communication is listed below; no physical Internet links are inferred.')
        hint.setWordWrap(True);layout.addWidget(hint)
        self.summary=QLabel('Waiting for observations');layout.addWidget(self.summary)
        bar=QHBoxLayout();self.remote_label=QLabel('Select a remote destination to inspect its traffic')
        bar.addWidget(self.remote_label,1);self.remote_ip=None;self.remote_buttons={}
        for name in ('Traffic','Connections'):
            b=QPushButton('View '+name);b.setEnabled(False)
            b.clicked.connect(lambda checked=False,n=name:self.remote_action.emit(n,self.remote_ip))
            self.remote_buttons[name]=b;bar.addWidget(b)
        layout.addLayout(bar)
        self.scene=QGraphicsScene(self);self.view=QGraphicsView(self.scene)
        self.view.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.view.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        self.communications=QTableWidget(0,5)
        self.communications.setHorizontalHeaderLabels(['Source','Destination','Evidence','Packets','Bytes'])
        self.communications.horizontalHeader().setStretchLastSection(True)
        self.communications.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        splitter=QSplitter(Qt.Orientation.Vertical);splitter.addWidget(self.view);splitter.addWidget(self.communications)
        splitter.setSizes([520,200]);layout.addWidget(splitter)
        self.nodes={};self.edges={};self.revisions=0;self.snapshot=None;self._headings=[]
        self._build_headings()

    def _build_headings(self):
        for text,x in [('LOCAL DEVICES',0),('INTERNET / REMOTE DESTINATIONS',760)]:
            item=self.scene.addSimpleText(text);item.setBrush(QBrush(QColor('#67d9e8')));item.setPos(x,-45)
            self._headings.append(item)

    def clear(self):
        self.scene.clear();self.nodes.clear();self.edges.clear();self._headings=[];self._build_headings()
        self.snapshot=None;self.communications.setRowCount(0);self.remote_ip=None
        for b in self.remote_buttons.values():b.setEnabled(False)
        self.summary.setText('Waiting for observations')

    def _remote_selected(self,ip):
        self.remote_ip=ip;self.remote_label.setText('Remote destination: '+ip)
        for b in self.remote_buttons.values():b.setEnabled(True)

    def update_snapshot(self,snapshot):
        self.snapshot=snapshot;self.revisions+=1
        wanted={d.ip for d in snapshot.devices}|{e.ip for e in snapshot.endpoints}
        for ip in set(self.nodes)-wanted:self.scene.removeItem(self.nodes.pop(ip)[0])
        groups=[sorted(snapshot.devices,key=lambda d:(0 if d.device_type=='This Device' else 1 if d.device_type=='Gateway' else 2,d.ip)),
                sorted(snapshot.endpoints,key=lambda e:(-e.bytes,e.ip))]
        for side,items in enumerate(groups):
            for i,d in enumerate(items):
                if d.ip not in self.nodes:
                    node=DeviceNode(d.ip,self._remote_selected if side else self.device_selected.emit)
                    self.scene.addItem(node)
                    icon=QGraphicsPixmapItem(node);icon.setPos(10,16)
                    text=QGraphicsSimpleTextItem(node);text.setPos(48,10);text.setBrush(QBrush(QColor('#e5edf5')))
                    self.nodes[d.ip]=(node,icon,text)
                node,icon,text=self.nodes[d.ip]
                node.callback=self._remote_selected if side else self.device_selected.emit
                node.setPos(side*760+(i%2)*330,(i//2)*130)
                symbol=QIcon(str(ICON_DIR/'internet.svg')) if side else device_icon(d.device_type)
                icon.setPixmap(symbol.pixmap(28,28))
                name=(d.hostname if d.hostname!='Unknown' else 'Remote / unclassified endpoint') if side else (d.device_type if d.device_type in ('This Device','Gateway') else d.display_name)
                if len(name)>28:name=name[:25]+'…'
                address=d.ip if len(d.ip)<29 else d.ip[:26]+'…'
                text.setText(f'{name}\n{address}\n{d.packets} packets · {human_bytes(d.bytes)}')
                node.setToolTip(f'{d.ip}\n{d.hostname}\n'+('View Traffic / Connections — not a local device' if side else '\n'.join(d.addresses)+'\nClick for local device evidence'))
        if self.remote_ip not in {e.ip for e in snapshot.endpoints}:
            self.remote_ip=None
            for b in self.remote_buttons.values():b.setEnabled(False)
        local={d.ip for d in snapshot.devices}
        routes=[e for e in snapshot.edges if e.kind=='route' and e.source in local and e.destination in local]
        wanted_edges={e.key for e in routes}
        for key in set(self.edges)-wanted_edges:
            for item in self.edges.pop(key):self.scene.removeItem(item)
        for e in routes:
            if e.key not in self.edges:
                pen=QPen(QColor('#f3bb63'),2,Qt.PenStyle.DashLine)
                line=self.scene.addLine(0,0,0,0,pen);label=self.scene.addSimpleText('default route')
                label.setBrush(QBrush(QColor('#f3bb63')))
                self.edges[e.key]=(line,label)
            line,label=self.edges[e.key]
            a=self.nodes[e.source][0].sceneBoundingRect().center();b=self.nodes[e.destination][0].sceneBoundingRect().center()
            line.setLine(a.x(),a.y(),b.x(),b.y());label.setPos((a+b)*.5)
            line.setToolTip(e.evidence)
        traffic=[e for e in snapshot.edges if e.kind=='traffic']
        self.communications.setRowCount(len(traffic))
        for row,e in enumerate(traffic):
            for col,value in enumerate((e.source,e.destination,'Observed traffic (logical)',str(e.packets),human_bytes(e.bytes))):
                item=QTableWidgetItem(value);item.setToolTip(e.evidence);self.communications.setItem(row,col,item)
        self.communications.resizeColumnsToContents()
        self.scene.setSceneRect(self.scene.itemsBoundingRect().adjusted(-20,-20,20,20))
        self.summary.setText(f'{len(snapshot.devices)} local devices · {len(snapshot.endpoints)} remote/unclassified endpoints · '
                             f'{len(traffic)} observed communications · {snapshot.omitted_nodes} nodes omitted')
