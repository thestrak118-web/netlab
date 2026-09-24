"""Explicit, bounded local discovery. No packet interception or background scans.

Nmap supplies ARP presence and name protocols; active evidence is labelled and
never increments passive capture counters. Workers return immutable records.
"""
from dataclasses import dataclass
import ipaddress
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import threading
import time
import xml.etree.ElementTree as ET

from PySide6.QtCore import QObject, Signal
from netlab.analyze.devices import Confidence, Evidence, NetworkContext, valid_mac


@dataclass(frozen=True)
class DiscoveredHost:
    ip: str
    mac: str
    evidence: tuple
    ts: float


def clean(value):
    # Nmap escapes UTF-8 bytes in script output; decode without interpreting
    # arbitrary Python escapes or accepting control characters from the LAN.
    value = re.sub(r'(?:\\x[0-9A-Fa-f]{2})+',
                   lambda m: bytes.fromhex(m[0].replace('\\x', '')).decode('utf8', 'replace'), value)
    return ''.join(' ' if c == '\u00a0' else c for c in value if c.isprintable() or c == '\u00a0').strip()[:200]


def parse_discovery(xml, context, ts=None):
    if len(xml) > 16 * 1024 * 1024:
        raise ValueError('Discovery response exceeds 16 MiB')
    ts = time.time() if ts is None else ts
    root = ET.fromstring(xml)
    if root.tag != 'nmaprun':
        raise ValueError('Not an Nmap report')
    records = []
    for host in root.findall('host')[:256]:
        if host.find('status') is None or host.find('status').get('state') != 'up':
            continue
        ip = next((a.get('addr') for a in host.findall('address') if a.get('addrtype') == 'ipv4'), '')
        if not context.on_link(ip) or ip in {a[0] for a in context.addresses}:
            continue
        addr = ipaddress.ip_address(ip)
        if addr.is_multicast or addr.is_unspecified:
            continue
        mac = next((valid_mac(a.get('addr')) for a in host.findall('address') if a.get('addrtype') == 'mac'), None)
        evidence = []
        def add(field, value, source, level=Confidence.OBSERVED):
            value = clean(value)
            if value and value.lower() not in ('unknown', '<unknown>'):
                evidence.append(Evidence(field, value, 'Active discovery: ' + source, level, ts))
        add('IP', ip, 'on-link response on ' + context.interface)
        if mac: add('MAC', mac, 'Nmap on-link address binding')
        for name in host.findall('hostnames/hostname'):
            add('Hostname', name.get('name', ''), 'reverse DNS')
        for script in host.findall('.//script'):
            sid = script.get('id')
            output = script.get('output', '')[:65536]
            if sid == 'dns-service-discovery':
                for field, pattern in [('Hostname', r'^\s*hostname:\s*(.+)$'),
                                       ('Friendly name', r'^\s*name:\s*(.+)$'),
                                       ('Exact device model', r'^\s*(?:model|am)=(.+)$')]:
                    for value in re.findall(pattern, output, re.M):
                        if field == 'Friendly name': value = re.sub(r'^[0-9a-fA-F]{12}@', '', value)
                        add(field, value, 'mDNS/DNS-SD advertisement')
                # Classification uses an explicit advertised model plus product
                # name, not OUI or the presence of an AirPlay port alone.
                models = [e.value for e in evidence if e.field == 'Exact device model']
                names = [e.value for e in evidence if e.field == 'Friendly name']
                if any(m.startswith('Mac') for m in models) and any(n.startswith('MacBook') for n in names):
                    add('Device type', 'Laptop', 'mDNS advertised MacBook name and Mac model')
                if any(m.startswith('iPhone') for m in models):
                    add('Device type', 'Smartphone', 'mDNS advertised iPhone model')
                if any(m.startswith('iPad') for m in models):
                    add('Device type', 'Tablet', 'mDNS advertised iPad model')
            elif sid == 'upnp-info':
                for field, key in [('Friendly name', 'friendlyName'), ('Exact device model', 'modelName'),
                                   ('Manufacturer', 'manufacturer')]:
                    match = re.search(r'^\s*' + key + r':\s*(.+)$', output, re.M)
                    if match: add(field, match[1], 'UPnP device description')
                server = re.search(r'^\s*server:\s*(.+)$', output, re.M)
                if server: add('OS', server[1], 'UPnP advertised server string')
                if 'urn:schemas-upnp-org:device:InternetGatewayDevice:' in output:
                    add('Device type', 'Router', 'UPnP advertised device type')
            elif sid == 'nbstat':
                match = re.search(r'NetBIOS name:\s*([^,\n]+)', output)
                if match: add('Hostname', match[1], 'NetBIOS node status')
        # Fingerprint guesses remain separate from advertised identity and icons.
        for match in host.findall('os/osmatch')[:3]:
            add('OS estimate', match.get('name', '') + ' (' + match.get('accuracy', '?') + '% match)',
                'Nmap fingerprint', Confidence.INFERRED)
        records.append(DiscoveredHost(ip, mac or '', tuple(dict.fromkeys(evidence)), ts))
    return tuple(records)


def discovery_targets(context):
    networks = sorted({str(ipaddress.ip_network(f'{ip}/{prefix}', strict=False))
                       for ip, _, prefix in context.addresses if ':' not in ip})
    if not networks:
        raise ValueError('Selected interface has no IPv4 on-link prefix')
    if sum(ipaddress.ip_network(n).num_addresses for n in networks) > 256:
        raise ValueError('Discovery is limited to 256 on-link IPv4 addresses; choose a smaller network interface')
    return networks


class DiscoveryRunner(QObject):
    progress = Signal(str)
    batch = Signal(int, object, object)
    finished = Signal(str)
    failed = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._thread = None
        self._cancel = threading.Event()
        self._proc = None
        self.report_dir = None

    @property
    def is_running(self):
        return self._thread is not None and self._thread.is_alive()

    def start(self, interface, generation, known_context=None):
        if self.is_running: return False
        self._cancel.clear()
        self._thread = threading.Thread(target=self._run, args=(interface, generation, known_context), daemon=True)
        self._thread.start()
        return True

    def cancel(self):
        self._cancel.set()
        if self._proc and self._proc.poll() is None:
            try: self._proc.terminate()
            except OSError: pass

    def _scan(self, nmap, args, name):
        argv = [nmap, *args, '-oX', '-']
        if os.geteuid() != 0:
            pkexec = shutil.which('pkexec')
            if not pkexec: raise RuntimeError('pkexec is required for local ARP/UDP discovery')
            timeout = shutil.which('timeout')
            if not timeout: raise RuntimeError('The timeout utility is required to bound elevated discovery')
            argv = [pkexec, timeout, '--signal=TERM', '--kill-after=3s', '120s', *argv]
        # The unprivileged parent writes reports, avoiding elevated processes
        # opening user-owned files. Both phases have a wall-clock bound.
        self._proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        deadline = time.monotonic() + 180
        while True:
            try:
                stdout, stderr = self._proc.communicate(timeout=.25)
                break
            except subprocess.TimeoutExpired:
                if self._cancel.is_set() or time.monotonic() > deadline:
                    try: self._proc.terminate()
                    except OSError: pass
                    raise RuntimeError('Discovery cancelled or timed out; any elevated scan is bounded by its Nmap host timeout')
        if self._cancel.is_set(): raise RuntimeError('Discovery cancelled')
        (self.report_dir / (name + '.xml')).write_bytes(stdout)
        (self.report_dir / (name + '.log')).write_bytes(stderr)
        if self._proc.returncode:
            raise RuntimeError(clean(stderr.decode(errors='replace')) or 'Nmap discovery failed')
        return stdout

    def _run(self, interface, generation, known_context):
        try:
            nmap = shutil.which('nmap')
            if not nmap: raise RuntimeError('Nmap is not installed; active discovery is unavailable')
            context = known_context or NetworkContext.discover(interface)
            targets = discovery_targets(context)
            self.report_dir = Path(tempfile.mkdtemp(prefix='netlab-discovery-'))
            self.progress.emit('Finding local devices on ' + ', '.join(targets) + ' — authentication may be required')
            xml = self._scan(nmap, ['-sn', '-PR', '-n', '-e', interface, '--max-retries', '1', '--host-timeout', '8s', *targets], 'presence')
            hosts = parse_discovery(xml, context)
            self.batch.emit(generation, context, hosts)
            if not hosts:
                self.finished.emit('No responding local devices found. Report: ' + str(self.report_dir)); return
            ips = [h.ip for h in hosts][:64]
            self.progress.emit(f'{len(hosts)} local addresses found. Querying advertised names/models for {len(ips)}…')
            xml = self._scan(nmap, ['-sU', '-n', '-e', interface, '-p', '137,1900,5353',
                '--script', 'nbstat,upnp-info,dns-service-discovery', '--script-timeout', '12s',
                '--max-retries', '1', '--host-timeout', '45s', *ips], 'identity')
            enriched = parse_discovery(xml, context)
            self.batch.emit(generation, context, enriched)
            named = sum(any(e.field in ('Hostname', 'Friendly name') for e in h.evidence) for h in enriched)
            if not named and not self._cancel.is_set():
                self.progress.emit('No advertised names received; retrying name protocols once…')
                xml = self._scan(nmap, ['-sU', '-n', '-e', interface, '-p', '137,1900,5353',
                    '--script', 'nbstat,upnp-info,dns-service-discovery', '--script-timeout', '20s',
                    '--script-args', 'dnssd.services={_airplay._tcp.local,_device-info._tcp.local,_googlecast._tcp.local,_ipp._tcp.local,_workstation._tcp.local}',
                    '--max-retries', '1', '--host-timeout', '50s', *ips], 'identity-retry')
                enriched = parse_discovery(xml, context)
                self.batch.emit(generation, context, enriched)
                named = sum(any(e.field in ('Hostname', 'Friendly name') for e in h.evidence) for h in enriched)
            self.finished.emit(f'{len(hosts)} local addresses · {named} named responses. Unadvertised names remain Unknown. Reports: {self.report_dir}')
        except Exception as exc:
            self.failed.emit(str(exc))
        finally:
            self._proc = None
