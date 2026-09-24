"""Streaming export of related packets; original bytes are copied from disk."""
import os
from pathlib import Path
import struct
import tempfile
from netlab.analyze.decode import decode
from netlab.capture.pcapio import iter_capture_file


def block(kind, payload):
    payload += b'\0' * (-len(payload) % 4)
    size = len(payload) + 12
    return struct.pack('<II', kind, size) + payload + struct.pack('<I', size)


def export_device_pcap(source, destination, ip):
    addresses = {ip} if isinstance(ip, str) else set(ip)
    source, destination = Path(source), Path(destination)
    if source.resolve() == destination.resolve():
        raise ValueError('Choose a different output file')
    boundary = source.stat().st_size
    interfaces = {}; count = 0
    fd, temporary = tempfile.mkstemp(prefix='.netlab-export-', dir=destination.parent)
    try:
        with os.fdopen(fd, 'wb') as out:
            out.write(block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1)))
            for raw in iter_capture_file(source):
                if raw.offset >= boundary:
                    break
                pkt = decode(raw.data, raw.linktype, raw.ts, raw.wirelen)
                if not addresses.intersection((pkt.src, pkt.dst)):
                    continue
                if raw.linktype not in interfaces:
                    interfaces[raw.linktype] = len(interfaces)
                    out.write(block(1, struct.pack('<HHI', raw.linktype, 0, 16777216)))
                ticks = round(raw.ts * 1000000)
                out.write(block(6, struct.pack('<IIIII', interfaces[raw.linktype], ticks >> 32,
                    ticks & 0xFFFFFFFF, len(raw.data), raw.wirelen) + raw.data))
                count += 1
        os.replace(temporary, destination)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise
    return count
