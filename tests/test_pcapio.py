"""Capture container parsing."""

import struct
import tempfile
import unittest
from pathlib import Path

from netlab.capture.pcapio import (CaptureFormatError, RandomAccessCapture,
                                   StreamingCaptureParser, iter_capture_file,
                                   probe_capture_file)
from tests.helpers import eth_ip_tcp, pcap_file, pcapng_file

FRAMES = [(1_700_000_000.5, 74, eth_ip_tcp(sport=1000 + i, payload=b"x" * i))
          for i in range(5)]


class TestPcapParsing(unittest.TestCase):
    def test_pcap_roundtrip(self):
        blob = pcap_file(FRAMES)
        parser = StreamingCaptureParser()
        packets = parser.feed(blob)
        self.assertEqual(parser.fmt, "pcap")
        self.assertEqual(len(packets), len(FRAMES))
        for got, (ts, wirelen, data) in zip(packets, FRAMES):
            self.assertAlmostEqual(got.ts, ts, places=5)
            self.assertEqual(got.wirelen, wirelen)
            self.assertEqual(got.data, data)

    def test_pcapng_roundtrip(self):
        blob = pcapng_file(FRAMES)
        parser = StreamingCaptureParser()
        packets = parser.feed(blob)
        self.assertEqual(parser.fmt, "pcapng")
        self.assertEqual(len(packets), len(FRAMES))
        for got, (ts, _wirelen, data) in zip(packets, FRAMES):
            self.assertAlmostEqual(got.ts, ts, places=5)
            self.assertEqual(got.data, data)

    def test_nanosecond_pcap(self):
        blob = pcap_file(FRAMES, nano=True)
        packets = StreamingCaptureParser().feed(blob)
        self.assertAlmostEqual(packets[0].ts, FRAMES[0][0], places=6)

    def test_pcapng_nanosecond_resolution(self):
        blob = pcapng_file(FRAMES, tsresol=9)
        packets = StreamingCaptureParser().feed(blob)
        self.assertAlmostEqual(packets[0].ts, FRAMES[0][0], places=6)

    def test_byte_at_a_time_is_identical(self):
        """A record split across reads must not be lost or duplicated."""
        for blob in (pcap_file(FRAMES), pcapng_file(FRAMES)):
            parser = StreamingCaptureParser()
            packets = []
            for i in range(len(blob)):
                packets.extend(parser.feed(blob[i:i + 1]))
            self.assertEqual(len(packets), len(FRAMES))
            self.assertEqual([p.data for p in packets],
                             [f[2] for f in FRAMES])

    def test_partial_trailing_record_is_held(self):
        blob = pcap_file(FRAMES)
        parser = StreamingCaptureParser()
        first = parser.feed(blob[:-20])
        self.assertEqual(len(first), len(FRAMES) - 1)
        rest = parser.feed(blob[-20:])
        self.assertEqual(len(rest), 1)

    def test_bad_magic_is_rejected(self):
        parser = StreamingCaptureParser()
        with self.assertRaises(CaptureFormatError):
            parser.feed(b"not a capture file at all, really")

    def test_absurd_record_length_is_rejected(self):
        blob = bytearray(pcap_file(FRAMES))
        struct.pack_into("<I", blob, 24 + 8, 0x7FFFFFFF)
        with self.assertRaises(CaptureFormatError):
            StreamingCaptureParser().feed(bytes(blob))

    def test_truncated_pcapng_block_is_counted_not_fatal(self):
        blob = bytearray(pcapng_file(FRAMES))
        # Corrupt one EPB's capture length so its body runs past the block.
        shb_len = struct.unpack_from("<I", blob, 4)[0]
        idb_len = struct.unpack_from("<I", blob, shb_len + 4)[0]
        epb = shb_len + idb_len
        struct.pack_into("<I", blob, epb + 8 + 12, 0xFFFF)
        parser = StreamingCaptureParser()
        packets = parser.feed(bytes(blob))
        self.assertEqual(len(packets), len(FRAMES) - 1)
        self.assertEqual(parser.malformed_blocks, 1)

    def test_offsets_allow_random_access(self):
        for builder, suffix in ((pcap_file, ".pcap"), (pcapng_file, ".pcapng")):
            with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as fh:
                fh.write(builder(FRAMES))
                path = Path(fh.name)
            try:
                reader = RandomAccessCapture(path)
                for packet in iter_capture_file(path):
                    again = reader.read_at(packet.offset)
                    self.assertIsNotNone(again)
                    self.assertEqual(again.data, packet.data)
                    self.assertAlmostEqual(again.ts, packet.ts, places=5)
                info = probe_capture_file(path)
                self.assertEqual(info["format"], suffix.lstrip("."))
                self.assertEqual(info["linktype"], 1)
            finally:
                path.unlink()

    def test_empty_stream_yields_nothing(self):
        parser = StreamingCaptureParser()
        self.assertEqual(parser.feed(b""), [])
        self.assertIsNone(parser.fmt)


if __name__ == "__main__":
    unittest.main()
