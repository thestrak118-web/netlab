"""Body text survives worst-case fragmentation and de-chunking.

The `http_fragmented.pcapng` fixture proves the metadata (byte counts, chunk
count, completeness) reassembles; this proves the actual body *content* does
too. It feeds the fixture's exact request and response one byte at a time --
the harshest fragmentation possible -- through the stream parser's body hook
and checks the bytes that come out, including a chunked body de-chunked back
to its plain text.
"""

import unittest

from netlab.analyze.http import HttpStreamParser

# The exact messages in tests/fixtures/http_fragmented.pcapng (confirmed with
# tshark): a length-delimited request body and a 3-chunk response body.
REQUEST = (
    b"POST /upload HTTP/1.1\r\n"
    b"Host: fragment.test\r\n"
    b"User-Agent: netlab-frag/1.0\r\n"
    b"Cookie: should-not-be-stored\r\n"
    b"Content-Type: text/plain\r\n"
    b"Content-Length: 26\r\n\r\n"
    b"abcdefghijklmnopqrstuvwxyz")

RESPONSE = (
    b"HTTP/1.1 200 OK\r\n"
    b"Server: netlab-frag-server\r\n"
    b"Content-Type: application/json\r\n"
    b"Set-Cookie: session=should-not-be-stored\r\n"
    b"Transfer-Encoding: chunked\r\n\r\n"
    b"5\r\nhello\r\n6\r\n world\r\n4\r\n!!!!\r\n0\r\n\r\n")


def _parse_one_byte_at_a_time(raw):
    """Feed `raw` a single byte per call and collect the delivered body."""
    body = bytearray()
    ends = []
    parser = HttpStreamParser(
        65536,
        on_body_data=lambda msg, chunk: body.extend(chunk),
        on_body_end=lambda msg, n, chunks, transfer, complete, gap:
            ends.append({"bytes": n, "chunks": chunks, "transfer": transfer,
                         "complete": complete, "gap": gap}))
    for byte in raw:
        parser.feed(bytes([byte]))
    return bytes(body), ends


class TestBodyTextReassembly(unittest.TestCase):
    def test_length_delimited_request_body_text(self):
        body, ends = _parse_one_byte_at_a_time(REQUEST)
        self.assertEqual(body, b"abcdefghijklmnopqrstuvwxyz")
        self.assertEqual(len(ends), 1)
        self.assertEqual(ends[0]["bytes"], 26)
        self.assertEqual(ends[0]["transfer"], "length")
        self.assertTrue(ends[0]["complete"])
        self.assertFalse(ends[0]["gap"])

    def test_chunked_response_body_is_dechunked_to_plain_text(self):
        body, ends = _parse_one_byte_at_a_time(RESPONSE)
        # Three chunks (hello / " world" / "!!!!") reassembled to one string,
        # with the chunk framing stripped.
        self.assertEqual(body, b"hello world!!!!")
        self.assertEqual(len(ends), 1)
        self.assertEqual(ends[0]["bytes"], 15)
        self.assertEqual(ends[0]["chunks"], 3)
        self.assertEqual(ends[0]["transfer"], "chunked")
        self.assertTrue(ends[0]["complete"])
        self.assertFalse(ends[0]["gap"])

    def test_chunk_framing_bytes_never_reach_the_body(self):
        body, _ = _parse_one_byte_at_a_time(RESPONSE)
        # The size lines and their CRLFs must not leak into the body text.
        for framing in (b"\r\n", b"5", b"6", b"4", b"0"):
            self.assertNotIn(b"\r\n", body)
        self.assertNotIn(b"6 world", body)


if __name__ == "__main__":
    unittest.main()
