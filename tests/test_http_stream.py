"""HTTP parsing over reassembled streams: splitting, chunking and gaps."""

import unittest

from netlab.analyze.http import HttpStreamParser

REQ = (b"POST /submit HTTP/1.1\r\n"
       b"Host: example.test\r\n"
       b"User-Agent: netlab-tests/2.0\r\n"
       b"Content-Type: application/x-www-form-urlencoded\r\n"
       b"Content-Length: 11\r\n"
       b"Cookie: secret=never-stored\r\n"
       b"Authorization: Bearer never-stored\r\n"
       b"\r\n"
       b"a=1&b=2&c=3")

RESP = (b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/html; charset=utf-8\r\n"
        b"Content-Length: 13\r\n"
        b"Server: netlab-test\r\n"
        b"\r\n"
        b"<html></html>")

CHUNKED = (b"HTTP/1.1 200 OK\r\n"
           b"Content-Type: application/json\r\n"
           b"Transfer-Encoding: chunked\r\n"
           b"\r\n"
           b"5\r\nhello\r\n"
           b"6\r\n world\r\n"
           b"3\r\n!!!\r\n"
           b"0\r\n\r\n")


class Collector:
    def __init__(self):
        self.messages = []
        self.bodies = []

    def on_message(self, msg, parser):
        self.messages.append(msg)

    def on_body_end(self, msg, nbytes, chunks, transfer, complete, gap):
        self.bodies.append(dict(msg=msg, bytes=nbytes, chunks=chunks,
                                transfer=transfer, complete=complete, gap=gap))


def run(data_chunks, limit=65536):
    c = Collector()
    p = HttpStreamParser(limit, c.on_message, c.on_body_end)
    for chunk in data_chunks:
        p.feed(chunk)
    return p, c


def split_every(blob, n):
    return [blob[i:i + n] for i in range(0, len(blob), n)]


class TestWholeMessages(unittest.TestCase):
    def test_request_with_body(self):
        p, c = run([REQ])
        self.assertEqual(len(c.messages), 1)
        msg = c.messages[0]
        self.assertEqual(msg.method, "POST")
        self.assertEqual(msg.target, "/submit")
        self.assertEqual(msg.headers["host"], "example.test")
        self.assertEqual(c.bodies[0]["bytes"], 11)
        self.assertEqual(c.bodies[0]["transfer"], "length")
        self.assertTrue(c.bodies[0]["complete"])

    def test_response_with_body(self):
        p, c = run([RESP])
        msg = c.messages[0]
        self.assertEqual(msg.status, 200)
        self.assertEqual(msg.headers["content-type"], "text/html; charset=utf-8")
        self.assertEqual(c.bodies[0]["bytes"], 13)

    def test_credentials_are_never_stored(self):
        p, c = run([REQ])
        msg = c.messages[0]
        self.assertTrue(msg.has_auth_header)
        self.assertTrue(msg.has_cookie_header)
        self.assertNotIn("authorization", msg.headers)
        self.assertNotIn("cookie", msg.headers)
        self.assertNotIn("never-stored", repr(msg))


class TestSplitAcrossSegments(unittest.TestCase):
    def test_headers_split_at_every_byte_boundary(self):
        """The result must not depend on where the stream was cut."""
        for size in (1, 2, 3, 7, 13, 64, 200):
            p, c = run(split_every(REQ, size))
            self.assertEqual(len(c.messages), 1, "split size %d" % size)
            self.assertEqual(c.messages[0].method, "POST")
            self.assertEqual(c.messages[0].headers["host"], "example.test")
            self.assertEqual(c.bodies[0]["bytes"], 11)
            self.assertTrue(c.bodies[0]["complete"])

    def test_header_terminator_split_across_segments(self):
        head, body = REQ.split(b"\r\n\r\n")
        chunks = [head + b"\r\n", b"\r\n" + body]
        p, c = run(chunks)
        self.assertEqual(len(c.messages), 1)
        self.assertEqual(c.bodies[0]["bytes"], 11)

    def test_body_split_across_segments(self):
        head, body = RESP.split(b"\r\n\r\n")
        p, c = run([head + b"\r\n\r\n", body[:4], body[4:9], body[9:]])
        self.assertEqual(c.bodies[0]["bytes"], 13)
        self.assertTrue(c.bodies[0]["complete"])

    def test_pipelined_messages_in_one_buffer(self):
        p, c = run([REQ + REQ + REQ])
        self.assertEqual(len(c.messages), 3)
        self.assertEqual([b["bytes"] for b in c.bodies], [11, 11, 11])

    def test_two_messages_split_across_one_boundary(self):
        blob = RESP + RESP
        p, c = run([blob[:20], blob[20:]])
        self.assertEqual(len(c.messages), 2)


class TestChunked(unittest.TestCase):
    def test_chunked_body_metadata(self):
        p, c = run([CHUNKED])
        self.assertEqual(c.messages[0].status, 200)
        body = c.bodies[0]
        self.assertEqual(body["transfer"], "chunked")
        self.assertEqual(body["bytes"], 14)        # hello + " world" + !!!
        self.assertEqual(body["chunks"], 3)
        self.assertTrue(body["complete"])

    def test_chunked_split_at_every_boundary(self):
        for size in (1, 3, 8, 17, 64):
            p, c = run(split_every(CHUNKED, size))
            self.assertEqual(len(c.bodies), 1, "size %d" % size)
            self.assertEqual(c.bodies[0]["bytes"], 14, "size %d" % size)
            self.assertEqual(c.bodies[0]["chunks"], 3, "size %d" % size)
            self.assertTrue(c.bodies[0]["complete"])

    def test_chunk_extensions_are_tolerated(self):
        blob = (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                b"4;name=value\r\nabcd\r\n0\r\n\r\n")
        p, c = run([blob])
        self.assertEqual(c.bodies[0]["bytes"], 4)
        self.assertTrue(c.bodies[0]["complete"])

    def test_chunked_trailers_are_consumed(self):
        blob = (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                b"3\r\nabc\r\n0\r\nX-Checksum: deadbeef\r\n\r\n"
                b"HTTP/1.1 204 No Content\r\n\r\n")
        p, c = run([blob])
        self.assertEqual(len(c.messages), 2)
        self.assertEqual(c.messages[1].status, 204)

    def test_incomplete_chunked_body_is_marked_incomplete(self):
        blob = (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                b"5\r\nhel")
        p, c = run([blob])
        p.on_close("FIN")
        self.assertFalse(c.bodies[0]["complete"])


class TestFramingEdgeCases(unittest.TestCase):
    def test_204_has_no_body(self):
        blob = b"HTTP/1.1 204 No Content\r\nServer: x\r\n\r\n"
        p, c = run([blob + b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"])
        self.assertEqual(len(c.messages), 2)
        self.assertIsNone(c.bodies[0]["transfer"])

    def test_response_without_framing_runs_to_close(self):
        blob = b"HTTP/1.0 200 OK\r\nServer: x\r\n\r\nbody bytes here"
        p, c = run([blob])
        p.on_close("FIN")
        self.assertEqual(c.bodies[0]["transfer"], "eof")
        self.assertEqual(c.bodies[0]["bytes"], 15)
        self.assertTrue(c.bodies[0]["complete"])

    def test_zero_content_length(self):
        p, c = run([b"GET / HTTP/1.1\r\nHost: a\r\nContent-Length: 0\r\n\r\n"])
        self.assertEqual(c.bodies[0]["bytes"], 0)
        self.assertTrue(c.bodies[0]["complete"])

    def test_get_without_body_then_next_request(self):
        blob = (b"GET /a HTTP/1.1\r\nHost: a\r\n\r\n"
                b"GET /b HTTP/1.1\r\nHost: b\r\n\r\n")
        p, c = run([blob])
        self.assertEqual([m.target for m in c.messages], ["/a", "/b"])


class TestGapsAndGarbage(unittest.TestCase):
    def test_gap_marks_the_message_incomplete_and_resyncs(self):
        head, body = RESP.split(b"\r\n\r\n")
        p, c = run([head + b"\r\n\r\n" + body[:5]])
        p.on_gap(500)
        self.assertFalse(c.bodies[0]["complete"])
        self.assertTrue(c.bodies[0]["gap"])
        self.assertEqual(p.resyncs, 1)

        # After the gap a fresh message must still be found.
        p.feed(REQ)
        self.assertEqual(len(c.messages), 2)
        self.assertEqual(c.messages[1].method, "POST")

    def test_binary_garbage_does_not_produce_a_message(self):
        p, c = run([bytes(range(256)) * 4])
        self.assertEqual(len(c.messages), 0)

    def test_oversized_header_block_is_abandoned_not_guessed(self):
        blob = b"GET / HTTP/1.1\r\nX-Big: " + b"A" * 5000
        p, c = run([blob], limit=1024)
        self.assertEqual(len(c.messages), 0)
        self.assertEqual(p.truncated_headers, 1)

    def test_parser_memory_stays_bounded_on_endless_garbage(self):
        p, c = run([], limit=4096)
        for _ in range(200):
            p.feed(b"\x00\xff" * 512)
        self.assertLessEqual(len(p._buf), 4096 + 1024)
        self.assertEqual(len(c.messages), 0)

    def test_resync_finds_a_start_line_mid_buffer(self):
        p, c = run([])
        p.on_gap(100)
        p.feed(b"\x00\x01\x02garbage-here" + REQ)
        self.assertEqual(len(c.messages), 1)
        self.assertEqual(c.messages[0].method, "POST")


if __name__ == "__main__":
    unittest.main()
