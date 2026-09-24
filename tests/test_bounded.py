"""Bounded containers: the memory guarantee under load."""

import threading
import unittest

from netlab.util.bounded import BoundedLRUDict, BoundedRing, DropCountingQueue


class TestDropCountingQueue(unittest.TestCase):
    def test_drops_when_full_and_counts_them(self):
        q = DropCountingQueue(3)
        self.assertTrue(all(q.put(i) for i in range(3)))
        self.assertFalse(q.put(99))
        self.assertEqual(q.dropped, 1)
        self.assertEqual(q.qsize(), 3)

    def test_batch_drain(self):
        q = DropCountingQueue(10)
        for i in range(7):
            q.put(i)
        batch = q.get_batch(5, timeout=0.01)
        self.assertEqual(batch, [0, 1, 2, 3, 4])
        self.assertEqual(q.qsize(), 2)

    def test_reset_clears_drop_count(self):
        q = DropCountingQueue(1)
        q.put(1)
        q.put(2)
        self.assertEqual(q.dropped, 1)
        q.reset()
        self.assertEqual(q.dropped, 0)
        self.assertEqual(q.qsize(), 0)

    def test_never_grows_past_bound_under_concurrency(self):
        q = DropCountingQueue(100)

        def flood():
            for i in range(5000):
                q.put(i)

        threads = [threading.Thread(target=flood) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertLessEqual(q.qsize(), 100)
        self.assertEqual(q.qsize() + q.dropped, 20000)


class TestBoundedRing(unittest.TestCase):
    def test_evicts_oldest(self):
        ring = BoundedRing(3)
        ring.extend([1, 2, 3, 4, 5])
        self.assertEqual(ring.snapshot(), [3, 4, 5])
        self.assertEqual(ring.total_seen, 5)
        self.assertEqual(len(ring), 3)

    def test_since_returns_only_new(self):
        ring = BoundedRing(10)
        ring.extend([1, 2, 3])
        items, marker = ring.since(0)
        self.assertEqual(items, [1, 2, 3])
        ring.extend([4, 5])
        items, marker = ring.since(marker)
        self.assertEqual(items, [4, 5])
        items, marker = ring.since(marker)
        self.assertEqual(items, [])

    def test_since_after_overflow_returns_what_survives(self):
        ring = BoundedRing(3)
        ring.extend([1, 2, 3])
        _items, marker = ring.since(0)
        ring.extend([4, 5, 6, 7, 8])
        items, _marker = ring.since(marker)
        self.assertEqual(items, [6, 7, 8])


class TestBoundedLRUDict(unittest.TestCase):
    def test_evicts_least_recently_used_and_counts(self):
        d = BoundedLRUDict(2)
        d.get_or_create("a", lambda: 1)
        d.get_or_create("b", lambda: 2)
        d.get_or_create("a", lambda: 99)         # refreshes 'a'
        d.get_or_create("c", lambda: 3)          # evicts 'b'
        self.assertIsNone(d.get("b"))
        self.assertEqual(d.get("a"), 1)
        self.assertEqual(d.evicted, 1)
        self.assertEqual(len(d), 2)

    def test_created_flag(self):
        d = BoundedLRUDict(4)
        _v, created = d.get_or_create("x", lambda: 1)
        self.assertTrue(created)
        _v, created = d.get_or_create("x", lambda: 1)
        self.assertFalse(created)


if __name__ == "__main__":
    unittest.main()
