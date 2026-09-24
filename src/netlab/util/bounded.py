"""Bounded containers used to keep memory flat under high packet rates.

Everything the capture and analysis threads write into is bounded.  When a
bound is hit we drop and *count* the drop rather than growing without limit,
and the counters are surfaced in the GUI so the operator always knows the
view is incomplete.
"""

from __future__ import annotations

import itertools
import threading
from collections import OrderedDict, deque
from typing import Any, Callable, Iterator


class DropCountingQueue:
    """A bounded FIFO that drops the newest item when full and counts drops.

    Chosen over `queue.Queue` blocking behaviour on purpose: blocking the
    capture reader would stall the drain of the dumpcap output file, which
    would in turn cause kernel-level drops that we could not observe or
    report.  Dropping here is visible and reportable.
    """

    def __init__(self, maxsize: int) -> None:
        self._maxsize = int(maxsize)
        self._dq: deque = deque()
        self._lock = threading.Lock()
        self._not_empty = threading.Condition(self._lock)
        self._dropped = 0
        self._closed = False

    @property
    def dropped(self) -> int:
        with self._lock:
            return self._dropped

    def qsize(self) -> int:
        with self._lock:
            return len(self._dq)

    def put(self, item: Any) -> bool:
        """Return True if queued, False if dropped because the queue was full."""
        with self._not_empty:
            if self._closed:
                return False
            if len(self._dq) >= self._maxsize:
                self._dropped += 1
                return False
            self._dq.append(item)
            self._not_empty.notify()
            return True

    def get_batch(self, max_items: int, timeout: float = 0.2) -> list:
        """Pop up to `max_items`, waiting up to `timeout` for the first one."""
        with self._not_empty:
            if not self._dq and not self._closed:
                self._not_empty.wait(timeout)
            out = []
            while self._dq and len(out) < max_items:
                out.append(self._dq.popleft())
            return out

    def close(self) -> None:
        with self._not_empty:
            self._closed = True
            self._not_empty.notify_all()

    def is_closed(self) -> bool:
        with self._lock:
            return self._closed

    def reset(self) -> None:
        with self._not_empty:
            self._dq.clear()
            self._dropped = 0
            self._closed = False


class BoundedRing:
    """Thread-safe fixed-capacity ring of records, oldest evicted first."""

    def __init__(self, capacity: int) -> None:
        self._dq: deque = deque(maxlen=int(capacity))
        self._lock = threading.Lock()
        self._total = 0

    @property
    def total_seen(self) -> int:
        with self._lock:
            return self._total

    def append(self, item: Any) -> None:
        with self._lock:
            self._dq.append(item)
            self._total += 1

    def extend(self, items) -> None:
        with self._lock:
            for it in items:
                self._dq.append(it)
                self._total += 1

    def snapshot(self) -> list:
        with self._lock:
            return list(self._dq)

    def since(self, marker: int) -> tuple[list, int]:
        """Return (items appended since `marker`, new marker).

        Lets the GUI copy only what is new instead of the whole ring on
        every refresh tick.  If more items were appended than the ring can
        hold, the overflow is simply gone and the caller sees the newest.
        """
        with self._lock:
            fresh = self._total - marker
            if fresh <= 0:
                return [], self._total
            n = min(fresh, len(self._dq))
            if n == len(self._dq):
                return list(self._dq), self._total
            start = len(self._dq) - n
            return list(itertools.islice(self._dq, start, len(self._dq))), self._total

    def __len__(self) -> int:
        with self._lock:
            return len(self._dq)

    def clear(self) -> None:
        with self._lock:
            self._dq.clear()
            self._total = 0


class BoundedLRUDict:
    """Thread-safe dict with an LRU cap, used for flow/host/session tables.

    Eviction is reported through `evicted` so the GUI can say "showing the
    most recent N of M" instead of silently lying about totals.
    """

    def __init__(self, capacity: int) -> None:
        self._capacity = int(capacity)
        self._od: OrderedDict = OrderedDict()
        self._lock = threading.RLock()
        self._evicted = 0

    @property
    def evicted(self) -> int:
        with self._lock:
            return self._evicted

    @property
    def capacity(self) -> int:
        return self._capacity

    def get_or_create(self, key: Any, factory: Callable[[], Any]) -> tuple[Any, bool]:
        """Return (value, created)."""
        with self._lock:
            val = self._od.get(key)
            if val is not None:
                self._od.move_to_end(key)
                return val, False
            val = factory()
            self._od[key] = val
            while len(self._od) > self._capacity:
                self._od.popitem(last=False)
                self._evicted += 1
            return val, True

    def get(self, key: Any, default: Any = None) -> Any:
        with self._lock:
            return self._od.get(key, default)

    def touch(self, key: Any) -> None:
        with self._lock:
            if key in self._od:
                self._od.move_to_end(key)

    def pop(self, key: Any, default: Any = None) -> Any:
        with self._lock:
            return self._od.pop(key, default)

    def values(self) -> list:
        with self._lock:
            return list(self._od.values())

    def items(self) -> list:
        with self._lock:
            return list(self._od.items())

    def __len__(self) -> int:
        with self._lock:
            return len(self._od)

    def __iter__(self) -> Iterator:
        return iter(self.values())

    def clear(self) -> None:
        with self._lock:
            self._od.clear()
            self._evicted = 0

    @property
    def lock(self):
        return self._lock
