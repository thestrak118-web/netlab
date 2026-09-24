"""The privileged helper's session gate.

The helper is the trust boundary, and its commands each run on their own
thread.  These tests pin down that only one engagement can be armed at a time
even when two arm commands race, and that a disarm frees the slot cleanly.
"""

import io
import threading
import time
import unittest

from netlab.priv import helper as helpermod
from netlab.intercept.scope import ScopeError
from netlab.intercept.session import InterceptError


AUTHORISED = {"name": "t", "interface": "eth0", "gateway": "10.0.0.1",
              "targets": ["10.0.0.5/32"], "authorised": True}


class FakeSession:
    """Stands in for InterceptSession: arm() is deliberately slow."""

    def __init__(self, eng, modules, ca_dir="", owner_uid=0, on_event=None):
        self.eng = eng
        self.armed = False
        self.arm_called = 0

    def arm(self):
        self.arm_called += 1
        time.sleep(0.15)          # widen the window a real arm would have
        self.armed = True
        return {"armed": True}

    def disarm(self):
        self.armed = False
        return {"armed": False}


class TestHelperSessionGate(unittest.TestCase):
    def setUp(self):
        self.helper = helpermod.Helper(stdin=io.BytesIO(), stdout=io.BytesIO())
        self._orig = helpermod.InterceptSession
        helpermod.InterceptSession = FakeSession

    def tearDown(self):
        helpermod.InterceptSession = self._orig

    def test_unauthorised_engagement_is_refused(self):
        with self.assertRaises(ScopeError):
            self.helper.cmd_arm(engagement=dict(AUTHORISED, authorised=False))

    def test_second_arm_is_rejected(self):
        self.helper.cmd_arm(engagement=AUTHORISED)
        with self.assertRaises(InterceptError):
            self.helper.cmd_arm(engagement=AUTHORISED)

    def test_two_racing_arms_only_one_wins(self):
        results = []
        lock = threading.Lock()
        barrier = threading.Barrier(2)

        def go():
            barrier.wait()
            try:
                self.helper.cmd_arm(engagement=AUTHORISED)
                with lock:
                    results.append("ok")
            except InterceptError:
                with lock:
                    results.append("rejected")

        threads = [threading.Thread(target=go) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)

        self.assertEqual(results.count("ok"), 1, results)
        self.assertEqual(results.count("rejected"), 1, results)
        # Exactly one session ever had arm() called on it.
        self.assertTrue(self.helper.session is not None)
        self.assertEqual(self.helper.session.arm_called, 1)

    def test_disarm_frees_the_slot(self):
        self.helper.cmd_arm(engagement=AUTHORISED)
        report = self.helper.cmd_disarm()
        self.assertFalse(report.get("armed", True))
        self.assertIsNone(self.helper.session)
        # A fresh engagement arms again after a disarm.
        self.helper.cmd_arm(engagement=AUTHORISED)
        self.assertIsNotNone(self.helper.session)

    def test_disarm_with_nothing_armed(self):
        report = self.helper.cmd_disarm()
        self.assertFalse(report.get("armed", True))


if __name__ == "__main__":
    unittest.main()
