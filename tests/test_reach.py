"""Unprivileged liveness probe used before arming a watch."""
from netlab.integrations import reach


class _Run:
    def __init__(self, stdout):
        self.stdout = stdout


def test_neighbour_present_true_for_a_bound_reachable_host(monkeypatch):
    monkeypatch.setattr(reach.subprocess, "run", lambda *a, **k: _Run(
        '[{"dst":"10.0.0.5","lladdr":"aa:bb:cc:dd:ee:ff","state":["REACHABLE"]}]'))
    assert reach.neighbour_present("10.0.0.5") is True


def test_neighbour_present_false_for_failed_or_absent(monkeypatch):
    monkeypatch.setattr(reach.subprocess, "run", lambda *a, **k: _Run(
        '[{"dst":"10.0.0.5","state":["FAILED"]}]'))
    assert reach.neighbour_present("10.0.0.5") is False
    monkeypatch.setattr(reach.subprocess, "run", lambda *a, **k: _Run("[]"))
    assert reach.neighbour_present("10.0.0.5") is False


def test_neighbour_present_false_on_empty_ip():
    assert reach.neighbour_present("") is False


def test_host_reachable_fast_path_skips_the_nudge(monkeypatch):
    monkeypatch.setattr(reach, "neighbour_present", lambda ip: True)
    nudges = []
    monkeypatch.setattr(reach, "_nudge", lambda *a, **k: nudges.append(1))
    assert reach.host_reachable("10.0.0.5") is True
    assert nudges == []          # already present -> no probing


def test_host_reachable_nudges_then_gives_up(monkeypatch):
    seen = []
    monkeypatch.setattr(reach, "neighbour_present", lambda ip: False)
    monkeypatch.setattr(reach, "_nudge", lambda *a, **k: seen.append(1))
    assert reach.host_reachable("10.0.0.5", attempts=2) is False
    assert len(seen) == 2        # tried, bounded by attempts


def test_host_reachable_wakes_a_dozing_host(monkeypatch):
    # Absent on the first look, present after one nudge.
    calls = {"n": 0}
    def present(ip):
        calls["n"] += 1
        return calls["n"] > 1
    monkeypatch.setattr(reach, "neighbour_present", present)
    monkeypatch.setattr(reach, "_nudge", lambda *a, **k: None)
    assert reach.host_reachable("10.0.0.5", attempts=3) is True
