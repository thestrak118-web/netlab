"""The flagship, at the frame level: what ARP poisoning actually puts on the
wire, and what restore undoes.

The end-to-end datapath (a forged frame leaving a real NIC and moving a real
victim's cache) can only be proved on real hardware or a two-VM lab -- this
kernel's namespaces do not carry AF_PACKET, and the CI sandbox has no
/run/netns.  What *can* be proved here, deterministically, is that the
Poisoner forges the right frames in both directions and heals with the true
MACs on restore.  A fake socket records every frame instead of sending it.
"""

from netlab.intercept.arp import Poisoner, RESTORE_ROUNDS

LOCAL_MAC = "aa:aa:aa:aa:aa:aa"
GW_IP, GW_MAC = "10.0.0.1", "bb:bb:bb:bb:bb:bb"
VICTIM_IP, VICTIM_MAC = "10.0.0.5", "cc:cc:cc:cc:cc:cc"


class FakeSock:
    """Records reply() calls; sends nothing."""

    def __init__(self):
        self.calls = []

    def reply(self, to_mac, to_ip, claim_ip, claim_mac=None):
        self.calls.append({"to_mac": to_mac, "to_ip": to_ip,
                           "claim_ip": claim_ip, "claim_mac": claim_mac})

    def close(self):
        pass


def _poisoner():
    return Poisoner("eth0", LOCAL_MAC, "10.0.0.2",
                    gateway_ip=GW_IP, gateway_mac=GW_MAC)


def test_a_round_forges_both_directions():
    p = _poisoner()
    p._sock = FakeSock()
    p.add_target(VICTIM_IP, VICTIM_MAC)
    p._poison_round()
    # Victim hears "the gateway is at our MAC"; the gateway hears "the victim
    # is at our MAC".  claim_mac is None on both, i.e. our own address.
    assert p._sock.calls == [
        {"to_mac": VICTIM_MAC, "to_ip": VICTIM_IP,
         "claim_ip": GW_IP, "claim_mac": None},
        {"to_mac": GW_MAC, "to_ip": GW_IP,
         "claim_ip": VICTIM_IP, "claim_mac": None},
    ]
    assert p.frames_sent == 2


def test_poison_never_carries_a_true_mac():
    # A claim_mac would tell the truth -- that is what restore does, and it
    # must never leak into the poison round for any target.
    p = _poisoner()
    p._sock = FakeSock()
    p.add_target(VICTIM_IP, VICTIM_MAC)
    p.add_target("10.0.0.6", "dd:dd:dd:dd:dd:dd")
    p._poison_round()
    assert all(c["claim_mac"] is None for c in p._sock.calls)
    assert p.frames_sent == 4          # two targets, two frames each


def test_restore_heals_with_the_true_macs():
    p = _poisoner()
    p._sock = FakeSock()
    p._restore_one(VICTIM_IP, VICTIM_MAC)
    # RESTORE_ROUNDS pairs, each stating the real bindings.
    assert len(p._sock.calls) == RESTORE_ROUNDS * 2
    assert p._sock.calls[0] == {
        "to_mac": VICTIM_MAC, "to_ip": VICTIM_IP,
        "claim_ip": GW_IP, "claim_mac": GW_MAC}
    assert p._sock.calls[1] == {
        "to_mac": GW_MAC, "to_ip": GW_IP,
        "claim_ip": VICTIM_IP, "claim_mac": VICTIM_MAC}
