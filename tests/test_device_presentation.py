"""An unnamed on-link host is shown as a device, never a blank "Unknown".

A randomised (locally-administered) MAC is a personal privacy address, so the
row reads as a phone; any other MAC as a plain device. These are presentation
choices driven by a fact in the MAC -- they add no classification evidence.
"""
import pytest

from netlab.analyze.devices import Confidence, DeviceSnapshot, Evidence, mac_is_local
from netlab.gui import device_icons
from netlab.gui.device_icons import fallback_type, icon_name, snapshot_icon


RANDOM_MAC = 'a2:a6:c6:df:40:8e'      # locally-administered bit set (privacy)
VENDOR_MAC = '44:37:0b:a9:2e:a1'      # universally-administered (real OUI)


def snap(**over):
    base = dict(ip='192.168.100.113', ipv6='Unknown', mac=RANDOM_MAC,
                hostname='Unknown', manufacturer='Unknown', os='Unknown',
                device_type='Unknown', scope='Local', status='Inactive',
                first_seen=0.0, last_seen=0.0, packets=0, upload=0, download=0,
                active_connections=0, packets_sec=0.0, bytes_sec=0.0,
                dns_names=(), evidence=(), recent=())
    base.update(over)
    return DeviceSnapshot(**base)


def test_mac_is_local_reads_the_privacy_bit():
    assert mac_is_local(RANDOM_MAC) is True
    assert mac_is_local(VENDOR_MAC) is False
    assert mac_is_local('Unknown') is False
    assert mac_is_local('') is False
    # Surrounding case/space are tolerated; a joined list classifies by its first.
    assert mac_is_local(' A2:A6:C6:DF:40:8E ') is True
    assert mac_is_local(RANDOM_MAC + ', ' + VENDOR_MAC) is True


def test_unnamed_random_mac_reads_as_a_private_device():
    assert snap(mac=RANDOM_MAC).display_name == 'Private device'


def test_unnamed_vendor_mac_reads_as_a_plain_device():
    assert snap(mac=VENDOR_MAC).display_name == 'Device'


def test_no_mac_stays_unknown():
    assert snap(mac='Unknown').display_name == 'Unknown Device'


def test_real_identity_still_wins_over_the_mac_fallback():
    assert snap(hostname='pixel-7').display_name == 'pixel-7'
    assert snap(device_type='Gateway', mac=VENDOR_MAC).display_name == 'Gateway'
    # display_name reads the vendor from evidence, so an OUI-named host (like the
    # TV panel in the host list) keeps its vendor and never falls back.
    vendor_ev = (Evidence('Manufacturer', 'Xiaomi', 'OUI', Confidence.OBSERVED, 0.0),)
    assert snap(evidence=vendor_ev).display_name == 'Xiaomi'


def test_fallback_type_maps_mac_to_a_device_glyph():
    assert fallback_type(RANDOM_MAC) == 'Smartphone'
    assert fallback_type(VENDOR_MAC) == 'Computer'
    assert fallback_type('Unknown') == 'Unknown'
    # The chosen types resolve to real, non-question-mark icons.
    assert icon_name('Smartphone') == 'smartphone'
    assert icon_name('Computer') == 'computer'


@pytest.fixture(scope='module')
def app():
    from PySide6.QtWidgets import QApplication
    return QApplication.instance() or QApplication([])


def test_snapshot_icon_prefers_os_then_type_then_mac(app):
    # Unnamed randomised MAC -> the smartphone glyph, not the '?' unknown one.
    assert snapshot_icon(snap(mac=RANDOM_MAC)) is device_icons.device_icon('Smartphone')
    assert snapshot_icon(snap(mac=VENDOR_MAC)) is device_icons.device_icon('Computer')
    # A verified OS wins.
    assert snapshot_icon(snap(os='Android')) is device_icons.os_icon('Android')
    # A verified device type wins over the MAC fallback.
    assert snapshot_icon(snap(device_type='Router')) is device_icons.device_icon('Router')
