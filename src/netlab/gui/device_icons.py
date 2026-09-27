"""Presentation symbols; icons never supply classification evidence."""
from functools import lru_cache
from pathlib import Path
from PySide6.QtGui import QIcon

ICON_DIR = Path(__file__).with_name('icons')
ICON_NAMES = ('computer', 'laptop', 'smartphone', 'tablet', 'router',
              'server', 'printer', 'iot', 'unknown', 'internet',
              'windows', 'linux', 'android', 'apple')

# Operating system → icon, so the host list reads at a glance like
# Intercepter-NG (a penguin for Unix, the Windows mark for Windows).
OS_ICONS = {'Windows': 'windows', 'Android': 'android', 'iOS': 'apple',
            'iPadOS': 'apple', 'macOS': 'apple', 'Linux': 'linux',
            'Unix': 'linux', 'ChromeOS': 'linux', 'Network device': 'router'}


def os_icon_name(os):
    """The icon for an OS string ('Unix', 'Windows', 'Android'…), or None."""
    if not os:
        return None
    return OS_ICONS.get(os.split(',')[0].strip())


@lru_cache(maxsize=16)
def os_icon(os):
    name = os_icon_name(os)
    return QIcon(str(ICON_DIR / (name + '.svg'))) if name else None


def icon_name(device_type):
    # Local-machine and gateway roles come from verified system context.
    return {'This Device': 'computer', 'Gateway': 'router',
            'Computer': 'computer', 'Laptop': 'laptop', 'Smartphone': 'smartphone',
            'Tablet': 'tablet', 'Router': 'router', 'Server': 'server',
            'Printer': 'printer', 'IoT': 'iot'}.get(device_type, 'unknown')


@lru_cache(maxsize=10)
def device_icon(device_type):
    return QIcon(str(ICON_DIR / (icon_name(device_type) + '.svg')))


def fallback_type(mac):
    """A device we could not classify still deserves a device glyph, never the
    '?' unknown mark. A randomised (locally-administered) MAC is a phone/laptop
    privacy address, so show a smartphone; any other real MAC gets a neutral
    computer symbol. Presentation only -- it adds no classification evidence."""
    from netlab.analyze.devices import mac_is_local, valid_mac
    if not valid_mac((mac or '').split(',')[0].strip()):
        return 'Unknown'
    return 'Smartphone' if mac_is_local(mac) else 'Computer'


def snapshot_icon(d):
    """The single source of a host row's icon: OS mark when the OS is known,
    else its verified device type, else a MAC-based device glyph so an
    unnamed host is a phone/computer symbol rather than a bare question mark."""
    os = getattr(d, 'os', 'Unknown')
    if os and os != 'Unknown':
        icon = os_icon(os)
        if icon:
            return icon
    kind = getattr(d, 'device_type', 'Unknown')
    if kind and kind != 'Unknown':
        return device_icon(kind)
    return device_icon(fallback_type(getattr(d, 'mac', '')))
