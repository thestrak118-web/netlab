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
