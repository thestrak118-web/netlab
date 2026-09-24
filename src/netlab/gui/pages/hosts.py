"""Hosts and Devices share the same evidence-backed HostTable projection."""
from netlab.gui.pages.devices import DevicesPage


class HostsPage(DevicesPage):
    def __init__(self, parent=None):
        super().__init__('Hosts')
