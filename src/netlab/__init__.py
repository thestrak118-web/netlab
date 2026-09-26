"""NetLab - network analysis and interception workbench for Kali Linux."""

__version__ = "2.28.0"
__appname__ = "NetLab"

# NetLab has two halves, and the split is the point.
#
# Everything under netlab.capture and netlab.analyze is passive: it reads
# what the interface was given and never puts a frame on the wire.
#
# Everything under netlab.intercept transmits -- forged ARP, forged DNS,
# terminated TLS, DHCP leases -- and none of it runs without an authorised
# engagement naming the interface and the hosts in scope, executed by the
# separate privileged helper in netlab.priv.
PASSIVE_CORE = ("netlab.capture", "netlab.analyze")
ACTIVE_PACKAGES = ("netlab.intercept", "netlab.priv")
