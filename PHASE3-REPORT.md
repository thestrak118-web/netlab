# NetLab Phase 3 release verification — 2026-09-21

Status: COMPLETE against the release criteria. NetLab 1.2.0 was built, installed,
and exercised through its real PySide6 GUI on Kali 2026.3 / Wayland using wlan0.
This report uses fresh Phase 3 captures, not Phase 2 acceptance results.

## Exact files changed

The following authored package files were compared byte-for-byte with
`/tmp/netlab-phase3-before` (the snapshot made before Phase 3 backend work).
That snapshot includes src, tests, assets, debian, README and pyproject.toml.
The new acceptance script and this report were created during GUI completion.
There is no Git history. Generated Debian staging/build files are not source edits.

```text
modified	src/netlab/__init__.py
modified	src/netlab/analyze/decode.py
added	src/netlab/analyze/devices.py
modified	src/netlab/analyze/engine.py
modified	src/netlab/analyze/flows.py
added	src/netlab/capture/export.py
added	src/netlab/gui/device_icons.py
modified	src/netlab/gui/filters.py
added	src/netlab/gui/icons/computer.svg
added	src/netlab/gui/icons/internet.svg
added	src/netlab/gui/icons/iot.svg
added	src/netlab/gui/icons/laptop.svg
added	src/netlab/gui/icons/printer.svg
added	src/netlab/gui/icons/router.svg
added	src/netlab/gui/icons/server.svg
added	src/netlab/gui/icons/smartphone.svg
added	src/netlab/gui/icons/tablet.svg
added	src/netlab/gui/icons/unknown.svg
modified	src/netlab/gui/main_window.py
modified	src/netlab/gui/models.py
added	src/netlab/gui/pages/devices.py
modified	src/netlab/gui/pages/hosts.py
modified	src/netlab/gui/pages/live.py
modified	src/netlab/gui/pages/pcapviewer.py
added	src/netlab/gui/pages/topology.py
modified	tests/test_flows.py
added	tests/test_phase3.py
modified	debian/changelog
modified	debian/control
modified	pyproject.toml
added	scripts/accept_phase3.py
added	PHASE3-REPORT.md
```

Generated evidence lives under `validation/phase3/`; the exact artifact inventory
is `validation/phase3/artifacts.txt`. This includes tests/build/install logs,
capture files, screenshots, package verification and this change manifest.

## Tests and regression diagnosis

- Final source suite: **198 passed**, no failed or skipped tests (`source-tests.txt`).
- Final installed-package suite: **198 passed**, no failed or skipped tests (`installed-tests.txt`).
- Package-build suite: **196 passed, 2 skipped**; only the explicitly disabled live capture tests skip in the build.
- Full source and installed runs enable those live loopback tests.
- Installed runs override pytest's source path with `-o pythonpath=.` and unset PYTHONPATH.
- Package verification compared 57 installed Python/SVG files with final source; all identical.
- `dpkg -V netlab`: no discrepancies.

The old MAC assertion used a valid locally administered unicast MAC, but supplied
no evidence that the IP endpoint belonged to the observed Ethernet segment. Its
fixture now supplies an explicit on-link prefix; the original MAC and local-host
assertions remain. Added tests prove that absent context and remote IP endpoints
do not inherit a next-hop MAC, and that ARP bindings work without system context.
Locally administered MACs are valid identities when observed, but vendor remains Unknown.

New tests exercise Devices model values and SVG pixel rendering for all ten assets,
identity evidence and OUI handling, exact device filtering (including IP prefix
collisions and DNS resolved addresses), all protocol navigation actions, Hosts
Device Details, PCAP byte preservation, stale/offline context rejection,
route/traffic edges and graph bounds/expiry, incremental item reuse, timer-driven
updates, stable device ordering and preservation of detail scroll position.

## Package

- File: `/home/erwin/loyiha/netlab_1.2.0_amd64.deb`
- Size: 117816 bytes
- SHA256: `ea97ac92f009c9b9b4379fea2f6579022278d7b99a757c767efbf686d4a528c5`
- Installed: `netlab 1.2.0 install ok installed`
- Required Qt SVG dependency and all ten SVG assets are included.

## Real wlan0 acceptance — final installed build

Evidence: `validation/phase3/wlan0-final/acceptance.json` and `wlan0-final.log`.
The harness imports `/usr/lib/python3/dist-packages/netlab/__init__.py`, creates and displays the actual
MainWindow on `wayland`, selects wlan0 and activates its production
buttons. Only save-path and informational dialogs are automated; no captured
packets, protocol results, device values or success checks are fabricated.

Capture: `netlab-wlan0-20260921-191658.pcapng`.
Filter: `arp or port 53 or tcp port 80 or tcp port 443 or icmp`.
Generated ordinary DNS through the system resolver, HTTP to httpforever.com,
and HTTPS to www.google.com. Both curl requests returned HTTP 200.
Ambient matching traffic is also present in the capture.

| Check | Result |
|---|---|
| NetLab / tshark / capinfos | 311 / 311 / 311 packets |
| Full export | Byte-identical to stopped source; 311 packets in all readers |
| Device export | 311 packets in all readers; every frame independently decoded to verify local-IP membership |
| Reopened full export | 311 packets |
| Captured wire bytes | 180718 |
| Flows / retained host addresses | 33 / 38 |
| DNS / HTTP / TLS records | 22 / 1 / 9 |
| Malformed / analysis drops / stream gaps | 0 / 0 / 0 |

The local device displayed `10.0.0.28`, MAC `f4:7b:09:70:46:26`, hostname
`nitro-acer`, and OUI vendor `Intel Corporate`. At its detail
snapshot it had 222 packets, 33625 upload bytes,
122575 download bytes and 15 active connections.
These are snapshot-time counters; traffic continued afterwards.
Default gateway `10.0.0.1` was confirmed from wlan0 routing data.
Observed remote IPs were shown. Exact remote device models/OS remained Unknown.

Device button navigation produced filtered populated existing pages:
Traffic 234 rows, Connections 24,
DNS 22, HTTP 1, TLS 8.
All used exact `device:10.0.0.28` correlation. DNS also matches IPs in answers.
Packet → HTTP connection drill-down passed. View PCAP opened the current source
with device packet filtering and device-only export. Offline reopen cleared all
system interface/default-route context instead of inheriting this machine's identity.

## Discovery and evidence

The existing HostTable is the sole device database. Devices and Hosts are projections.
Packet endpoints, ARP bindings, DNS answers, HTTP Host and TLS SNI provide separate
observations. HTTP Host and SNI are not promoted to exact device identity.
Background NetworkContext discovery reads `ip -j address`, IPv4/IPv6 default routes,
and neighbors for the selected interface; system hostname is also recorded.
It runs at capture start and about every 10 seconds. Generation tokens reject stale
results after clearing/importing; offline sessions never run system discovery.

Evidence is shown per attribute: packet IP/MAC/DNS and OUI are OBSERVED;
local system role/hostname/OS and default-gateway role are CONFIRMED.
Unknown model, type, OS, MAC or vendor stays Unknown. OUI identifies an interface
vendor, not a computer model. No active discovery probes are introduced.

## Topology evidence and live updates

The recorded live snapshot contains 12 nodes and 10 edges.
Traffic edges are directed observed flow counters. Dashed route edges come only
from verified selected-interface default routes. No gateway-to-remote link is
invented and no physical topology is asserted.

During the live check, graph revisions advanced from
2 to 3;
analysis advanced from 1 to
183 packets while capture remained running.
The original local-node graphics object was retained. GUI snapshots are batched
at 500 ms (subject to the configured 250–1000 ms GUI timer), with incremental node
and edge updates rather than per-packet scene rebuilds. Paths avoid intermediate
nodes, arrows show direction, and tooltips expose endpoints/evidence/counters.

The acceptance event-loop heartbeat recorded 163
samples, with maximum gap 0.590 seconds
across the whole run, including screenshots, stopping, export and external verification.
This is a short functional responsiveness check, not a sustained-load benchmark.

## Screens implemented and inspected

- Devices: SVG icons, IP/MAC, hostname/vendor/type/scope, packets/bytes,
  active connections/status, first/last timestamps.
- Shared Device Details: identity evidence, traffic/rates, Connections, DNS,
  HTTP, TLS, timeline and all six navigation actions.
- Hosts: same database projection and Device Details, with icons and activity.
- Topology: live logical graph, verified route/traffic legend and node selection.
- Live Traffic: Device, Direction, Protocol, Source, Destination, Domain, Size,
  plus packet index/time/ports/summary and existing packet/connection detail.
- PCAP Viewer: selected-device source, filtered packets and device export.

Screenshots are in `validation/phase3/wlan0-final/`: `devices-detail.png`,
`hosts.png`, `topology-live.png`, `device-traffic.png`, `device-connections.png`,
`device-dns.png`, `device-http.png`, `device-tls.png`, `reopened-pcap.png`.

## Known limitations

- Passive visibility does not enumerate silent devices or traffic not visible to wlan0.
- Devices are address-based: IPv4 and IPv6 addresses are not asserted to be one
  physical machine. DNS-only references can appear with zero packets; status
  distinguishes these from active traffic.
- All ten requested SVG assets exist. Automatic classification currently establishes
  only This Device and Gateway from system evidence. Other types remain Unknown;
  phone/laptop/printer/etc. icons are not assigned from vendor/name guesses.
  No synthetic Internet node or unsupported Internet edges are added.
- Graph bounds: 80 nodes, 160 edges, 120-second traffic-edge expiry; omitted totals
  are shown. Large graphs require scrolling and dense edge labels can overlap;
  full edge evidence remains in tooltips. Route evidence can lag system changes
  by the discovery interval. Bounded stores can evict older correlations.
- The short acceptance run does not establish sustained high-rate GUI performance.
  Current exports/independent verification may briefly block the GUI.
- No IP-fragment reassembly, HTTP/2, HTTP/3, TLS decryption, or TLS 1.3 encrypted
  certificate inspection. DNS-over-TCP remains packet-based. Tuple reuse and
  missing capture segments retain the Phase 2 limitations.
- Matching file counts verifies readers/export consistency, not the absence of
  packets dropped before dumpcap wrote the file.

An earlier Phase 3 attempt failed because public DNS 1.1.1.1 and example.com
resolution timed out. Its artifacts are retained in `validation/phase3/wlan0/`.
A subsequent 440-packet run passed before the final usability fixes; final release
claims above use only `wlan0-final` against the installed final build.
The initial harness also required unavailable QtTest; it was changed to normal
QPushButton.click() automation, with all production action handlers preserved.

## Reproduction

```sh
# Installed suite (isolated config/data recommended)
env -u PYTHONPATH QT_QPA_PLATFORM=offscreen QT_QPA_PLATFORMTHEME=generic \
  NETLAB_LIVE_TESTS=1 python3 -m pytest tests -q -o pythonpath=.
# Installed GUI acceptance on the actual desktop; fresh output/config/data paths
env -u PYTHONPATH QT_QPA_PLATFORMTHEME=generic \
  XDG_CONFIG_HOME=/tmp/netlab-p3-repeat/config \
  XDG_DATA_HOME=/tmp/netlab-p3-repeat/data \
  python3 scripts/accept_phase3.py --output /tmp/netlab-p3-repeat/capture
```
