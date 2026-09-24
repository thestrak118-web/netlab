NetLab 1.4.0 — local Devices correction, verified 2026-09-21

The installed Wayland GUI was tested against a fresh wlan0 capture on this Kali machine. This is new evidence for the local-device correction; no Phase 2/3/4 acceptance result is reused as proof.

1. Behavior delivered

Devices and Hosts now project local device identities from the existing HostTable. Internet observations remain EndpointSnapshot records in the same analyzer. A device requires selected-interface membership, a verified gateway route, kernel-neighbor binding, an observed ARP binding, or captured traffic in the selected interface's on-link prefix. A DNS answer or arbitrary captured IP alone does not establish a device.

The capture machine's IPv4 and IPv6 addresses share interface:wlan0. Other addresses can merge through one unambiguous observed MAC with on-link evidence. A peer cannot merge with the gateway or this machine just because their MAC was seen on its frames. Conflicting MAC histories remain separate IP fallbacks, with Unknown vendor. DNS names alone never merge identities.

Devices has All Local, Gateway, Active, Unknown and High Traffic filters. The primary address appears in the row; all addresses, MACs and evidence appear in Device Details. Monitor is offered only for device rows; the backend and GUI reject a remote monitor request. Existing Traffic, Connections, DNS, HTTP, TLS and PCAP navigation expands the selected device to its address set. Capture and protocol analysis are not duplicated.

Topology has separate LOCAL DEVICES and INTERNET / REMOTE DESTINATIONS groups. The drawn dashed line is the verified default route. Observed IP communications appear in the evidence table as logical traffic relationships, without invented physical links to Internet servers. Remote nodes offer View Traffic / View Connections.

2. Tests

- Final installed-package suite: 225 passed, 0 failed, 0 skipped (13.55 seconds), including live capture tests.
- Final Debian build suite: 223 passed, 0 failed, 2 explicitly skipped live capture tests, as configured for package builds.
- 11 new local-device regression tests cover local prefix/ARP/gateway evidence, remote IPv4/IPv6 and DNS exclusion, multi-address/interface merging, stable MAC merging, shared gateway and conflicting MACs, untrusted hostnames, device/remote monitor eligibility, local filters, separated topology, and byte-preserving multi-address PCAP export including real IPv6 frame fixtures.
- Existing Phase 3/4 tests remain. Tests whose old premise was “every IP is a Device” now use EndpointSnapshot for remote observations or explicit local evidence for monitoring. Correlation, lifecycle, thread, export and direction assertions remain.
- An initial sandbox run could not enumerate/open real interfaces; the complete final suite was rerun outside the sandbox. Final suite has no failures.

Logs: [installed tests](validation/local-devices-final/tests-installed.txt), [build](validation/local-devices-final/build.log), [install](validation/local-devices-final/install.log).

3. Fresh real wlan0 GUI acceptance

- Installed module: /usr/lib/python3/dist-packages/netlab; version 1.4.0; actual Wayland display.
- Started capture with wlan0 selected and no BPF restriction. Generated normal DNS, plaintext HTTP and HTTPS requests; all commands succeeded, both curl requests returned HTTP 200.
- Initial GUI inspection had 3 local rows: This Device, gateway 10.0.0.1, and unknown local 10.0.0.2. During capture, 10.0.0.15 appeared as a fourth local row. Independent tshark evidence for that host is frame 940, source 10.0.0.15 to mDNS multicast 224.0.0.251, Ethernet source 92:29:00:64:9c:61. No make/model or OS is inferred for it.
- This Device appeared exactly once, containing 10.0.0.28 and fe80::9048:8450:680c:5ef9, MAC f4:7b:09:70:46:26. IPv6 membership is established by interface evidence; this acceptance does not claim generated IPv6 application traffic. Synthetic wire-frame tests cover IPv6 monitor/export behavior separately.
- Gateway appeared once: 10.0.0.1, MAC 08:36:c9:e5:22:d2, Netgear OUI. Gateway role comes from the selected-interface default route, not its vendor.
- Internet addresses including 104.18.32.47, 149.154.166.110, 142.251.152.119 and 172.67.132.115 were excluded from Devices and remained visible in Traffic/Connections.
- Initial own-device packet counter increased 0 → 181; the final Devices screenshot shows 2253 own-device packets while capture is running. Rows and counters changed during the same session.
- Topology snapshot revisions increased 1 → 8 by the topology check: 3 local devices, 28 remote/unclassified endpoints, 22 observed communications; the only drawn edge was This Device → Gateway, backed by the route.
- Monitoring selected interface:wlan0 with both addresses. Snapshot contained 18 DNS events, 1 HTTP session, 7 TLS sessions and 22 active connections. Only associated traffic appeared. HTTPS metadata remains encrypted-payload metadata, not decrypted contents.
- Exported selected-device PCAP: 903 packets in NetLab, tshark and capinfos. Every decoded packet matched a selected address; the original captured bytes were preserved.
- Stop Monitoring removed its subscription while global capture continued: global packets 929 → 2029.
- Capture stopped cleanly. The full capture contains 2419 packets, equal in a fresh NetLab offline reimport, tshark and capinfos.

Evidence: [acceptance JSON](validation/local-devices-final/acceptance.json), [GUI log](validation/local-devices-final/gui-acceptance.log), [independent package/PCAP checks](validation/local-devices-final/package-verification.json).

Screenshots were opened and visually inspected:

- [Corrected Devices with expanded IPv4 + IPv6 identity](validation/local-devices-final/devices-corrected-final.png)
- [Separated topology](validation/local-devices-final/topology-separated.png)
- [Traffic retains remote destinations](validation/local-devices-final/traffic-remote-destinations.png)
- [Connections retain remote destinations](validation/local-devices-final/connections-remote-destinations.png)
- [Selected local device monitor](validation/local-devices-final/monitor-local-device.png)

4. Release artifact

Package: /home/erwin/loyiha/netlab_1.4.0_amd64.deb
Installed version: 1.4.0
SHA256: 62a49f5a99b05c07d12e5bcc67ee75c9c2ab437c7dd56e37d5aa7770bef6d7dd

`dpkg -V netlab` is clean. All 59 source/assets files under src/netlab match their installed counterparts byte for byte. Existing open processes must be restarted to load the new installed code.

5. Exact source/test/packaging files changed from the pre-correction backup

- src/netlab/__init__.py
- src/netlab/analyze/devices.py
- src/netlab/analyze/engine.py
- src/netlab/analyze/flows.py
- src/netlab/analyze/monitor.py
- src/netlab/capture/export.py
- src/netlab/gui/main_window.py
- src/netlab/gui/models.py
- src/netlab/gui/pages/devices.py
- src/netlab/gui/pages/live.py
- src/netlab/gui/pages/monitor.py
- src/netlab/gui/pages/pcapviewer.py
- src/netlab/gui/pages/topology.py
- tests/test_local_devices.py
- tests/test_phase3.py
- tests/test_phase4.py
- scripts/accept_local_devices.py
- pyproject.toml
- debian/changelog
- src/netlab.egg-info/PKG-INFO
- src/netlab.egg-info/SOURCES.txt
- LOCAL-DEVICES-REPORT.md

The two egg-info files are generated package metadata. validation/local-devices-final/ contains this run's new logs, JSON evidence, screenshots and capture files; changed-files.txt records the same source manifest. validation/local-devices/ preserves the preliminary acceptance before the conservative vendor adjustment.

6. Known limits

- Passive capture shows only traffic the interface actually receives. It does not enumerate every WLAN client or provide another client's encrypted payloads. The live monitor acceptance selected this capture machine, not an unobserved peer.
- IP-only identities remain when stronger evidence is unavailable. Shared gateways, proxy ARP, multiple/conflicting MACs and DNS names are not sufficient to assert one physical device. Conflicting/shared-MAC peer vendors stay Unknown.
- Offline imports do not inherit this machine's routing or interface state. Without captured local evidence, endpoints can remain unclassified and absent from Devices.
- Topology is bounded to 80 nodes and 160 relationships, with omission counts. It is a logical observation view, not a physical network map. Monitor tables retain bounded rows, and rates use the existing five-second window.
- Per-device lifetime traffic totals aggregate member-address counters; traffic between two addresses of the same grouped device contributes to both address counters. Captured packet lists/PCAP exports select each original packet only once.
- Device model/OS remains Unknown unless independently evidenced. Vendor lookup depends on the installed OUI registry; randomized MACs do not establish a vendor.
