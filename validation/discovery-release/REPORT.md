# NetLab 1.5.1 verification report

Installed version: **1.5.1**. Package: `/home/erwin/loyiha/netlab_1.5.1_amd64.deb`.
SHA256: `0a4b6244b16e37f08eb2b9c6c4b75932779514200e9cd7a7f17398539ddf0033`.
All changed packaged Python modules match the installed files byte for byte.

## Changes

Devices/Hosts have explicit Discover devices and cancel controls. Discovery uses
Nmap ARP presence then bounded NetBIOS, UPnP and mDNS name queries on the selected
IPv4 subnet. It retries name protocols once if none answer. Capture remains a
separate passive pipeline. Active evidence supplies advertised names/models and
supported type icons, without inventing traffic counts or authenticating claims.

Fixed two bugs exposed by the real test: unanswered ARP targets were promoted to
devices, and interface-filtered `ip neighbor` JSON omitted the `dev` field so
neighbor bindings were lost. Referenced ARP targets stay available as endpoints
for compatibility but do not appear as devices or Internet topology nodes.
Known next-hop MACs do not overwrite unrelated local peer identities. A changed
MAC invalidates prior active identity evidence. Topology displays device names.

## Tests

- Source: **249 passed** (`source-tests.txt`).
- Installed 1.5.1: **249 passed** (`installed-tests.txt`), including actual loopback capture.
- Debian build: **247 passed, 2 skipped** under `NETLAB_LIVE_TESTS=0` (`build.log`).
- New coverage includes scope, model evidence, icon selection, unknowns, MAC
  changes, gateway role, no fabricated counters, inactivity, offline-safe reset,
  explicit UI requests, ARP probe targets and neighbor JSON interface handling.

## Real GUI and wlan0 evidence

Final installed runs used the Wayland GUI and the installed module under
`/usr/lib/python3/dist-packages/netlab`, not a substituted source build.

- `installed-final/acceptance.json`: capture stayed running through discovery and
  Monitor navigation; live count increased 0 → 1898. Maximum GUI heartbeat gap
  was 0.167 seconds. Own IPv4 and IPv6 were one device.
- `final-visual/acceptance.json`: second successful installed run; live count
  increased 0 → 2460, maximum heartbeat gap 0.136 seconds. Final screenshot
  was explicitly taken on Devices. Capture stopped only during test cleanup.
- Final discovery answered from three local addresses and returned one name:
  router advertised **R8000 (Gateway)** / **R8000**, manufacturer NETGEAR.
- Fourteen local identities included current observations and existing kernel
  neighbor bindings; this does NOT mean fourteen clients were currently online.
  Cached, quiet neighbors appear Inactive.
- Earlier live source runs and the installed 1.5.0 recheck obtained
  **MacBook Pro — MacBook / Mac15,6** on `.4` and `.21`. These addresses did not
  respond to discovery in the final 1.5.1 runs, so no fresh MacBook discovery is
  claimed for those runs. Their matching advertised identifiers suggest one
  physical device, but different MAC identities remain separate in this release.

## PCAP verification

`installed-final/pcap-verification.json`: NetLab and tshark both counted **1941**
packets in the stopped capture. The existing device export selected **91** gateway
packets; tshark also counted **91**. Every exported packet's original bytes
matched its corresponding source packet. This export verification used the
installed backend, not an automated click of the export dialog.

## Earlier failures retained

The first source GUI trial revealed 256 phantom ARP targets; this was fixed and
regression tested. One installed 1.5.0 trial returned no name-script output and
failed acceptance. A later 1.5.0 trial obtained names but capture was no longer
running at the monitor check; its stop cause was not established. These failed
runs remain recorded. They are not presented as passed acceptance. Two subsequent
installed 1.5.1 live tests passed.

## Limits

Device names/models are self-reported observations, not verified hardware
inventory. Silent, sleeping, isolated or non-advertising devices can remain
Unknown. Nmap OS fingerprint estimates are not exact identity. Active discovery
currently sweeps IPv4 only (maximum 256 addresses, identity queries for up to 64).
IPv6 neighbor observations still participate in the device model. Each elevated
scan is limited to 120 seconds; cancel cannot always immediately signal a
privileged subprocess from an unprivileged desktop. Late session results are
rejected by generation/interface checks. Identity reports are temporary unless
copied, as these acceptance reports have been.

Discovery does not make other Wi-Fi clients' independent traffic visible and
does not decrypt WPA2/WPA3 or HTTPS. No new monitor-mode, spoofing, injection,
MITM, routing or firewall functionality was implemented.

## Exact changed source and project files

- `README.md`
- `debian/changelog`
- `debian/control`
- `pyproject.toml`
- `scripts/accept_discovery.py`
- `src/netlab/__init__.py`
- `src/netlab/analyze/devices.py`
- `src/netlab/analyze/engine.py`
- `src/netlab/analyze/flows.py`
- `src/netlab/gui/main_window.py`
- `src/netlab/gui/pages/devices.py`
- `src/netlab/gui/pages/topology.py`
- `src/netlab/integrations/discovery.py`
- `tests/test_discovery.py`

Additional generated artifacts are under this validation directory and the
normal Debian build directories. This workspace has no Git repository; changes
were checked against the pre-edit backup plus the explicitly edited file list.
