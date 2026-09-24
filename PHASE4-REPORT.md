# NetLab Phase 4 — Selected Device Live Monitor

Status: implemented, installed and verified on real Kali 2026.3 / Wayland / wlan0.
Version: **1.3.0**. Verification date: 2026-09-21.

## Workflow and behavior

Devices → select an observed address → **Monitor**. Every row has a Monitor
button, with an additional keyboard-accessible Monitor selected device button.
The Selected Device page shows an evidence-backed icon, IP, observed MAC(s),
hostname/vendor, per-field evidence levels, activity and first/last timestamps.
It exposes only one selected device at a time; the bounded internal registry
supports multiple subscriptions for future use (capacity eight).

The page presents packet/byte totals, five-second rates, active connections and
retained DNS/HTTP/TLS record counts. Tabs contain Live Activity, Active Connections,
DNS, HTTP and TLS. Activity rows use existing packet indices and flow keys, with
exact canonical IP matching for IPv4 and IPv6. OUT means selected-IP source;
IN means selected-IP destination and displays its sending peer; LOCAL means both.
A connection click opens the existing connection/session view. Activity rows also
support double-click connection navigation.

Monitor snapshots join existing analyzer records off the GUI thread. No packet
decoding, second capture, network probing or interception is added. One worker
request can be outstanding at a time, requested by the existing bounded GUI tick
(default 500 ms; configuration clamped to 250–1000 ms). A plain Python queue
returns detached snapshots; a lightweight GUI timer delivers them to Qt models.
Workers never own Qt widgets. Each monitor table displays at most 1,000 retained
rows, with omitted counts shown.

- **Pause** freezes detached rows/counters, while global capture and analysis continue.
- **Resume** refreshes from the current retained analysis; it does not create a new capture.
- **Stop Monitoring** removes the subscription, clears its tables/indicator, and leaves global capture running.
- **Monitor** can restart the retained selection. Selecting another device replaces the single UI subscription.
- Source changes/clear invalidate subscriptions and in-flight generations.
- The status bar shows an evidence-based icon and MONITORING / PAUSED with the selected IP.
- Active uses the existing host policy: observed traffic within 30 seconds. Otherwise Inactive.
- TLS is explicitly labeled encrypted, metadata only. Offered ALPN is labeled offered;
  a negotiated value is not inferred when it is encrypted or absent.
- HTTP uses existing parsed metadata with credential-presence flags, not credential values.
- Export Device Traffic uses the existing source-file PCAP exporter on a worker thread;
  original packet bytes are copied without reconstruction. Raw PCAP naturally retains
  original captured bytes; the monitor adds no credential extraction or credential store.

## Tests

- Source: **214 passed**, zero failures/skips (`validation/phase4/source-tests.txt`).
- Installed package: **214 passed**, zero failures/skips (`installed-tests.txt`).
- Debian build: **212 passed, 2 skipped** (live capture tests disabled only during build).
- Full source and installed suites include real loopback capture tests.
- Sixteen Phase 4 tests cover selection and per-row Monitor activation, exact IPv4/IPv6
  filtering, direction, ingestion-driven counters, DNS/HTTP/TLS correlation, flow IDs,
  active connections/navigation, byte-preserving selected export, pause/resume/stop,
  stale result rejection, source reset, unknown/inactive/evicted hosts, MAC changes
  without cross-IP merges, off-thread work, row bounds and worker/widget lifetime.
- An initial build caught a Qt destruction crash caused by a worker retaining a QWidget.
  It was fixed by queue-based delivery with no worker widget reference. A regression
  explicitly destroys the widget while a worker is pending. The failed build log is
  retained as `build-initial-failed.log`; final build/tests passed.

## Fresh real acceptance

Evidence: `validation/phase4/wlan0/acceptance.json` and `validation/phase4/wlan0.log`.
The installed application imports `/usr/lib/python3/dist-packages/netlab/__init__.py` and runs on `wayland`.
Actual GUI button handlers are activated; only the export save-path dialog is automated.
No fabricated packets or canned success results are used.

Selected `10.0.0.28` is this machine's real wlan0 address. Generated ordinary
DNS queries through its system resolver and HTTP/HTTPS requests. Other observed
endpoints are listed in the JSON; no unobserved peer or phone is claimed as monitored.

- Nine addresses had actual packets at the observed-endpoint checkpoint.
- Monitor packets increased from **0 to 124** at the initial checked snapshot.
- That snapshot contained **124 activity rows**, both IN and OUT,
  **11 active connections**, **14 DNS events**, **1 HTTP transaction**,
  and **4 TLS sessions**. All rows were checked against the selected IP.
- Observed HTTP: `GET httpforever.com`, response **200**.
- Observed TLS: `www.google.com`, **TLS 1.3**, cipher **TLS_AES_256_GCM_SHA384**;
  ALPN offered `h2`, `http/1.1`; selected ALPN not observable. HTTPS payload was not inspected.
- Pause held **301 packets** while capture continued; Resume updated to **421**.
- Selected export: **453 packets** in NetLab, tshark and capinfos. A tshark address
  filter independently confirmed every exported packet belongs to the selected IP.
  Exported packet bytes match the original source's selected-packet prefix exactly.
- Stop Monitoring removed the subscription and cleared rows/indicator. Global capture
  remained running and increased from **465 to 474 packets**.
- Global capture was stopped only during acceptance cleanup. Final analysis had
  **501 packets**, **0 malformed packets**, and **0 analysis drops**.

Screenshots saved (activity, TLS and stopped-state views visually inspected): `monitor-activity.png`, `monitor-connections.png`,
`monitor-dns.png`, `monitor-http.png`, `monitor-tls.png`, `monitor-paused.png`,
`monitor-stopped-capture-running.png`, under `validation/phase4/wlan0/`.

## Package

- Path: `/home/erwin/loyiha/netlab_1.3.0_amd64.deb`
- SHA256: `de144801a1e875390208bffc97af63a051aaffb34ebf62ee77de578682729fe0`
- Installed: `netlab 1.3.0 install ok installed`
- `dpkg -V netlab` is clean; all 59 installed Python/SVG files match final source.
- Package verification JSON, build/install/test logs and capture evidence are in `validation/phase4/`.

## Exact authored file changes

Compared against `/tmp/netlab-phase4-before`; generated caches and Debian staging
files are excluded. New release report and validation artifacts are additional deliverables.

```text
modified	src/netlab/__init__.py
added	src/netlab/analyze/monitor.py
modified	src/netlab/gui/main_window.py
modified	src/netlab/gui/pages/devices.py
added	src/netlab/gui/pages/monitor.py
added	tests/test_phase4.py
added	scripts/accept_phase4.py
modified	pyproject.toml
modified	debian/changelog
added	PHASE4-REPORT.md
```

## Limitations

- Monitoring is scoped to an IP in the current capture, not a proven physical-device identity.
  It does not merge different IPs based on MAC/vendor. Historical MAC observations for
  one IP remain visible; DHCP address reuse is not a physical-device identity tracker.
- Silent or otherwise invisible devices cannot be monitored. The real acceptance selected
  this host's observed traffic; other-device interception was neither added nor tested.
- Counters cover current capture/retained analysis, not only the time after pressing Monitor.
  Protocol counts and resumed history depend on existing bounded stores. Older records can
  be evicted; an evicted host displays Inactive/Unknown rather than invented identity/counters.
- IPv6 exact filtering/direction is covered by regression tests; this live acceptance used IPv4.
- Activity is per observed packet. Flow-derived domain labels are correlated metadata,
  not proof that every packet in a reused tuple has the same application identity.
- No encrypted payload visibility, HTTP/2/HTTP/3 decoding, TLS decryption, active interception,
  certificate bypass or new traffic-injection functionality is provided. Existing parser
  limitations remain. Raw capture export preserves original bytes.
- This is a short functional real-network acceptance, not a sustained-load performance benchmark.

## Reproduce

```sh
env -u PYTHONPATH QT_QPA_PLATFORM=offscreen QT_QPA_PLATFORMTHEME=generic \
  NETLAB_LIVE_TESTS=1 python3 -m pytest tests -q -o pythonpath=.
env -u PYTHONPATH QT_QPA_PLATFORMTHEME=generic \
  XDG_CONFIG_HOME=/tmp/netlab-p4-repeat/config \
  XDG_DATA_HOME=/tmp/netlab-p4-repeat/data \
  python3 scripts/accept_phase4.py --output /tmp/netlab-p4-repeat/capture
```
