# NetLab Phase 2 validation — 2026-09-21

## Status

**NetLab 1.1.0 is installed and installed-package acceptance passed on real
Kali 2026.3.** dpkg reports `netlab 1.1.0 install ok installed`; `dpkg -V netlab`
reports no modified package files. Both GUI acceptance runs imported
`/usr/lib/python3/dist-packages/netlab/__init__.py` on the Wayland desktop.
The installed `/usr/bin/netlab -r` launcher also opened a real PCAP successfully.

The capture architecture remains kernel/libpcap → dumpcap → pcapng → reader →
bounded analysis queue. No active MITM functionality was added.

## Tests and real capture

- Full suite: **166 passed in 2.82 seconds against the installed package**, including real loopback capture.
- Debian build: **164 passed, 2 skipped**; live capture is deliberately disabled
  during package builds. No failing tests.
- wlan0: **82 packets**, matching NetLab, tshark, capinfos and reopened
  PCAP counts. Two TCP flows, two GET requests, two HTTP 200 responses, complete
  chunked bodies of 11,513 bytes each. **26,080 bytes reassembled**, five
  retransmissions and 15 out-of-order segments; zero stream gaps, malformed
  packets or analysis drops.
- Local loopback HTTP: **72 packets**, matching all three readers and
  reopen. Two requests/responses with intentionally split method, status line,
  headers, header terminator and chunked bodies; both 11-byte bodies complete.
- Both runs verify live GUI packet rows, packet → flow relations, connection
  detail, offset-based raw packet reads, saving and reopening the capture.
- The HTTP-only capture filter excludes DNS/TLS. TLS was covered by the protocol
  regression suite and replay of the earlier real mixed capture, not by these
  HTTP acceptance runs.

Evidence: `validation/installed-tests.txt`, `validation/installed-wlan0/acceptance.json`,
`validation/installed-loopback/acceptance.json`, their PCAPs and GUI screenshots.
The acceptance script constructs the actual MainWindow and exercises its capture
and import actions. A separate launcher smoke test is recorded in
`validation/installed-launcher.txt`; clicking the desktop menu itself was not tested.

The first fresh wlan0 run exposed FIN arriving before missing response segments.
The corrected reassembler waits for those bytes; replay recovers both responses
with no gap. That real 72-packet capture is now a mandatory regression fixture,
`tests/fixtures/http_fin_out_of_order.pcapng`.

## Performance and bounds

Five streaming replays of the existing 8,238-packet / 5,850,858-wire-byte mixed
capture: median **92,688 packets/second**, peak process RSS **37,828 KiB**.
Includes capture-file parsing and analysis, excludes GUI and live capture.
This short cached-file workload is not a sustained throughput ceiling or a
comparison with the earlier 60k-packet benchmark. See `validation/benchmark.json`.

Defaults:

| Limit | Value |
|---|---:|
| TCP streams | 20,000 |
| Out-of-order payload per direction | 256 KiB |
| Out-of-order payload per flow (two directions) | 512 KiB |
| Out-of-order segments per direction | 256 |
| Global retained out-of-order payload | 64 MiB |
| Idle expiry | 120 seconds, swept about every 5 seconds |
| HTTP header buffer per direction | 64 KiB |
| TLS handshake buffer per direction | 32 KiB |
| Analysis queue | 200,000 packets |
| Packet row metadata | 100,000 rows |

The 64 MiB limit is **not a whole-process RAM cap**: protocol parser buffers,
queue packet bytes, Python objects and bounded metadata stores are additional.
In-order bytes go directly to parsers. Packet rows retain offsets rather than
packet payloads. Limits cause explicit incomplete/gap reporting; no missing
bytes are fabricated. Retired/evicted stream counters remain cumulative.

## Build and installation

Project: `/home/erwin/loyiha/netlab`; source tree inventory: `PROJECT-TREE.txt`.

Build dependencies: debhelper-compat (=13), dh-python, python3-all,
python3-setuptools, pybuild-plugin-pyproject, python3-pytest,
python3-pyside6.qtwidgets. Runtime: python3, python3-pyside6.qtcore,
python3-pyside6.qtgui, python3-pyside6.qtwidgets, wireshark-common.
Recommended: nmap, python3-pyside6.qtsvg, pkexec. Acceptance also uses tshark.

```sh
cd /home/erwin/loyiha/netlab
dpkg-buildpackage -us -uc -b
sudo apt-get install -y /home/erwin/loyiha/netlab_1.1.0_amd64.deb
```

Package: `/home/erwin/loyiha/netlab_1.1.0_amd64.deb` (108,108 bytes).
SHA-256: `22952162fd273cfdaba2d2708d508eead96162d6d516e70a91528fd1d828ee45`.
Package name/binary: `netlab`; desktop entry: `netlab.desktop`.

To repeat acceptance, run the script without PYTHONPATH so its JSON
records `/usr/lib/python3/dist-packages/netlab/__init__.py`. For installed-only
pytest runs, also override the project's source-path setting with
`python3 -m pytest tests -q -o pythonpath=.`:

```sh
env -u PYTHONPATH QT_QPA_PLATFORMTHEME=generic \
  XDG_CONFIG_HOME=/tmp/netlab-installed-check/config \
  XDG_DATA_HOME=/tmp/netlab-installed-check/data \
  python3 scripts/accept_phase2.py --interface wlan0 \
  --output "$PWD/validation/installed-wlan0"
```

## Known limitations

- No IP fragment reassembly, HTTP/2, HTTP/3, TLS decryption, or visibility into
  TLS 1.3 encrypted certificates. DNS over TCP remains packet-based.
- Midstream captures cannot recover bytes before the first observed sequence.
  Conflicting retransmitted bytes already delivered are not reconsidered.
- Four-tuples are the correlation key; rapid tuple reuse is not a complete
  TCP connection-generation model. HTTP upgrade/CONNECT tunnels are not fully
  modeled as a new protocol session.
- Partial streams abandoned under global memory pressure/expiry remain
  incomplete. A missing tail without a later sequence/FIN cannot be measured.
- Frame MACs can be a router/next-hop MAC; they are not proof of a remote host's
  own interface identity. Names are separate observations, not merged sites.
- Credential values are omitted from derived HTTP records. Original raw PCAPs,
  temporary parsing buffers and raw hex views necessarily contain captured bytes.
- Analysis drops cannot damage dumpcap's disk file, but kernel/dumpcap drops and
  capture truncation remain possible. Matching file counts does not prove that
  every packet on the network was captured.
- Large offline imports use the same bounded queue; check the analysis-drop count.

## Changed files

Python additions/changes compared against the actual Phase 1 Debian package:

```text
src/netlab/__init__.py
src/netlab/analyze/decode.py
src/netlab/analyze/engine.py
src/netlab/analyze/flows.py
src/netlab/analyze/http.py
src/netlab/analyze/reassembly.py
src/netlab/analyze/tls.py
src/netlab/config.py
src/netlab/gui/main_window.py
src/netlab/gui/models.py
src/netlab/gui/pages/connections.py
src/netlab/gui/pages/dashboard.py
src/netlab/gui/pages/hosts.py
src/netlab/gui/pages/live.py
src/netlab/util/bounded.py
```

Additional Phase 2 delivery files: README.md, debian/changelog, debian/rules,
pyproject.toml (version), tests/helpers.py, tests/test_engine.py,
tests/test_reassembly.py, tests/test_http_stream.py, tests/test_fixture_http.py,
tests/test_phase2_regressions.py, tests/fixtures/http_fragmented.pcapng,
tests/fixtures/http_fin_out_of_order.pcapng, scripts/accept_phase2.py,
scripts/benchmark_phase2.py, PHASE2-REPORT.md, PROJECT-TREE.txt and validation/.
The supplied project had no Git repository; only Python package changes could
be independently compared with the installed Phase 1 artifact.
