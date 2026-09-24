# NetLab v2.0.0 — Interception, Credentials and the Privileged Helper

Status: implemented, built, installed and verified on real Kali 2026.3 / Linux 7.0.
Version: **2.0.0**. Verification date: 2026-09-23.

This is the report for the release that ended NetLab's passive-only era. Phases
1–4 built a capture-and-decode workbench that never put a frame on the wire.
v2.0.0 adds the active half — ARP poisoning, SSL strip, TLS interception,
DNS spoofing, rogue DHCP, traffic rewriting and file carving — behind an
explicit, on-disk, scope-gated engagement, and it adds the Passwords page that
reads credentials and hashes out of the readable protocols on the path.

## What v2.0.0 adds

### The two halves, and the wall between them

`netlab.capture` and `netlab.analyze` still never transmit. Everything that
transmits lives in `netlab.intercept` (the modules) and `netlab.priv` (the
privileged helper). The GUI itself stays unprivileged: it never holds
`CAP_NET_RAW` or `CAP_NET_ADMIN`. Anything that needs them is asked of
`netlab-helper`, started through `pkexec` over a pipe, which owns every raw
socket, every nftables change and every `ip_forward` write.

### Active modules (Interception page)

| Module | What it does | Restored on disarm |
|---|---|---|
| ARP poisoning | Full-duplex: victim told the gateway is at our MAC, gateway told the victim is | yes — and on SIGTERM, pipe close and atexit |
| SSL strip | Rewrites `https://`→`http://` toward the victim, carries the request upstream over real TLS; drops HSTS, `Secure`, SRI | n/a |
| SSL MITM | Terminates TLS with a per-SNI certificate from NetLab's own CA; does not defeat the browser warning | n/a |
| DNS spoofing | Answers matched names with a chosen address; forwards and truthfully answers everything unmatched | n/a |
| Rogue DHCP | Offers leases naming this host as router and resolver | leases expire |
| Traffic changer | Literal/regex find-replace on readable traffic in flight | n/a |
| Cookie killer | Expires a target's cookies once per host to force a fresh login | n/a |
| File carving | Writes readable response bodies to the engagement dir, hashed and typed | n/a |
| Sniffer probe | ARP probes a normal card would filter, to find a host in promiscuous mode | n/a |

### The Passwords page

Cleartext, read as it crossed the wire: FTP, Telnet (reassembled keystroke by
keystroke), POP3/APOP, IMAP, SMTP (SASL PLAIN/LOGIN), NNTP, IRC, Redis, SOCKS5,
rlogin, LDAP simple bind, SNMP communities, MSSQL TDS7 (nibble-swap + `0xA5`
XOR undone), and HTTP Basic/form/cookie.

Challenge/response, emitted crackable and mode-tagged: NetNTLMv2/v1 (SMB, HTTP,
LDAP, MSSQL, SMTP), MySQL native (`-m 11200`), PostgreSQL md5 (`-m 11100`),
Kerberos AS-REQ pre-auth etype 23 (`-m 7500`), HTTP Digest (`-m 11400`), VNC.
A response whose challenge was never captured is reported observed and marked
*not crackable* rather than turned into a hash that would never crack.

### The engagement gate

No active module transmits until an engagement is declared, its hosts named and
the operator confirms authorisation. Scope is enforced in the privileged helper
— not the GUI — and out-of-scope clients are dropped by the proxies, the DNS
spoofer and the DHCP server alike. Every active action is written to a JSONL
audit log that can be attached to a report.

## Tests

- Source suite: **325 passed**, zero failures/skips
  (`QT_QPA_PLATFORM=offscreen NETLAB_LIVE_TESTS=1 python3 -m pytest tests -q`).
- Installed dist-packages suite: **325 passed**, run against
  `/usr/lib/python3/dist-packages` with source `PYTHONPATH` removed.
- The interception tests need no root and touch no real network: the proxies,
  the DNS spoofer and the CA are exercised over loopback, the frame builders
  against captured layouts, and the scope gate against the addresses it must
  refuse (`tests/test_intercept.py`). Credential and hash extraction is covered
  by `tests/test_creds.py` and `tests/test_protocols.py`.

## Live end-to-end interception proof

Harness: `scripts/live_intercept_test.py`. Evidence:
`validation/intercept-v2/live-intercept.log`.

The harness builds its own lab — a private bridge and network namespaces on
`10.77.0.0/24` — arms a NetLab engagement scoped to exactly one address inside
it, drives every active module against that address, and tears the lab down.
The engagement never names an interface or address that exists outside the
script. **This run was rootless**, so `AF_PACKET` receive was unavailable and
the harness fell back to *routed* mode: the victim reaches the gateway through
the attacker by route instead of by ARP forgery, which exercises the whole
redirect → proxy → DNS → TLS → credential → teardown path but does not put
poisoned ARP frames on the wire.

**22/22 checks passed.** In order:

- victim reaches the gateway before arming (436 bytes); its ARP entry points at
  the real gateway
- engagement armed: `ip_forward`, `sslstrip`, `ssl-mitm`, `dns-spoof`, redirects
- scope resolved the target's hardware address
- nftables redirects installed: `tcp/80→:18080`, `tcp/443→:18443`, `udp/53→:15353`
- SSL strip rewrote the `https` links; **HSTS removed**, **`Secure` flag
  stripped** from `Set-Cookie`, **SRI attribute removed**
- traffic changer rewrote the body in flight
- form credentials read from the stripped session (2 credentials total);
  HTTP Basic credentials read from the stripped session
- matched DNS name answered with the attacker's address `10.77.0.13`; an
  unmatched name still got its real answer `203.0.113.77`
- TLS terminated with a NetLab-minted certificate and the plaintext read;
  credentials read from inside the TLS session
- a client that does **not** trust the CA still refuses (curl exit 60) — the
  warning is not defeated
- teardown: nftables redirects removed, the `netlab` table gone, `ip_forward`
  restored (`1 → 1`), victim gets the untouched page again
- the audit log recorded the whole engagement: **17 entries, 15 actions**

Real ARP poisoning (the one check skipped in routed mode) is covered by running
the same harness with `AF_PACKET`, i.e. under `sudo` on the host, where it still
builds and confines itself to the private `10.77.0.0/24` lab:

```sh
sudo python3 scripts/live_intercept_test.py
```

## Package

- Path: `/home/erwin/loyiha/netlab_2.0.0_amd64.deb`
- SHA256: `a8b98393c9a7f88bf014fb00a7a330169a5cbec128812d8b7a10a549868dc2bd`
- Installed: `netlab 2.0.0 install ok installed`
- `dpkg -V netlab` is clean; **80** installed Python/SVG files match the package.
- Ships a polkit action `uz.netlab.helper.policy` and the `netlab-helper`
  entry point so the GUI can raise the helper through `pkexec` on demand.

## Exact authored file changes

New `.py` files in 2.0.0 versus 1.5.1, established by diffing the two packages'
file lists (`dpkg-deb -c`). **19 files added, none removed** (50 → 69 modules).
Existing files (`app.py`, `config.py`, `__init__.py`, the DNS/TLS/hosts pages,
`main_window.py`, `debian/changelog`, `pyproject.toml`) were modified to wire in
the new packages and pages and to bump the version.

```text
added	src/netlab/analyze/creds.py          credential + hash extraction
added	src/netlab/analyze/credfmt.py        hashcat/john formatting
added	src/netlab/intercept/scope.py        engagement scope gate
added	src/netlab/intercept/session.py      engagement lifecycle + audit log
added	src/netlab/intercept/arp.py          full-duplex ARP poisoning + restore
added	src/netlab/intercept/proxy.py        SSL strip / SSL MITM / changer
added	src/netlab/intercept/ca.py           per-SNI CA
added	src/netlab/intercept/dns.py          DNS spoof + real forwarding
added	src/netlab/intercept/dhcp.py         rogue DHCP
added	src/netlab/intercept/netcfg.py       ip_forward / nftables / redirects
added	src/netlab/intercept/carve.py        file carving
added	src/netlab/intercept/promisc.py      promiscuous-host probe
added	src/netlab/priv/helper.py            privileged helper (pkexec)
added	src/netlab/priv/protocol.py          helper wire protocol
added	src/netlab/priv/client.py            GUI-side helper client
added	src/netlab/gui/pages/mitmpage.py     Interception page
added	src/netlab/gui/pages/credspage.py    Passwords page
added	src/netlab/gui/pages/changerpage.py  Rules page
added	src/netlab/gui/pages/filespage.py    Files page
```

## Limitations

- **This live run was rootless (routed mode); real ARP-poisoning frames were
  not put on the wire.** Poisoning logic and restore are covered by unit tests
  and by the harness under `sudo`; the rootless run proves everything downstream
  of the redirect.
- NetLab cannot decrypt a TLS session it is not terminating, and does not defeat
  the certificate warning SSL MITM produces on a device that does not trust the
  CA — the harness confirms an untrusting client refuses.
- Active modules transmit only inside an armed, scoped engagement; scope is
  enforced in the helper. Nothing here was run against a real third-party
  network — the proof lab is private namespaces the script builds and destroys.
- SNMP/community, cookie and credential harvesting record values only while
  harvesting is explicitly enabled; the passive default records presence and
  discards the value.
- A challenge/response whose challenge was never seen is reported observed and
  not crackable, not converted into an uncrackable hash.

## Reproduce

```sh
# tests, source tree, including loopback capture tests
env -u PYTHONPATH QT_QPA_PLATFORM=offscreen NETLAB_LIVE_TESTS=1 \
  python3 -m pytest tests -q

# tests against the installed package
env -u PYTHONPATH QT_QPA_PLATFORM=offscreen NETLAB_LIVE_TESTS=1 \
  python3 -m pytest tests -q -o pythonpath=/usr/lib/python3/dist-packages:.

# end-to-end interception in a private lab (rootless routed mode)
python3 scripts/live_intercept_test.py
# add sudo to also exercise real ARP poisoning, still in the private lab
```

---

# v2.1.0 addendum — Intercepter-NG parity pass

Verification date: 2026-09-23. Built, tested; installs over 2.0.0.

Prompted by a feature-by-feature comparison against Intercepter-NG (its side
verified from sniff.su / the published source, NetLab's side from its own
code). This release closes the credential-breadth gap and adds the one active
module Intercepter-NG had that NetLab lacked.

## Added

**Credential parsers** (all passive, all unit-tested offline):

| Protocol | What is read | Crackable |
|---|---|---|
| CVS pserver | scrambled password descrambled with the CVS scramble table | cleartext |
| DC++ / NMDC | `$MyPass` password, nick from `$ValidateNick` | cleartext |
| BNC (IRC bouncer) | `user:password` in the IRC `PASS` line | cleartext |
| RADIUS CHAP | `response:challenge:id` | hashcat `-m 4800` |
| RADIUS PAP | decrypted with the configured shared secret (RFC 2865); otherwise username recorded, password marked encrypted | cleartext if secret known |

The CVS scramble table is the authentic 256-byte table from CVS `src/scramble.c`
(reproduced via git-cvsserver). A test asserts it is an involution
(`SHIFTS[SHIFTS[b]] == b` for all 256 bytes), which fails on any transcription
error. RADIUS PAP decryption and CHAP formatting are tested against
RFC-2865-computed vectors.

**HTTP injection** — the traffic changer gained an `inject` mode: it inserts
content (a script, a banner) into HTML responses before an anchor tag
(default `</body>`; appends if the anchor is absent). It runs in the same
scope-gated, audited rule pipeline as find/replace, and is on the Rules page
beside it.

## Not built (documented gaps, deliberately not claimed done)

These need a real lab or live target to validate, so they are **not** shipped
as working: NTLM relay (SMB/LDAP — the highest-value next step, since NetLab
already parses NetNTLMv1/v2), WPAD, SSH MiTM, ICMP-redirect positioning,
Heartbleed, Kerberos downgrade, an Oracle O5LOGON hash extractor, and chat-
message reconstruction (dead IM protocols).

## Evidence

- Source suite: **336 passed** (was 325; +8 credential tests, +3 injection tests).
- `scripts/live_intercept_test.py`: **22/22** (rootless routed mode), unchanged.
- Package: `/home/erwin/loyiha/netlab_2.1.0_amd64.deb`,
  SHA256 `eea3efb58c13bef5f66b7731b18b8fbd4014eef740f554e44ebb3aa95e0639be`.

## New/changed files

```text
modified  src/netlab/analyze/creds.py      CVS/NMDC/BNC handlers, RADIUS datagram
modified  src/netlab/analyze/credfmt.py    descramble_cvs, parse_radius, decrypt, chap
modified  src/netlab/intercept/proxy.py    ChangerRule mode=inject + anchor
modified  src/netlab/gui/pages/changerpage.py   inject UI, Mode/Anchor columns
modified  src/netlab/gui/pages/settingspage.py  RADIUS shared-secret field
modified  src/netlab/config.py             radius_secret default
modified  tests/test_creds.py              +8 tests (CVS/NMDC/BNC/RADIUS)
modified  tests/test_intercept.py          +3 tests (HTTP injection)
```
