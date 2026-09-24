# NetLab

Network analysis and interception workbench for Kali Linux, with a Qt
(PySide6) GUI. Built around the workflow of Intercepter-NG.

NetLab has two halves, and the split between them is the whole design.

**The passive half** captures with `dumpcap`/libpcap into a real pcap/pcapng
file, then decodes those bytes itself: live traffic, connections, hosts and
devices, DNS, cleartext HTTP, TLS handshake metadata, and the credentials and
hashes that readable protocols hand to anyone on the path. It never puts a
frame on the wire.

**The active half** transmits. ARP poisoning, SSL stripping, TLS interception
with a locally generated CA, DNS spoofing, rogue DHCP, traffic rewriting,
cookie expiry. None of it runs without an *engagement* you declared and
confirmed, and every address it touches is checked against that engagement.

> Active interception is for networks you have been authorised to test.
> NetLab makes that explicit rather than assumed: it will not transmit until
> you have named the hosts in scope and confirmed you may test them, and it
> writes everything it did to an audit log you can attach to a report.

## What it does

### Passive

| | |
|---|---|
| Captures real packets via dumpcap | yes |
| Writes standard pcap/pcapng | yes |
| TCP reassembly, then HTTP/TLS from the byte stream | yes |
| Decodes DNS, mDNS, LLMNR, HTTP, TLS metadata | yes |
| Extracts credentials and hashes from readable protocols | opt-in |
| Decrypts TLS passively | **no — it is not possible** |
| Transmits | no |

### Active (Interception page)

| Module | What it does |
|---|---|
| ARP poisoning | Full-duplex: the target is told the gateway is at our MAC, the gateway is told the target is. Restored on disarm, on exit and on crash. |
| SSL strip | Rewrites `https://` to `http://` toward the target and carries the request upstream over TLS. No warning for the victim — and no padlock. |
| SSL MITM | Terminates TLS with a certificate minted per SNI by NetLab's own CA. Unless that CA is installed on the device under test, its browser warns. NetLab does not work around the warning. |
| DNS spoofing | Answers matching names with an address you choose. Everything unmatched is forwarded to the real resolver and answered truthfully. |
| Rogue DHCP | Offers leases naming this host as router and resolver. The most disruptive module here. |
| Traffic changer | Literal or regex find/replace applied to readable traffic in flight. |
| HTTP injection | Inserts content (a script, a banner) into HTML responses before an anchor tag such as `</body>`. |
| NTLM relay | Relays a target's SMB/NTLM authentication, live, to an in-scope server (SMB2 + SPNEGO), so the target authenticates *you* to it instead of the hash being cracked offline. Fails where SMB signing/MIC is required — NetLab does not defeat it. |
| Cookie killer | Expires the cookies a target presents, once per host, to force a fresh login. |
| File capture | Writes readable response bodies to the engagement directory, hashed. |
| Sniffer probe | ARP probes with destinations a normal card filters, to find another host in promiscuous mode. |

## Credentials and hashes

The Passwords page collects two kinds of thing.

**Cleartext**, read as it crossed the wire:
FTP, Telnet (reassembled from the characters as they were typed), POP3 with
APOP, IMAP, SMTP with SASL `PLAIN` and `LOGIN`, NNTP, IRC, IRC-bouncer (BNC)
`user:password`, Redis, SOCKS5, rlogin, LDAP simple bind, SNMP community
strings, CVS pserver (the scrambled password is descrambled), DC++/NMDC
`$MyPass`, and HTTP Basic, form posts and session cookies. MSSQL is in this
list too: TDS7 does not encrypt the password, it swaps nibbles and XORs with
`0xA5`, which NetLab undoes. RADIUS PAP is decrypted when you give NetLab the
shared secret; without it the username is recorded and the password marked
encrypted.

**Challenge/response**, where both halves were observed and the result is
crackable offline:

| Protocol | Format | hashcat |
|---|---|---|
| NTLMSSP over SMB, HTTP, LDAP, MSSQL, SMTP | NetNTLMv2 | `-m 5600` |
| NTLMSSP, older clients | NetNTLMv1 | `-m 5500` |
| MySQL native auth | `$mysqlna$` | `-m 11200` |
| PostgreSQL md5 | `$postgres$` | `-m 11100` |
| Kerberos AS-REQ pre-auth, etype 23 | `$krb5pa$23$` | `-m 7500` |
| HTTP Digest | `$sip$` | `-m 11400` |
| RADIUS CHAP | `response:challenge:id` | `-m 4800` |
| VNC | `$vnc$` | john `--format=vnc` |

A response whose challenge was never captured is reported as observed and
explicitly marked *not crackable*, rather than being turned into a hash that
would never crack.

`Export hashes` writes them grouped by mode with the command in a comment.

## Two rules that did not change

* **Nothing is invented.** A protocol field that was not observed is shown as
  `—`, never guessed. TLS 1.3 encrypts the certificate, so certificate
  columns stay empty for those sessions and say why.
* **Encrypted stays encrypted, unless you broke it on purpose.** A TLS
  session passing by is labelled `ENCRYPTED` and its payload is counted,
  never read. The only way to see inside one is to run SSL MITM, which
  announces itself to the victim's browser.

## Install

```sh
sudo apt install ./netlab_2.17.1_amd64.deb
```

Then launch **NetLab** from the Applications menu, or run `netlab`.

## Privileges

NetLab runs as a normal desktop user, and stays that way.

**Capture** rights live in `dumpcap`:

```sh
sudo dpkg-reconfigure wireshark-common     # answer "yes"
sudo usermod -aG wireshark $USER           # then log out and back in
netlab --check                             # confirm
```

**Interception** needs `CAP_NET_RAW` and `CAP_NET_ADMIN`, which live in a
separate process: `netlab-helper`. The GUI starts it through `pkexec` the
first time you arm something, talks to it over a pipe, and never holds those
privileges itself. Everything raw — ARP frames, sysctl, nftables, the DHCP
socket — happens there.

When the GUI exits, the pipe closes, and that is the helper's signal to
restore the network and exit. A crashed GUI cannot leave a subnet poisoned.

## Running an engagement

1. Pick the interface in the toolbar.
2. Open **Interception**. Give the engagement a name, and list what is in
   scope — addresses, CIDR blocks, or `10.0.0.20-40` ranges.
3. **Discover hosts** ARP-sweeps the subnet so you can see what is there.
   Select the ones you want and press **Scope to selection**.
4. Tick the modules you want.
5. **Arm interception.** The dialog states the interface, the gateway, the
   hosts, and every module that is about to run. It needs the authorisation
   checkbox and the word `ARM` typed in.
6. Watch **Passwords**, **Files** and the event log fill.
7. **Disarm and restore.** ARP tables go back first, then the redirect
   rules, then the proxies, then packet forwarding.

Everything is written to
`~/.local/share/netlab/engagements/<date>-<name>/audit.jsonl`, one JSON
object per line, alongside the engagement record and any carved files.

### For SSL MITM

Export the CA from the Interception page and install it on the device under
test. Without it, every HTTPS page shows a certificate warning — which is the
correct behaviour, and is the thing this attack has always been detectable
by. Remove the CA from the device when the engagement ends.

## Usage

```sh
netlab                          # GUI
netlab -i wlan0 --start         # start capturing on wlan0 immediately
netlab -i eth0 -f "not port 22" # preload a BPF capture filter
netlab -r capture.pcapng        # open a capture file
netlab --check                  # privileges + interfaces, no display needed
netlab-helper --check           # interception prerequisites (run as root)
```

### Two kinds of filter

* **BPF capture filter** (toolbar) — applied by libpcap *before* packets are
  written. Excluded packets are never captured at all. Validated against
  libpcap before a capture starts.
* **Display filter** (per-page box) — narrows rows already captured, losing
  nothing:

  ```
  ip:10.0.0.5     port:443      proto:tls|http
  host:example.com    -proto:arp     10.0.0.
  ```

## Settings worth knowing

| Setting | Default | Why |
|---|---|---|
| Extract credentials | off | The passive parser records that an `Authorization` or `Cookie` header was *present* and discards the value. Turning this on keeps it, so the Passwords page can show it. |
| Verify upstream certificates | off | On, NetLab refuses to relay to a server whose own certificate does not verify, so a broken upstream is visible rather than masked by the interception. Labs with self-signed services usually want it off. |
| Forward unspoofed DNS to | blank | Blank uses this machine's own resolver. Names with no matching rule get the real answer. |
| Re-poison every | 2 s | Faster keeps the forged binding pinned against the target's own ARP traffic; slower is quieter. |

## What NetLab still will not do

* Decrypt a TLS session it is not terminating.
* Transmit to an address outside the armed engagement — the scope is checked
  in the privileged helper, not in the GUI, and out-of-scope clients are
  dropped by the proxies, the DNS spoofer and the DHCP server alike.
* Hide the certificate warning that SSL MITM produces on a device that does
  not trust its CA.
* Leave the network changed. ARP, `ip_forward`, `send_redirects` and the
  nftables table are restored on disarm, on `SIGTERM`, on pipe close and from
  an `atexit` hook.

## Layout

```
src/netlab/
  capture/     dumpcap control, pcap/pcapng read and write, privileges
  analyze/     decode, flows, reassembly, DNS/HTTP/TLS, creds, credfmt
  intercept/   scope, arp, dns, dhcp, proxy, ca, promisc, carve, session
  priv/        the privileged helper, its protocol and the GUI's client
  gui/         pages, models, theme
```

`netlab.capture` and `netlab.analyze` never transmit. `netlab.intercept` and
`netlab.priv` are the only packages that do.

## Tests

```sh
QT_QPA_PLATFORM=offscreen python3 -m pytest tests/ -q
```

The interception tests do not need root and do not touch a real network: the
proxies, the DNS spoofer and the CA are exercised over loopback, the frame
builders against captured layouts, and the scope gate against the addresses
it is supposed to refuse.

## Licence

MIT. See `LICENSE`.
