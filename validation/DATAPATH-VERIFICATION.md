# Verifying the interception datapath

NetLab's active flagship is: **ARP poison → kernel redirect (nftables) →
transparent proxy**.  This note records how far that path is verified
automatically, what blocks the rest here, and the one command that closes the
gap on real hardware.

## What is verified automatically (no root, no network)

| Layer | How | Tests |
|---|---|---|
| ARP poison frames | Poisoner driven against a fake socket; asserts the two forged frames per target and the healing frames on restore | `tests/test_poison_frames.py` |
| Targeted ARP resolve | `resolve_many()` over a fake socket | `tests/test_arp_resolve.py` |
| Redirect → HTTP/SSL-strip proxy | real proxy over loopback, credentials read back | `tests/test_intercept.py` |
| Redirect → TLS MITM | CA mints a leaf, plaintext read inside | `tests/test_intercept.py` |
| DNS spoof / rogue DHCP / NTLM relay | loopback + captured layouts | `test_intercept.py`, `test_ntlm_relay.py` |
| Scope gate refusing out-of-scope clients | every active module | `test_intercept.py` |

So both ends of the path — the forged frames that start it and the proxies
that terminate it — are covered.  What is **not** covered automatically is a
forged frame actually moving a *real* victim's ARP cache and its packets then
traversing the datapath.

## Why the end-to-end datapath is not automated here

`scripts/live_intercept_test.py` builds its own two-namespace lab and drives
the whole path.  On this host it cannot:

- **AF_PACKET receive returns nothing** inside a veth/bridge namespace on this
  kernel, even as real root — send succeeds, no frame is ever delivered — so
  the script itself detects this and falls back to routed mode.
- **`/run/netns` is not writable** in the sandbox, so even the routed lab
  cannot be built here.

Both are environment limits, not NetLab bugs.

## The one command that closes it

On a real Linux host with two machines on the same L2 segment (physical LAN,
or a KVM/VirtualBox lab with a shared bridge — *not* namespaces on this
kernel), run:

```sh
sudo python3 scripts/live_intercept_test.py
```

It arms an engagement scoped to one address in the lab and proves, in order:

1. the victim reaches the gateway normally before arming
2. ARP poisoning moves the victim's gateway entry onto our MAC
3. redirected :80 lands in the SSL-strip proxy (links rewritten, HSTS/Secure
   dropped)
4. posted credentials are read
5. a spoof-matched DNS name is answered by us; an unmatched one truthfully
6. TLS is terminated with a NetLab-minted cert and the plaintext read
7. disarm restores the ARP entry, `ip_forward` and the nftables table

Save its output beside this file as the datapath proof for a release.
