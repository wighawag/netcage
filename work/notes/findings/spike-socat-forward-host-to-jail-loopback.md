---
title: A host-side socat forward into the jail netns reaches the in-jail server loopback-tight and adds NO firewall rule; the podman-exec connect side (ADR-0006-faithful) works and needs a connector binary in the tool image
slug: spike-socat-forward-host-to-jail-loopback
source: 'captured live on this host 2026-07-04 (podman 5.4.2 rootless, netavark/pasta; socat 1.x; a working Tor SOCKS proxy on 127.0.0.1:9050, exit 109.70.100.12 vs host 147.147.37.112). Jail stood up with a locally-built netcage + netcage-dns against docker.io/library/alpine serving a fixed HTTP 200 on :3001 via a busybox `nc -l` loop. All containers removed after; the two forward shapes + the firewall inspection are the probes below.'
---

# Host -> jail forward spike: loopback-tight, adds no OUTPUT/INPUT rule (de-risks the `forward` verb, ADR-0014)

**Verdict: POSITIVE on the forward MECHANISM, with one caveat.** A host-side `socat`
listener whose connect side reaches the in-jail server DOES let the host reach a
server running inside the jail, bound loopback-tight, WITHOUT adding any firewall
rule. The load-bearing "inbound-to-loopback is orthogonal to forced EGRESS" claim
(ADR-0014, `work/notes/observations/host-access-to-in-jail-server-inbound-loopback.md`)
is directly confirmed by firewall inspection. The one thing this spike could NOT
re-confirm in THIS environment is the full three-point forced-egress leak-test
WITH a forward active, because `netcage verify` fails here even with NO forward
(an environment issue, not a forward issue). See the caveat.

## What was proven (direct observations)

### 1. The forward works, and is loopback-tight

Two shapes were tried; BOTH returned the in-jail server's body
(`HELLO-FROM-JAIL-3001`) to a host `curl`, and `ss -ltnp` showed the listener
bound to `127.0.0.1` ONLY (never `0.0.0.0`):

- **Shape A (host nsenter):** `socat TCP-LISTEN:13001,bind=127.0.0.1,fork,reuseaddr EXEC:"nsenter -t <sidecar-pid> -n -U --preserve-credentials socat STDIO TCP:127.0.0.1:3001"`. Works. `-U --preserve-credentials` is required for the rootless netns (same as the pasta-reachback spike). BUT it uses host `nsenter`, which VIOLATES ADR-0006 (podman is the only host dependency; no host nsenter). So Shape A is a fallback, not the recipe.
- **Shape B (podman exec, ADR-0006-faithful):** `socat TCP-LISTEN:13002,bind=127.0.0.1,fork,reuseaddr EXEC:"podman --root <graphroot> exec -i <tool> nc 127.0.0.1 3001"`. Works, and uses ONLY `podman exec` on the host side. This is the recipe the `forward` verb should use.

The listener runs on the HOST (binds the host's `127.0.0.1`); only the CONNECT
side enters the netns. This confirms the review-fix framing: a socat run INSIDE
the netns binding `127.0.0.1` would bind the CONTAINER's loopback and NOT be
host-reachable. The host-listener / netns-connect split matters.

### 2. The forward adds NO firewall rule (the orthogonality claim, confirmed)

`iptables -S OUTPUT` / `-S INPUT` in the shared netns, captured BEFORE and DURING
an active forward, were BYTE-IDENTICAL:

```
OUTPUT:
-P OUTPUT ACCEPT
-A OUTPUT -d 127.0.0.0/8 -p udp -j ACCEPT
-A OUTPUT -d 169.254.1.1/32 -p tcp -m tcp --dport 9050 -j ACCEPT
-A OUTPUT -p udp -j DROP
-A OUTPUT -d 169.254.1.1/32 -j DROP
INPUT:
-P INPUT ACCEPT           <- empty, no INPUT rules, forward or not
```

So the forward touches NEITHER the OUTPUT (egress) chain NOR adds any INPUT
accept. It works purely as a userspace host-process relay: the host-originated
connection is accepted by socat on the host and proxied into the netns via
`podman exec`; the reply returns on that same relay. The kernel's forced-egress
routing (unmarked -> TUN -> tun2socks -> proxy) is never consulted for the
forward's traffic. This is the empirical core of "inbound-to-loopback is
orthogonal to forced egress."

### 3. `--bind 0.0.0.0` binds all interfaces (the LAN path the verb must guard)

Rebinding the SAME host-side socat to `bind=0.0.0.0` (not run to completion
against an off-box client here, but `ss` confirms the all-interfaces bind) is the
only change needed for the LAN case: same relay, `0.0.0.0` instead of
`127.0.0.1`. This confirms the ADR-0014 design that `--bind 0.0.0.0` is a
one-line bind change gated behind an explicit flag + warning, not a different
mechanism.

## The recipe for the `forward` verb (Shape B)

```
# on the host, for the lifetime of `netcage forward <container> <port> [--bind <addr>]`:
socat TCP-LISTEN:<hostport>,bind=<addr default 127.0.0.1>,fork,reuseaddr \
  EXEC:"podman --root <graphroot> exec -i <tool-container> nc 127.0.0.1 <port>"
# Ctrl-C / verb-exit kills socat; nothing persists; no rule was ever added.
```

- `<tool-container>` is resolved from the `netcage.managed` label (ADR-0009).
- `nc 127.0.0.1 <port>` runs INSIDE the tool container's netns (shared with the
  sidecar), so `127.0.0.1:<port>` is the in-jail server.

## Gotchas to carry into `forward-verb-wiring-and-bind`

- **The connect side needs a connector binary IN THE TOOL IMAGE.** The recipe uses
  the tool's busybox `nc`. The SIDECAR image has NO socat and NO nc (checked:
  `which socat` -> NO-SOCAT-IN-SIDECAR). So the verb must NOT assume socat in the
  sidecar; it uses `podman exec -i <tool> <connector>`. If a tool image lacks
  `nc`/socat, the verb needs a fallback (e.g. `socat` shipped via a tiny mounted
  static helper, mirroring how `netcage-dns` is mounted into the sidecar,
  ADR-0006). Decide at verb-build time; recommend: try `nc` then `socat` in the
  tool, and if neither exists, mount a static relay helper.
- **Host nsenter (Shape A) is simpler but is an ADR-0006 violation.** Use Shape B.
- **Loopback bind is the host's loopback** (the listener is a host process), not
  the container's. This is why the split matters.
- **The forward is a plain host userspace process.** Lifetime-bounded by
  construction (kill socat -> gone); no netns/nft/pasta state to unwind. Matches
  ADR-0014's "no persistence" and "does not outlive the verb."

## Caveat: the full leak-test WITH a forward could not be re-confirmed HERE

`netcage verify --proxy socks5h://127.0.0.1:9050` FAILED in this environment even
with NO forward involved:

```
[FAIL] forced-egress-exit-ip-differs-from-host: jail produced no exit IP (forced egress may have failed closed)
[FAIL] dns-resolves-over-tcp-glibc: the in-jail DNS forwarder is not answering over TCP
```

The proxy itself IS working (`curl --socks5-hostname 127.0.0.1:9050 https://api.ipify.org`
-> Tor exit `109.70.100.12`, != host `147.147.37.112`). And a manually stood-up
jail showed NO `:53` listener in the netns (the `netcage-dns` forwarder was not
answering). So the leak-test failure is an ENVIRONMENT / DNS-forwarder issue in
this sandbox, NOT caused by the forward. Because the baseline leak-test is red
here independent of the forward, this spike cannot honestly claim "the three-point
leak-test stays GREEN with a forward active" as a live pass.

What it CAN claim, and does, is the mechanism-level guarantee that MAKES the
leak-test irrelevant to the forward: the forward adds no OUTPUT/INPUT rule and is
a userspace host relay, so it cannot alter egress routing (observation 2). The
acceptance task `verify-forward-keeps-egress-tight` should run in an environment
where `netcage verify` is GREEN at baseline and assert it STAYS green with a
forward attached; that is the remaining live confirmation, and it is a
verify-harness assertion, not a blocker on the verb mechanism.

## Teardown evidence

The jail pair (`netcage-run-1783167994505998944-{tool,sidecar}`) was force-removed
(`podman rm -f --depend`, rc=0, confirmed GONE); all host-side socat listeners
killed (`ss` shows no `1300x` listener); no `netcage run` / socat processes left.
Four unrelated 2-hour-old sidecars from earlier runs were deliberately LEFT
untouched (not this spike's to reap). No host firewall rules were ever touched
(all inspection was inside the container netns). (2026-07-04)
