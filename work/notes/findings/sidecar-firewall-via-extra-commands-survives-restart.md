---
title: Baking the jail firewall into the sidecar's EXTRA_COMMANDS makes it re-apply on every (re)start, closing the raw-`podman start` bypass leak
slug: sidecar-firewall-via-extra-commands-survives-restart
source: "spiked live against podman 5.4.2 + the pinned tun2socks sidecar (docker.io/xjasonlyu/tun2socks@sha256:aa931665...) + a real host-loopback socks5 proxy (wireproxy on 127.0.0.1:1080), 2026-07-03; commands + outputs in body"
---

## The problem this solves

netcage currently applies the jail firewall (UDP drop, RFC1918 drops,
host-loopback reachback narrowing) and starts the DNS forwarder at RUNTIME via
`podman exec` (ADR-0006). Those exec-applied steps are NOT part of the sidecar
container's definition, so they are LOST on a restart. This matters for the
podman-fidelity-and-lifecycle prd's "leave a reusable jailed container" goal:

- podman AUTO-STARTS a stopped `--network container:` sidecar dependency when you
  `podman start` the tool joined to it (see finding
  podman-network-container-dependency-lifecycle).
- The auto-revived sidecar restores tun2socks routing (its `PROXY=` /
  `TUN_EXCLUDED_ROUTES=` env is baked in at create time), but NOT the
  exec-applied firewall/DNS.
- Result of a raw `podman start <tool>` on a leftover tool (TESTED): public TCP
  still goes through the proxy (routing is baked in), BUT **LAN / RFC1918
  destinations LEAK** (no firewall to drop them: `192.168.1.1:53` was REACHED),
  and DNS is dead. So a raw bypass is NOT fully fail-closed - it violates the
  strict-jail invariant for local/LAN traffic.

## The tun2socks entrypoint runs EXTRA_COMMANDS on EVERY start

Read from the pinned image's `/entrypoint.sh`: `run()` does `create_tun` ->
`create_table` -> `config_route` -> then, `if [ -n "$EXTRA_COMMANDS" ]; then sh
-c "$EXTRA_COMMANDS"; fi` -> then `exec tun2socks ...`. Because `EXTRA_COMMANDS`
is a CONTAINER ENV (set at `podman create`/`run` time), it is retained by the
container and re-executed on EVERY `podman start` - including podman's automatic
dependency-revive. So a firewall passed as `EXTRA_COMMANDS` is self-healing
across restarts, with NO modification to the pinned upstream image (it is a
native env knob of the image netcage already pins).

## Spike result (all reproduced, podman 5.4.2)

Baked the exact netcage firewall (UDP drop + loopback-UDP accept + reachback
narrow + RFC1918 drops) into `EXTRA_COMMANDS` at sidecar create time instead of a
runtime `podman exec`. Then compared the full-jail path vs the raw-bypass path
(host public IP 147.147.37.112, proxy exit IP 188.240.57.227):

| Path | PUBLIC egress | LAN 192.168.1.1:53 |
| --- | --- | --- |
| [A] full netcage jail (firewall in EXTRA_COMMANDS + DNS exec'd) | proxy 188.240.57.227 | DROPPED |
| [B] raw `podman start` bypass (sidecar auto-revived; DNS NOT re-run) | FAILCLOSED (DNS dead) | DROPPED |

So with the firewall in `EXTRA_COMMANDS`, the raw-bypass path is FULLY
fail-closed: LAN dropped, DNS dead (no name resolution), and by-IP public TCP
still forced through the proxy. The LAN leak is closed.

## Implications for the design

- **Move the firewall from `podman exec` (ADR-0006) to the sidecar's
  `EXTRA_COMMANDS` env** so it is re-applied on every (re)start. This is the
  fail-closed-by-default hardening that makes a leftover reusable container safe
  even against a raw `podman start` outside netcage. It REFINES ADR-0006 (the
  sidecar still owns its firewall; it now owns it via a create-time env instead
  of a runtime exec, so it survives restart) - record as a new/superseding ADR.
- **The DNS forwarder is a separate process** (`podman exec -d netcage-dns`), NOT
  re-run by `EXTRA_COMMANDS`, so on a raw bypass DNS stays dead (which is
  fail-closed - names don't resolve). For the SUPPORTED reuse path,
  `netcage start` must re-start the DNS forwarder itself (re-exec it) after the
  sidecar is up. A raw `podman start` that leaves DNS dead is acceptable
  (fail-closed), but `netcage start` is the path that restores full function.
- **`verify` must gain a raw-bypass leak assertion**: after a non-`--rm` run,
  a raw `podman start <tool>` (NOT via netcage) must NOT reach a LAN/RFC1918
  host and must NOT egress DNS - proving the leftover container is fail-closed
  outside netcage. This is the acceptance seam for the hardening.

## RESOLVED by spike: EXTRA_COMMANDS CANNOT fail-close the sidecar (do not rely on it for the failure path)

Spiked 2026-07-03 against the pinned image. The entrypoint's `run()` calls
`sh -c "$EXTRA_COMMANDS"` as a CHILD subshell and does NOT check its exit status
before proceeding to `exec tun2socks`. Consequences, all TESTED:

- A DELIBERATELY-FAILING firewall (`set -e` + a bad `iptables` invocation) prints
  its error but the sidecar STAYS UP and tun2socks starts anyway (the `[STACK]`
  line is reached). `set -e` aborts only the SUBSHELL, not PID 1.
- `kill -TERM 1` / `kill -9 1` from inside `EXTRA_COMMANDS` does NOT abort the
  container (PID 1 = entrypoint.sh ignores the signal, then `exec tun2socks`
  replaces it). `exec sleep infinity` inside the subshell only replaces the
  subshell, not PID 1, so tun2socks still starts.
- So a HALF-APPLIED firewall via `EXTRA_COMMANDS` would leave tun2socks running
  with a partial firewall = a LEAK, and `EXTRA_COMMANDS` has no way to stop it.

The HAPPY path is rock-solid: a VALID firewall via `EXTRA_COMMANDS` re-applies
fully (8/8 rules) on every restart, tested across 5 `podman restart` cycles.
iptables rules do not accumulate (fresh netns each start).

### The fail-loud design (what the build MUST do)

Use a TWO-LAYER guard - do NOT rely on `EXTRA_COMMANDS` alone for fail-closed:

1. **`EXTRA_COMMANDS` self-heals the firewall on every (re)start** (the proven
   happy-path mechanism) - this is what closes the raw-`podman start` LAN/UDP
   leak on a bypass restart.
2. **netcage's own run/start path VERIFIES the firewall after the sidecar is up**
   (a `podman exec ... iptables -S` probe asserting the exact expected rule set),
   and ABORTS the jail loudly (fail-closed, tear down) if the rules are missing
   or partial. This is the Go-side exit-code check that the CURRENT code already
   gets for free from `podman exec`; it MUST be preserved as an explicit
   post-(re)start verification now that the firewall moved into `EXTRA_COMMANDS`.
   Both `netcage run` and `netcage start` run this verification.
3. The ONLY unguarded path is a raw `podman start` OUTSIDE netcage (no netcage
   process to verify). There, the happy-path `EXTRA_COMMANDS` re-applies the full
   firewall (proven), and a hypothetical firewall FAILURE on that path leaves
   tun2socks running with a partial firewall. To bound THAT residual: the baked
   firewall should be ORDERED so its FIRST effective action is the broadest DROP
   it can be while still letting tun2socks reach the proxy + loopback (so a
   later-rule failure leaves MORE dropped, not more open), and netcage documents
   that the SUPPORTED reuse path is `netcage start` (which verifies), not a raw
   `podman start`. A raw bypass is best-effort-closed, never guaranteed - which is
   acceptable because the supported path IS guaranteed and a bypass is already
   out-of-contract.

Bottom line: `EXTRA_COMMANDS` gives self-healing on restart (closing the LAN/UDP
leak on the happy path); the fail-LOUD guarantee comes from netcage's post-start
firewall VERIFICATION on the run/start paths, NOT from `EXTRA_COMMANDS` aborting.

## DROP-first ordering bounds the residual on a mid-script failure (spiked)

On the ONE unguarded path (a raw `podman start` outside netcage, where netcage's
verification layer does not run), a mid-script firewall FAILURE leaves a partial
chain. The ORDER of the baked rules decides whether that partial chain is more
open or more closed. Spiked 2026-07-03, injecting a failing rule mid-script:

| Ordering | LAN gw (192.168.1.1:53) on partial apply | Public (proxied) |
| --- | --- | --- |
| APPEND-style (RFC1918 drops LAST, current shape) | REACHED (LEAK) | reached |
| DROP-FIRST (broad DROPs before the narrow trailing ACCEPT) | DROPPED | reached |

So ordering the baked firewall so its broad DROPs (all-egress-UDP drop, the
RFC1918/link-local drops, the reachback drop) come BEFORE the narrow trailing
ACCEPTs means a mid-script failure leaves MORE dropped, not more open. It bounds
the raw-bypass residual with ZERO image change - just a rule-order change in the
script netcage already generates.

Happy-path (full success) is UNAFFECTED - tested end-to-end: public egress =
proxy exit IP, LAN dropped, DNS proxy-side. The ONE ordering constraint the spike
surfaced: the proxy-port reachback ACCEPT (and every split-tunnel direct ACCEPT)
MUST precede the `169.254.0.0/16` link-local DROP and the RFC1918 drops
respectively - otherwise the sidecar's own dial to the pasta-mapped proxy
(`169.254.1.1:1080`) or an allowlisted direct is caught by a broad drop. The
current `writeSplitTunnelRules` already emits direct-ACCEPTs before the RFC1918
drops; DROP-first keeps that invariant and adds it for the proxy-port ACCEPT vs
the link-local drop.

This is DEFENSE-IN-DEPTH on the out-of-contract bypass path, NOT the primary
guarantee (that is netcage's verification layer). It does not make a raw bypass
GUARANTEED-closed on failure (only netcage's verify does), but it makes the
failure mode fail SAFER for free. The GUARANTEED-closed-on-failure option (a
rebuilt/wrapped sidecar image with the firewall in a custom entrypoint) is
DECLINED - see ADR `no-custom-sidecar-image-keep-upstream-pin`.
- The split-tunnel allowlist ACCEPT rules (ADR-0005) are part of the same
  firewall script and must move into `EXTRA_COMMANDS` together, so an allowlisted
  reusable container also re-applies its directs on restart.
