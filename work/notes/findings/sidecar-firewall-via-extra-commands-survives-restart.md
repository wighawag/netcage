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

## Caveat / still to confirm during build

- `EXTRA_COMMANDS` runs under `sh -c` WITHOUT `set -e` (the entrypoint does not
  add it), so a partially-applied firewall would NOT abort the sidecar the way
  the current `podman exec ... sh -c 'set -e; ...'` does. The baked script MUST
  begin with `set -e` itself (and be verified to abort the sidecar start on a
  rule failure) so a half-applied firewall fails the sidecar loudly rather than
  leaking. Confirm the entrypoint's `run || exit 1` actually kills the container
  when `EXTRA_COMMANDS` exits non-zero.
- The split-tunnel allowlist ACCEPT rules (ADR-0005) are part of the same
  firewall script and must move into `EXTRA_COMMANDS` together, so an allowlisted
  reusable container also re-applies its directs on restart.
