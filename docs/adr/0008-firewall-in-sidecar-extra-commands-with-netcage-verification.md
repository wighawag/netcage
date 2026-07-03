# The jail firewall lives in the sidecar's create-time `EXTRA_COMMANDS`, with netcage's post-start verification as the fail-loud layer

**Status:** accepted (refines ADR-0006)

The jail firewall (UDP drop + loopback-UDP accept + host-loopback reachback
narrowing + RFC1918/link-local drops + the split-tunnel ACCEPTs) is now BAKED
into the redirector sidecar's create-time `EXTRA_COMMANDS` container env, set in
`SidecarRunArgs`, instead of being applied once via a runtime `podman exec` after
the sidecar starts (the ADR-0006 shape). The pinned `xjasonlyu/tun2socks` image's
entrypoint runs `EXTRA_COMMANDS` on EVERY start (before it execs tun2socks), so
the firewall re-applies automatically whenever the sidecar (re)starts, INCLUDING
when podman auto-revives a stopped sidecar as the `--network container:`
dependency of a raw `podman start <tool>`. This closes a proven leak: a firewall
applied only at runtime was LOST on such a revive, leaving a leftover tool
started outside netcage with LAN/RFC1918 + UDP reachable (a leak), even though
public TCP still went through the proxy. This refines ADR-0006: the sidecar still
owns its firewall; it now owns it via a create-time env instead of a runtime
exec, so it survives restart.

## Why not rely on `EXTRA_COMMANDS` alone for fail-closed

`EXTRA_COMMANDS` CANNOT fail-close the sidecar (spiked, see
`work/notes/findings/sidecar-firewall-via-extra-commands-survives-restart.md`):
the entrypoint runs `sh -c "$EXTRA_COMMANDS"` as a CHILD subshell and does NOT
check its exit before `exec tun2socks`, so a failing/half-applied firewall leaves
tun2socks running with a partial firewall (a leak); neither `set -e` nor `kill 1`
from inside the subshell can abort PID 1. The happy path is rock-solid (a valid
firewall re-applies fully on every restart, no rule accumulation - the netns is
fresh each start), but the FAILURE path is not self-guarding. So we use a
TWO-LAYER guard:

1. **`EXTRA_COMMANDS` self-heals the firewall on every (re)start** - the proven
   happy-path mechanism that closes the raw-restart LAN/UDP leak.
2. **netcage VERIFIES the firewall after the sidecar is up** (`verifyFirewall`: a
   `podman exec ... iptables -S OUTPUT` / `ip6tables -S OUTPUT` probe asserting
   the exact expected rule set) and aborts the jail LOUDLY (fail-closed,
   teardown) if any rule is missing/partial. This preserves the fail-loud
   guarantee the old runtime `podman exec ... 'set -e; ...'` got for free from its
   Go-side exit-code check. Both `netcage run` and `netcage start` run this
   verification; it is the PRIMARY fail-closed guarantee.

## The DNS forwarder stays a separate process

The `netcage-dns` forwarder is NOT baked into `EXTRA_COMMANDS`; it stays a
separate `podman exec -d` process started by netcage after the sidecar is up. So
a raw `podman start` outside netcage revives the sidecar WITHOUT DNS: names do
not resolve, which IS fail-closed (a dead resolver is not a leak). The supported
reuse path (`netcage start`) re-execs the forwarder to restore full function; a
raw bypass leaving DNS dead is acceptable and out-of-contract.

## Consequences

- A netcage tool container accidentally `podman start`-ed OUTSIDE netcage is
  FAIL-CLOSED: LAN/RFC1918 + UDP dropped, DNS dead, public TCP still forced
  through the proxy. This is the security foundation the "leave a reusable jailed
  container" work sits on.
- **DROP-first rule ordering** in the baked firewall (spiked) bounds the residual
  on the ONE unguarded path (a raw bypass, where netcage's verification does not
  run) if a rule fails mid-script: the ENABLING accepts (loopback UDP, the
  proxy-port reachback ACCEPT, each split-tunnel direct ACCEPT) come FIRST, then
  ALL the broad DROPs in one contiguous block, so a partial apply leaves MORE
  dropped, not more open. The ordering CONSTRAINT (also spiked): the proxy-port
  ACCEPT must precede the reachback / link-local drop, and every split-tunnel
  direct ACCEPT must precede the RFC1918 drops, else the sidecar's own dial to the
  pasta-mapped proxy or an allowlisted direct is caught by a broad drop. A unit
  test pins this order so it cannot silently regress.
- The whole verification step goes through the Runner seam (podman argv only), so
  ADR-0006's "netcage is a pure podman client" is intact (the `EXTRA_COMMANDS`
  move is if anything MORE pure-podman-client than the runtime exec: the firewall
  is now part of the container's own definition, not a post-start host-driven
  step).
- The decline of a custom sidecar image that would make the raw bypass
  GUARANTEED-closed on a firewall failure is a SEPARATE decision, already recorded
  in ADR-0007 (it destroys the registry-verifiable digest pin, adds a
  build/publish pipeline, and fights ADR-0006). This ADR is the restart-MECHANISM
  decision; ADR-0007 is the image-rebuild-decline decision. DROP-first + netcage's
  verification is the accepted approach.
