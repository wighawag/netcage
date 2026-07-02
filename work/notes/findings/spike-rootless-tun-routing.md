---
title: Rootless Podman CAN route a container's traffic through a TUN (ADR-0001 confirmed)
slug: spike-rootless-tun-routing
source: 'captured live on this host 2026-06-30 (podman 5.4.2, rootless, netavark, kernel /dev/net/tun crw-rw-rw-); the spike probe + the two-mode run below. The probe sources live in work/tasks/ready/spike-rootless-tun-routing/probe/.'
---

# Rootless TUN routing works under Podman (spike result)

**Verdict: POSITIVE.** ADR-0001's load-bearing assumption holds. Under **rootless Podman 5.4.2 (netavark backend)**, a container given `/dev/net/tun` + `CAP_NET_ADMIN` (inside its user namespace) can create a TUN interface, make it the default route, and have an in-container process's traffic delivered to the TUN fd. The `jail-run-forced-egress` and `vendor-pin-redirector` tasks (which carry `needsAnswers: true` pending this) may now be cleared and built against the recipe below.

## The working recipe

Environment (preflight, all read-only):

- `podman 5.4.2`, `rootless: true`, `networkBackend: netavark`, default `rootlessNetworkCmd: pasta`.
- `/dev/net/tun` present on host as `crw-rw-rw-` (world-rw, so it passes into a rootless container without extra perms).
- `subuid`/`subgid`: `100000:65536` for the user.

The container invocation that worked:

```
podman run --rm \
  --name netcage-spike-tun \
  --network none \
  --device /dev/net/tun \
  --cap-add NET_ADMIN \
  -v <probe-binary>:/tun-probe:ro,z \
  debian:bookworm-slim \
  /tun-probe -mode=wire
```

Key points for the jail task to reuse verbatim:

- **`--device /dev/net/tun`** passes the host TUN device in. No `--privileged` needed.
- **`--cap-add NET_ADMIN`** is sufficient (inside the rootless userns) to `TUNSETIFF`, bring the link up, add an address, and install a route. No other cap was required.
- **`--network none`** is the right shape for the jail: the container has NO podman/pasta networking of its own; its ONLY route out is the TUN it creates. This IS the forced-egress topology (the wrapped tool has nowhere to go except the TUN). (Reachback to a host-loopback proxy is a SEPARATE concern handled by pasta in the sidecar netns; see ADR-0002 / the pasta spike. `--network none` here is for the TOOL container.)
- **No `iproute2` / `ip` binary needed in the image.** The TUN device, address (`10.255.255.1/30`), link-up, and `default dev <tun>` route were all done via the `/dev/net/tun` ioctl (`TUNSETIFF` with `IFF_TUN|IFF_NO_PI`) + raw RTNETLINK (`RTM_NEWADDR`/`RTM_NEWLINK`/`RTM_NEWROUTE`) using only the Go stdlib + `golang.org/x/sys/unix`. `debian:bookworm-slim` was used purely as a rootfs.

## Two gotchas the probe had to solve (record so the jail task does not re-hit them)

1. **A TUN char device is "not pollable".** Wrapping `/dev/net/tun` in an `*os.File` and calling `Read` fails immediately with `read /dev/net/tun: not pollable` (the Go runtime registers the fd with the netpoller, which a TUN does not support). FIX: open with `unix.Open` and read with raw `unix.Read` on the int fd, bounding the blocking read with a `select` + timeout in a goroutine (NOT an fd read deadline, which also does not work on a TUN).
2. **The assertion must be falsifiable.** The first cut "passed" in both modes because the timeout branch returned success for the baseline. FIX: the probe now matches the IP-header destination of the read packet against the off-link target (`203.0.113.7`, TEST-NET-3), and reports BASELINE-OK (no packet without a route) vs WIRED-OK (packet present with the route) distinctly. The two runs differ ONLY in whether the default route was installed, so the WIRED pass genuinely proves routing-through-the-TUN.

## Run evidence (2026-06-30)

```
-mode=assert-only -> "PROBE BASELINE OK: with no route to the TUN, no off-link packet reached the TUN fd" (exit 0)
-mode=wire        -> "PROBE WIRED OK: ... an off-link packet from an in-netns process was observed at the TUN fd (rootless TUN routing works)" (exit 0)
```

Teardown: `--rm` removed the container (and its ephemeral netns/TUN) on exit; `podman ps -a` showed no leftover after each run. No host nft rules, host routes, or host ports were touched (`--network none`).

## Caveats / not-yet-proven by THIS spike

- This proves the TUN ROUTING primitive, not the full tun2socks dial-out. The jail task still wires a real `tun2socks` reading that TUN and dialing the socks5h proxy.
- Reachback (sidecar reaching a host-loopback proxy) is the SEPARATE `spike-pasta-loopback-reachback` spike; this spike used `--network none` and asserted only the TUN path.
- The probe lives as a separate Go module (`netcage.spike/tun-probe`) under the task's sidecar folder so it does not enter the main module's `go build ./...` / verify gate.
