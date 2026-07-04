---
title: The forward connector must exec into the SIDECAR (pinned image, ships nc), NOT the tool image, which may have no nc/socat/python (v0.8.0 shipped broken for such images)
slug: forward-connector-must-use-sidecar-nc-not-tool
source: 'captured live on this host 2026-07-04 (podman 5.4.2 rootless) against a real running jail whose tool image is localhost/anon-pi/pi-webveil (the motivating anon-pi caller). Probes: `podman exec` connector-availability checks on the tool AND the sidecar, plus end-to-end host curl through socat via each. The pinned redirector image checked with `--entrypoint sh`.'
---

# `netcage forward` connector: use the SIDECAR's `nc`, not the tool image's

**Verdict: v0.8.0's forward is BROKEN for any tool image lacking `nc`.** The
`internal/forward` connector execs `podman exec -i <TOOL> nc 127.0.0.1 <port>`,
but the tool image is ARBITRARY and may ship no `nc`. The real anon-pi image
(`localhost/anon-pi/pi-webveil`, the motivating caller) has NO `nc`, NO `socat`,
NO ncat, NO wget: `netcage forward` there fails with a retry storm:

```
Error: crun: executable file `nc` not found in $PATH ... exited with status 127
```

## Root cause

The connector-in-the-tool-image assumption is wrong: netcage does not control the
tool image. The spike used a busybox-`nc` alpine tool, so `nc` was present; a real
image (node/python/distroless/anon-pi) often is not. My earlier fix that dropped
the `nc`-then-`socat` inline fallback (to fix the socat-EXEC quote bug) left `nc`
as the SOLE connector, so an image without `nc` has no path at all.

## The fix (proven live): exec into the SIDECAR, which netcage OWNS and PINS

The tool joins the SIDECAR's netns (`--network container:<sidecar>`), so
`127.0.0.1:<port>` is the SAME in-jail server from EITHER container. The sidecar
is the netcage-pinned redirector image (`xjasonlyu/tun2socks`, digest-pinned,
ADR-0001/0007), which netcage controls. That image SHIPS a connector:

```
# pinned redirector image, entrypoint overridden:
nc: /usr/bin/nc
busybox: /bin/busybox
socat: none
```

So routing the connect side through the SIDECAR guarantees `nc` for ANY tool
image, needs no `podman cp`, no shipped relay binary, and stays ADR-0006-faithful
(podman exec only). Live-proven end-to-end against the anon-pi jail:

- `socat TCP-LISTEN:P,bind=127.0.0.1,fork EXEC:podman --root <gr> exec -i <SIDECAR> nc 127.0.0.1 <port>` -> host `curl` returns the anon-pi server's real HTML, listener bound `127.0.0.1` only. WORKS.
- The same via the TOOL (`anon-pi` image) -> `nc not found`, status 127. FAILS.

## What must change in `internal/forward`

- **Connector target = the SIDECAR, not the tool.** `resolveManagedTool` already
  yields the run id; build the SIDECAR name (`netcage-run-<id>-sidecar`) for the
  connector's `podman exec`, while STILL requiring the TOOL to be running (the
  tool serves; a stopped tool means nothing to reach). Both share the netns, so
  the connector reaches `127.0.0.1:<port>` via the sidecar.
- **Fail-fast, no storm.** socat `fork` re-spawns the connector per inbound
  connection, so a broken connector (or a not-yet-listening server) produces one
  failed child PER attempt and the listener stays up spewing errors. The verb
  should FAIL LOUD and stop early when the connector cannot run at all (exit 127
  from the exec), rather than looping. At minimum, a preflight `podman exec
  <sidecar> nc` capability probe before binding the host socket turns "storm of
  127s" into one clear error.

## Fallbacks considered (rejected in favour of the sidecar)

- **`podman cp` a python relay script + exec `python3`** — works (proven live on
  the anon-pi image, which has python3), but depends on the tool image having an
  interpreter and adds a cp step. Unnecessary once the sidecar `nc` is used.
- **`podman cp` a shipped static `netcage-relay` binary** — the fully universal
  option (needs nothing from any image), but adds a new release artifact + cp
  wiring. Not needed: the sidecar `nc` already covers every tool image, since the
  sidecar is netcage-pinned. Keep this as the future fallback ONLY if the pinned
  redirector image ever drops `nc`.
- **bash `/dev/tcp`** — needs bash in the image and reintroduces the socat-EXEC
  quoting trap. Rejected.
