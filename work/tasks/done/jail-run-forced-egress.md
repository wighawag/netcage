---
title: netcage run — forced-egress jail (tun2socks sidecar, fail-closed, UDP-dropped)
slug: jail-run-forced-egress
spec: netcage
blockedBy: [spike-rootless-tun-routing, spike-pasta-loopback-reachback, socks5h-test-fixture, cli-skeleton-and-proxy-parse, vendor-pin-redirector]
covers: [1, 3, 4, 5, 11, 12, 14]
---

> `needsAnswers` cleared 2026-06-30: BOTH spikes returned POSITIVE results. See `work/notes/findings/spike-rootless-tun-routing.md` (rootless TUN routing works with `--device /dev/net/tun --cap-add NET_ADMIN --network none`, no `--privileged`, no `iproute2`) and `work/notes/findings/spike-pasta-loopback-reachback.md` (pasta reachback + an in-netns nft drop narrows to exactly the proxy port). Build against the exact recipes those findings capture. CRUCIAL nuance from the pasta spike: pasta's host-loopback map is ADDRESS-scoped, not port-scoped, so the "exactly the proxy port" guarantee is enforced by an **nft drop rule in the sidecar netns** (allow `daddr <map-addr> tcp dport <proxyport>`, drop the rest), NOT by pasta alone. (Still `blockedBy` the spikes' + the other deps' completion records.)

## What to build

The core vertical: `netcage run` actually jails the wrapped tool's network so EVERY TCP packet and DNS query is forced through the socks5h proxy, fail-closed, with all UDP dropped.

End-to-end thin path, wiring the pieces the prior tasks proved/produced:

- A **tun2socks (gVisor netstack) sidecar** (ADR-0001) is the tool container's ONLY route out; the tool container's default route is the sidecar's TUN. Forced egress, not configured egress — the wrapped tool is proxy-unaware.
- An **nft ruleset DROPs anything not destined for the redirector** (fail-closed): if the sidecar can't dial the proxy, traffic has nowhere to go.
- **ALL UDP is hard-dropped** unconditionally (ADR-0003). DNS still works because it is proxy-side over TCP via socks5h, not client UDP.
- **Host-loopback proxy reachback via pasta** scoped to the sidecar only (ADR-0002): pasta provides host-loopback REACHABILITY (pin an explicit `--map-host-loopback` address), and an **nft drop rule in the sidecar netns** provides the per-port NARROWING (allow only `daddr <map-addr> tcp dport <proxyport>`, drop the rest) — pasta alone is address-scoped, not port-scoped. A remote `socks5h://user:pass@bastion:1080` proxy needs no special reachback (the sidecar dials it over normal outbound).
- **Helpful reachback diagnostic** (story 14): when the host-loopback proxy is not reachable from the jail, emit a clear, self-explanatory message naming the most common footgun — not an opaque connection error.
- **Wrap any existing image unchanged** (story 12): the jail confines an arbitrary image+command with no changes to the tool, which is what lets webscan's binaries be wrapped for free.
- **Pass-through** of mounts and tool args (story 11) so the tool is usable for real work.
- **Run-attributable resources**: the sidecar, netns, nft ruleset, and tool container are labeled/named so they are enumerable as belonging to this run (the seam the `teardown-invariant` task uses to assert zero residue).

Build on the `cli-skeleton-and-proxy-parse` config types; test the forced-egress behaviour against the `socks5h-test-fixture` (assert the probe's exit IP equals the fixture's). This task MUTATES THE SYSTEM (containers/netns/nft) — run with explicit confirmation, not unattended.

(Teardown and the full three-assertion `verify` are SEPARATE tasks — `teardown-invariant` and `verify-leak-test` — that build on this one. This task's own test is the single highest-value assertion: traffic through the jail exits via the proxy.)

## Acceptance criteria

- [ ] Test written FIRST and RED before the wiring: a probe container run through the jail against the `socks5h-test-fixture` observes an exit IP equal to the FIXTURE's exit IP (not the host's), failing until the jail forces egress.
- [ ] The tool container has NO route except the tun2socks sidecar's TUN (forced egress); the wrapped tool needs zero proxy awareness.
- [ ] nft drops everything not destined for the redirector (fail-closed): with the proxy unreachable, the probe gets NO egress (a focused assertion here; the full proxy-kill case is in `verify-leak-test`).
- [ ] ALL UDP from the tool is dropped; DNS still resolves (proxy-side, socks5h).
- [ ] Host-loopback proxy reached via pasta scoped to the sidecar; remote proxy (with auth) works without special reachback.
- [ ] Mounts and tool args pass through to the wrapped tool.
- [ ] An arbitrary existing image+command is wrapped with NO changes to the tool (story 12).
- [ ] When the host-loopback proxy is unreachable from the jail, a clear reachback diagnostic is emitted (story 14), not an opaque error.
- [ ] The sidecar, netns, nft ruleset, and tool container are labeled/named run-attributably so `teardown-invariant` can enumerate them.
- [ ] Tests cover the new behaviour and run against the fixture (deterministic, no real Tor). System-mutating tests isolate to throwaway containers/netns and assert the host is untouched after the run.

## Blocked by

- `spike-rootless-tun-routing`, `spike-pasta-loopback-reachback` (mechanism confirmation; clear `needsAnswers` after they land), `socks5h-test-fixture` (the test harness), `cli-skeleton-and-proxy-parse` (the config + CLI surface), `vendor-pin-redirector` (so the jail consumes the pinned redirector digest, not an unpinned guess).

## Prompt

> Goal: make `netcage run` actually jail the wrapped tool so all TCP + DNS egress is forced through the socks5h proxy, fail-closed, UDP dropped. Read ADR-0001 (tun2socks sidecar), ADR-0002 (pasta reachback), ADR-0003 (hard-block UDP), `CONTEXT.md` (jail, forced egress, fail-closed, redirector, reachback, socks5h), and the prd Solution section.
>
> FIRST and CRITICALLY, check this task against current reality: this task carries `needsAnswers: true` until BOTH spikes land. Read `work/notes/findings/` for the spike results and build against the EXACT recipes they captured (device/cap flags for TUN; pasta invocation for reachback). If either spike returned a negative result, the mechanism this task assumes is dead — route to needs-attention and reconcile the ADR, do NOT build on the stale premise.
>
> This MUTATES THE SYSTEM (containers, netns, nft rules). Do NOT run unattended — explain what you will create and get explicit confirmation before creating containers/netns/nft rules.
>
> Write the probe FIRST (testFirst is ON): run a probe container through the jail against the `socks5h-test-fixture` and assert its exit IP equals the FIXTURE's exit IP, not the host's. Red until forced egress is wired. Then wire the minimum: tun2socks sidecar as the only route, tool default route into the TUN, nft drop of non-redirector traffic, UDP hard-dropped, pasta reachback for the host-loopback case, mount/arg pass-through.
>
> "Done" means the forced-egress probe is green against the fixture, UDP is dropped while DNS still resolves proxy-side, host-loopback and remote (auth) proxies both work, and the system-mutating tests isolate to throwaway containers and leave the host untouched. Teardown and the full three-assertion verify are SEPARATE tasks built on this one. RECORD non-obvious in-scope decisions (nft rule shape, route metric choices) as ADRs or done-record notes per the task-template guidance.

## Requeue 2026-06-30

RESOLVED (2026-06-30, human-confirmed): the two blockers that stopped the prior build are answered. BUILD NOW; do not stop to ask again on these.

1. SYSTEM MUTATION IS PRE-APPROVED for this build. You MAY create/tear-down Podman containers, netns, TUN devices, and nft rules as part of writing + running the tests. You do NOT need to ask a human before mutating the system in this task. Label everything run-attributably (netcage-run-<id>) and tear it ALL down via --rm + defer; leave no residue.

2. TOPOLOGY DECISION = OPTION A (shared netns). Wire it exactly like this:
   - Start the tun2socks sidecar from the pinned digest (redirector.RunPathImageReference()) with: --network pasta:--map-host-loopback,169.254.1.1 --cap-add NET_ADMIN --device /dev/net/tun and env PROXY=socks5h://[user:pass@]<proxyaddr> so the image's own /entrypoint.sh creates the TUN, sets up policy routing, and runs tun2socks against the proxy. For a HOST-LOOPBACK proxy the proxyaddr is the mapped 169.254.1.1:<port>; for a REMOTE proxy it is the real host:port and no --map-host-loopback is needed.
   - Run the wrapped tool container with --network container:<sidecar> so it SHARES the sidecar's netns: the tool's egress hits the TUN and is forced through the proxy, tool stays proxy-unaware (forced egress, not configured egress).
   - NARROWING + FAIL-CLOSED + UDP-DROP via nft applied FROM THE HOST into the shared netns with: nsenter -t <sidecar-pid> -n -U --preserve-credentials nft -f - (the image ships iptables not nft, and the pasta spike proved this nsenter form works rootless). Rules in that shared netns: (a) allow only ip daddr 169.254.1.1 tcp dport <proxyport> accept then ip daddr 169.254.1.1 drop (the reachback narrowing: exactly the proxy port, nothing else on the host); (b) drop all UDP (ADR-0003); (c) the fail-closed default is that the only egress is the TUN, so if tun2socks can't reach the proxy, traffic has nowhere to go.

3. TEST AGAINST THE FIXTURE (deterministic, no real Tor): use internal/socks5hfixture as the host-loopback proxy under test. The highest-value gate assertion: a probe run THROUGH the jail against the fixture observes an exit IP equal to the FIXTURE's exit IP, not the host's. Also assert: UDP dropped while DNS still resolves proxy-side; a remote (auth) proxy works without --map-host-loopback; mounts/args pass through; a clear reachback diagnostic on an unreachable host-loopback proxy (story 14); resources labeled run-attributably for the teardown task.

4. RECIPES ARE IN work/notes/findings/spike-rootless-tun-routing.md and spike-pasta-loopback-reachback.md: follow them verbatim (device/cap flags, the nsenter nft form, the pasta map). Build test-first (the failing probe before the wiring), keep the gate green (the system-mutating tests must isolate to throwaway containers and leave the host untouched after).
