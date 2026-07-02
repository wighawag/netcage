---
title: Split-tunnel LAN allowlist (reach a trusted RFC1918 host directly while all else stays jailed)
slug: split-tunnel-lan-allowlist
taskedAfter: []
---

> Launch snapshot - records intent at creation, NOT maintained. Current truth: `docs/adr/` (decisions) + the code; remaining work: `work/tasks/ready/` tasks. (The technical-detail sections below are trimmed by `to-task` once the work is tasked - they move into tasks/ADRs and this prd settles to its durable framing: Problem / Solution / User Stories / Out of Scope.)

## Problem Statement

I want to run something inside the netcage jail (for example an agent harness like `pi`, or any tool) so that ALL of its internet egress is forced through the SOCKS5h proxy, anonymized and fail-closed. But that same jailed process also needs to reach ONE trusted service on my local network that must NOT go through the proxy, for example a `llama.cpp` server on `192.168.1.150:8080` over the LAN.

Today the jail makes this impossible, by design: the tool container has NO route except the tun2socks TUN, so every packet (including one addressed to `192.168.1.150`) is pushed into the proxy. For a Tor / anonymizing proxy that means the LAN host is unreachable (Tor cannot and must not route to an RFC1918 address). So the user is forced to choose: either jail the process (and lose the LAN service) or run it unjailed (and leak the real IP for its internet traffic). There is no way to say "force the INTERNET through the proxy, but let these specific trusted local destinations through directly."

The tension is real and deliberate: an allowlist is, by definition, a hole in a leak-proof jail, so it must be introduced so tightly that it cannot become the fail-open leak this whole project exists to prevent.

## Solution

A **split-tunnel allowlist**: `netcage run` gains an opt-in flag to name specific trusted destinations (`IP`/`CIDR` + optional port) that are reached DIRECTLY over the real LAN, while ALL other egress stays forced through the SOCKS5h proxy, fail-closed, exactly as today. Empty allowlist (the default) is byte-for-byte today's strict jail.

From the user's perspective:

```
netcage run --allow-direct 192.168.1.150:8080 --proxy socks5h://127.0.0.1:9050 -it <image> sh
```

Inside that jail, `192.168.1.150:8080` is reachable directly over the LAN; everything else (the whole internet, all DNS, every other host) still exits through the proxy or is dropped. A jailed `pi` can talk to a local `llama.cpp` while its web/search/tool egress stays anonymized.

The mechanism is already proven (see `work/notes/findings/spike-split-tunnel-lan-allowlist.md`): netcage adds the allowlisted `HOST/32` to the sidecar's `TUN_EXCLUDED_ROUTES` (so it egresses the real NIC via pasta instead of the TUN) AND an `ip daddr HOST tcp dport PORT accept` nft rule before the fail-closed drops. Both together, and nothing wider. The spike confirmed: the allowlisted host is reachable, a non-allowlisted host on the same LAN is dropped, a public destination still tunnels through the proxy, UDP stays hard-dropped even to the allowed host, and today's default jail already blocks the LAN (so this ADDS a narrow hole, it does not paper over an existing leak).

Guardrails that keep it from becoming a leak (all load-bearing):

- **Off by default.** No `--allow-direct` means today's exact strict jail. The allowlist is opt-in and explicit.
- **RFC1918 / link-local only.** Allowed directs are restricted to private ranges (`10/8`, `172.16/12`, `192.168/16`, `169.254/16`) so a user cannot accidentally allow a PUBLIC IP that would be a real anonymity leak. A public-IP direct, if ever wanted, is a separate louder opt-in, NOT part of this feature.
- **IP / CIDR only, no hostnames.** A LAN hostname cannot resolve through the proxy (DNS is proxy-side, socks5h), and a local-resolver exception would be another hole. Bare IP/CIDR sidesteps it entirely.
- **TCP only.** UDP stays hard-dropped (ADR-0003) even to allowlisted hosts.
- **Still fail-closed for everything else.** The allow rule is an accept for exactly the named `daddr` (+ port) placed BEFORE the drops; it is not a policy flip. Everything not named still goes to the proxy or is dropped.
- **verify proves it stays tight.** The leak-test is extended so that, with an allowlist active, it asserts BOTH that the named directs are reachable AND that the three core leak assertions (exit-IP is the proxy's, DNS is proxy-side, fail-closed on proxy-kill) still hold for all NON-allowlisted traffic. `approve` means "proven leak-tight outside the allowlist," not "the direct host works."

## User Stories

1. As an operator running a jailed agent harness (`pi`) that needs a local model server, I want `netcage run --allow-direct 192.168.1.150:8080 ...` to let the jailed process reach that LAN host directly, so that the harness uses my local `llama.cpp` while ALL its internet egress stays anonymized through the proxy.
2. As a security-conscious operator, I want the allowlist OFF by default (no flag == today's strict jail), so that the leak-proof guarantee is never weakened unless I explicitly ask.
3. As a security-conscious operator, I want allowed directs restricted to RFC1918 / link-local ranges, so that I cannot accidentally allow a public IP that would deanonymize me; a public direct must be a separate, louder opt-in that this feature does not provide.
4. As an operator, I want to specify allowed directs as `IP` or `CIDR` with an optional `:port` (e.g. `192.168.1.150:8080`, `10.0.0.0/24`), and NOT as hostnames, so that no LAN name resolution has to leak or need a resolver exception.
5. As a security-conscious operator, I want everything NOT on the allowlist to still be forced through the proxy or dropped (fail-closed), so that the allowlist is a narrow hole for exactly the named destinations and nothing else (not a fallback path).
6. As a security-conscious operator, I want UDP to remain hard-dropped even to an allowlisted host (ADR-0003), so that the directs are TCP-only and no UDP side channel opens.
7. As a security-conscious operator, I want a non-allowlisted host on the SAME LAN as an allowed one to be BLOCKED, so that allowing `192.168.1.150` does not silently expose the rest of `192.168.1.0/24`.
8. As a CI maintainer, I want `verify` extended so that, with an allowlist active, it proves BOTH that the named directs are reachable AND that the three core leak assertions still hold for all non-allowlisted traffic, so that a split-tunnel run is proven leak-tight, not merely functional.
9. As an operator, I want a clear error if I pass a public IP, a hostname, or a malformed value to `--allow-direct`, so that an unsafe or unparseable allowlist entry fails loud at startup rather than silently doing the wrong thing.
10. As an operator, I want the reachback / diagnostics to make it clear when a direct destination is unreachable on my LAN (vs blocked by the jail), so that I can tell a LAN problem from a jail-policy block.

### Autonomy notes

- **`humanOnly` NOT set (prd-level):** this repo runs no CI / autonomous tasker, so there is nothing to race and no auto-task to block; the flag's sole effect (blocking auto-tasking) would be inert. A human drives the tasking here by circumstance, not by a gate. (If an autonomous tasker were ever added, revisit: this feature deliberately opens a guardrailed hole in the forced-egress invariant, which is the kind of security-critical decomposition a human should drive.)
- **`needsAnswers`:** NOT set. The mechanism is de-risked by a live spike (`work/notes/findings/spike-split-tunnel-lan-allowlist.md`) and the guardrails are decided (see Implementation Decisions). Remaining choices (exact flag spelling, CIDR-vs-single-IP surface, how verify is parameterised) are tasking-time design details with a recorded direction, not blocking ambiguities.

> Tasked 2026-07-01 (human-driven path). The launch-time Implementation Decisions and Testing Decisions have been relocated into the emitted tasks (`allow-direct-cli-parse-and-validate`, `split-tunnel-jail-wiring`, `verify-proves-split-tunnel-tight` in `work/tasks/ready/`), which now own what-to-build and how-to-test. The proven mechanism + the decisive matrix live durably in `work/notes/findings/spike-split-tunnel-lan-allowlist.md`; the split-tunnel decision + guardrails are to be recorded as a new ADR by the jail-wiring task. The durable framing below (Problem / Solution / User Stories / Out of Scope) remains.

## Out of Scope

- **Public-IP direct exceptions.** v1 is RFC1918 / link-local only. Allowing a public IP direct (a real anonymity-leak risk) is deliberately excluded; if ever wanted it is a separate, louder opt-in feature.
- **Hostname allowlist entries.** IP/CIDR only; a LAN-hostname direct would need a local-resolver exception (another hole) and is not built here.
- **UDP directs.** ADR-0003 hard-block stands; directs are TCP-only. A UDP-capable direct is a future-trigger, not this feature.
- **Config-reuse / home-folder sharing for a jailed harness.** Considered and DROPPED as a netcage feature: it is already achievable with the existing `-v` mounts (mount project-local config into the work folder), and sharing the global `~/.pi` / `$HOME` is undesirable anyway (it can carry identity-linking material, keys, even `models.json`), which is self-defeating for anonymity. See `work/notes/ideas/anonymity-shell-and-lan-split-tunnel.md` (Thread 2 sub-ask 2) for the reasoning. No netcage mechanism needed.
- **The anonymity-shell reframe** (netcage as a no-tool-in-mind anonymous shell) is a framing/doc matter already latent in the shipped interactive-shell slice, not part of this network feature.

## Further Notes

- Motivating trail: exploring running a `pi` agent harness jailed (so its web/search egress is anonymized via `webveil` + SOCKS) surfaced the need to still reach a trusted local `llama.cpp`, and the earlier `gh`-bypass incident (see the idea note) sharpened that egress-jailing and identity-jailing are orthogonal. This feature is the egress-split half; the identity half is handled by NOT sharing host credentials (the dropped config-reuse thread).
- Builds directly on the shipped forced-egress jail (`SidecarRunArgs` `TUN_EXCLUDED_ROUTES`, `nftRuleset`, the DNS forwarder) and the leak-test. The `TUN_EXCLUDED_ROUTES` mechanism is the SAME one the proxy reachback already uses; this feature generalises it to a user-named allowlist.
- The spike ran against a real `llama.cpp` on `192.168.1.150:8080` with Tor as the proxy and left no residue.
