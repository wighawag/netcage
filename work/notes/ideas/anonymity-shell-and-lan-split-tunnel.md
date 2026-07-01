---
title: Anonymity shell (no tool in mind) + split-tunnel LAN allowlist exceptions
slug: anonymity-shell-and-lan-split-tunnel
---

# Anonymity shell + split-tunnel LAN allowlist

Proposed idea, captured 2026-07-01 while tasking `jailed-interactive-repo-run`. NOT tasked; recorded so it does not evaporate. Two related threads, one small (a reframe) and one that pokes a decided invariant (needs its own design/PRD before build).

## Thread 1: tooljail as an anonymity shell (no tool in mind at the start)

Framing broadening, not new mechanism. tooljail's value is not only "wrap a known tool"; it is "give me a jailed environment where ALL egress is forced through SOCKS5h, fail-closed." So a user with NO specific tool in mind can use it to just *do stuff anonymously*: `tooljail run -it <default-image> bash` and work in a shell whose every TCP/DNS egress goes through the proxy.

This is already LATENT in the `jailed-interactive-repo-run` slice (interactive TTY + a default dev image = an anonymity shell). So Thread 1 likely needs no new machinery, only a framing update: the parent prd's Problem could broaden from "I found a tool (a repo)" to also "I want to work anonymously in a shell." Worth a small prd/doc touch later; not urgent, not a mechanism change.

## Thread 2: split-tunnel LAN allowlist (the invariant-poking one)

Concrete use case: run an agent harness (e.g. `pi`) INSIDE the jail so its internet egress is anonymized through SOCKS, but let it ALSO reach a trusted LAN service that must NOT go through the proxy, e.g. a `llama.cpp` server on `192.168.1.150` over the LAN. Tor cannot route to RFC1918 anyway, and you would not want it to. Two sub-asks:

1. **Allowlisted direct destinations (split tunnel).** Permit explicitly-named local/trusted destinations (e.g. `192.168.1.150`, or a CIDR) to be reached DIRECTLY, while ALL other egress still goes through SOCKS5h, fail-closed. This is a deliberate, named hole in the jail: "force *internet* egress through SOCKS; permit these explicit destinations direct."
2. **Inherit host config into the jailed harness.** Mount/inherit the host's `pi` config + extensions into the jailed harness so it runs with the user's existing setup. Partly overlaps the repo-mount ergonomics already tasked (it is a `-v` mount question), plus an isolation question (which host config is safe to expose to a jailed, possibly-untrusted-tool-running harness).

### Why this contradicts the current design (and must be designed, not bolted on)

- **Directly opposes the core invariant.** The jail's nft ruleset DROPs everything not destined for the redirector, ALL UDP is hard-dropped (ADR-0003), and forced egress is leak-proof BY CONSTRUCTION. An allowlist is, by definition, a leak surface: every allowed destination is a potential deanonymization / exfiltration path (a malicious tool could relay out through an "allowed" LAN host).
- So the concept is NOT "weaken the jail"; it is a **split-tunnel / egress-allowlist** concept that must be introduced coherently against forced-egress + fail-closed, with guardrails, or it silently becomes the fail-open leak this project exists to prevent.

### Guardrails a safe version would likely need (open, to decide at PRD time)

- **Off by default; explicit and narrow.** No allowlist unless the user names it; empty allowlist = today's strict jail.
- **Constrain to non-routable ranges?** Consider restricting allowlisted directs to RFC1918 / link-local so a user cannot accidentally allow a PUBLIC IP that becomes an anonymity leak. (Open: is a public-IP exception ever legitimate? If so it needs a louder opt-in.)
- **Still fail-closed for everything else.** The tool must still be UNABLE to reach the internet except via SOCKS; only the named destinations are direct. The nft ruleset gains an allow rule for `daddr <allowed>` BEFORE the drop, not a policy flip.
- **DNS for allowlisted hosts.** Named LAN hosts vs bare IPs: DNS is proxy-side (socks5h) today; a LAN hostname would not resolve through Tor. Bare IPs sidestep this; hostnames would need a local-resolver exception (another hole). Prefer bare-IP/CIDR allowlist first.
- **Attribution + verify.** The leak-test (`verify`) currently asserts NO egress escapes the proxy; with an allowlist, verify must be taught the allowlist so it asserts "everything EXCEPT the named directs goes through the proxy, and the named directs are reachable" without weakening the three core assertions for the non-allowlisted path.

## Relationship to current work

- Does NOT block or change the three `jailed-interactive-repo-run` tasks now in `tasks/ready/` (podman-shaped CLI, interactive TTY, default image + repo mount). Those stand alone.
- Thread 1 (anonymity shell) is mostly a framing/doc broadening of that slice once it lands.
- Thread 2 (split-tunnel allowlist) is a SEPARATE, larger surface that touches ADR-0003 and the nft ruleset and the leak-test, and should get its own PRD (and likely an ADR recording the split-tunnel decision + guardrails) before any build. Do NOT implement an allowlist as an unscoped flag on the current tasks.

## Open threads (for when this is picked up)

- Is the allowlist bare-IP/CIDR only, or hostnames too (and how does DNS work for an allowlisted LAN hostname without a resolver leak)?
- RFC1918/link-local-only, or arbitrary IPs with a louder opt-in?
- How does `verify` prove the jail is still leak-proof for everything OUTSIDE the allowlist (teach it the allowlist; keep the three assertions for the non-allowed path)?
- Host-config inheritance for a jailed harness (pi extensions): which config is safe to expose, and does it overlap the repo-mount ergonomics or need its own isolation policy?
- Does this warrant relaxing ADR-0003's UDP hard-block for allowlisted LAN destinations (e.g. a LAN service that speaks UDP), or stay TCP-only even for directs?
