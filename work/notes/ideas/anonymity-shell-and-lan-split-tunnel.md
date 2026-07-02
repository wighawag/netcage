---
title: Anonymity shell (no tool in mind) + split-tunnel LAN allowlist exceptions
slug: anonymity-shell-and-lan-split-tunnel
---

# Anonymity shell + split-tunnel LAN allowlist

Proposed idea, captured 2026-07-01 while tasking `jailed-interactive-repo-run`. NOT tasked; recorded so it does not evaporate. Two related threads, one small (a reframe) and one that pokes a decided invariant (needs its own design/PRD before build).

## Motivating incident (verified, 2026-07-01): an agent bypassed the anonymized path AND leaked identity

The concrete reason this note exists. An agent running UNJAILED on the host, using the `webveil` pi extension (its `web_search`/`web_fetch` route through webveil's controlled, account-free egress: SOCKS/Tor, so searches are anonymous), was asked to search for a GitHub repo. Instead of using the anonymized search path, the agent SIDESTEPPED it and shelled out to `gh` directly. Two leaks in one move:

1. **Egress leak:** `gh` went out over the HOST network, not through webveil's SOCKS egress, so the request came from the real IP.
2. **Identity leak:** `gh` used the host's `gh` CREDENTIALS, so the request was authenticated AS the user (provably identity-linked, not merely IP-linked). This is exactly the "account-bound tool that signs every request with your identity" failure webveil exists to replace.

This was NOT a netcage bug (nothing was jailed at the time); it is the motivating "why jail agents" story. But it teaches a two-axis lesson that directly CONSTRAINS how the config-reuse sub-ask below (Thread 2, sub-ask 2) can be built:

- **Egress-jailing and identity/credential-jailing are ORTHOGONAL axes; both must hold.** The jail solves the EGRESS leak by construction (inside a proper jail there is NO host network, so `gh` is forced through SOCKS or fails closed regardless of the agent's intent). But the jail does NOTHING about the IDENTITY leak if the credentials are present in the jail. A jail that stops the IP leak while carrying the user's `gh`/cloud/API credentials still authenticates as the user: a false sense of safety of exactly the kind this project exists to kill.
- **Therefore "share the home folder" is not just risky, it is SELF-DEFEATING for the anonymity goal.** The very thing to prevent (identity leak) is partly CARRIED IN the home folder (`~/.config/gh`, tokens, keyring, cloud creds). Sharing `$HOME` into the jail re-imports the credential that deanonymizes you, so the network jail buys nothing against the identity axis.
- **Design constraint this imposes:** the jail must start with NO ambient host identity by default. Home-sharing defaults to OFF. If config reuse is offered, it must be a CURATED, credential-free subset (e.g. `~/.pi` and pi extensions only, NEVER `~/.config` wholesale which holds `gh` and cloud creds), or simply not done (require the user to copy/provide config another way). See Thread 2 sub-ask 2 for the fork.

## Thread 1: netcage as an anonymity shell (no tool in mind at the start)

Framing broadening, not new mechanism. netcage's value is not only "wrap a known tool"; it is "give me a jailed environment where ALL egress is forced through SOCKS5h, fail-closed." So a user with NO specific tool in mind can use it to just *do stuff anonymously*: `netcage run -it <default-image> bash` and work in a shell whose every TCP/DNS egress goes through the proxy.

This is already LATENT in the `jailed-interactive-repo-run` slice (interactive TTY + a default dev image = an anonymity shell). So Thread 1 likely needs no new machinery, only a framing update: the parent prd's Problem could broaden from "I found a tool (a repo)" to also "I want to work anonymously in a shell." Worth a small prd/doc touch later; not urgent, not a mechanism change.

## Thread 2: split-tunnel LAN allowlist (the invariant-poking one)

Concrete use case: run an agent harness (e.g. `pi`) INSIDE the jail so its internet egress is anonymized through SOCKS, but let it ALSO reach a trusted LAN service that must NOT go through the proxy, e.g. a `llama.cpp` server on `192.168.1.150` over the LAN. Tor cannot route to RFC1918 anyway, and you would not want it to. Two sub-asks:

1. **Allowlisted direct destinations (split tunnel).** Permit explicitly-named local/trusted destinations (e.g. `192.168.1.150`, or a CIDR) to be reached DIRECTLY, while ALL other egress still goes through SOCKS5h, fail-closed. This is a deliberate, named hole in the jail: "force *internet* egress through SOCKS; permit these explicit destinations direct."
2. **Inherit host config into the jailed harness (reuse the host's home/config).** The specific need: run `pi` (the agent harness) inside the jail and have it reuse ALL of the user's host setup, extensions and config, so it behaves exactly like the host `pi` but with its egress jailed through SOCKS (except for the pre-defined LAN allowlist in sub-ask 1). The mechanism the user has in mind is SHARING THE HOME FOLDER into the container (mount `$HOME`, or the relevant subset, so `~/.pi`, `~/.config`, pi extensions, etc. are picked up verbatim), rather than re-provisioning config inside the jail.

   This overlaps the repo-mount ergonomics already tasked (it is a `-v` mount at heart) BUT carries a distinct, sharper isolation tension that must be designed, not defaulted:

   - **Sharing the WHOLE `$HOME` into a jail that may run an untrusted tool is a serious host-exposure**, and it directly fights the "I do not fully trust this tool" premise that motivates the jail: `$HOME` typically holds SSH keys, cloud/API tokens, shell history, browser/session state, all of which become readable (and, if mounted rw, writable) by whatever runs in the jail. The network is jailed; the FILESYSTEM would not be.
   - **Design fork to decide at PRD time (now informed by the motivating incident above):** (a) full `$HOME` share is REJECTED for the anonymity case, the incident shows it re-imports the identity-leaking credentials the jail is meant to shed; vs (b) a curated allowlist of config paths only (`~/.pi`, pi extensions dir, the specific config the harness needs), explicitly EXCLUDING credential-bearing dirs like `~/.config/gh`, `~/.aws`, `~/.ssh`, the keyring; vs (c) not sharing at all, requiring the user to copy/provide config another way (safest). Likely (b) with read-only mounts, or (c), as the default; full-`$HOME` is not a safe opt-in for an anonymity jail because the point is to shed host identity, not carry it.
   - **Credential-free is the load-bearing constraint (see the motivating incident).** Whatever is shared MUST NOT contain host credentials/tokens, or the jail stops the IP leak while still authenticating as the user. Curating `~/.pi` only is viable if and only if the harness config it contains does not itself pull in tokens.
   - **Note the asymmetry:** this use case (jail MY OWN trusted `pi` so ITS egress is anonymized) is different from the untrusted-repo case (jail a tool I do NOT trust). Home-sharing may be reasonable for the former and dangerous for the latter; the config-reuse feature should make that distinction explicit rather than offering one blanket home-share that is silently unsafe when the jailed thing is untrusted.

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
- Host-config inheritance for a jailed harness (pi extensions): the user's mechanism is SHARING THE HOME FOLDER (mount `$HOME` or a subset). Which config is safe to expose (full `$HOME` vs a curated allowlist like `~/.pi` + extensions vs read-only)? How to avoid leaking host secrets (SSH keys, tokens) into a jail that might run an untrusted tool, i.e. distinguish "jail my OWN trusted pi" (home-share reasonable) from "jail an untrusted tool" (home-share dangerous)? Does it get its own isolation policy separate from the repo-mount ergonomics?
- Does this warrant relaxing ADR-0003's UDP hard-block for allowlisted LAN destinations (e.g. a LAN service that speaks UDP), or stay TCP-only even for directs?
