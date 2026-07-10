---
kind: idea
title: Reach ONE host-loopback service (e.g. a same-host model server) from the jail, directly
slug: loopback-reachback-for-a-host-local-service
status: proposed
relates: [split-tunnel, ADR-0002, ADR-0005]
sibling: anonctl task `loopback-exemption`
---

## The want

Let a jailed tool reach ONE service running on the HOST's `127.0.0.1:<port>` (e.g. a local AI/model server bound to loopback) DIRECTLY, while all other egress stays forced through the proxy fail-closed. Today the only sanctioned way to reach a same-host model is to bind it to `0.0.0.0` and `--allow-direct <host-lan-ip>:<port>`, which exposes the model to the whole LAN and hairpins host-local traffic out the NIC and back. Binding loopback-only and reaching it directly keeps the model private to the host.

This is the sibling of anonctl tasks (`allow-require-explicit-port-and-rename` + `loopback-exemption` in the anonctl repo). anonctl and netcage share the exemption vocabulary and the RFC1918-only guardrail, so the WANT is the same. The MECHANISM is NOT: this note exists because netcage's namespace model makes "reach host loopback" a fundamentally different (and more delicate) problem than anonctl's per-UID nftables port-allow.

## A prerequisite netcage finding (independent of loopback): the all-ports form is a deanonymization leak

While working through this, an existing hole surfaced that applies to netcage's `--allow-direct` too, INDEPENDENTLY of loopback: the port-omitted (bare-IP / all-ports) form. netcage's `--allow-direct 192.168.1.150` opens all TCP (bar clear-DNS ports) to that host directly. If that LAN host runs ANY forwarding proxy on some other port (an `ssh -D` SOCKS on 1080, squid on 3128, Tor SOCKS on 9050, a socat tunnel), the jailed tool can dial that proxy directly and egress to the WHOLE internet from the real IP. This is a real leak, not just a wide hole. anonctl is fixing this as a clean break: PORT MANDATORY, the all-ports form removed, and the flag renamed `--allow-direct` -> `--allow`. netcage should do the same to stay aligned (its guardrail lives in `internal/cli/allowdirect.go` + ADR-0005; the all-ports/`!=53` behaviour is in its firewall generation). Recommend: make netcage's direct exemption port-mandatory and rename to `--allow` in lockstep. That also makes the loopback reachback (below) the same exact-host:port shape.

## Why netcage is NOT just "add 127.0.0.1 to --allow-direct"

Two structural facts:

1. **`127.0.0.1` inside the jail is the JAIL's loopback, not the host's.** netcage's `--allow-direct` opens a hole in the FORCED-EGRESS firewall for RFC1918/link-local destinations reached over the jail's route. A `127.0.0.1` there would mean "the tool's own container loopback", which is useless for reaching a HOST service. So a naive "add loopback to the allow-direct guardrail" (which is the whole change on the anonctl side) does NOTHING useful here.

2. **Host reachback is already the single most leak-prone seam, and is deliberately scoped to the SIDECAR only (ADR-0002).** netcage already reaches host `127.0.0.1:<proxyport>` via pasta, but ONLY the redirector sidecar has that reachback, and ONLY to the proxy port; the TOOL netns has NO host reachback at all (its only route is the TUN, ADR-0001). ADR-0002 calls this "the single most leak-prone seam in the project" and requires a spike to confirm the sidecar reaches the proxy port and NOTHING ELSE. Widening this to also expose a host MODEL port to the TOOL is exactly the kind of change that seam was scoped tight to prevent.

So the real question for netcage is: "can we surgically extend the pasta host-loopback reachback to expose ONE additional host `127.0.0.1:<modelport>` to the tool (or via the sidecar), without re-opening the broad host-loopback exposure ADR-0002 deliberately closed?"

## Sketch of the possible mechanisms (to be pressure-tested, not chosen here)

- **A: pasta per-port host-loopback forward to the tool netns.** pasta was chosen precisely for "surgical per-port loopback forwarding" (ADR-0002). If pasta can map host `127.0.0.1:<modelport>` to an in-jail address the tool dials (e.g. the same reachback address the sidecar uses for the proxy port), that reuses the vetted mechanism. Risk: this puts a host-loopback hole on the TOOL netns, which ADR-0002 currently forbids entirely. It must stay exactly one port, TCP-only, and the firewall must still DROP everything else, mirroring `--allow-direct`'s "narrow, everything-else-forced" shape.
- **B: forward THROUGH the sidecar.** Keep the tool netns with no host reachback; instead run a tiny per-port forwarder in the sidecar (which already has host-loopback reachback to the proxy port) that bridges an in-jail address:port to host `127.0.0.1:<modelport>`. This confines the host-loopback exposure to the sidecar, consistent with ADR-0002's "scoped to the sidecar only" invariant, at the cost of an extra hop and a forwarder to own. This is the more conservative option and probably the right default.
- **C: reuse the `forward` verb's plumbing, inverted.** `forward` already stands up a HOST->jail forward (host `<bind>:<hostPort>` -> in-jail `<jailPort>`). This want is the INVERSE (jail -> host loopback). The verb machinery (bind validation, TCP-only, exactly-one-port, loopback-by-default, teardown-on-exit) is a good precedent to mirror for a `--allow-host-loopback <port>` style option, but the data direction and the netns crossing differ, so it is a precedent, not a reuse.

## Guardrail (must mirror the anonctl loopback guardrail's INTENT)

Whatever the mechanism, the guardrail must be the loopback analogue of the RFC1918 one, and STRICTER than `--allow-direct`, because host loopback is where the proxy/control surfaces live:

- **Port MANDATORY**, host FIXED to host-`127.0.0.1` (no all-ports form).
- **Refuse anonymizer/control ports**: the configured proxy port and the conventional Tor/SOCKS/control ports (9050/9150/**9051 control**/1080), and 53 (clear-DNS). Allowing the proxy port would let the tool dial the SOCKS surface directly and bypass the forced path; allowing 9051 is a self-deanonymization vector. This blocklist is load-bearing and belongs in an ADR (mirror anonctl's).
- **TCP only** (UDP stays hard-dropped, ADR-0003), **off by default** (empty allow == byte-identical strict jail, ADR-0005's stance), and **verify-covered**: prove the exempted host-loopback port is reachable from the tool AND that the broad host loopback (and the proxy/control ports) are STILL unreachable, fail-loud if the probe cannot run.

## Naming (shared with anonctl): unified `--allow`

anonctl is collapsing to ONE flag `--allow` (renamed from `--allow-direct`), covering every direct-destination class (LAN, loopback, and any future public opt-in), dispatching on the typed address, with the all-ports form removed. netcage should follow: rename `--allow-direct` -> `--allow` and route by address class, so the two tools' vocabulary stays identical. This is a clean break (no compat alias); at this stage neither tool cares about backward compatibility. The host-vs-jail loopback distinction is handled by DOCS + the branch behaviour, not by a distinct flag name.

## Config surface: ONE flag, class-dispatch (no separate field, no cross-misuse machinery)

Match anonctl's decision: do NOT add a separate flag/field for the host-loopback case. The user types `127.0.0.1:<port>` vs a LAN `<ip>:<port>`, so the destination class is self-evident at the call site; a unified `--allow` (netcage's renamed `--allow-direct`) with internal class-dispatch is simpler and needs no "wrong flag" cross-misuse errors (there is only one flag). The parse routes on the typed address: a jail-LAN destination -> the LAN branch; a host-loopback `127.0.0.1:<port>` -> the host-loopback reachback branch (whatever mechanism A/B/C below wins). Both are exact-host:port (port mandatory, per the prerequisite finding above). The one caveat unique to netcage: `127.0.0.1` here means the HOST's loopback, not the jail's own (which is already freely reachable inside the netns), so the docs and the branch must be explicit that an `--allow 127.0.0.1:<port>` reaches a HOST service via the reachback, not a container-local port.

## Open questions / risks to resolve before this becomes a task

- Does pasta allow a per-port host-loopback forward scoped to exactly one extra port for the TOOL netns without re-opening broad host loopback? (Mechanism A viability; this is the ADR-0002 spike, re-run for a second port.)
- Is the sidecar-forwarder (B) preferable for keeping ADR-0002's "sidecar-only" invariant literally true? What does it cost (extra process, lifecycle, DNS)?
- How does this interact with a REMOTE proxy config (no host-loopback reachback exists in that case, per ADR-0002)? The host model is still on host loopback regardless of proxy locality, so the reachback for the model is orthogonal to the proxy's reachback and may need its own path.
- Verify story: what is the concrete probe that proves "the model port is reachable but the rest of host loopback is not" from INSIDE the jail (image-independently, like `ports` reads `/proc/net/tcp*` via the sidecar)?

## Why capture it now

The want surfaced from an anonctl conversation (running a same-host model for an anonymized coding-agent account) and applies identically to netcage users, but the netcage mechanism is non-obvious and touches the project's most leak-prone seam, so it deserves a considered spike + ADR rather than being bolted onto `--allow-direct`. The paired anonctl change is already written as a task; this note is the netcage counterpart so the two tools' `--allow-*` families evolve coherently.
