---
title: tooljail — force any tool's egress through a SOCKS5h proxy, fail-closed
slug: tooljail
promptGuidance.testFirst: true
---

> Launch snapshot — records intent at creation, NOT maintained. Current truth: `docs/adr/` (decisions) + the code; remaining work: `work/tasks/ready/` tasks. (The technical-detail sections below are trimmed by `to-task` once the work is tasked — they move into tasks/ADRs and this prd settles to its durable framing: Problem / Solution / User Stories / Out of Scope.)

## Problem Statement

When you run a recon, scanning, or fetching tool and want its traffic to go through a SOCKS5 proxy (Tor, an SSH dynamic tunnel, a remote bastion) so your real IP and DNS queries are not exposed, app-level proxying does not actually contain it. Setting `ALL_PROXY` / `HTTP_PROXY` only works for tools that choose to honor it; raw sockets, libraries that ignore the env, and above all **DNS resolution** escape straight to the host network. The result is a false sense of safety: the tool "uses the proxy" for some requests while leaking your real IP via a side channel and leaking every hostname you look up to your local resolver.

There is no general, tool-agnostic way to take an arbitrary tool and guarantee that **all** of its egress — every TCP connection and every DNS query — is forced through a `socks5h://` endpoint, with no leak path, and with a hard fail-closed guarantee if the proxy is down. The webscan project (the immediate motivating case) orchestrates ~8 external binaries (nuclei, nikto, ffuf, sqlmap, testssl.sh, trivy, gitleaks, semgrep), each with a different proxy story or none; per-tool proxy flags cannot close the DNS and raw-socket leaks.

## Solution

`tooljail`, a Go CLI that confines an arbitrary containerized tool inside a network jail whose ONLY route to the outside is a SOCKS5h redirector. The wrapped tool needs zero proxy awareness: the network layer forces every TCP packet and every DNS query into the proxy, and if the proxy is unreachable, traffic is dropped (fail-closed), never leaked to the host network.

One command shape (podman-native positional grammar: the image is the first positional and the tool command follows it, like `podman run [flags] IMAGE [CMD...]`; the proxy comes from `--proxy` or the `TOOLJAIL_PROXY` env):

```
tooljail run --proxy socks5h://[user:pass@]host:port <image> <tool> <args...>
```

And a first-class proof:

```
tooljail verify --proxy socks5h://...
```

which runs a probe through the same jail and asserts: (1) the observed exit IP is the proxy's, not the host's; (2) a unique hostname resolves through the proxy's resolver, not the host resolver; (3) with the proxy deliberately killed, the probe fails closed (no egress). The leak-test is the project's top acceptance seam: it is what makes "no leaks" a checked property rather than a hope. It is run during development and CI, not on every wrapped invocation.

Built on Podman: a tiny `tun2socks` (gVisor netstack) redirector sidecar (ADR-0001) is the tool container's only route out; the tool container's default route is the sidecar's TUN, so anything the sidecar cannot dial through the proxy has nowhere to go (fail-closed by construction). DNS is remote (`socks5h`) intrinsically, since the sidecar's dialer resolves proxy-side. All UDP is hard-dropped unconditionally (ADR-0003); this does not break DNS, which is proxy-side over TCP. When the proxy is on the host's loopback, the sidecar (and only the sidecar) reaches it via pasta, scoped to exactly the proxy port (ADR-0002). The whole thing wraps any tool, including all of webscan's external binaries, with no changes to them.

## User Stories

1. As an operator, I want to run `tooljail run --proxy socks5h://127.0.0.1:9050 projectdiscovery/nuclei nuclei -u https://target`, so that nuclei scans entirely through my Tor proxy with no IP or DNS leak. (The image is the first positional; a bare name like `nuclei` with no `/`, `:`, `@`, or `.` is read as a command against the default dev image, so name the image explicitly, e.g. `projectdiscovery/nuclei` or `nuclei:latest`.)
2. As an operator, I want a host-loopback SOCKS5h proxy (local Tor, `ssh -D`) to be reachable from inside the jail, so that I do not have to expose a remote proxy just to use the tool.
3. As an operator, I want a remote `socks5h://user:pass@bastion:1080` proxy (with auth) to work identically, so that the same wrapper serves both local and remote tunnels.
4. As a security-conscious user, I want DNS to resolve INSIDE the proxy, so that my local resolver and ISP never see the hostnames I am investigating.
5. As a security-conscious user, I want all non-TCP/DNS egress (UDP, ICMP, raw sockets) hard-dropped rather than leaked, so that a tool that tries to ping or do raw UDP cannot bypass the tunnel.
6. As a security-conscious user, I want the jail to FAIL CLOSED when the proxy is down, so that "the proxy died" results in the tool failing, never in traffic silently escaping to my real network.
7. As an operator, I want `tooljail verify` to prove the three leak assertions (exit IP is the proxy's, DNS goes through the proxy, fail-closed on proxy-kill), so that I can trust the jail without manually testing each tool.
8. As a CI maintainer, I want `verify` to run in CI and gate releases, so that a regression that reintroduces a leak fails the build.
9. As an operator, I want clear teardown: when the tool exits or I Ctrl-C, the sidecar, netns, and nft rules are all removed, so that no half-applied firewall state or orphaned container is left behind (a botched teardown is itself a leak/footgun).
10. As an operator, I want a non-zero exit and a clear message when the proxy is unreachable at startup, so that I know the run did not silently leak or silently no-op.
11. As an operator, I want to pass through mounts and arguments to the wrapped tool (e.g. an output directory, a wordlist), so that the tool is usable for real work, not just a demo.
12. As a webscan user, I want to wrap each of webscan's external binaries with tooljail without modifying webscan, so that the existing scanner gains leak-proof proxying for free.
13. As an operator, I want the redirector image/binary vendored or pinned, so that runs are reproducible and I am not pulling an unaudited image at scan time.
14. As an operator, I want helpful diagnostics when reachback fails (proxy on host loopback not reachable from the jail), so that the most common setup footgun is self-explanatory.

> Implementation and testing detail (redirector mechanism, reachback, UDP policy, the leak-test harness, teardown invariant) has been TASKED — it now lives in `work/tasks/ready/` and the durable _why_ in `docs/adr/` (ADR-0001 tun2socks sidecar, ADR-0002 pasta reachback, ADR-0003 hard-block UDP). Durable framing only remains below.

## Out of Scope (v1)

- **Automated image creation / minimal-setup-from-a-repo (the Q5 ambition):** a default base image that runs an arbitrary repo via a provided-or-generated Nix flake, reusing host-installed deps where possible, to get the minimal setup to run a repo. Deliberately deferred — v1 wraps an existing image. Captured as an idea in `work/notes/ideas/` for later; it is a separate, larger project surface.
- **Wrapping an arbitrary host binary** (mounting a host command into a base image) rather than an existing image — harder to make leak-proof and portable; not v1.
- **Non-Podman runtimes** (Docker, nerdctl) — Podman first; others later if needed.
- **In-process tun2socks** (dropping the sidecar by linking gVisor netstack directly) — a future optimization the Go choice keeps open, not v1.
- **UDP-associate support** (ADR-0003 hard-blocks all UDP in v1; UDP-associate is a future-trigger, not built).

## Further Notes

- Motivating consumer: the `web-app-scanner` / webscan project, whose ~8 external binaries each lack a leak-proof proxy story. tooljail wraps them with no changes to webscan.
- The "jail" framing is deliberate: the security boundary is the kernel (netns + nft), not the language. Fail-closed-by-construction is the whole value proposition.
- Sibling project to `dorfl` (uses the same `work/` contract) but independent and language-different by design.
