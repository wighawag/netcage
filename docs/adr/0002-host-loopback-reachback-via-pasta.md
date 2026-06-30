# Host-loopback reachback via pasta, scoped to the redirector sidecar

**Status:** accepted

When the SOCKS5h proxy listens on the host's `127.0.0.1` (the common case: local Tor or `ssh -D`), the redirector sidecar reaches it via **pasta**, not `slirp4netns` with `allow_host_loopback`. The reachback hole is scoped to the **sidecar only**: the sidecar's netns may reach exactly the host loopback proxy port and nothing else, while the tool container's netns has no host reachback at all (its only route is the TUN, per ADR-0001).

We chose pasta over the originally-leaned slirp4netns because it fits the security requirement better and is the supported default. The requirement is "reach exactly the proxy port and nothing else on the host"; `slirp4netns`'s `allow_host_loopback` is a blunt instrument that maps the gateway to host loopback and has historically been a source of "container reaches host services it should not" concerns. pasta is Podman 5.x's default rootless network mode on netavark and offers more surgical loopback/port forwarding, so it gives a narrower host hole. This is the one decision where the initial lean was reversed after pressure-testing.

## Considered Options

- **pasta (chosen).** Podman's current default; surgical per-port loopback forwarding; narrower host exposure.
- **slirp4netns + `allow_host_loopback` (rejected).** The originally-leaned option, but `allow_host_loopback` is broad (whole host loopback via the gateway), it is the legacy path, and it is the more leak-prone fit for "exactly the proxy port, nothing else."

## Consequences

- This is the single most leak-prone seam in the project, so a **spike confirms** the invariant before the CLI is built around it: the sidecar reaches host `127.0.0.1:<proxyport>` and nothing else on the host, and the tool netns cannot reach host loopback at all. If pasta cannot enforce the narrow scope, this decision must be revisited.
- The mechanism matters only for the **host-loopback proxy** config. A **remote proxy** (`socks5h://user:pass@bastion:1080`) is a normal routable host the sidecar dials over its real outbound, so it needs no special reachback mechanism. The two are treated as distinct reachback configs.
