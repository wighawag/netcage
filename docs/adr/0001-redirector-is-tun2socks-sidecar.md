# Redirector is a tun2socks (gVisor netstack) sidecar

**Status:** accepted

The jail's only route out is a `tun2socks` sidecar (gVisor user-space netstack, the `xjasonlyu/tun2socks` project, pinned by image/binary digest per user story 13) rather than `redsocks` + an `nft` transparent-redirect. We chose tun2socks because it makes the leak-proof guarantee a property of the *topology* rather than of a set of independently-correct rules: the tool container's default route is the TUN, so if the sidecar is not dialing the proxy there is simply nowhere for packets to go (fail-closed by construction), and `socks5h` remote DNS is intrinsic to the dialer instead of bolted on with a separate dnsmasq/dns2socks shim. `redsocks` is lighter but assembles fail-closed out of separate TCP-redirect, DNS, and drop pieces, and it leaves the default route pointing at a real gateway, so its no-leak property is something you *verify* rather than something that is *true*.

## Considered Options

- **tun2socks sidecar (chosen).** True `socks5h` DNS-through-proxy; default route into the TUN is the only egress; fail-closed is the topology.
- **redsocks + nft transparent redirect (rejected).** Lighter, but DNS-through-proxy needs extra plumbing, the drop ruleset must be provably complete for fail-closed to hold, and a UDP/DNS hole is easy to leave open. Recorded here so it is not re-proposed as "the lighter option" later.

## Consequences

- A `/dev/net/tun` device and `CAP_NET_ADMIN` inside the user namespace are needed to stand up and route the TUN under rootless Podman. This is an assumption, not yet proven, so the **first task is a spike that proves rootless TUN routing works** before the CLI is built around it; if the spike fails, this decision must be revisited.
- The sidecar binary/image is vendored and pinned by digest for reproducibility (no unaudited pull at scan time).
- **In-process tun2socks** (linking gVisor netstack directly and dropping the sidecar) is deliberately kept open as future work, not v1. The Go language choice exists partly to keep that path available.
