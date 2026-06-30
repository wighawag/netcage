---
title: pasta reachback narrows to exactly the proxy port (with an in-netns nft drop); ADR-0002 confirmed
slug: spike-pasta-loopback-reachback
source: 'captured live on this host 2026-06-30 (podman 5.4.2 rootless, netavark, pasta/passt; nftables v1.1.3); the spike probes (listener + dialer) + the A/B/C run below. Probe sources in work/tasks/ready/spike-pasta-loopback-reachback/probe/.'
---

# pasta host-loopback reachback, scoped to exactly the proxy port (spike result)

**Verdict: POSITIVE, with a crucial nuance.** ADR-0002 holds: the sidecar can reach EXACTLY the host-loopback proxy port and nothing else, and the tool netns reaches no host loopback at all. BUT the narrowing is NOT done by pasta alone, it is done by an **nft drop rule inside the sidecar netns**. pasta provides the host-loopback REACHABILITY (by address); the nft rule provides the per-port NARROWING. The `jail-run-forced-egress` task must wire BOTH.

## The three assertions, proven

Setup: two throwaway host-loopback TCP listeners, `127.0.0.1:19050` (banner PROXY) and `127.0.0.1:19051` (banner CONTROL), both confirmed free first. A pasta-networked "sidecar" container and a `--network none` "tool" container ran a small dialer against them.

1. **Reachback works (sidecar -> proxy port).** With `--network pasta:--map-host-loopback,169.254.1.1`, the container reached the host's `127.0.0.1:19050` via the mapped address `169.254.1.1:19050`. (Probe A1, B1.)
2. **Narrowing works (sidecar reaches NOTHING else on the host).** By DEFAULT pasta's map is blunt: the container ALSO reached `169.254.1.1:19051` (the control port) — this is exactly the "all host loopback" hole ADR-0002 warned of (Probe A2). After applying an nft drop rule in the sidecar netns allowing only `ip daddr 169.254.1.1 tcp dport 19050`, the control port became UNREACHABLE while the proxy port stayed reachable (Probe B: B0 both reachable -> rule -> B1 reach, B2 blocked). The ONLY change between reachable and blocked was the nft rule, so the narrowing is genuinely what closes the hole.
3. **Tool netns has no host reachback.** A `--network none` container reached NEITHER the mapped address NOR host `127.0.0.1` directly, on any port (Probe C1/C2/C3). The tool's only route is its TUN (per ADR-0001 / the rootless-TUN spike).

## The working recipe (for the jail task to reuse)

**Reachback (sidecar):** podman pasta with an explicit, dedicated host-loopback map address (link-local `169.254.1.1` used here so it is not a real LAN host):

```
podman run --network pasta:--map-host-loopback,169.254.1.1 --cap-add NET_ADMIN ...
```

- The container reaches host loopback services via `169.254.1.1:<port>`. (Default without `--map-host-loopback` maps to the real default gateway, e.g. `192.168.1.1` here — works but ugly; pin an explicit address.)
- A remote proxy (`socks5h://user:pass@bastion:1080`) needs NONE of this — the sidecar dials it over normal outbound; reachback mapping is only for the host-loopback proxy case.

**Narrowing (the leak-proof guarantee):** an nft ruleset in the SIDECAR netns. Applied from the host into the rootless container's userns+netns via:

```
nsenter -t <container-pid> -n -U --preserve-credentials nft -f - <<'EOF'
table inet jail {
  chain out {
    type filter hook output priority 0; policy accept;
    ip daddr 169.254.1.1 tcp dport 19050 accept
    ip daddr 169.254.1.1 drop
  }
}
EOF
```

- `nsenter ... -U --preserve-credentials` is what makes host `nft` work inside the ROOTLESS container netns (the netns is inside the user's userns). Confirmed exit 0.
- In the real jail the sidecar will own this rule itself (it has `CAP_NET_ADMIN`); the `nsenter` form is the spike's way to inject it from the host without adding nftables to the slim image.
- The rule shape that matters: ACCEPT only `daddr <map-addr> tcp dport <proxyport>`, DROP the rest to `<map-addr>`. Generalise the DROP to the whole host map address so no other host-loopback port is reachable.

## Gotchas to carry into the jail task

- **pasta alone is NOT sufficient for the "exactly one port" guarantee.** Its host-loopback map is address-scoped, not port-scoped. The per-port narrowing MUST be an nft rule in the sidecar netns. (This is consistent with ADR-0002's "scoped to the sidecar only" — the scope is enforced, not assumed.)
- **Pin an explicit `--map-host-loopback` address** (e.g. a link-local) rather than relying on the gateway default, so the rule's `daddr` is stable and not a real LAN host.
- **Tool container uses `--network none`** (per the TUN spike) so it has zero host reachback by construction; only the SIDECAR gets the pasta map + the narrowing rule.
- Slim images lack `nft`; the sidecar image must ship nftables (or the rule is applied via the host as in this spike). Decide at jail-build time.

## Teardown evidence

Both host listeners killed and ports `19050`/`19051` released; all containers `--rm`/removed; no leftover containers; the netns nft died with each container. No HOST nft rules were ever touched (all rules were inside container netns). (2026-06-30)
