# We keep pinning the STOCK upstream tun2socks image by digest; we do NOT build/wrap a custom sidecar image

**Status:** accepted

netcage's redirector sidecar is the stock `docker.io/xjasonlyu/tun2socks`
image, pinned by an immutable `@sha256:` digest (ADR-0001, `internal/redirector`,
`docs/redirector-pin.md`). When we hardened the jail to survive podman's
dependency auto-revive (the firewall now lives in the sidecar's `EXTRA_COMMANDS`
so it re-applies on every restart; see the finding
`sidecar-firewall-via-extra-commands-survives-restart.md`), one residual
remained: on a raw `podman start` OUTSIDE netcage (an out-of-contract bypass of
the supported `netcage start` path), a mid-script firewall FAILURE could leave a
partial firewall, because the image entrypoint runs `EXTRA_COMMANDS` in a child
subshell and does not check its exit before `exec tun2socks` (spiked: neither
`set -e` nor `kill 1` from inside can abort the sidecar).

The tempting way to make that residual GUARANTEED-closed is to build our OWN
sidecar image (`FROM xjasonlyu/tun2socks@sha256:... + COPY firewall + a custom
entrypoint that fail-closes`). **We decline that route.** We instead bound the
residual with a zero-infrastructure change (DROP-first rule ordering, below) and
keep netcage's PRIMARY fail-closed guarantee where it already is: netcage's own
post-(re)start firewall VERIFICATION on the `run`/`start` paths.

## Why not a custom/wrapped image

- **It destroys the third-party-verifiable pin (story 13's whole point).** The
  current digest is the registry's own `Docker-Content-Digest` for stock
  tun2socks: anyone can re-run one documented `curl` against Docker Hub and prove
  netcage runs unmodified upstream bytes. A rebuilt image is OUR artifact, not a
  registry-verifiable upstream one; a reviewer can no longer verify it with a
  public query, and container builds are notoriously non-bit-reproducible.
- **It creates a build+publish+host pipeline that does not exist today.** A
  custom image must live somewhere podman can pull it (a registry namespace or
  shipped with the binary), must be multi-arch (the current pin is a multi-arch
  manifest list resolving per-host), and must be rebuilt+re-pushed+re-pinned on
  EVERY upstream tun2socks release. Today re-pinning is a one-line digest bump.
- **It fights ADR-0006 ("netcage is a pure podman client").** ADR-0006's payoff
  is driving a REMOTE podman (macOS `podman machine`, WSL2) from a native binary.
  A stock public image is pullable from any podman anywhere; a custom image
  reintroduces the "netcage needs its own artifact distribution" coupling
  ADR-0006 removed.
- **The threat it closes is already out-of-contract.** A raw `podman start`
  bypass is explicitly unsupported (the supported reuse path is `netcage start`,
  which verifies the firewall and aborts loudly on a partial apply). On the happy
  path (firewall applies - proven rock-solid across restarts) the bypass is
  already fail-closed. The residual is a DOUBLE-conditional (a firewall failure
  AND a raw bypass), so paying an architectural cost to close it is a bad trade.

## What we do instead

- **Primary guarantee: netcage VERIFIES the firewall after the sidecar is up**
  (an `iptables -S` probe of the exact expected rule set) on both `run` and
  `netcage start`, and aborts the jail loudly (fail-closed, teardown) if the
  rules are missing or partial. This preserves the fail-loud guarantee the
  earlier runtime `podman exec ... 'set -e; ...'` got from its Go-side exit-code
  check.
- **Defense-in-depth: DROP-first rule ordering in the baked firewall.** Order the
  `EXTRA_COMMANDS` firewall so its broad DROPs (all-egress-UDP drop, the
  RFC1918/link-local drops, the reachback drop) come BEFORE the narrow trailing
  ACCEPTs, so a mid-script FAILURE on the one unguarded (raw-bypass) path leaves
  MORE dropped, not more open. Spiked: with append-style ordering a partial apply
  LEAKED the LAN gateway; with DROP-first it was DROPPED. Zero image change.

## Consequences

- The redirector stays the stock, digest-pinned, registry-verifiable upstream
  image; re-pinning stays a one-line digest bump; netcage stays a pure podman
  client (ADR-0006 intact) and remote-podman-ready.
- A raw `podman start` bypass on a firewall FAILURE is bounded (DROP-first) but
  NOT guaranteed-closed - guaranteed-closed exists only on the SUPPORTED paths
  (`run`/`start`), via netcage's verification. This is an accepted, documented
  residual, not an oversight: the bypass is out-of-contract by design.
- One ordering CONSTRAINT the DROP-first design carries: the proxy-port reachback
  ACCEPT and every split-tunnel direct ACCEPT MUST precede the link-local /
  RFC1918 drops respectively, else the sidecar's own dial to the pasta-mapped
  proxy (`169.254.1.1:1080`) or an allowlisted direct is caught by a broad drop.
- If a future requirement genuinely needs a raw-bypass-proof sidecar, this
  decision is revisited deliberately (with the pin/verifiability/distribution
  costs above on the table), not slipped in.
