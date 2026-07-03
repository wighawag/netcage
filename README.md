# netcage

Run any containerized tool with **all of its TCP and DNS egress forced through a SOCKS5h proxy, fail-closed**, so a recon/scan/agent tool cannot leak your real IP or DNS. netcage wraps an existing image + command + a socks5h URL, and ships a `verify` leak-test that proves no traffic escapes the proxy.

The forced egress is done by the **network layer**, not by the tool's own proxy awareness. This is the opposite of app-level `HTTP_PROXY`/`ALL_PROXY` (which raw sockets and DNS ignore, and which therefore leaks). If the proxy is unreachable, traffic is **dropped, never sent to the host network** (fail-closed). That is the whole point of the tool, and the `verify` command exists to prove it.

## Requirements

netcage runs on a **Linux kernel** (see [Platform](#platform) for macOS/Windows, which work through Podman's Linux VM). It needs:

- **Rootless [Podman](https://podman.io/) 5.x** using the **pasta** rootless network backend (Podman 5's default on netavark). The host-loopback reachback and the forced-egress jail are built on it (ADR-0002). Podman is the ONLY runtime tool netcage invokes: the jail's firewall and DNS forwarder run inside the sidecar container via `podman exec` (ADR-0006), so the host needs no `nft`/`nsenter`.
- **`/dev/net/tun`** available to the rootless user (the redirector sidecar is a TUN device).
- A running **SOCKS5h proxy** to send egress through (local Tor, `ssh -D`, a remote SOCKS5 endpoint, ...). Only `socks5h://` is accepted; plain `socks5://` resolves DNS locally and is a leak, so it is rejected.

The redirector sidecar and the default dev image are **pinned by digest** and pulled by Podman on first use; there is nothing extra to install or publish. First run pulls them (and caches them).

netcage ships as two binaries: `netcage` and its DNS-forwarder helper `netcage-dns` (the jail mounts it into the sidecar and runs it there, ADR-0003/0006). The helper must sit next to the `netcage` binary, or on `PATH`, or be pointed at by `NETCAGE_DNS_BIN`, and it must be a **static** build (release builds are; it execs inside the musl-based sidecar image). Without it the jail cannot run. Every install method below places both together.

### Install script (recommended)

```sh
curl -fsSL https://github.com/wighawag/netcage/releases/latest/download/install.sh | sh
```

This detects your architecture (amd64 / arm64 / armv7 / armv6), downloads the latest release, **verifies its sha256 checksum**, and installs **both** `netcage` and `netcage-dns` to `~/.local/bin` (or `/usr/local/bin` if writable). Override with env vars:

```sh
# a specific version, and a custom install dir
curl -fsSL https://github.com/wighawag/netcage/releases/latest/download/install.sh | NETCAGE_VERSION=v0.2.1 PREFIX=$HOME/bin sh
```

The installer is served as a release asset (stable storage). The same script also lives at [`install.sh`](https://github.com/wighawag/netcage/blob/main/install.sh) in the repo; prefer not to pipe to `sh`? Download it, read it, then run it. The armv6/armv7 builds cover older Raspberry Pi models.

### go install

```sh
go install github.com/wighawag/netcage@latest
CGO_ENABLED=0 go install github.com/wighawag/netcage/cmd/netcage-dns@latest
```

`go install` places both in the same `$GOBIN`, so `netcage` finds `netcage-dns` as its sibling. Install **both**: the second one is required for the jail to run. The `CGO_ENABLED=0` on the helper matters: it executes inside the musl-based sidecar container (ADR-0006), which cannot load a glibc-dynamic binary.

### Manual download

Download a prebuilt Linux archive (amd64 / arm64 / armv7 / armv6) from the [Releases](https://github.com/wighawag/netcage/releases) page and extract it. Each archive contains **both** `netcage` and `netcage-dns` side by side; put them on your `PATH` (in the same directory).

## Usage

```
netcage run    [flags] [<image>] [<cmd> <args...>]
netcage verify [--proxy socks5h://[user:pass@]host:port]
```

`run` uses podman-native grammar: the image is the first positional and the tool command + args follow it, like `podman run [flags] IMAGE [CMD...]`.

The proxy is **required**: pass `--proxy socks5h://[user:pass@]host:port` or set `NETCAGE_PROXY` (the flag wins). If neither is set, the run refuses (fail-closed).

### Examples

Run a scanner with its egress anonymized through a local Tor SOCKS proxy:

```sh
netcage run --proxy socks5h://127.0.0.1:9050 \
  docker.io/projectdiscovery/nuclei:latest nuclei -u https://target.example
```

Drop into an interactive shell in a jailed dev environment, working on a local repo (the default dev image is a pinned broad dev base with git + build toolchains):

```sh
netcage run --proxy socks5h://127.0.0.1:9050 -it -v ./my-repo
```

Or shell into a specific image directly:

```sh
netcage run --proxy socks5h://127.0.0.1:9050 -it alpine sh
```

- **Podman-native grammar:** the **first positional is always the image** and the rest is the tool command, exactly like `podman run [flags] IMAGE [CMD...]`. So `run -it alpine sh` means image `alpine`, command `sh`, with no `--` marker and no guessing.
- **Default dev image:** if you give **no** positional image at all (e.g. `run -it -v ./my-repo`), the pinned dev base is used and its own shell runs. The default applies only when no image is supplied.
- **Repo-mount ergonomics:** `-v <repo>` with no target defaults to `<repo>:/work`, and a mount at `/work` with no `-w` defaults the workdir to `/work`, so a repo is worked in without hand-writing `-w`.

### Allowed run flags

`-i`, `-t`, `-it`/`-ti`, `--rm`, `-v`/`--volume host:container[:opts]`, `-w`/`--workdir <dir>`, `-e`/`--env KEY=VALUE`, `-u`/`--user <user>`, `--entrypoint <path>`, and `--allow-direct` (see below).

**`--rm` is netcage-owned:** it makes the run **ephemeral** (both the tool container and its sidecar are removed on exit). **WITHOUT `--rm`** the stopped tool container and its sidecar are **left behind** (inspectable/restartable like `podman run`), kept fail-closed by the jail's baked firewall so a leftover container never has a working un-jailed network. netcage interprets its own `--rm`; it never passes a raw podman `--rm` through.

**Jail-breaching flags are rejected** (`--network`, `-p`/`--publish`, `--dns`, `--privileged`, `--cap-add`, `--device`, `--name`): netcage owns the container network and isolation to keep the jail leak-proof. Any other flag is rejected by default.

## verify: prove it does not leak

`verify` is the trust anchor. It runs a probe through the same jail and asserts three things:

1. the observed **exit IP is the proxy's**, not the host's;
2. a **unique hostname resolves through the proxy's resolver**, not the host's; and
3. with the **proxy killed, the probe fails closed** (no egress to the host network).

```sh
netcage verify --proxy socks5h://127.0.0.1:9050
```

It exits non-zero if any assertion fails, so CI can gate on it. Run it during development/CI, not per use.

## Split tunnel: reach one local service directly

`--allow-direct <IP|CIDR>[:port]` (repeatable) opens a **narrow, guardrailed hole** in the forced egress for specific **RFC1918 / link-local** destinations, so a jailed tool can reach a trusted local service (e.g. a local model at `192.168.1.150:8080`) DIRECTLY over the LAN, while ALL other egress stays forced through the proxy, fail-closed.

```sh
netcage run --proxy socks5h://127.0.0.1:9050 \
  --allow-direct 192.168.1.150:8080 \
  -it -v ./work my/agent-image agent
```

Guardrails (see ADR-0005): **off by default** (an empty allowlist is byte-identical to the strict jail); **private ranges only** (public IPs / hostnames / malformed values are rejected loudly at startup, because a public direct would be a real anonymity leak); **TCP only** (UDP stays hard-dropped even to an allowlisted host, ADR-0003); and everything outside the allowlist stays leak-proof. `verify` proves the jail is still leak-tight for all non-allowlisted traffic when a split tunnel is active.

## Platform

The jail is built on Linux kernel primitives (network namespaces, a per-container TUN, pasta), so netcage always executes against a Linux kernel. On macOS and Windows that kernel is the Linux VM Podman already requires there; netcage runs **inside it**. That is not an extra layer netcage adds: containers on those platforms live in that VM regardless.

### macOS (podman machine)

Run netcage inside the Podman machine VM:

```sh
podman machine ssh
# inside the VM: install netcage (the install script works; the VM is Linux)
curl -fsSL https://github.com/wighawag/netcage/releases/latest/download/install.sh | sh
```

Two seams are VM-boundary-sensitive, both about addresses:

- **A proxy on your Mac's `127.0.0.1`** (local Tor, `ssh -D`) is the *Mac's* loopback, not the VM's. From inside the VM, reach the Mac via the VM's host gateway address (commonly `192.168.127.254` under gvproxy; check your machine's routes) and make sure the proxy listens on an interface the VM can reach (e.g. bind `ssh -D` to `0.0.0.0` or use an SSH reverse tunnel into the VM). Then pass that address as `--proxy`.
- **`--allow-direct`** sees the *VM's* network, not your Mac's LAN. A LAN host may still be routable through the VM's NAT, but the address semantics are the VM's.

`verify` runs inside the VM and proves the same three assertions there; "the host" in its assertions is the VM.

### Windows (WSL2)

Podman on Windows runs in a WSL2 distribution, which is a full Linux kernel with everything the jail needs. Install and run netcage **inside your WSL2 distro** (the install script works there). The same two address seams apply: a proxy on Windows' `127.0.0.1` is reachable from WSL2 via the Windows host address (see `/etc/resolv.conf`'s nameserver or `ip route show default` in the distro, or enable WSL2's mirrored networking mode, which shares localhost), and `--allow-direct` sees the WSL2 network.

### Native ports

There is no VM-free native jail for macOS/Windows and none is planned: those platforms have no container to jail outside the Linux VM, and the kernel primitives (`netns`, TUN-per-container, pasta) plus `verify`'s guarantees do not transfer. Since every jail step now flows through podman alone (ADR-0006), a future native netcage *binary* driving the VM's podman remotely is possible; the jail itself stays in the VM either way.

## Design

The security rationale lives in the ADRs under [`docs/adr/`](docs/adr/):

- **0001** the redirector: a tun2socks sidecar (the jail's only route out).
- **0002** host-loopback reachback via pasta (the most leak-prone seam, scoped to the sidecar only).
- **0003** UDP is hard-blocked (DNS goes proxy-side; other UDP is dropped).
- **0004** the default dev image is a pinned buildpack-deps base.
- **0005** the split-tunnel LAN allowlist is a guardrailed hole in forced egress.
- **0006** the sidecar owns its firewall + DNS forwarder; netcage never uses host nsenter (podman is the only host dependency).

## Development

Unit tests need no runtime and run everywhere:

```sh
go test ./...
```

The jail and `verify` integration tests are behind the `integration` build tag because they stand up a real jail (rootless podman + pasta + `/dev/net/tun`). Run them on a capable Linux host:

```sh
go test -tags integration ./...
```

## License

[AGPL-3.0-only](LICENSE).
