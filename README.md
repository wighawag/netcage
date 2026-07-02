# tooljail

Run any containerized tool with **all of its TCP and DNS egress forced through a SOCKS5h proxy, fail-closed**, so a recon/scan/agent tool cannot leak your real IP or DNS. tooljail wraps an existing image + command + a socks5h URL, and ships a `verify` leak-test that proves no traffic escapes the proxy.

The forced egress is done by the **network layer**, not by the tool's own proxy awareness. This is the opposite of app-level `HTTP_PROXY`/`ALL_PROXY` (which raw sockets and DNS ignore, and which therefore leaks). If the proxy is unreachable, traffic is **dropped, never sent to the host network** (fail-closed). That is the whole point of the tool, and the `verify` command exists to prove it.

## Requirements

tooljail is **Linux only** (see [Platform](#platform)). It relies on Linux kernel primitives with no cross-platform equivalent:

- **Linux** with network namespaces and **nftables**.
- **Rootless [Podman](https://podman.io/) 5.x** using the **pasta** rootless network backend (Podman 5's default on netavark). The host-loopback reachback and the forced-egress jail are built on it (ADR-0002).
- **`/dev/net/tun`** available to the rootless user (the redirector sidecar is a TUN device).
- A running **SOCKS5h proxy** to send egress through (local Tor, `ssh -D`, a remote SOCKS5 endpoint, ...). Only `socks5h://` is accepted; plain `socks5://` resolves DNS locally and is a leak, so it is rejected.

The redirector sidecar and the default dev image are **pinned by digest** and pulled by Podman on first use; there is nothing extra to install or publish. First run pulls them (and caches them).

## Install

```sh
go install github.com/wighawag/tooljail@latest
```

Or download a prebuilt Linux binary (amd64 / arm64 / armv7 / armv6) from the [Releases](https://github.com/wighawag/tooljail/releases) page. The armv6/armv7 builds cover older Raspberry Pi models.

## Usage

```
tooljail run    [flags] [<image>] [<cmd> <args...>]
tooljail verify [--proxy socks5h://[user:pass@]host:port]
```

`run` uses podman-native grammar: the image is the first positional and the tool command + args follow it, like `podman run [flags] IMAGE [CMD...]`.

The proxy is **required**: pass `--proxy socks5h://[user:pass@]host:port` or set `TOOLJAIL_PROXY` (the flag wins). If neither is set, the run refuses (fail-closed).

### Examples

Run a scanner with its egress anonymized through a local Tor SOCKS proxy:

```sh
tooljail run --proxy socks5h://127.0.0.1:9050 \
  docker.io/projectdiscovery/nuclei:latest nuclei -u https://target.example
```

Drop into an interactive shell in a jailed dev environment, working on a local repo (the default dev image is a pinned broad dev base with git + build toolchains):

```sh
tooljail run --proxy socks5h://127.0.0.1:9050 -it -v ./my-repo bash
```

- A **bare command-shaped** first positional (e.g. `run -it bash`) is taken as the COMMAND, with the default dev image. A first positional that looks like an image (has `/`, `:`, `@`, or `.`) is the image. Force a bare-token image with `run -- alpine sh`.
- **Repo-mount ergonomics:** `-v <repo>` with no target defaults to `<repo>:/work`, and a mount at `/work` with no `-w` defaults the workdir to `/work`, so a repo is worked in without hand-writing `-w`.

### Allowed run flags

`-i`, `-t`, `-it`/`-ti`, `-v`/`--volume host:container[:opts]`, `-w`/`--workdir <dir>`, `-e`/`--env KEY=VALUE`, `-u`/`--user <user>`, `--entrypoint <path>`, and `--allow-direct` (see below).

**Jail-breaching flags are rejected** (`--network`, `-p`/`--publish`, `--dns`, `--privileged`, `--cap-add`, `--device`, `--name`, `--rm`): tooljail owns the container network and isolation to keep the jail leak-proof. Any other flag is rejected by default.

## verify: prove it does not leak

`verify` is the trust anchor. It runs a probe through the same jail and asserts three things:

1. the observed **exit IP is the proxy's**, not the host's;
2. a **unique hostname resolves through the proxy's resolver**, not the host's; and
3. with the **proxy killed, the probe fails closed** (no egress to the host network).

```sh
tooljail verify --proxy socks5h://127.0.0.1:9050
```

It exits non-zero if any assertion fails, so CI can gate on it. Run it during development/CI, not per use.

## Split tunnel: reach one local service directly

`--allow-direct <IP|CIDR>[:port]` (repeatable) opens a **narrow, guardrailed hole** in the forced egress for specific **RFC1918 / link-local** destinations, so a jailed tool can reach a trusted local service (e.g. a local model at `192.168.1.150:8080`) DIRECTLY over the LAN, while ALL other egress stays forced through the proxy, fail-closed.

```sh
tooljail run --proxy socks5h://127.0.0.1:9050 \
  --allow-direct 192.168.1.150:8080 \
  -it -v ./work my/agent-image agent
```

Guardrails (see ADR-0005): **off by default** (an empty allowlist is byte-identical to the strict jail); **private ranges only** (public IPs / hostnames / malformed values are rejected loudly at startup, because a public direct would be a real anonymity leak); **TCP only** (UDP stays hard-dropped even to an allowlisted host, ADR-0003); and everything outside the allowlist stays leak-proof. `verify` proves the jail is still leak-tight for all non-allowlisted traffic when a split tunnel is active.

## Platform

tooljail is Linux only. macOS and Windows have no network-namespace + nftables jail, so there is no native port. Podman on macOS/Windows runs inside a Linux VM, so tooljail can run **inside that VM**, but two seams are VM-boundary-sensitive: `--allow-direct` reaches the *VM's* NIC (not your host LAN), and host-loopback proxy reachback (`ssh -D`/Tor on the host's `127.0.0.1`) is the host loopback, not the VM's. Treat non-Linux as best-effort-via-VM, not supported.

## Design

The security rationale lives in the ADRs under [`docs/adr/`](docs/adr/):

- **0001** the redirector: a tun2socks sidecar (the jail's only route out).
- **0002** host-loopback reachback via pasta (the most leak-prone seam, scoped to the sidecar only).
- **0003** UDP is hard-blocked (DNS goes proxy-side; other UDP is dropped).
- **0004** the default dev image is a pinned buildpack-deps base.
- **0005** the split-tunnel LAN allowlist is a guardrailed hole in forced egress.

## License

[AGPL-3.0-only](LICENSE).
