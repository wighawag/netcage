# netcage

Run any containerized tool with **all of its TCP and DNS egress forced through a SOCKS5h proxy, fail-closed**, so a recon/scan/agent tool cannot leak your real IP or DNS. netcage wraps an existing image + command + a socks5h URL, and ships a `verify` leak-test that proves no traffic escapes the proxy.

The forced egress is done by the **network layer**, not by the tool's own proxy awareness. This is the opposite of app-level `HTTP_PROXY`/`ALL_PROXY` (which raw sockets and DNS ignore, and which therefore leaks). If the proxy is unreachable, traffic is **dropped, never sent to the host network** (fail-closed). That is the whole point of the tool, and the `verify` command exists to prove it.

## Requirements

netcage runs on a **Linux kernel** (see [Platform](#platform) for macOS/Windows, which work through Podman's Linux VM). It needs:

- **Rootless [Podman](https://podman.io/) 5.x** using the **pasta** rootless network backend (Podman 5's default on netavark). The host-loopback reachback and the forced-egress jail are built on it (ADR-0002). Podman is the ONLY runtime tool netcage invokes: the jail's firewall and DNS forwarder run inside the sidecar container via `podman exec` (ADR-0006), so the host needs no `nft`/`nsenter`.
- **`/dev/net/tun`** available to the rootless user (the redirector sidecar is a TUN device).
- A running **SOCKS5h proxy** to send egress through (local Tor, `ssh -D`, a remote SOCKS5 endpoint, ...). Only `socks5h://` is accepted; plain `socks5://` resolves DNS locally and is a leak, so it is rejected. Supply it per-run with `--proxy`/`NETCAGE_PROXY`, or persist a default once with `netcage setup-default` (see [Configuring a default proxy](#configuring-a-default-proxy-setup-default)) so a bare `netcage run` needs no `--proxy`.

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
netcage run          [flags] [<image>] [<cmd> <args...>]
netcage start        [--proxy ...] [--allow-direct ...] [-it] [--rm] <container>
netcage verify       [--proxy socks5h://[user:pass@]host:port]
netcage detect-proxy [--json]
netcage setup-default
netcage forward      [--bind 127.0.0.1|0.0.0.0] <container> [hostPort:]jailPort
netcage ports        <container> [--json]
netcage ps | images | inspect | logs | exec | stop | rm | commit | build | pull | load
```

`run` uses podman-native grammar: the image is the first positional and the tool command + args follow it, like `podman run [flags] IMAGE [CMD...]`.

The proxy is **required**, and it is resolved from three sources in this order: **`--proxy` flag > `NETCAGE_PROXY` env > config file** (`~/.config/netcage/config.json`, written by `netcage setup-default`). If none of the three yields a proxy, the run refuses (fail-closed). The config file is the lowest-priority default, so env/flag always win, and a config-sourced proxy is still validated (`socks5h://` only) and preflighted on every run exactly like a flag/env one. See [Configuring a default proxy](#configuring-a-default-proxy-setup-default) and [ADR-0012](docs/adr/0012-config-is-a-new-fail-closed-proxy-source-never-a-bypass.md).

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

`-i`, `-t`, `-it`/`-ti`, `--rm`, `-v`/`--volume host:container[:opts]`, `-w`/`--workdir <dir>`, `-e`/`--env KEY=VALUE`, `-u`/`--user <user>`, `--entrypoint <path>`, the vetted network-irrelevant pass-throughs `--memory`, `--cpus`, `--memory-swap`, `-l`/`--label`, `--tmpfs`, `--read-only`, `--hostname`, `--pull`, `--platform`, `--env-file`, `--ulimit`, `--shm-size`, and `--allow-direct` (see below).

The allow-list is **curated and fail-closed**: a flag is allowed only if it cannot alter the container network/netns, add capabilities/devices/privilege, publish/bind ports, affect DNS/resolv, or collide with a netcage-owned name/lifecycle field (`--name`/`--rm`/`--network`). See [ADR-0010](docs/adr/0010-widened-run-flag-allowlist-is-vetted-network-irrelevant.md).

**`--rm` is netcage-owned:** it makes the run **ephemeral** (both the tool container and its sidecar are removed on exit). **WITHOUT `--rm`** the stopped tool container and its sidecar are **left behind** (inspectable/restartable like `podman run`), kept fail-closed by the jail's baked firewall so a leftover container never has a working un-jailed network. netcage interprets its own `--rm`; it never passes a raw podman `--rm` through.

**Jail-breaching flags are rejected** (`--network`, `-p`/`--publish`, `--dns`, `--privileged`, `--cap-add`, `--device`, `--name`, `--add-host`): netcage owns the container network and isolation to keep the jail leak-proof. `--add-host` is refused because it pins a hostname->IP that sidesteps proxy-side DNS. Any other (unknown) flag is rejected by default (fail-closed on the unknown).

## verify: prove it does not leak

`verify` is the trust anchor. It runs a probe through the same jail and asserts three things:

1. the observed **exit IP is the proxy's**, not the host's;
2. a **unique hostname resolves through the proxy's resolver**, not the host's; and
3. with the **proxy killed, the probe fails closed** (no egress to the host network).

```sh
netcage verify --proxy socks5h://127.0.0.1:9050
```

It resolves the proxy the same way `run` does (`--proxy` > `NETCAGE_PROXY` > config file), so a bare `netcage verify` tests your persisted default, and it prints which source supplied the proxy (`source: flag|env|config`). It exits non-zero if any assertion fails, so CI can gate on it. Run it during development/CI, not per use.

## Configuring a default proxy: setup-default

So netcage is a true drop-in `podman` replacement, you can persist a **default proxy** once and then run `netcage run <image>` with no `--proxy`. `netcage setup-default` is the interactive, re-runnable onboarding verb that writes it (it is the ONLY thing that writes the config file):

```sh
netcage setup-default
```

It **detects** a local SOCKS proxy (via `detect-proxy`), lets you **choose** a detected candidate or enter one, **verifies** it (shows the exit IP as evidence it differs from your host IP), **warns once** about the silent-default tradeoff (from then on a bare `run` egresses through the persisted proxy without you naming it), and **persists** the choice to `~/.config/netcage/config.json` (`0600`, XDG-aware). It is re-runnable and **confirms before overwriting** an existing config.

The persisted default is **credential-free by construction**: `setup-default` **refuses** to write a proxy carrying embedded `user:pass@` credentials, so the file never accumulates secrets at rest (backups / dotfile repos / screen-shares stay safe). Keep an authed proxy in `NETCAGE_PROXY` / `--proxy` instead (transient). The config is a new proxy **source**, never a bypass: its `proxy` round-trips the same `socks5h://`-enforcing validator, each `allowDirect` entry round-trips the same RFC1918/link-local guardrail, and a config-sourced proxy is still preflighted fail-closed on every run. A missing config is a clean no-op (you still hit the fail-closed refusal); a present-but-broken one is a loud error. See [ADR-0012](docs/adr/0012-config-is-a-new-fail-closed-proxy-source-never-a-bypass.md).

The file is small and hand-editable if you prefer:

```json
{
  "proxy": "socks5h://127.0.0.1:9050",
  "allowDirect": ["192.168.1.150:8080"]
}
```

`allowDirect` is optional (the [split tunnel](#split-tunnel-reach-one-local-service-directly) list). A CLI `--allow-direct` **replaces** the config list for that run (it never rides along additively). A hand-edited credentialed proxy still loads (the credential-free rule constrains what netcage *writes*, not what it reads), matching how env/flag already carry credentials.

### detect-proxy: find a local SOCKS proxy

`detect-proxy` is the detection primitive `setup-default` drives, also usable standalone. It **probes the common local SOCKS ports** (`127.0.0.1:9050` Tor, `:9150` Tor Browser, `:1080` generic), **confirms** each open port really speaks SOCKS5 via an RFC1928 handshake (an open port is not enough), and prints **evidence-only** findings (open ports, handshake result, weak hedged process hints, and best-effort the exit IP as proof the egress is not your host IP). It never names or labels the exit provider, carries no `--proxy` (it is looking *for* one), and does no egress of its own.

```sh
netcage detect-proxy          # human-readable evidence findings
netcage detect-proxy --json   # a versioned, provider-field-free machine contract
```

## What netcage hides and what it does NOT

netcage's one **guarantee** is **network egress confinement**: every TCP and DNS packet is forced through the proxy, fail-closed, and `verify` proves it. On top of that guarantee it also hides a few host-identity signals a jailed tool could otherwise fingerprint you with; and some signals it deliberately does **not** hide, because a container shares the host kernel (it is not a VM). Knowing the boundary means the residual fingerprint is documented, not surprising. The full rationale is in [ADR-0013](docs/adr/0013-host-identity-hardening-scope.md).

**Hidden (in addition to the network guarantee):**

- **Host machine name.** The tool container gets a synthesized localhost-only `/etc/hosts` and a fixed neutral `--hostname`, so a tool reading `/etc/hosts` or `hostname` does not learn your machine's name.
- **Operator username.** Podman's storage graphroot is relocated to a username-free path under `/var/tmp` (`/var/tmp/netcage-storage-<uid>`, scoped by your numeric user id so multiple users on one host do not collide), so the overlay source paths in the container's `/proc/self/mountinfo` no longer embed `/home/<you>`. The path carries a numeric uid, not your login name.
- **Host NIC name / MAC.** The in-netns interface is given a fixed name (`netcage0`) instead of being named after your host's default-route NIC (whose systemd `enx<MAC>` name re-exposes the NIC MAC).

**NOT hidden (accepted residual):**

- **Host hardware and kernel version** (`/proc/cpuinfo`, `/proc/meminfo`, `uname`, and the boot-time / uptime clock signals in `/proc`). The kernel is **shared**: a container is not a VM, `/proc/cpuinfo` reports the physical CPUs regardless of cgroup limits, and faking these breaks tools. Hiding them needs a different isolation model (gVisor/Kata), which is out of scope.
- **Environment baked into the tool / wrapper image** (e.g. `ANON_PI_STAGE`, `SEARXNG_HOME`). This env comes from the image's own Dockerfile, not from netcage, so stripping it is that image's concern. netcage's own `netcage-run-<id>-*` container names and `netcage.managed` labels are deliberate and low-sensitivity (ADR-0009).

### Keep your username out of `-v` mount paths

A `-v` bind mount's **source path is preserved as-is** in the container's mount table, so mounting a project from under your home directory still reveals your username in that path:

```sh
netcage run --proxy socks5h://127.0.0.1:9050 -it -v ~/dev/foo:/work   # leaks /home/<you>/dev/foo in the mount table
```

The source path is **your own choice**, so netcage cannot neutralize it without hiding what you asked to mount. If you care, mount the project from a path **outside `$HOME`**:

```sh
netcage run --proxy socks5h://127.0.0.1:9050 -it -v /srv/work/foo:/work   # source path carries no username
```

### Clearing netcage's storage

netcage's relocated storage lives at **`/var/tmp/netcage-storage-<uid>`** (the graphroot: image cache + kept containers), where `<uid>` is your numeric user id, so different users on the same host keep separate, non-colliding stores. (Run `id -u` to see yours; if you set the `NETCAGE_GRAPHROOT` override, use that path instead.) To clear it, use podman's own reset, which removes the store cleanly:

```sh
podman --root /var/tmp/netcage-storage-"$(id -u)" system reset --force
```

**Do not `rm -rf` it.** The rootless overlay `diff/` tree is owned by id-mapped subuids, so a plain `rm -rf` fails with permission errors. Clearing the store costs only a re-pull of images on the next run (podman self-heals a missing graphroot), but it also discards any kept containers, exactly as losing the home store would.

## start: resume a kept jailed container

A plain `netcage run` (no `--rm`) leaves a stopped tool container and its sidecar behind. `netcage start <name>` **resumes** that container with its full forced-egress jail restored, so a named reusable jailed container is a **durable environment**:

```sh
netcage run   --proxy socks5h://127.0.0.1:9050 -it -v ./my-repo   # leaves a kept pair on exit
netcage start --proxy socks5h://127.0.0.1:9050 -it netcage-run-<id>-tool   # resume it, state intact
```

`start` **revives** the existing sidecar (its baked firewall re-applies on start, then netcage **verifies** it), **re-execs the DNS forwarder**, and re-enters the tool with its filesystem state intact. It is the jail-aware exception to the other verbs: it carries a `--proxy` (and any `--allow-direct`) and **reconciles** it against the config the container was created with. A **different** proxy/allowlist is **refused** (remove the container and `run` again, or start it with the same jail config) rather than silently reviving a stale jail or discarding container state. A non-netcage or unknown container is refused. Without `--rm` the pair is left stopped again (fail-closed via the baked firewall); with `--rm` the resume is ephemeral (both removed on exit). See [ADR-0011](docs/adr/0011-netcage-start-revives-jail-refuses-changed-config.md).

## Host access: reach an in-jail server from the host

A jailed tool sometimes runs a server you want to open on the host (a dev/preview server on `:3001`, a local API). `-p`/`--publish` stays **refused** (it would open an inbound path around the jail); host access is a separate, explicit, out-of-band verb instead, the netcage analogue of `kubectl port-forward` / `ssh -L`:

```sh
# terminal 1: the jailed tool starts a server on :3001 (unchanged run)
netcage run --proxy socks5h://127.0.0.1:9050 -it -v ./app netcage-run-<id>-tool
# terminal 2: the HUMAN opens the window, explicitly, per port
netcage forward netcage-run-<id>-tool 3001
# -> forwarding http://127.0.0.1:3001 -> netcage-run-<id>-tool:3001 (Ctrl-C to stop)
```

The port positional is `[hostPort:]jailPort` (the familiar `docker -p` / `kubectl port-forward` order), so you can expose the in-jail server on a **different** host port when `:3001` is already taken or you just want `:8080`:

```sh
netcage forward netcage-run-<id>-tool 8080:3001
# -> forwarding http://127.0.0.1:8080 -> netcage-run-<id>-tool:3001 (Ctrl-C to stop)
```

The bare single-port form (`... 3001`) is the zero-remap special case (host port == jail port), so it is unchanged. Both sides are validated `1-65535`; a bad host side, bad jail side, or extra colons (`1:2:3`) is a loud usage error. Only the **host** bind port is remappable: the in-jail connect side is always `127.0.0.1:<jailPort>` in the shared netns.

`forward` stands up ONE host `<bind>:<hostPort>` -> in-jail `<jailPort>` forward for as long as the verb runs, then tears it down on Ctrl-C (nothing revives it, a reboot ends it). Guardrails (see [ADR-0014](docs/adr/0014-host-access-to-in-jail-server-is-a-forward-verb-not-a-publish-flag.md)): **loopback by default** (the bare verb binds `127.0.0.1`, so nothing off-box can reach the server); **TCP only** and **exactly the one named port** (UDP stays hard-dropped, ADR-0003); **netcage-managed containers only** (label-scoped, ADR-0009, a non-netcage or stopped jail is refused loudly); and it **never touches the egress firewall** (no OUTPUT rule, so forced egress and fail-closed are exactly as before, the reply just rides the established inbound socket).

For LAN access (e.g. viewing the preview from a phone on the same network) `--bind 0.0.0.0` binds all interfaces, but it is a **separate, louder opt-in**: it prints a **warning** naming what it exposes (the container, the port, and that any LAN host can reach the jailed tool's server) before forwarding. No bind value other than `127.0.0.1` and `0.0.0.0` is accepted.

```sh
netcage forward --bind 0.0.0.0 netcage-run-<id>-tool 8080:3001
# -> WARNING: exposing netcage-run-<id>-tool:3001 on ALL interfaces (0.0.0.0:8080); any
#    host on your LAN can reach the jailed tool's server. Ctrl-C to stop.
```

**Nothing about host access persists.** After a reboot, re-establish it explicitly: `netcage start <container>` (revive the jail), relaunch the server if it was a tool-run process, then `netcage forward <container> [hostPort:]jailPort` again.

## ports: list a jail's open TCP listeners

Before you `forward` a port you often need to know WHICH ports the jailed tool is listening on. `netcage ports <container>` lists the in-jail **TCP LISTEN** sockets, **image-independently**: it reads `/proc/net/tcp*` from inside the shared netns via the **sidecar** (`podman exec <sidecar> cat /proc/net/tcp*`), so it works even for a minimal or distroless tool image that ships no `ss`/`netstat`/`nc` (the same reason `forward` execs the sidecar, not the tool). It only **reads** `/proc`: it carries no `--proxy`, does no egress, and adds no firewall rule.

```sh
netcage ports netcage-run-<id>-tool
# ADDRESS    PORT   SCOPE
# 127.0.0.1  53     loopback        (netcage DNS forwarder)
# 0.0.0.0    3001   all-interfaces
```

Each listener is reported with its bind **address**, **port**, and **scope**: `loopback` (bound `127.0.0.0/8` or `::1`, reachable only inside the netns, the exact `forward` case) vs `all-interfaces` (`0.0.0.0`/`::`). netcage's own in-jail DNS forwarder on `127.0.0.1:53` is **shown** (annotated as `netcage DNS forwarder`), never silently filtered, so the list can't hide a real listener. IPv4 and IPv6 listeners are both reported. Only **LISTEN** sockets appear (not established connections, not UDP, ADR-0003). A non-netcage or stopped container is refused loudly (label-scoped, ADR-0009); see [ADR-0015](docs/adr/0015-ports-verb-lists-jail-listeners-via-sidecar-proc-with-a-json-reuse-contract.md).

`--json` emits a **stable, documented reuse contract** (like `detect-proxy --json`) so a tool can consume it without screen-scraping the table. It is an array of `{address, port, loopbackOnly}`, IPv4 and IPv6 in the **same array**, addresses rendered `127.0.0.1` / `0.0.0.0` / `::1` / `::`:

```sh
netcage ports netcage-run-<id>-tool --json
# [
#   { "address": "127.0.0.1", "port": 53,   "loopbackOnly": true  },
#   { "address": "0.0.0.0",   "port": 3001, "loopbackOnly": false }
# ]
```

The field names `address` (string), `port` (int), and `loopbackOnly` (bool) are the contract; the array is sorted stably (by port, then address) and an empty result is `[]`. A caller (e.g. an agent) uses this to show a pick-list and then `netcage forward` the chosen port, without the user knowing the port in advance.

## Manage netcage containers: ps / logs / inspect / exec / stop / rm / commit / images

The pass-through management verbs let you inspect and manage the containers a kept `netcage run` leaves behind with familiar podman vocabulary, **scoped to netcage's own containers** via the `netcage.managed` label (ADR-0009) so you never see (or act on) unrelated podman containers:

```sh
netcage ps                    # list netcage's containers (kept pairs), incl. stopped
netcage logs    <container>   # the tool container's logs
netcage inspect <container>   # full podman inspect JSON
netcage exec -it <container> <cmd>   # run a command inside the existing jailed netns
netcage stop    <container>   # stop a jailed container (its baked firewall re-applies on restart)
netcage rm      <container>   # remove the whole tool+sidecar pair (no orphaned sidecar)
netcage commit  <container> <image>   # snapshot a jailed container's filesystem to a new image
netcage images                # the images netcage uses
```

These are inspection/lifecycle **only**: none stands up or tears down a jail, none egresses (so none needs a `--proxy`), and `exec` enters the container's **existing** jailed netns (never a fresh un-jailed one) and refuses if the jail is not running (`netcage start <c>` first). A non-netcage container is refused loudly.

### Image store: build / pull / load

`netcage build`, `pull`, and `load` are the **write side** of netcage's image store, siblings of the read verb `images`. netcage relocates podman's store to a username-free graphroot (see [Clearing netcage's storage](#clearing-netcages-storage)), so these write into the **same** store `netcage run` and `netcage images` read: a locally built or pulled image is then visible to `netcage run <image>`. They forward their arguments verbatim to the underlying `podman build`/`pull`/`load` against that store:

```sh
netcage build -t my/tool .          # build into netcage's store
netcage pull docker.io/library/alpine:latest
netcage load -i my-tool.tar
netcage run --proxy socks5h://127.0.0.1:9050 -it my/tool   # now visible
```

They act on images (not run-labelled containers), do not egress a jail, and **refuse a user-supplied `--root`** (honouring it would split the single store; relocate the whole store with `NETCAGE_GRAPHROOT` instead). See [ADR-0013](docs/adr/0013-host-identity-hardening-scope.md) and [ADR-0017](docs/adr/0017-graphroot-default-is-uid-scoped-for-multi-user-hosts.md).

### Machine-readable ps and inspect (podman-faithful)

`netcage ps` and `netcage inspect` are **podman-faithful for machine-readable output**: they forward podman's own output/query flags to the underlying podman verb, over netcage's managed set, so a consumer (e.g. an agent that stamps a label on each container and reads it back) can list and query netcage's containers **without screen-scraping the human table**.

`netcage ps` forwards `--format <go-template>`, `--format json`, `-q`/`--quiet`, and additional `--filter`, with the `netcage.managed` scope **always enforced on top** (a user `--filter` composes ON TOP of it, it never replaces it), so these behave exactly as `podman ps` does over netcage's containers:

```sh
netcage ps --format '{{.ID}}\t{{.Labels}}'   # IDs + labels, tab-separated
netcage ps --format json                     # a stable JSON array
netcage ps -q                                # IDs only
netcage ps --filter label=anon-pi.key=abc    # AND-ed on top of netcage.managed
```

`netcage inspect <container> --format <go-template>` forwards the template to `podman inspect` (the no-`--format` default stays full JSON), so a single label is read back directly:

```sh
netcage inspect netcage-run-<id>-tool --format '{{index .Config.Labels "anon-pi.key"}}'
# -> the anon-pi.key label value, nothing else
```

These are **read-only query flags**: they only shape the output, so they cannot egress, alter a netns/firewall, or touch a container's lifecycle. The managed-scope filter (for `ps`) and the `netcage.managed` label guard (for `inspect`) stay enforced no matter what flags you pass, and neither verb touches the egress firewall. See [ADR-0016](docs/adr/0016-pass-through-query-verbs-forward-podman-output-flags.md).

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
- **0009** `--rm` is honoured; a kept pair is left fail-closed by its baked firewall; verbs are label-scoped.
- **0010** the widened run-flag allowlist is vetted network-irrelevant (curated, fail-closed).
- **0011** `netcage start` revives the jail and refuses a changed proxy/allowlist.
- **0012** the config file is a new fail-closed proxy SOURCE, never a bypass; the persisted default is credential-free.
- **0013** host-identity hardening scope (what a jail hides and what it does not).
- **0014** host access to an in-jail server is a `forward` verb, not a `--publish` flag.
- **0015** `ports` lists jail listeners via the sidecar's `/proc`, with a JSON reuse contract.
- **0016** the pass-through query verbs forward podman's read-only output flags.
- **0017** the graphroot default is uid-scoped (`/var/tmp/netcage-storage-<uid>`) for multi-user hosts; `NETCAGE_GRAPHROOT` is a supported override.

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
