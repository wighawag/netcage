---
title: Pure /proc/net/tcp* -> TCP LISTEN listener parser (image-independent enumeration core)
slug: proc-net-tcp-listener-parser
prd: ports-verb-list-jail-listeners
blockedBy: []
covers: [3, 4, 8]
---

## What to build

The pure, podman-free CORE of `netcage ports`: a function that parses raw `/proc/net/tcp` + `/proc/net/tcp6` text into the list of TCP LISTENING sockets, with each listener's bind address, port, and whether it is loopback-only. This is the image-independent source of truth (every Linux container has `/proc/net/tcp*` regardless of installed userspace), so it is where the enumeration correctness lives and is fully unit-testable without a container.

Behaviour:

- Input: the two file bodies (v4 + v6). Output: an ordered slice of listeners, each `{Address string, Port int, LoopbackOnly bool}`.
- Parse each data row's `local_address` field (`HEXIP:HEXPORT`). IPv4 is 8 hex chars, LITTLE-ENDIAN byte order (`0100007F` -> `127.0.0.1`); IPv6 is 32 hex chars, decoded to a normalised `::1` / `::` / full form. The port is 4 hex chars, BIG-ENDIAN (`0BB9` -> 3001, `0035` -> 53).
- Keep ONLY rows in the LISTEN state: the `st` column equals `0A`. Every other state (ESTABLISHED `01`, TIME_WAIT `06`, etc.) is filtered OUT.
- Set `LoopbackOnly` when the address is in `127.0.0.0/8` (v4) or is `::1` (v6). A wildcard bind (`0.0.0.0` / `::`) and any routable address are NOT loopback-only.
- Render the address human-readably: `127.0.0.1`, `0.0.0.0`, `::1`, `::` (or the full v6 form for a specific address).
- Tolerate the header line and blank/short lines without panicking (skip malformed rows rather than crash).

netcage's own in-jail DNS forwarder listens on `127.0.0.1:53`; it is NOT special-cased or filtered here (the parser reports every LISTEN socket faithfully; any annotation is the presentation layer's job, prd story 8).

## Acceptance criteria

- [ ] `parseProcNetTCP(v4, v6 string) []Listener` returns the LISTEN sockets with address, port, and loopbackOnly.
- [ ] IPv4 little-endian decode is correct (`0100007F` -> `127.0.0.1`, `00000000` -> `0.0.0.0`); port big-endian decode is correct (`0BB9` -> 3001).
- [ ] IPv6 decode is correct for loopback (`::1`) and wildcard (`::`), and `LoopbackOnly` is true only for `::1` (v6) / `127.0.0.0/8` (v4).
- [ ] Non-LISTEN rows (st != `0A`) are filtered out; the header and malformed/short lines are skipped without panic.
- [ ] Tests cover IPv4 loopback + wildcard, IPv6 loopback + wildcard, a filtered non-LISTEN row, and the port decode, against fixture `/proc/net/tcp*` lines (pure, no podman, no container).

## Blocked by

- None — can start immediately. (File-orthogonal to `ports-verb-cli-parse`.)

## Prompt

> Self-contained. Goal: build the pure parser that turns raw `/proc/net/tcp` + `/proc/net/tcp6` text into the list of TCP LISTENING sockets (address, port, loopbackOnly), so `netcage ports` can enumerate a jail's listeners IMAGE-INDEPENDENTLY (no ss/netstat/nc needed in the tool image).
>
> FIRST check against current reality (launch snapshot): confirm the prd `work/prds/ready/ports-verb-list-jail-listeners.md` and the finding `work/notes/findings/forward-connector-must-use-sidecar-nc-not-tool.md` (the same "don't depend on in-image tools" lesson). This task is PURE parsing; no podman, no Runner.
>
> The `/proc/net/tcp` format (live-verified on this project's jail): each data row has a `local_address` field `HEXIP:HEXPORT` and a state field `st`. IPv4 hex is LITTLE-ENDIAN (`0100007F` = 127.0.0.1), the port hex is BIG-ENDIAN (`0BB9` = 3001), and `st == 0A` means LISTEN. IPv6 (`/proc/net/tcp6`) uses a 32-hex-char address. Real observed rows from a jail: `0100007F:0035 ... 0A` (the netcage DNS forwarder on 127.0.0.1:53, loopback-only) and `00000000:0BB9 ... 0A` (a server on 0.0.0.0:3001, wildcard).
>
> Where to look: this is a new pure function (a new file in a new `internal/ports` package, or a `procnet` sub-file) with a `Listener{Address, Port, LoopbackOnly}` type the wiring task will consume. Look at how `internal/cli` parses/validates for the repo's test style (table-driven). Seam to test at: the pure `parseProcNetTCP` with fixture strings.
>
> "Done" means: the decoder is correct for v4/v6, loopback vs wildcard, LISTEN-only, and robust to the header/malformed lines, all covered by table tests with fixture lines. Record any non-obvious decision (e.g. the exact `Listener` shape the wiring + json will consume) so the next task builds on a settled type.
