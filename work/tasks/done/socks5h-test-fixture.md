---
title: Controllable local SOCKS5h test fixture (known exit IP + DNS view, killable)
slug: socks5h-test-fixture
prd: tooljail
blockedBy: []
covers: [7]
---

## What to build

A controllable, in-repo SOCKS5h proxy fixture (pure Go) that makes the three leak assertions DETERMINISTIC without needing real Tor. It is the harness every leak test runs against, so it must expose three known, assertable facts:

1. **Known exit IP** — connections dialed through the fixture exit from an address the test knows, so `verify` can assert "exit IP == the proxy's, not the host's".
2. **Known DNS view (socks5h)** — the fixture does proxy-side hostname resolution and resolves a UNIQUE test hostname that only it knows about (and that the host resolver would fail / resolve differently), so a test can assert the lookup went through the proxy's resolver, not the host's.
3. **Killable on demand** — the fixture can be stopped mid-test so a "proxy killed ⇒ fails closed" assertion has a deterministic trigger.
4. **Proxy-side resolution observability** — the fixture exposes a hook to observe WHICH hostnames it was asked to resolve proxy-side, so a caller (the `verify` task) can assert a given lookup arrived at the proxy and NOT at the host resolver. This is the seam `verify` assertion 2 (DNS-through-proxy, not host-side) binds to.

End-to-end thin path: a Go type that starts a SOCKS5h listener on a **caller-chosen bind address/port**, records/echoes the exit IP it would present, resolves the unique hostname proxy-side (recording the lookup for observation), and has a `Close()`/kill that makes subsequent dials fail. Pure Go, no Podman, no system mutation in the unit tests — so it can be built in parallel with the spikes.

**Reachable-from-the-jail requirement:** the later jail/verify tasks consume this fixture as "the host-loopback proxy under test" — a probe INSIDE the jail's netns dials it THROUGH the jail (exercising the pasta reachback path). So the bind address must be caller-chosen (host loopback is the common case) and reachable from a separate netns, not hard-wired to in-process-only. The fixture itself stays pure Go; it is the jail tasks that point pasta at its address.

## Acceptance criteria

- [ ] Tests are written FIRST and RED before the fixture exists: a client dialing the fixture observes the KNOWN exit IP; a `socks5h` lookup of the UNIQUE hostname resolves proxy-side; after kill, dials FAIL.
- [ ] The fixture resolves the unique test hostname proxy-side (socks5h), distinguishable from a host-resolver answer.
- [ ] The fixture exposes a deterministic kill/Close that makes subsequent dials fail closed.
- [ ] The fixture binds on a CALLER-CHOSEN address/port (not hard-wired in-process), reachable from a separate netns, so the jail/verify tasks can use it as the host-loopback proxy under test.
- [ ] The fixture exposes a hook to observe which hostnames were resolved proxy-side (so `verify` can assert a lookup arrived proxy-side, not host-side).
- [ ] No real environment is touched: the fixture binds only a local test port (chosen/ephemeral) and writes nothing to shared/global locations; tests assert the fixture is fully torn down after each run.
- [ ] Tests cover the new behaviour (mirror the repo's existing test style).

## Blocked by

- None — can start immediately. Pure Go; parallel-safe with the spikes (file-orthogonal).

## Prompt

> Goal: build the controllable local SOCKS5h fixture that makes the three leak assertions deterministic without real Tor. Read `CONTEXT.md` (domain terms: socks5h, verify/leak-test) and the prd's Testing Decisions section. The three jail leak assertions (exit IP is the proxy's; unique hostname resolves proxy-side; proxy-killed fails closed) ALL test against THIS fixture, so it must make each fact known and assertable.
>
> FIRST, check against current reality: confirm `socks5h` (remote/proxy-side DNS) is still the target (ADR-0003 hard-blocks UDP but DNS is proxy-side over TCP, so the fixture resolves hostnames itself).
>
> Write the tests FIRST (testFirst is ON): (1) a client dialing the fixture sees the known exit IP; (2) a socks5h lookup of the unique hostname resolves proxy-side and differs from what the host resolver would give; (3) after the fixture is killed, dials fail. Then build the minimum fixture to make them green.
>
> This is pure Go — NO Podman, NO netns, NO system mutation in the fixture's own tests. Bind on a caller-chosen address/port (default to a local/ephemeral port for the unit tests) and tear it down per test (isolate: touch no shared/global location, assert the fixture is gone after each run). The bind address must be caller-chosen and reachable from a separate netns, because the jail/verify tasks consume this as "the host-loopback proxy under test" (a probe inside the jail dials it through the jail). "Done" means the fixture self-tests are green and the fixture is reusable by the `verify` task through a clean Go API: the known exit IP, the unique hostname, a proxy-side-resolution observation hook, and a kill switch.
