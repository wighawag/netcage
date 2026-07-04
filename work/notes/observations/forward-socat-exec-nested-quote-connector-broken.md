# forward's socat EXEC connector (`sh -c '...'`) is broken: socat does not shell-split it

Date: 2026-07-04

While writing the `verify-forward-keeps-egress-tight` acceptance test I found that
`netcage forward` does not actually reach the in-jail server today. `internal/forward`'s
`ListenArgs` builds the connect side as:

```
EXEC:podman --root <graphroot> exec -i <tool> sh -c 'exec nc 127.0.0.1 <port> 2>/dev/null || exec socat STDIO TCP:127.0.0.1:<port>'
```

socat's `EXEC:` does NOT run a shell and does NOT honour quotes: it splits the address on
whitespace and `execvp`s the raw tokens (so `'exec`, the quote chars, `||`, `2>/dev/null`
are passed literally to podman). The connector child dies at EOF and a host GET returns an
empty body.

Proven live on this host (podman 5.4.2 rootless, socat 1.x, alpine tool with busybox nc),
same jail for both:
- Spike's SIMPLE shape `EXEC:podman --root <gr> exec -i <tool> nc 127.0.0.1 <port>` -> returns the server body (WORKS).
- Current production nested-`sh -c`-single-quote shape -> empty body (FAILS).

So the `forward-verb-wiring-and-bind` recipe diverged from the spike-proven Shape B
(`work/notes/findings/spike-socat-forward-host-to-jail-loopback.md`, which used the plain
`nc 127.0.0.1 <port>` connector, no `sh -c` wrapper). The `nc`-then-`socat` fallback that
was added for cross-image robustness is exactly what breaks it under socat's EXEC parsing.
Its unit tests (`internal/forward/forward_test.go`) only assert the argv STRING contains the
right substrings, so they never caught that socat can't parse it.

Likely fix (for whoever owns the forward wiring, not this observation): either
`EXEC:...,pty` is not enough; use `SYSTEM:` (which DOES invoke `/bin/sh -c` and honours the
quoting) instead of `EXEC:`, or drop the `sh -c` wrapper and use the spike's plain `nc`
connector. This is out of scope for the acceptance-test task; captured here so the signal
is not lost.
