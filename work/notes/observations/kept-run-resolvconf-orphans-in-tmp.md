2026-07-03: The jail-aware `netcage start` task made the tool's resolv.conf a
STABLE, run-attributable host path (`$TMPDIR/netcage-resolv-<runID>.conf`,
`internal/jail/run.go`) so a KEPT container's bind-mount source survives a
restart (a random temp file removed on run exit made `podman start` fail with
crun "cannot stat"). Only an EPHEMERAL run removes it now. Consequence: when a
user later removes a KEPT pair via `netcage rm` (or a raw `podman rm`), the
durable `$TMPDIR/netcage-resolv-<runID>.conf` is left orphaned (a harmless
2-line `nameserver 127.0.0.1` file, but it accumulates). A future `netcage rm`
could sweep the matching resolv file, or netcage could relocate these under a
single `netcage`-owned dir it can prune. Out of scope for this task.
