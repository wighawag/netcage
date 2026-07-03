---
title: Orphaned netcage-run-<unixnano> sidecar+tool pair left running on the dev host (unrelated to any current test)
slug: orphaned-netcage-run-containers-on-dev-host
---

2026-07-03: Noticed a leftover `netcage-run-1783011274917980348-{sidecar,tool}`
pair on the dev host, "Up 19 hours" (created 2026-07-02 17:54). The RunID is the
`time.Now().UnixNano()` default (jail.Run's fallback when Config.RunID is empty),
not any integration test's prefix, so it is NOT residue from the current
fail-closed-restart work; it predates it. Left it in place (removing another
run's containers is out of scope and unconfirmed). If it is a stale teardown
escape, worth checking whether a cancelled/timed-out `jail.Run` can leave the
pair when the deferred Teardown's own context also expires.
