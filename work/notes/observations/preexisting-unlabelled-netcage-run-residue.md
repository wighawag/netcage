# Pre-existing unlabelled netcage-run residue on the dev host (2026-07-03)

While running the teardown-split integration tests I found a leftover pair
`netcage-run-1783011274917980348-{tool,sidecar}` created 2026-07-02 with NO
`netcage.managed` label (predates ADR-0009's label). Not created by this task's
tests (my runs used keptrun/ephrun/itest prefixes and cleaned up via
`t.Cleanup`). Likely a crashed/cancelled pre-label dev run. Left untouched (not
mine to remove); flagging so it can be reaped and, if it recurs, investigated as
a teardown-escape on some exit path.
