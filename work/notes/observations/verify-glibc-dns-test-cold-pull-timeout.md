# verify integration test `TestVerify_DNSResolvesOverTCPForGlibc` times out on the buildpack-deps cold pull

type: observation
status: spotted
spotted: 2026-07-04

While running the forced-egress leak-test integration suite (`go test -tags
integration ./internal/verify/`), `TestVerify_DNSResolvesOverTCPForGlibc` fails
with an EMPTY tool output at exactly the 5-minute ctx budget (301s). The test
uses the ~950MB glibc `buildpack-deps` image against a FRESH per-run scratch
graphroot (`NETCAGE_GRAPHROOT` under `/var/tmp`), so it cold-pulls that image
every run; in this environment the pull does not persist/complete within the
budget (the alpine-based `TestVerify_DNSResolvesProxySideNotHost` passes in
~3.4s). Verified it fails IDENTICALLY on a clean baseline (git stash of unrelated
work), so it is an environment/pull-time flake, NOT a resolution regression. The
three core leak-test assertions (exit-ip-is-proxys, dns-resolves-proxy-side,
fails-closed-on-proxy-kill) and the full/split-tunnel/raw-bypass reports all
pass. Possible follow-up: give this test a larger budget, pre-pull the dev image
into the scratch store in TestMain, or reuse a warm store.
