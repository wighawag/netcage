package jail

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Result is the outcome of a jail run. ToolStdout / ToolStderr are the wrapped
// tool's CAPTURED output, kept separate (stderr is never merged into stdout).
// When Config.ToolStdout / Config.ToolStderr live sinks are set, the same output
// was ALSO streamed to them as it arrived; the capture here is what the
// verify/leak-test probes assert on.
type Result struct {
	ToolStdout string
	ToolStderr string
	ToolExit   int
}

// ErrReachback is returned when a host-loopback proxy cannot be reached from the
// jail, with a self-explanatory message (story 14).
var ErrReachback = errors.New("the proxy on the host's loopback is not reachable from inside the jail")

// Run stands up the forced-egress jail, runs the wrapped tool, and tears
// everything down. It is the production path behind `netcage run`.
//
// Steps (Option A, shared netns; every in-netns step goes through podman, never
// host nsenter, ADR-0006):
//  1. start the tun2socks sidecar (pasta + map-host-loopback for a loopback
//     proxy), with the netcage-dns helper mounted in and the firewall baked into
//     its EXTRA_COMMANDS env (ADR-0008), so the entrypoint applies it on every
//     (re)start before it execs tun2socks
//  2. VERIFY the firewall INSIDE the sidecar via a podman exec `iptables -S`
//     probe (the fail-loud layer: EXTRA_COMMANDS cannot abort the sidecar, so
//     netcage aborts loudly here if a rule is missing/partial)
//  3. start the DNS-to-SOCKS-TCP forwarder INSIDE the sidecar via podman exec -d
//     and point resolv.conf at it
//  4. run the tool sharing the sidecar netns
//  5. tear it all down (deferred, best-effort, idempotent; the firewall and the
//     forwarder live in the sidecar container, so removing it removes them)
func Run(ctx context.Context, r Runner, cfg Config) (Result, error) {
	if cfg.RunID == "" {
		cfg.RunID = fmt.Sprintf("%d", time.Now().UnixNano())
	}

	// Resolve the netcage-dns helper BEFORE starting anything: the sidecar mounts
	// it (SidecarRunArgs), and failing early beats tearing down a half-built jail.
	dnsBin, err := dnsHelperPath()
	if err != nil {
		return Result{}, err
	}
	cfg.dnsHelperPath = dnsBin

	// Teardown is deferred immediately so any later failure (or a cancelled ctx)
	// still cleans up. Teardown uses a FRESH context (not the run ctx) so it runs
	// to completion even when the run was cancelled by SIGINT. It is idempotent +
	// best-effort + aggregates errors.
	defer func() {
		tdCtx, tdCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer tdCancel()
		if err := Teardown(tdCtx, r, cfg); err != nil {
			fmt.Fprintf(os.Stderr, "netcage: teardown: %v\n", err)
		}
	}()

	// 1. sidecar
	if _, serr, err := runPodman(ctx, r, cfg.SidecarRunArgs()...); err != nil {
		return Result{}, fmt.Errorf("start tun2socks sidecar: %w%s", err, stderrSuffix(serr))
	}

	// 2. VERIFY the firewall INSIDE the sidecar (ADR-0008). The firewall itself is
	// baked into the sidecar's EXTRA_COMMANDS env (SidecarRunArgs) and applied by
	// the image entrypoint on every (re)start, so it self-heals across restarts
	// (closing the raw-`podman start` LAN/UDP leak). But EXTRA_COMMANDS cannot
	// abort the sidecar on a half-applied firewall (spiked), so netcage VERIFIES
	// the exact rule set is present (a `podman exec ... iptables -S` probe) and
	// aborts the jail LOUDLY here if any rule is missing/partial. This preserves
	// the fail-loud guarantee the old runtime `podman exec ... 'set -e; ...'` got
	// from its Go-side exit-code check.
	if err := verifyFirewall(ctx, r, cfg); err != nil {
		return Result{}, fmt.Errorf("verify firewall in jail netns: %w", err)
	}

	// 3. DNS-to-SOCKS-TCP forwarder INSIDE the sidecar (podman exec -d), bound on
	// 127.0.0.1:53 so the tool's resolv.conf (127.0.0.1) resolves proxy-side over
	// TCP. It dials the proxy at the reachable address (the pasta map for a
	// host-loopback proxy). DNS never egresses as UDP; the host resolver never
	// sees the name (ADR-0003 + the dns-to-socks-bridge finding). It dies with the
	// sidecar container at teardown; no host-side process to kill.
	if err := startSidecarDNS(ctx, r, cfg); err != nil {
		return Result{}, fmt.Errorf("start in-jail DNS forwarder: %w", err)
	}
	cfg.dnsServer = "127.0.0.1:53"

	// Mount a resolv.conf into the tool pointing at the in-netns forwarder. The
	// tool container BIND-MOUNTS this host file, so its path must OUTLIVE the run
	// for a KEPT container: podman re-mounts the SAME source path on every restart
	// (a `netcage start` or a raw `podman start`), and a removed temp file would
	// make the restart fail (crun: cannot stat). So the path is run-attributable and
	// STABLE (resolvConfPathFor), and it is cleaned up ONLY on an EPHEMERAL run;
	// a kept run leaves it durable next to the kept pair (netcage start re-materialises
	// it idempotently anyway).
	resolvPath := resolvConfPathFor(cfg.RunID)
	if err := writeResolvConfAt(resolvPath); err != nil {
		return Result{}, fmt.Errorf("write tool resolv.conf: %w", err)
	}
	if cfg.Ephemeral {
		defer os.Remove(resolvPath)
	}
	cfg.resolvConfPath = resolvPath

	// 3. reachback diagnostic for a host-loopback proxy (story 14): a clear
	// message instead of an opaque tool failure when the sidecar cannot reach the
	// proxy port through the pasta map.
	if cfg.ProxyOnHostLoopback {
		if err := checkReachback(ctx, r, cfg); err != nil {
			return Result{}, fmt.Errorf("%w: %v (is the proxy listening on the host's 127.0.0.1:%s? the jail reaches it via the pasta map %s)",
				ErrReachback, err, cfg.Proxy.Port, mappedHostLoopback)
		}
	}

	// 3b. split-tunnel direct-reachability diagnostic (story 10): for each
	// allowlisted direct with a specific port, probe it from the jail netns and
	// WARN (not fail) if it does not answer, so an unreachable-on-LAN allowed
	// direct is told apart from a jail-policy block. It is a WARNING, not a
	// hard-fail: unlike the proxy (whose absence means fail-closed), a down direct
	// is not a leak and must not stop the jailed tool's proxy egress from running.
	warnUnreachableDirects(ctx, r, cfg)

	// 4. run the tool sharing the sidecar netns, with its resolv.conf pointed at
	// the forwarder (via --dns) so all name resolution goes proxy-side. stdout and
	// stderr are captured SEPARATELY so a podman/runtime SETUP failure (podman's
	// own 125/126/127 diagnostic, which podman writes to ITS stderr) is told apart
	// from the wrapped tool's own non-zero exit.
	// The live sinks (when set by `netcage run`) stream the tool's stdout/stderr
	// to os.Stdout/os.Stderr as they arrive; the returned strings are still
	// captured for the probes. When nil (verify/leak-test), Run captures only.
	//
	// In INTERACTIVE mode (`netcage run -it`) toolRunSpec instead requests RAW
	// passthrough (stdin wired, no capture, no tee): podman's `-it` owns the
	// container PTY, so the jailed shell behaves like a normal `podman run -it`.
	// The network jail is IDENTICAL either way (same sidecar/netns/firewall/forced
	// egress/fail-closed above); only the tool's stdio wiring differs.
	out, errOut, runErr := r.Run(ctx, cfg.toolRunSpec())
	res := Result{ToolStdout: out, ToolStderr: errOut}
	if runErr != nil {
		var ee *exec.ExitError
		if errors.As(runErr, &ee) {
			if setupErr := classifyPodmanSetupFailure(ee.ExitCode(), errOut); setupErr != nil {
				// podman/the runtime never got the tool running (bad image, missing
				// command, runtime exec failure). Surface it as a jail SETUP error, NOT
				// as the tool's exit code, so a broken image is not hidden behind a
				// plausible-looking "tool exited 125".
				return res, setupErr
			}
			res.ToolExit = ee.ExitCode()
			return res, nil // tool ran but exited non-zero; that is the tool's result
		}
		return res, fmt.Errorf("run wrapped tool: %w%s", runErr, stderrSuffix(errOut))
	}
	return res, nil
}

// ErrJailSetup is returned when podman or the OCI runtime never got the wrapped
// tool running (a bad/unpullable image, a tool command not found in the image, or
// a runtime exec failure). It is distinct from a wrapped tool that RAN and merely
// exited non-zero, whose code flows to Result.ToolExit instead.
var ErrJailSetup = errors.New("the wrapped tool never started: podman/runtime setup failure")

// classifyPodmanSetupFailure decides whether a non-zero podman exit is a
// podman/runtime SETUP failure (the tool never ran) rather than the wrapped
// tool's own exit code, and if so returns a jail setup error naming the failure
// with podman's own diagnostic. It returns nil when the exit should be treated
// as the tool's result.
//
// Signals, in order of strength:
//
//   - Podman writes its OWN setup diagnostic to STDERR prefixed with "Error:"
//     (e.g. an unpullable image, or crun's "executable file ... not found").
//     Because the tool-run step captures podman's stderr SEPARATELY from the
//     tool's stdout, an "Error:" line on podman's stderr is an unambiguous
//     podman-level failure: the tool never produced output, podman did.
//   - The 125 (podman config/pull) / 126 (runtime could not exec) / 127 (command
//     not found) convention corroborates it.
//
// Residual ambiguity: a wrapped tool could itself exit 125/126/127 AND, in
// theory, print a line beginning "Error:" to stderr. We resolve it in favour of
// NOT hiding a setup failure, but ONLY when podman's stderr carries a diagnostic
// that names a podman/runtime setup fault. A bare 125/126/127 with no such
// diagnostic on stderr is treated as the tool's own exit (the tool ran). This
// keeps a genuine tool exit (TestJail_PropagatesToolExitCode) propagating while
// still catching the broken-image / missing-command cases.
func classifyPodmanSetupFailure(code int, podmanStderr string) error {
	switch code {
	case 125, 126, 127:
		if diag := podmanSetupDiagnostic(podmanStderr); diag != "" {
			return fmt.Errorf("%w (podman exit %d): %s", ErrJailSetup, code, diag)
		}
	}
	return nil
}

// podmanSetupDiagnostic returns the podman/runtime setup diagnostic line from
// podman's captured stderr, or "" if the stderr does not look like a
// podman-level setup fault. podman prefixes its own errors with "Error:"; the
// OCI runtime (crun/runc) failures surface there too ("OCI runtime", "crun:",
// "executable file ... not found").
func podmanSetupDiagnostic(stderr string) string {
	trimmed := strings.TrimSpace(stderr)
	if trimmed == "" {
		return ""
	}
	lower := strings.ToLower(trimmed)
	markers := []string{
		"error:",         // podman's own error prefix (config/pull, unknown flag)
		"oci runtime",    // runtime could not exec (126) / not found (127)
		"crun:", "runc:", // the runtimes' own prefixes
		"executable file",  // "executable file ... not found in $PATH" (127)
		"manifest unknown", // image tag/digest not found on pull (125)
		"reading manifest", // pull/manifest failure (125)
	}
	matched := false
	for _, m := range markers {
		if strings.Contains(lower, m) {
			matched = true
			break
		}
	}
	if !matched {
		return ""
	}
	// Prefer the line that actually carries the fault (the "Error:" line, or a
	// runtime/manifest diagnostic) over noise like podman's "Trying to pull..."
	// progress line, so the surfaced message names the real failure.
	lines := strings.Split(trimmed, "\n")
	for _, line := range lines {
		s := strings.TrimSpace(line)
		ls := strings.ToLower(s)
		for _, m := range markers {
			if strings.Contains(ls, m) {
				return s
			}
		}
	}
	// Fall back to the first non-empty line.
	for _, line := range lines {
		if s := strings.TrimSpace(line); s != "" {
			return s
		}
	}
	return trimmed
}

// stderrSuffix formats a captured podman stderr for appending to an error
// message, or "" when empty, so setup failures carry podman's own diagnostic.
func stderrSuffix(stderr string) string {
	if s := strings.TrimSpace(stderr); s != "" {
		return ": " + s
	}
	return ""
}

// ErrFirewallNotApplied is returned when the post-start firewall verification
// finds the baked EXTRA_COMMANDS firewall missing or partial in the sidecar's
// netns. It is the fail-loud layer (ADR-0008): because the tun2socks entrypoint
// runs EXTRA_COMMANDS in a child subshell whose exit it ignores before `exec
// tun2socks`, a half-applied firewall would otherwise leave tun2socks running
// with a partial firewall (a leak); netcage aborts the jail loudly instead.
var ErrFirewallNotApplied = errors.New("the jail firewall is missing or partially applied in the sidecar netns")

// verifyFirewall VERIFIES the baked EXTRA_COMMANDS firewall is fully present in
// the sidecar's netns AFTER the sidecar is up, via `podman exec ... iptables -S
// OUTPUT` (and `ip6tables -S OUTPUT`) probes asserting the exact expected rule
// set. It aborts the jail loudly (returning ErrFirewallNotApplied) if any rule
// is missing/partial. This is the fail-loud layer (ADR-0008): EXTRA_COMMANDS
// self-heals the firewall on every (re)start but cannot abort the sidecar on a
// half-apply, so netcage's own verification is what guarantees fail-closed on
// the run/start paths. The whole step goes through the Runner seam (podman
// only), so netcage stays a pure podman client and can drive a remote podman.
func verifyFirewall(ctx context.Context, r Runner, cfg Config) error {
	wantV4, wantV6 := cfg.firewallVerifyRules(cfg.Proxy.Port)

	v4, serr, err := runPodman(ctx, r, "exec", cfg.sidecarName(), "iptables", "-S", "OUTPUT")
	if err != nil {
		return fmt.Errorf("probe iptables OUTPUT chain: %w%s", err, stderrSuffix(serr))
	}
	if err := checkRulesPresent(wantV4, v4); err != nil {
		return fmt.Errorf("%w (IPv4): %v\nobserved rules:\n%s", ErrFirewallNotApplied, err, v4)
	}

	v6, serr, err := runPodman(ctx, r, "exec", cfg.sidecarName(), "ip6tables", "-S", "OUTPUT")
	if err != nil {
		return fmt.Errorf("probe ip6tables OUTPUT chain: %w%s", err, stderrSuffix(serr))
	}
	if err := checkRulesPresent(wantV6, v6); err != nil {
		return fmt.Errorf("%w (IPv6): %v\nobserved rules:\n%s", ErrFirewallNotApplied, err, v6)
	}
	return nil
}

// startSidecarDNS launches the netcage-dns forwarder INSIDE the sidecar via
// `podman exec -d` (ADR-0006), bound on 127.0.0.1:53 in the shared netns,
// dialing the proxy at the reachable address. The helper binary was mounted into
// the sidecar at sidecarDNSHelperPath by SidecarRunArgs. It is
// container-lifecycle-bound: teardown's `podman rm -f` of the sidecar kills it,
// so there is no host-side process to track.
func startSidecarDNS(ctx context.Context, r Runner, cfg Config) error {
	proxyAddr := cfg.Proxy.Address()
	if cfg.ProxyOnHostLoopback {
		proxyAddr = mappedHostLoopback + ":" + cfg.Proxy.Port
	}
	args := []string{
		"exec", "-d", cfg.sidecarName(),
		sidecarDNSHelperPath, "-listen", "127.0.0.1:53", "-proxy", proxyAddr,
	}
	if cfg.DNSUpstream != "" {
		args = append(args, "-upstream", cfg.DNSUpstream)
	}
	if cfg.Proxy.Username != "" {
		args = append(args, "-user", cfg.Proxy.Username, "-pass", cfg.Proxy.Password)
	}
	if _, serr, err := runPodman(ctx, r, args...); err != nil {
		// The most likely exec failure is a NON-STATIC helper binary: the sidecar
		// image is musl-based, so a glibc-dynamic netcage-dns cannot exec there.
		// Release/install.sh builds are static; a hand-built one must be too.
		return fmt.Errorf("%w%s (is netcage-dns a static binary? build it with CGO_ENABLED=0; the sidecar image cannot exec a glibc-dynamic one)", err, stderrSuffix(serr))
	}
	// Give it a moment to bind before the tool starts resolving.
	time.Sleep(300 * time.Millisecond)
	return nil
}

// resolvConfPathFor is the STABLE, run-attributable host path of the tool's
// resolv.conf (nameserver 127.0.0.1). It is deterministic in the run id so a
// KEPT container's bind-mount source is the SAME on the original run and on every
// `netcage start` revive: podman re-mounts this exact path on restart, so it must
// not be a random temp name that a later revive cannot reproduce. It lives under
// the OS temp dir (world-writable-safe: it only ever says `nameserver 127.0.0.1`).
func resolvConfPathFor(runID string) string {
	return filepath.Join(os.TempDir(), "netcage-resolv-"+runID+".conf")
}

// writeResolvConfAt writes the in-netns-forwarder resolv.conf (127.0.0.1:53) to
// the given stable path, idempotently (overwrite is fine: the content is fixed).
// Used by both the run path and `netcage start` (which re-materialises the same
// file before reviving, so a revive works even if the durable file was removed).
func writeResolvConfAt(path string) error {
	return os.WriteFile(path, []byte("nameserver 127.0.0.1\noptions use-vc\n"), 0o644)
}

// dnsHelperPath locates the netcage-dns binary: an env override (set in tests),
// else a sibling of the running executable (how the release archive ships the
// pair), else on PATH.
func dnsHelperPath() (string, error) {
	if p := os.Getenv("NETCAGE_DNS_BIN"); p != "" {
		return p, nil
	}
	if exe, err := os.Executable(); err == nil {
		if exe, err = filepath.EvalSymlinks(exe); err == nil {
			sibling := filepath.Join(filepath.Dir(exe), "netcage-dns")
			if info, err := os.Stat(sibling); err == nil && !info.IsDir() {
				return sibling, nil
			}
		}
	}
	if p, err := exec.LookPath("netcage-dns"); err == nil {
		return p, nil
	}
	return "", errors.New("netcage-dns helper not found (set NETCAGE_DNS_BIN, place it next to the netcage binary, or install it on PATH)")
}

// ErrDirectUnreachable names a split-tunnel allowlisted direct that did not
// answer on the LAN (story 10). It is a DIAGNOSTIC signal, not a run failure:
// its wording deliberately says the destination is ON THE ALLOWLIST but did not
// answer, so an operator can tell a LAN problem (the direct host is down /
// wrong-IP / firewalled on the LAN) apart from a jail-policy block (a
// non-allowlisted destination the jail dropped). It is surfaced as a WARNING to
// stderr, never returned from Run, because a down direct is not a leak and must
// not stop the jailed tool's proxy egress.
var ErrDirectUnreachable = errors.New("a split-tunnel allowlisted direct did not answer on the LAN")

// warnUnreachableDirects probes each PORT-carrying allowlist entry from the jail
// netns and prints a story-10 diagnostic to stderr for any that do not answer.
// It skips port-less entries (a bare IP or CIDR with no :port has no single
// probe target). Probe failures are advisory only: the message distinguishes
// "on the allowlist but unreachable on the LAN" from a jail-policy block, so the
// operator is not left guessing why a direct destination is silent. Any probe
// infrastructure error (e.g. no alpine image) is swallowed: the diagnostic is a
// convenience, never a gate.
func warnUnreachableDirects(ctx context.Context, r Runner, cfg Config) {
	for _, a := range cfg.AllowDirect {
		if a.Port == 0 {
			continue // no single host:port to probe (all-ports / CIDR entry)
		}
		host := a.Network.IP.String()
		if err := probeDirect(ctx, r, cfg, host, a.Port); err != nil {
			fmt.Fprintln(os.Stderr, directUnreachableDiagnostic(host, a.Port, a.Raw))
		}
	}
}

// directUnreachableDiagnostic is the story-10 message for an allowlisted direct
// that did not answer on the LAN. Kept as a pure function so its wording (the
// LAN-problem-vs-policy-block distinction that is the whole point of story 10) is
// unit-testable without podman. It names the direct, that it is ON the allowlist,
// and that non-allowlisted destinations are dropped by design, so an operator can
// tell an unreachable-on-LAN allowed direct apart from a jail-policy block.
func directUnreachableDiagnostic(host string, port int, raw string) string {
	return fmt.Sprintf(
		"netcage: %v: %s:%d (allowlisted --allow-direct %q) did not answer over the LAN; this is a LAN problem (host down / wrong IP / LAN-firewalled), NOT a jail-policy block. Non-allowlisted destinations are dropped by design; this one is allowed but silent.",
		ErrDirectUnreachable, host, port, raw)
}

// probeDirect TCP-connects to an allowlisted direct host:port from inside the
// jail netns (a short-lived container sharing the sidecar netns), mirroring
// checkReachback. A non-nil error means the direct did not answer.
func probeDirect(ctx context.Context, r Runner, cfg Config, host string, port int) error {
	_, _, err := runPodman(ctx, r, "run", "--rm", "--network", "container:"+cfg.sidecarName(),
		"docker.io/library/alpine:latest", "sh", "-c",
		fmt.Sprintf("nc -z -w 3 %s %d", host, port))
	return err
}

// checkReachback dials the proxy port from inside the jail netns to give a clear
// diagnostic (story 14) before running the tool.
func checkReachback(ctx context.Context, r Runner, cfg Config) error {
	// Use a throwaway probe in the shared netns: nc-style TCP connect to the
	// mapped proxy. We use the sidecar's own netns via a short-lived exec.
	_, _, err := runPodman(ctx, r, "run", "--rm", "--network", "container:"+cfg.sidecarName(),
		"docker.io/library/alpine:latest", "sh", "-c",
		fmt.Sprintf("nc -z -w 3 %s %s", mappedHostLoopback, cfg.Proxy.Port))
	return err
}

// Teardown enforces the jail LIFECYCLE chosen by cfg.Ephemeral (the
// podman-fidelity split, ADR-0009):
//
//   - EPHEMERAL (cfg.Ephemeral true: the netcage `--rm` flag + every internal
//     one-shot) removes BOTH run-attributable containers, the tool and the
//     sidecar. The netns, the firewall rules, and the in-sidecar DNS forwarder
//     are lifecycle-bound to the sidecar container (they live in its
//     namespace/process tree), so removing it destroys them too; once no
//     netcage-run-<id>-* container remains, nothing of the run remains.
//   - KEPT (cfg.Ephemeral false: a plain `netcage run`) removes NEITHER, LEAVING
//     the stopped tool + its stopped sidecar behind (podman-run fidelity). This
//     is safe because the sidecar's firewall is baked into its EXTRA_COMMANDS
//     (ADR-0008), so the pair is fail-closed at rest and on any restart (LAN/UDP
//     dropped, DNS dead) even against a raw `podman start` outside netcage. The
//     tool container carries the netcage.managed label so it stays identifiable.
//     "Sidecar gone, tool kept" is not reachable (the `--network container:` edge
//     blocks removing the sidecar while the tool exists, and `--depend` cascades
//     to the tool - see the finding), so leave-both is the only coherent kept
//     end-state.
//
// It is the single teardown entry point wired to ALL exit paths (normal, error,
// and ctx-cancel/SIGINT, via Run's deferred call on a fresh context). On the
// removal (ephemeral) path it is:
//
//   - idempotent: removing an already-gone container is not an error (podman rm
//     -f -i ignores a missing container), so a second call is a clean no-op;
//   - best-effort-complete: a failure removing one resource still attempts the
//     rest; and
//   - error-surfacing: any genuine removal failure is aggregated and returned
//     (no silent partial teardown).
func Teardown(ctx context.Context, r Runner, cfg Config) error {
	// KEPT run: leave BOTH containers behind (the podman-fidelity feature). The
	// leftover pair is fail-closed via the baked EXTRA_COMMANDS firewall (ADR-0008)
	// and labelled netcage-managed, so it is safe and identifiable at rest.
	if !cfg.Ephemeral {
		return nil
	}
	var errs []error
	// Order: tool first (it shares/depends on the sidecar netns), then sidecar
	// (which takes the netns + firewall + DNS forwarder with it). -i (ignore) makes a missing container
	// a no-op, which is what gives idempotency.
	for _, name := range []string{cfg.toolName(), cfg.sidecarName()} {
		if _, serr, err := runPodman(ctx, r, "rm", "-f", "-i", name); err != nil {
			errs = append(errs, fmt.Errorf("removing %s: %w: %s", name, err, serr))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("jail teardown left residue: %w", errors.Join(errs...))
	}
	return nil
}
