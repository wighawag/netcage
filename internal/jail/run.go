package jail

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Result is the outcome of a jail run.
type Result struct {
	ToolStdout string
	ToolExit   int
}

// ErrReachback is returned when a host-loopback proxy cannot be reached from the
// jail, with a self-explanatory message (story 14).
var ErrReachback = errors.New("the proxy on the host's loopback is not reachable from inside the jail")

// Run stands up the forced-egress jail, runs the wrapped tool, and tears
// everything down. It is the production path behind `tooljail run`.
//
// Steps (Option A, shared netns):
//  1. start the tun2socks sidecar (pasta + map-host-loopback for a loopback proxy)
//  2. apply the nft ruleset in the shared netns (UDP drop + reachback narrowing)
//  3. start the DNS-to-SOCKS-TCP forwarder in the netns and point resolv.conf at it
//  4. run the tool sharing the sidecar netns
//  5. tear it all down (deferred, best-effort, idempotent)
func Run(ctx context.Context, r Runner, cfg Config) (Result, error) {
	if cfg.RunID == "" {
		cfg.RunID = fmt.Sprintf("%d", time.Now().UnixNano())
	}

	// Teardown is deferred immediately so any later failure (or a cancelled ctx)
	// still cleans up. Teardown uses a FRESH context (not the run ctx) so it runs
	// to completion even when the run was cancelled by SIGINT. It is idempotent +
	// best-effort + aggregates errors.
	defer func() {
		tdCtx, tdCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer tdCancel()
		if err := Teardown(tdCtx, r, cfg); err != nil {
			fmt.Fprintf(os.Stderr, "tooljail: teardown: %v\n", err)
		}
	}()

	// 1. sidecar
	if _, err := r.Run(ctx, "podman", cfg.SidecarRunArgs()...); err != nil {
		return Result{}, fmt.Errorf("start tun2socks sidecar: %w", err)
	}

	pid, err := sidecarPID(ctx, r, cfg)
	if err != nil {
		return Result{}, fmt.Errorf("resolve sidecar pid: %w", err)
	}

	// 2. nft ruleset in the shared netns: drop all egress UDP (ADR-0003) and
	// narrow host-loopback reachback to exactly the proxy port. The tool->DNS hop
	// is loopback-internal to the netns (127.0.0.1:53), so it needs no egress rule.
	if err := applyNft(ctx, pid, cfg.nftRuleset(cfg.Proxy.Port)); err != nil {
		return Result{}, fmt.Errorf("apply nft ruleset in jail netns: %w", err)
	}

	// 3. DNS-to-SOCKS-TCP forwarder INSIDE the shared netns (via nsenter), bound
	// on 127.0.0.1:53 so the tool's resolv.conf (127.0.0.1) resolves proxy-side
	// over TCP. It dials the proxy at the reachable address (the pasta map for a
	// host-loopback proxy). DNS never egresses as UDP; the host resolver never
	// sees the name (ADR-0003 + the dns-to-socks-bridge finding).
	dnsProc, err := startNetnsDNS(ctx, pid, cfg)
	if err != nil {
		return Result{}, fmt.Errorf("start in-netns DNS forwarder: %w", err)
	}
	defer func() {
		if dnsProc != nil && dnsProc.Process != nil {
			_ = dnsProc.Process.Kill()
		}
	}()
	cfg.dnsServer = "127.0.0.1:53"

	// Mount a resolv.conf into the tool pointing at the in-netns forwarder.
	resolvPath, cleanupResolv, err := writeResolvConf()
	if err != nil {
		return Result{}, fmt.Errorf("write tool resolv.conf: %w", err)
	}
	defer cleanupResolv()
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

	// 4. run the tool sharing the sidecar netns, with its resolv.conf pointed at
	// the forwarder (via --dns) so all name resolution goes proxy-side.
	out, runErr := r.Run(ctx, "podman", cfg.ToolRunArgs()...)
	res := Result{ToolStdout: out}
	if runErr != nil {
		var ee *exec.ExitError
		if errors.As(runErr, &ee) {
			res.ToolExit = ee.ExitCode()
			return res, nil // tool ran but exited non-zero; that is the tool's result
		}
		return res, fmt.Errorf("run wrapped tool: %w", runErr)
	}
	return res, nil
}

// sidecarPID returns the host-side PID of the sidecar container (for nsenter).
func sidecarPID(ctx context.Context, r Runner, cfg Config) (string, error) {
	out, err := r.Run(ctx, "podman", "inspect", "--format", "{{.State.Pid}}", cfg.sidecarName())
	if err != nil {
		return "", err
	}
	pid := strings.TrimSpace(out)
	if pid == "" || pid == "0" {
		return "", errors.New("sidecar has no pid (did it fail to start? check `podman logs`)")
	}
	return pid, nil
}

// applyNft pipes the ruleset into nft inside the shared netns via nsenter (the
// rootless form proven by spike-pasta-loopback-reachback).
func applyNft(ctx context.Context, pid, ruleset string) error {
	cmd := exec.CommandContext(ctx, "nsenter", "-t", pid, "-n", "-U", "--preserve-credentials", "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(ruleset)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// startNetnsDNS launches the tooljail-dns forwarder inside the shared netns via
// nsenter, bound on 127.0.0.1:53, dialing the proxy at the reachable address.
func startNetnsDNS(ctx context.Context, pid string, cfg Config) (*exec.Cmd, error) {
	bin, err := dnsHelperPath()
	if err != nil {
		return nil, err
	}
	proxyAddr := cfg.Proxy.Address()
	if cfg.ProxyOnHostLoopback {
		proxyAddr = mappedHostLoopback + ":" + cfg.Proxy.Port
	}
	args := []string{
		"-t", pid, "-n", "-U", "--preserve-credentials",
		bin, "-listen", "127.0.0.1:53", "-proxy", proxyAddr,
	}
	if cfg.DNSUpstream != "" {
		args = append(args, "-upstream", cfg.DNSUpstream)
	}
	if cfg.Proxy.Username != "" {
		args = append(args, "-user", cfg.Proxy.Username, "-pass", cfg.Proxy.Password)
	}
	cmd := exec.CommandContext(ctx, "nsenter", args...)
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	// Give it a moment to bind.
	time.Sleep(300 * time.Millisecond)
	return cmd, nil
}

// writeResolvConf writes a temp resolv.conf pointing at the in-netns forwarder
// (127.0.0.1:53) and returns its path + a cleanup func.
func writeResolvConf() (string, func(), error) {
	f, err := os.CreateTemp("", "tooljail-resolv-*.conf")
	if err != nil {
		return "", func() {}, err
	}
	if _, err := f.WriteString("nameserver 127.0.0.1\noptions use-vc\n"); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", func() {}, err
	}
	f.Close()
	return f.Name(), func() { os.Remove(f.Name()) }, nil
}

// dnsHelperPath locates the tooljail-dns binary: an env override (set in tests),
// else a sibling of the running executable, else on PATH.
func dnsHelperPath() (string, error) {
	if p := os.Getenv("TOOLJAIL_DNS_BIN"); p != "" {
		return p, nil
	}
	if p, err := exec.LookPath("tooljail-dns"); err == nil {
		return p, nil
	}
	return "", errors.New("tooljail-dns helper not found (set TOOLJAIL_DNS_BIN or install it on PATH)")
}

// checkReachback dials the proxy port from inside the jail netns to give a clear
// diagnostic (story 14) before running the tool.
func checkReachback(ctx context.Context, r Runner, cfg Config) error {
	// Use a throwaway probe in the shared netns: nc-style TCP connect to the
	// mapped proxy. We use the sidecar's own netns via a short-lived exec.
	_, err := r.Run(ctx, "podman", "run", "--rm", "--network", "container:"+cfg.sidecarName(),
		"docker.io/library/alpine:latest", "sh", "-c",
		fmt.Sprintf("nc -z -w 3 %s %s", mappedHostLoopback, cfg.Proxy.Port))
	return err
}

// Teardown removes EVERY run-attributable resource the jail created: the tool
// container and the sidecar container. The netns and the nft ruleset are
// lifecycle-bound to the sidecar container (they live in its network namespace),
// so removing the sidecar destroys them too; once no tooljail-run-<id>-*
// container remains, no netns/nft for the run remains either.
//
// It is the single teardown entry point wired to ALL exit paths (normal, error,
// and ctx-cancel/SIGINT, via Run's deferred call on a fresh context). It is:
//
//   - idempotent: removing an already-gone container is not an error (podman rm
//     -f -i ignores a missing container), so a second call is a clean no-op;
//   - best-effort-complete: a failure removing one resource still attempts the
//     rest; and
//   - error-surfacing: any genuine removal failure is aggregated and returned
//     (no silent partial teardown).
func Teardown(ctx context.Context, r Runner, cfg Config) error {
	var errs []error
	// Order: tool first (it shares/depends on the sidecar netns), then sidecar
	// (which takes the netns + nft with it). -i (ignore) makes a missing container
	// a no-op, which is what gives idempotency.
	for _, name := range []string{cfg.toolName(), cfg.sidecarName()} {
		if out, err := r.Run(ctx, "podman", "rm", "-f", "-i", name); err != nil {
			errs = append(errs, fmt.Errorf("removing %s: %w: %s", name, err, out))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("jail teardown left residue: %w", errors.Join(errs...))
	}
	return nil
}
