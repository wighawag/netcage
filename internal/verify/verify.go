// Package verify is netcage's leak-test: the project's top acceptance seam. It
// runs probes through the SAME jail that `netcage run` builds and asserts the
// three leak properties, returning a Report whose Ok is false (=> non-zero exit,
// CI-gating) if ANY assertion fails:
//
//  1. Exit IP is the proxy's   — an IP-echo through the jail observes the proxy's
//     exit IP, not the host's (forced TCP egress).
//  2. DNS goes through the proxy — a unique hostname resolves PROXY-SIDE (the
//     proxy's resolver sees the lookup), NOT via the host resolver. Checked for
//     BOTH musl (alpine nslookup, UDP) and glibc (getent, which honours
//     resolv.conf `use-vc` and queries over TCP), so a UDP-only forwarder that
//     breaks glibc images cannot pass verify.
//  3. Fail-closed on proxy-kill — with the proxy killed, a probe FAILS CLOSED
//     (no egress), never falling back to the host network.
//
// The assertions are deterministic against internal/socks5hfixture (known exit
// IP, known DNS view, killable), so they need no real Tor. verify MUTATES THE
// SYSTEM (it stands up the jail), so its tests are podman-gated.
package verify

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/wighawag/netcage/internal/cli"
	"github.com/wighawag/netcage/internal/devimage"
	"github.com/wighawag/netcage/internal/jail"
)

// Assertion is one leak-test result.
type Assertion struct {
	Name   string
	Ok     bool
	Detail string // human-readable evidence (observed vs expected)
	Err    error  // non-nil if the probe itself errored (counts as a failure)
}

// Report is the outcome of a verify run.
type Report struct {
	Assertions []Assertion
}

// Ok reports whether EVERY assertion passed. A verify run is a pass iff Ok.
func (r Report) Ok() bool {
	for _, a := range r.Assertions {
		if !a.Ok {
			return false
		}
	}
	return len(r.Assertions) > 0
}

// ExitCode is the process exit code for the report: 0 iff every assertion
// passed, else 1. This is the CI-gating contract (story 8): any failed leak
// assertion makes `netcage verify` exit non-zero.
func (r Report) ExitCode() int {
	if r.Ok() {
		return 0
	}
	return 1
}

// String renders a per-assertion pass/fail summary.
func (r Report) String() string {
	var b strings.Builder
	for _, a := range r.Assertions {
		mark := "FAIL"
		if a.Ok {
			mark = "PASS"
		}
		fmt.Fprintf(&b, "[%s] %s", mark, a.Name)
		if a.Detail != "" {
			fmt.Fprintf(&b, ": %s", a.Detail)
		}
		if a.Err != nil {
			fmt.Fprintf(&b, " (error: %v)", a.Err)
		}
		b.WriteString("\n")
	}
	return b.String()
}

// JailRunner runs a jail config and returns its result. jail.Run satisfies this;
// tests can substitute it.
type JailRunner func(ctx context.Context, cfg jail.Config) (jail.Result, error)

// DefaultJailRunner runs the real jail via jail.Run with the real ExecRunner.
func DefaultJailRunner(ctx context.Context, cfg jail.Config) (jail.Result, error) {
	return jail.Run(ctx, jail.ExecRunner{}, cfg)
}

// Check is one named leak check: it runs (typically a probe through the jail)
// and returns the assertion result. The orchestrator composes the three.
type Check struct {
	Name string
	Run  func(ctx context.Context) Assertion
}

// Run executes the checks in order and collects them into a Report. It does NOT
// short-circuit: every assertion runs so the report is complete (a leak-test
// should show ALL failures, not just the first).
func Run(ctx context.Context, checks []Check) Report {
	var rep Report
	for _, c := range checks {
		a := c.Run(ctx)
		if a.Name == "" {
			a.Name = c.Name
		}
		rep.Assertions = append(rep.Assertions, a)
	}
	return rep
}

// ExitIPProbe runs an IP-echo probe through the jail (cfg's ToolArgv must fetch
// an echo that returns the observed source IP) and returns the IP the echo saw.
// The caller asserts it equals the proxy's exit IP.
func ExitIPProbe(ctx context.Context, run JailRunner, cfg jail.Config) (observedIP string, err error) {
	res, err := run(ctx, cfg)
	if err != nil {
		return "", fmt.Errorf("exit-IP probe: jail run: %w", err)
	}
	return firstIP(res.ToolStdout), nil
}

// DNSProbe runs a name-resolution probe through the jail (cfg's ToolArgv must
// resolve a unique name and print the answer). It returns the tool's stdout so
// the caller can assert the unique name resolved to the proxy-side answer; the
// caller separately checks the proxy-side observability hook (the fixture's
// ResolvedHosts) and that the HOST resolver did not see the name.
func DNSProbe(ctx context.Context, run JailRunner, cfg jail.Config) (toolStdout string, err error) {
	res, err := run(ctx, cfg)
	if err != nil {
		return "", fmt.Errorf("dns probe: jail run: %w", err)
	}
	return res.ToolStdout, nil
}

// FailClosedProbe runs a probe through the jail with the proxy expected to be
// DOWN (the caller kills it first). It returns whether the probe egressed: true
// means the tool reached the target (a LEAK / fail-open), false means no egress
// (fail-closed, the desired outcome). egress is detected by the marker appearing
// in the tool output.
func FailClosedProbe(ctx context.Context, run JailRunner, cfg jail.Config, egressMarker string) (egressed bool, err error) {
	res, err := run(ctx, cfg)
	if err != nil {
		// A jail-run error here is NOT egress; the tool failed to reach anything,
		// which is the fail-closed outcome. Surface it as no-egress.
		return false, nil
	}
	return strings.Contains(res.ToolStdout, egressMarker), nil
}

// DirectReachableProbe runs a probe through the jail to a split-tunnel
// allowlisted DIRECT endpoint (cfg's ToolArgv must attempt the direct and print
// egressMarker iff it answered). It returns whether the direct was reached: true
// means the named direct answered over the split-tunnel hole (the desired
// outcome for an allowlisted run), false means it did not.
//
// It is the mirror of FailClosedProbe (same marker-in-output detection) with the
// polarity of "good" flipped: for the direct, reaching it IS the pass. Unlike
// FailClosedProbe (where a jail-run error is the fail-closed SUCCESS), a jail-run
// error here is a FAILURE (the direct probe could not run, so the direct is not
// proven reachable) and is propagated, so an unreachable/broken direct fails the
// report rather than passing silently.
func DirectReachableProbe(ctx context.Context, run JailRunner, cfg jail.Config, egressMarker string) (reached bool, err error) {
	res, err := run(ctx, cfg)
	if err != nil {
		return false, fmt.Errorf("direct-reachability probe: jail run: %w", err)
	}
	return strings.Contains(res.ToolStdout, egressMarker), nil
}

// SplitTunnelChecks composes the allowlist-aware leak-test check list: the three
// CORE leak assertions (exit-IP is the proxy's, DNS is proxy-side, fail-closed on
// proxy-kill) ALWAYS run, and each DIRECT-reachability check is appended AFTER
// them. The core checks come first because they are the whole point: an
// allowlist is a hole in a leak-proof jail, so verify must first prove the jail
// is STILL leak-tight for all NON-allowlisted traffic, then that the named
// directs work.
//
// The greenness contract falls out of Report.Ok (every assertion must pass): an
// allowlist-active report (directs non-empty) is green ONLY when the directs are
// reachable AND all three core assertions hold; a leak on the non-allowlisted
// path fails the report even if the directs work, and an unreachable direct fails
// it even if the jail is leak-tight. So `approve` means "proven leak-tight
// outside the allowlist," not merely "the direct host works."
//
// With NO directs (an EMPTY allowlist), the result is EXACTLY the three core
// checks, unchanged and in order: the no-allowlist path is byte-for-byte today's
// composition, this is purely additive.
func SplitTunnelChecks(core []Check, directs []Check) []Check {
	if len(directs) == 0 {
		return core
	}
	out := make([]Check, 0, len(core)+len(directs))
	out = append(out, core...)
	out = append(out, directs...)
	return out
}

// RunCommandVerify runs the leak-test against a REAL configured proxy (the
// `netcage verify` CLI path) and returns the report. Unlike the deterministic
// fixture-backed test suite (which knows the exit IP, the DNS view, and can kill
// the proxy), against a live proxy verify asserts the property it CAN observe
// without controllable infrastructure: forced egress is active, i.e. the jail's
// observed exit IP DIFFERS from the host's own direct exit IP (the tool did not
// egress on the host network). The deterministic three-assertion proof lives in
// the fixture-backed leak-test (the project's acceptance gate); this CLI path is
// the operator's on-demand smoke against their real proxy.
//
// It uses a public IP-echo over HTTP; if the host-side baseline cannot be
// obtained (offline), the check reports an error (a failure), never a false
// pass.
func RunCommandVerify(ctx context.Context, proxy cli.ProxyConfig) Report {
	cfg := jail.Config{
		Proxy:               proxy,
		ProxyOnHostLoopback: isHostLoopback(proxy.Host),
		Image:               "docker.io/library/alpine:latest",
		ToolArgv:            []string{"sh", "-c", "wget -qO- -T 10 " + ipEchoURL + " 2>&1 || true"},
	}
	// A glibc DNS probe: resolve a public name with getent (glibc getaddrinfo),
	// which HONOURS resolv.conf's `options use-vc` and queries DNS over TCP. This
	// is the exact path a UDP-only forwarder broke while musl (alpine) still
	// worked, so exercising it here stops that regression from passing verify.
	// The default dev image is buildpack-deps (glibc + getent).
	dnsCfg := jail.Config{
		Proxy:               proxy,
		ProxyOnHostLoopback: isHostLoopback(proxy.Host),
		Image:               devimage.ImageReference(),
		ToolArgv: []string{
			"sh", "-c",
			// print an A record via glibc getaddrinfo; empty output on failure
			"getent ahostsv4 " + dnsProbeName + " 2>/dev/null | head -n1 || true",
		},
	}

	return Run(ctx, []Check{
		{Name: "forced-egress-exit-ip-differs-from-host", Run: func(ctx context.Context) Assertion {
			hostIP, herr := hostExitIP(ctx)
			if herr != nil {
				return Assertion{Ok: false, Err: fmt.Errorf("could not get host baseline exit IP (offline?): %w", herr)}
			}
			jailIP, jerr := ExitIPProbe(ctx, DefaultJailRunner, cfg)
			if jerr != nil {
				return Assertion{Ok: false, Err: jerr}
			}
			if jailIP == "" {
				return Assertion{Ok: false, Detail: "jail produced no exit IP (forced egress may have failed closed)"}
			}
			if jailIP == hostIP {
				return Assertion{Ok: false, Detail: "jail exit IP " + jailIP + " EQUALS the host's: traffic is NOT forced through the proxy (leak)"}
			}
			return Assertion{Ok: true, Detail: "jail exit IP " + jailIP + " differs from host " + hostIP + " (forced egress active)"}
		}},
		{Name: "dns-resolves-over-tcp-glibc", Run: func(ctx context.Context) Assertion {
			out, err := DNSProbe(ctx, DefaultJailRunner, dnsCfg)
			if err != nil {
				return Assertion{Ok: false, Err: err}
			}
			if ip := firstIP(out); ip != "" {
				return Assertion{Ok: true, Detail: "glibc getaddrinfo resolved " + dnsProbeName + " to " + ip + " (DNS-over-TCP via the proxy works)"}
			}
			return Assertion{Ok: false, Detail: "glibc getaddrinfo could NOT resolve " + dnsProbeName +
				" in the jail: the in-jail DNS forwarder is not answering over TCP (resolv.conf sets use-vc). " +
				"A UDP-only forwarder breaks glibc images; check netcage-dns."}
		}},
	})
}

// dnsProbeName is a stable public hostname the glibc DNS check resolves. Its
// actual IP is irrelevant (we only assert it resolves to SOMETHING), so a
// well-known always-up name is used.
const dnsProbeName = "one.one.one.one"

// ipEchoURL is a public service returning the caller's IP as plain text.
const ipEchoURL = "http://api.ipify.org/"

// hostExitIP fetches the host's own direct exit IP (no jail) as the baseline.
func hostExitIP(ctx context.Context) (string, error) {
	req, err := httpGet(ctx, ipEchoURL)
	if err != nil {
		return "", err
	}
	ip := firstIP(req)
	if ip == "" {
		return "", fmt.Errorf("no IP in host baseline response")
	}
	return ip, nil
}

func isHostLoopback(host string) bool {
	return host == "127.0.0.1" || host == "::1" || host == "localhost"
}

// httpGet fetches url directly (NO jail, for the host baseline) and returns the
// body as a string.
func httpGet(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256))
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// firstIP returns the first IPv4 literal found in s, else "".
func firstIP(s string) string {
	for _, tok := range strings.FieldsFunc(s, func(r rune) bool {
		return r == '\n' || r == '\r' || r == ' ' || r == '\t'
	}) {
		tok = strings.TrimSpace(tok)
		if isIPv4(tok) {
			return tok
		}
	}
	return ""
}

func isIPv4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "" || len(p) > 3 {
			return false
		}
		n := 0
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
			n = n*10 + int(c-'0')
		}
		if n > 255 {
			return false
		}
	}
	return true
}
