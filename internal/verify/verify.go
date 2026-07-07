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
	// Proxy is the RESOLVED proxy verify ran against; Source is which of
	// flag|env|config supplied it (from the CLI resolution). They are reported in
	// the header (see String) so `netcage verify` answers "which proxy am I on?"
	// on demand. They are a pure resolution fact (no jail run needed to know
	// them), so the header is testable without podman.
	Proxy  cli.ProxyConfig
	Source cli.ProxySource

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

// String renders the resolved-proxy header (proxy + source) followed by the
// per-assertion pass/fail summary. The header states which proxy verify ran
// against and where it came from (flag|env|config), so `netcage verify` doubles
// as the on-demand "which proxy am I on?" inspector. It prints only the
// credential-free socks5h://host:port (never any embedded user:pass@), so a
// shared/logged report leaks no secret. The header is omitted when no proxy is
// set (a zero Report), keeping the pure-orchestration tests unaffected.
func (r Report) String() string {
	var b strings.Builder
	if r.Proxy.Host != "" {
		fmt.Fprintf(&b, "proxy: socks5h://%s", r.Proxy.Address())
		if r.Source != "" {
			fmt.Fprintf(&b, " (source: %s)", r.Source)
		}
		b.WriteString("\n")
	}
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

// DefaultRunner is the real podman Runner (ExecRunner) used for host-network
// podman steps that are NOT a jail run, e.g. pre-pulling the DNS-probe image
// before the timed jail run (jail.PullImage). Like DefaultJailRunner it carries
// the graphroot `--root` injection through ExecRunner, so the pull lands in the
// same store the jail runs from.
var DefaultRunner jail.Runner = jail.ExecRunner{}

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

// ExitIPForProxy runs the SAME IP-echo exit-IP probe RunCommandVerify uses, but
// against an arbitrary resolved socks5h proxy, and returns the exit IP the jail
// observed. It is the exit-IP machinery REUSED by `detect-proxy` for its optional
// exit-IP EVIDENCE (proof the egress is not the host IP) so that verb does not
// reinvent the jail-run-plus-IP-echo path.
//
// It is EVIDENCE-gathering, not a leak assertion: it makes NO claim about whose
// exit it is (the honesty constraint forbids labelling the provider) and does NOT
// compare against the host IP. It fetches the exit IP over the SAME public IP-echo
// through an EPHEMERAL jail (remove both, no residue). An unreachable proxy /
// unavailable podman / empty answer returns an error so the caller OMITS the
// evidence rather than presenting a false one.
func ExitIPForProxy(ctx context.Context, run JailRunner, proxy cli.ProxyConfig) (exitIP string, err error) {
	cfg := jail.Config{
		Proxy:               proxy,
		ProxyOnHostLoopback: isHostLoopback(proxy.Host),
		Image:               "docker.io/library/alpine:latest",
		ToolArgv:            []string{"sh", "-c", "wget -qO- -T 10 " + ipEchoURL + " 2>&1 || true"},
		Ephemeral:           true, // internal one-shot: remove both, no residue
	}
	ip, err := ExitIPProbe(ctx, run, cfg)
	if err != nil {
		return "", err
	}
	if ip == "" {
		return "", fmt.Errorf("exit-IP probe produced no IP (the proxy may have failed closed)")
	}
	return ip, nil
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

// NoClearLANDNSProbe runs a probe through a SPLIT-TUNNEL-ACTIVE jail that aims a
// DIRECT clear-DNS query (tcp/udp 53) at the ALLOWED LAN resolver and reports
// whether it got a clear answer STRAIGHT from the LAN. cfg's ToolArgv must print
// directAnsweredMarker iff the direct clear query resolved (the LEAK), and MUST
// NOT print it when the query was dropped / unanswered.
//
// This is the row-2 (Tails leak catalogue) probe. It is the black-hole/counter
// shape mandated by ADR-0003 and dns-through-socks-is-tcp-not-udp.md, NOT the
// naive "direct dig must time out": under netcage the tool's ORDINARY DNS is
// served by the loopback forwarder, so a query CAN answer; the leak is whether a
// query aimed DIRECTLY at the LAN resolver (bypassing the forwarder) answers
// from the LAN. answered=true means --allow-direct opened a clear-DNS hole (a
// FAILURE); answered=false means it was dropped and DNS stays on the proxy path.
// A jail-run error is propagated (no verdict), never a false pass.
func NoClearLANDNSProbe(ctx context.Context, run JailRunner, cfg jail.Config, directAnsweredMarker string) (directAnswered bool, err error) {
	res, err := run(ctx, cfg)
	if err != nil {
		return false, fmt.Errorf("no-clear-LAN-DNS probe: jail run: %w", err)
	}
	return strings.Contains(res.ToolStdout, directAnsweredMarker), nil
}

// NoClearLANDNSAssertion renders the row-2 verdict from the two observations the
// live probe makes (plus any probe error), as a pure function so the message
// split is unit-testable without podman (it is exported so the podman-gated
// integration probe in verify_test can reuse the exact same verdict logic):
//
//   - probeErr != nil: the probe/jail itself errored, so there is NO verdict on
//     the hole. Surfaced as an Err (a failure), never a false pass or a false
//     leak claim.
//   - directAnswered: a clear-DNS query aimed DIRECTLY at the allowed LAN
//     resolver got an answer from the LAN => --allow-direct opened the exact
//     clear-DNS hole Tails forbids (a @LAN-resolver query can reveal the local
//     network's public IP). FAIL, naming the leak.
//   - !forwarderResolved: the direct was dropped (good) but the loopback
//     DNS-over-SOCKS forwarder did NOT resolve, so DNS is not actually served
//     the RIGHT way (a merely-dead resolver is not proof the hole is closed).
//     FAIL.
//   - !directAnswered && forwarderResolved: the direct clear query was dropped
//     AND DNS still resolves via the proxy-side forwarder. PASS: the split-tunnel
//     hole carries no direct clear DNS to the LAN.
func NoClearLANDNSAssertion(directAnswered, forwarderResolved bool, probeErr error) Assertion {
	if probeErr != nil {
		return Assertion{Ok: false, Err: fmt.Errorf("the no-clear-LAN-DNS probe could not run (a jail/runtime error, NOT a verdict on the hole): %w", probeErr)}
	}
	if directAnswered {
		return Assertion{Ok: false, Detail: "LEAK: a clear DNS query aimed DIRECTLY at the allowed LAN resolver was answered from the LAN; --allow-direct opened a clear-DNS hole (a @LAN-resolver query can reveal the local network's public IP). DNS must stay on the proxy-side forwarder."}
	}
	if !forwarderResolved {
		return Assertion{Ok: false, Detail: "the direct clear-DNS query was dropped (good) but the loopback DNS-over-SOCKS forwarder did NOT resolve: DNS is not being served over the proxy path, so the hole is not proven closed the right way"}
	}
	return Assertion{Ok: true, Detail: "direct clear DNS to the LAN resolver is dropped; DNS is served by the jail's loopback DNS-over-SOCKS forwarder (no direct clear query egresses to the LAN)"}
}

// IPv6EgressFailsClosedProbe runs a probe through the jail that attempts BOTH v6
// egress paths and reports which reached the real network. cfg's ToolArgv must
// try a v6-literal TCP connect and a v6 DNS/AAAA lookup, printing v6TCPMarker iff
// the v6 TCP attempt egressed and v6DNSMarker iff the v6 DNS attempt egressed,
// and MUST NOT print either when the attempt was dropped / unrouted.
//
// It is the Tails row-3 probe (IPv6 as a total bypass). netcage does not carry
// v6 at all: the jail's forced egress is v4-through-the-TUN (CLONE_MAIN=0 leaves
// the netns with only a v4 `default dev tun0`, so v6 TCP is unrouted) and egress
// v6 UDP is hard-dropped (firewallScript's ip6tables DROP, ADR-0003 parity), so
// BOTH markers must be ABSENT. A marker's PRESENCE is a LEAK. A jail-run error is
// propagated (no verdict), never a false pass.
func IPv6EgressFailsClosedProbe(ctx context.Context, run JailRunner, cfg jail.Config, v6TCPMarker, v6DNSMarker string) (v6TCPReached, v6DNSReached bool, err error) {
	res, err := run(ctx, cfg)
	if err != nil {
		return false, false, fmt.Errorf("ipv6-egress-fails-closed probe: jail run: %w", err)
	}
	return strings.Contains(res.ToolStdout, v6TCPMarker), strings.Contains(res.ToolStdout, v6DNSMarker), nil
}

// IPv6EgressFailsClosedAssertion renders the Tails row-3 verdict (IPv6 as a total
// bypass) from the two observations the live probe makes (plus any probe error),
// as a pure function so the message split is unit-testable without podman (it is
// exported so the podman-gated integration probe can reuse the exact same verdict
// logic). The PASS is that netcage does not carry v6: neither a v6-literal TCP
// attempt nor a v6 DNS/AAAA attempt from the jail reaches the real network. Its
// INTENT matches anonctl's equivalent v6-drop assertion (assert v6 is dropped,
// not proxied):
//
//   - probeErr != nil: the probe/jail itself errored, so there is NO verdict on
//     the v6 drop. Surfaced as an Err (a failure), never a false pass or a false
//     leak claim.
//   - v6TCPReached: a v6-literal TCP connect from the jail reached the real
//     network => v6 bypassed the forced egress (the classic transparent-proxy
//     leak: v4 forced, v6 in the clear). FAIL, naming the v6 TCP leak.
//   - v6DNSReached: a v6 DNS/AAAA path from the jail reached the real network =>
//     v6 DNS bypassed the proxy-side resolver. FAIL, naming the v6 DNS leak.
//   - neither reached: BOTH v6 egress paths failed closed (v6 TCP unrouted, v6
//     UDP/DNS dropped). PASS: netcage does not carry v6.
func IPv6EgressFailsClosedAssertion(v6TCPReached, v6DNSReached bool, probeErr error) Assertion {
	if probeErr != nil {
		return Assertion{Ok: false, Err: fmt.Errorf("the ipv6-egress-fails-closed probe could not run (a jail/runtime error, NOT a verdict on the v6 drop): %w", probeErr)}
	}
	if v6TCPReached {
		return Assertion{Ok: false, Detail: "LEAK: a v6-literal TCP connect from the jail REACHED the real network; IPv6 bypassed the forced egress (the classic transparent-proxy leak: v4 forced, v6 in the clear). All v6 egress must fail closed."}
	}
	if v6DNSReached {
		return Assertion{Ok: false, Detail: "LEAK: a v6 DNS/AAAA path from the jail REACHED the real network; IPv6 DNS bypassed the proxy-side resolver. All v6 egress must fail closed."}
	}
	return Assertion{Ok: true, Detail: "IPv6 egress fails closed: neither a v6-literal TCP connect nor a v6 DNS/AAAA path from the jail reached the real network (netcage does not carry v6: v6 TCP is unrouted, egress v6 UDP is dropped)"}
}

// NonTCPUDPDroppedProbe runs a probe through the jail that fires BOTH raw-UDP
// egress attempts and reports which reached the real network. cfg's ToolArgv must
// send a raw non-53 UDP datagram to an off-box host and a UDP/443 (QUIC) datagram
// to an off-box host, printing udpMarker iff the generic non-53 UDP attempt
// egressed and quic443Marker iff the UDP/443 attempt egressed, and MUST NOT print
// either when the datagram was dropped / unanswered.
//
// It is the Tails row-5 probe (raw non-53 UDP incl. UDP/443 QUIC). netcage
// hard-drops ALL UDP unconditionally (ADR-0003: "UDP is dropped, period"), so
// BOTH markers must be ABSENT. A marker's PRESENCE is a LEAK. Note this does NOT
// conflict with DNS: DNS still works DESPITE the UDP drop because the in-jail
// DNS-over-SOCKS forwarder is a client-side UDP->TCP conversion (ADR-0003 /
// dns-through-socks-is-tcp-not-udp.md), and this probe targets NON-53 UDP. A
// jail-run error is propagated (no verdict), never a false pass.
func NonTCPUDPDroppedProbe(ctx context.Context, run JailRunner, cfg jail.Config, udpMarker, quic443Marker string) (udpReached, quic443Reached bool, err error) {
	res, err := run(ctx, cfg)
	if err != nil {
		return false, false, fmt.Errorf("non-tcp-udp-dropped probe: jail run: %w", err)
	}
	return strings.Contains(res.ToolStdout, udpMarker), strings.Contains(res.ToolStdout, quic443Marker), nil
}

// NonTCPUDPDroppedAssertion renders the Tails row-5 verdict (raw non-53 UDP incl.
// UDP/443 QUIC) from the two observations the live probe makes (plus any probe
// error), as a pure function so the message split is unit-testable without podman
// (it is exported so the podman-gated integration probe can reuse the exact same
// verdict logic). The PASS is that netcage hard-drops ALL UDP: neither a generic
// non-53 UDP datagram nor a UDP/443 (QUIC / HTTP-3) datagram from the jail reaches
// the real network. Its INTENT matches anonctl's equivalent non-tcp-udp-drop
// assertion (assert UDP is dropped, not proxied):
//
//   - probeErr != nil: the probe/jail itself errored, so there is NO verdict on
//     the UDP drop. Surfaced as an Err (a failure), never a false pass or a false
//     leak claim.
//   - udpReached: a raw non-53 UDP datagram from the jail reached the real network
//     => raw UDP bypassed the hard-drop (a leak surface for QUIC/HTTP3/ping-style
//     traffic). FAIL, naming the raw-UDP leak.
//   - quic443Reached: a UDP/443 (QUIC / HTTP-3) datagram from the jail reached the
//     real network => the QUIC case specifically escaped. FAIL, naming the UDP/443
//     leak.
//   - neither reached: BOTH raw-UDP egress paths failed closed. PASS: netcage
//     hard-drops all UDP (a real client is expected to degrade to TCP; that is
//     client behaviour, not asserted here).
func NonTCPUDPDroppedAssertion(udpReached, quic443Reached bool, probeErr error) Assertion {
	if probeErr != nil {
		return Assertion{Ok: false, Err: fmt.Errorf("the non-tcp-udp-dropped probe could not run (a jail/runtime error, NOT a verdict on the UDP drop): %w", probeErr)}
	}
	if udpReached {
		return Assertion{Ok: false, Detail: "LEAK: a raw non-53 UDP datagram from the jail REACHED the real network; raw UDP bypassed the hard-drop (a leak surface for QUIC/HTTP3/ping-style traffic). All UDP must be dropped (ADR-0003)."}
	}
	if quic443Reached {
		return Assertion{Ok: false, Detail: "LEAK: a UDP/443 (QUIC / HTTP-3) datagram from the jail REACHED the real network; the QUIC case specifically escaped. All UDP must be dropped (ADR-0003)."}
	}
	return Assertion{Ok: true, Detail: "raw non-53 UDP is dropped: neither a generic non-53 UDP datagram nor a UDP/443 (QUIC) datagram from the jail reached the real network (netcage hard-drops all UDP, ADR-0003; a real client degrades to TCP)"}
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
func RunCommandVerify(ctx context.Context, proxy cli.ProxyConfig, source cli.ProxySource) Report {
	cfg := jail.Config{
		Proxy:               proxy,
		ProxyOnHostLoopback: isHostLoopback(proxy.Host),
		Image:               "docker.io/library/alpine:latest",
		ToolArgv:            []string{"sh", "-c", "wget -qO- -T 10 " + ipEchoURL + " 2>&1 || true"},
		// An internal one-shot probe: EPHEMERAL (remove both tool + sidecar), so
		// verify leaves no residue. Only a user `netcage run` without --rm is kept.
		Ephemeral: true,
	}
	// A glibc DNS probe: resolve a public name with getent (glibc getaddrinfo),
	// which HONOURS resolv.conf's `options use-vc` and queries DNS over TCP. This
	// is the exact path a UDP-only forwarder broke while musl (alpine) still
	// worked, so exercising it here stops that regression from passing verify.
	//
	// The image is the SMALL glibc debian:*-slim probe base (devimage.
	// DNSProbeImageReference), NOT the heavyweight buildpack-deps default: the
	// check only needs glibc + getent, and a large image pull is what made a
	// slow-proxy verify time out and misreport the TCP-DNS path as broken. The
	// image is pre-pulled on the HOST network BELOW (outside the jail/proxy) so the
	// timed jail run never pays that pull.
	dnsCfg := jail.Config{
		Proxy:               proxy,
		ProxyOnHostLoopback: isHostLoopback(proxy.Host),
		Image:               devimage.DNSProbeImageReference(),
		Ephemeral:           true, // internal one-shot: remove both, no residue
		ToolArgv: []string{
			"sh", "-c",
			// print an A record via glibc getaddrinfo; empty output on failure
			"getent ahostsv4 " + dnsProbeName + " 2>/dev/null | head -n1 || true",
		},
	}

	rep := Run(ctx, []Check{
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
			// Pre-pull the small glibc probe image on the HOST network (NOT through the
			// jail/proxy) so the timed jail run below never pays an image pull, then run
			// the probe. dnsOverTCPAssertion turns the three outcomes (pull failed /
			// jail run errored / container ran) into the verdict, so ONLY a container
			// that ran and returned empty is blamed on the TCP forwarder.
			pullErr := jail.PullImage(ctx, DefaultRunner, devimage.DNSProbeImageReference())
			var out string
			var runErr error
			if pullErr == nil {
				out, runErr = DNSProbe(ctx, DefaultJailRunner, dnsCfg)
			}
			return dnsOverTCPAssertion(out, runErr, pullErr)
		}},
	})
	// Record the resolved proxy + its source on the report so it also answers
	// "which proxy am I on?" (the leak assertions above are untouched).
	rep.Proxy = proxy
	rep.Source = source
	return rep
}

// dnsOverTCPAssertion renders the verdict of the glibc DNS-over-TCP check from
// its three distinct outcomes, so an infrastructure failure is NEVER misreported
// as "the forwarder is not answering over TCP" (the false-negative that made a
// slow-proxy verify condemn a healthy TCP-DNS path). It is a pure function so the
// message split is unit-testable without podman:
//
//   - pullErr != nil: the small glibc probe image could not be prepared (a
//     setup/network problem on the HOST side, before the jail even ran). NOT a
//     DNS-over-TCP verdict.
//   - runErr != nil: the jail/probe container itself errored (podman/runtime/
//     timeout), so it produced no verdict on the forwarder. NOT (necessarily) a
//     DNS-over-TCP failure.
//   - out has an IP: glibc getaddrinfo resolved over TCP (use-vc). PASS.
//   - out empty, no errors: the container RAN and getent returned nothing. THIS
//     is the genuine TCP-forwarder failure the check is for; only here do we
//     blame the in-jail DNS forwarder.
func dnsOverTCPAssertion(out string, runErr, pullErr error) Assertion {
	if pullErr != nil {
		return Assertion{Ok: false, Err: fmt.Errorf("could not prepare the glibc DNS-probe image (a setup/network problem, NOT a DNS-over-TCP failure): %w", pullErr)}
	}
	if runErr != nil {
		return Assertion{Ok: false, Err: fmt.Errorf("the glibc DNS probe could not run (a jail/runtime error, NOT necessarily a DNS-over-TCP failure): %w", runErr)}
	}
	if ip := firstIP(out); ip != "" {
		return Assertion{Ok: true, Detail: "glibc getaddrinfo resolved " + dnsProbeName + " to " + ip + " (DNS-over-TCP via the proxy works)"}
	}
	return Assertion{Ok: false, Detail: "glibc getaddrinfo could NOT resolve " + dnsProbeName +
		" in the jail even though the probe container ran: the in-jail DNS forwarder is not answering over TCP (resolv.conf sets use-vc). " +
		"A UDP-only forwarder breaks glibc images; check netcage-dns."}
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
