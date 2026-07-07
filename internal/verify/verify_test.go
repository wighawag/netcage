package verify

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/wighawag/netcage/internal/cli"
	"github.com/wighawag/netcage/internal/jail"
)

// fakeRunner returns a canned jail.Result / error without touching the system,
// so the verify orchestration logic is unit-testable without podman.
func fakeRunner(out string, err error) JailRunner {
	return func(ctx context.Context, cfg jail.Config) (jail.Result, error) {
		return jail.Result{ToolStdout: out}, err
	}
}

func TestReport_OkRequiresEveryAssertionAndAtLeastOne(t *testing.T) {
	if (Report{}).Ok() {
		t.Fatal("an empty report must NOT be Ok (nothing was asserted)")
	}
	pass := Report{Assertions: []Assertion{{Name: "a", Ok: true}, {Name: "b", Ok: true}}}
	if !pass.Ok() {
		t.Fatal("all-pass report should be Ok")
	}
	mixed := Report{Assertions: []Assertion{{Name: "a", Ok: true}, {Name: "b", Ok: false}}}
	if mixed.Ok() {
		t.Fatal("a report with any failed assertion must NOT be Ok")
	}
}

func TestReport_ExitCode(t *testing.T) {
	if (Report{Assertions: []Assertion{{Ok: true}}}).ExitCode() != 0 {
		t.Fatal("all-pass report must exit 0")
	}
	if (Report{Assertions: []Assertion{{Ok: true}, {Ok: false}}}).ExitCode() != 1 {
		t.Fatal("a report with any failure must exit non-zero (CI-gating)")
	}
	if (Report{}).ExitCode() != 1 {
		t.Fatal("an empty report must exit non-zero (nothing asserted is not a pass)")
	}
}

func TestRun_ExecutesEveryCheckAndDoesNotShortCircuit(t *testing.T) {
	var ran []string
	checks := []Check{
		{Name: "a", Run: func(ctx context.Context) Assertion { ran = append(ran, "a"); return Assertion{Ok: true} }},
		{Name: "b", Run: func(ctx context.Context) Assertion { ran = append(ran, "b"); return Assertion{Ok: false} }},
		{Name: "c", Run: func(ctx context.Context) Assertion { ran = append(ran, "c"); return Assertion{Ok: true} }},
	}
	rep := Run(context.Background(), checks)
	if len(ran) != 3 || ran[0] != "a" || ran[2] != "c" {
		t.Fatalf("all checks must run in order even past a failure; ran=%v", ran)
	}
	if rep.Ok() {
		t.Fatal("report with a failing check must not be Ok")
	}
	if rep.Assertions[0].Name != "a" {
		t.Fatalf("check Name should default onto the assertion; got %q", rep.Assertions[0].Name)
	}
}

func TestExitIPProbe_ExtractsObservedIP(t *testing.T) {
	got, err := ExitIPProbe(context.Background(), fakeRunner("127.0.0.2", nil), jail.Config{})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if got != "127.0.0.2" {
		t.Fatalf("observed IP = %q, want 127.0.0.2", got)
	}
}

func TestExitIPProbe_FindsIPAmongNoise(t *testing.T) {
	got, _ := ExitIPProbe(context.Background(), fakeRunner("HTTP/1.0 200 OK\r\n\r\n203.0.113.55", nil), jail.Config{})
	if got != "203.0.113.55" {
		t.Fatalf("observed IP = %q, want 203.0.113.55", got)
	}
}

func TestExitIPProbe_PropagatesRunError(t *testing.T) {
	_, err := ExitIPProbe(context.Background(), fakeRunner("", errors.New("boom")), jail.Config{})
	if err == nil {
		t.Fatal("a jail-run error must propagate from ExitIPProbe")
	}
}

func TestFailClosedProbe_NoEgressWhenMarkerAbsent(t *testing.T) {
	egressed, err := FailClosedProbe(context.Background(), fakeRunner("wget: bad address", nil), jail.Config{}, "EGRESS-OK")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if egressed {
		t.Fatal("marker absent => no egress (fail-closed); got egressed=true")
	}
}

func TestFailClosedProbe_EgressWhenMarkerPresent(t *testing.T) {
	egressed, _ := FailClosedProbe(context.Background(), fakeRunner("EGRESS-OK reached", nil), jail.Config{}, "EGRESS-OK")
	if !egressed {
		t.Fatal("marker present => egress (a LEAK); got egressed=false")
	}
}

func TestFailClosedProbe_JailErrorCountsAsNoEgress(t *testing.T) {
	// If the jail run itself errors with the proxy down, the tool reached
	// nothing: that is the fail-closed outcome, not a leak.
	egressed, err := FailClosedProbe(context.Background(), fakeRunner("", errors.New("proxy down")), jail.Config{}, "EGRESS-OK")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if egressed {
		t.Fatal("a jail error with the proxy down must count as no-egress (fail-closed)")
	}
}

// --- glibc DNS-over-TCP: the message-split verdict (pure) ---

// TestDNSOverTCPAssertion_PassOnResolvedIP: the container ran and getent returned
// an IP => PASS with the DNS-over-TCP-works detail.
func TestDNSOverTCPAssertion_PassOnResolvedIP(t *testing.T) {
	a := dnsOverTCPAssertion("1.1.1.1", nil, nil)
	if !a.Ok {
		t.Fatalf("a resolved IP must PASS; got %+v", a)
	}
	if !strings.Contains(a.Detail, "1.1.1.1") || !strings.Contains(a.Detail, "DNS-over-TCP via the proxy works") {
		t.Fatalf("pass detail must name the IP and the working TCP path; got %q", a.Detail)
	}
}

// TestDNSOverTCPAssertion_EmptyOutputBlamesForwarder: the container RAN (no
// errors) but getent returned nothing => the genuine TCP-forwarder failure, and
// ONLY here may the message blame the in-jail DNS forwarder.
func TestDNSOverTCPAssertion_EmptyOutputBlamesForwarder(t *testing.T) {
	a := dnsOverTCPAssertion("", nil, nil)
	if a.Ok {
		t.Fatal("empty getent output must FAIL")
	}
	if a.Err != nil {
		t.Fatalf("a ran-but-empty result is a Detail verdict, not an Err; got Err=%v", a.Err)
	}
	if !strings.Contains(a.Detail, "not answering over TCP") || !strings.Contains(a.Detail, "probe container ran") {
		t.Fatalf("only the ran-but-empty case may blame the forwarder, and must say the container ran; got %q", a.Detail)
	}
}

// TestDNSOverTCPAssertion_PullErrorIsNotAForwarderVerdict: a pre-pull failure is
// a setup/network problem reported as an Err, and must NOT claim the forwarder is
// broken (the false-negative this whole fix removes).
func TestDNSOverTCPAssertion_PullErrorIsNotAForwarderVerdict(t *testing.T) {
	a := dnsOverTCPAssertion("", nil, errors.New("pull timeout"))
	if a.Ok {
		t.Fatal("a pull failure must FAIL the assertion")
	}
	if a.Err == nil {
		t.Fatal("a pull failure must be surfaced as an Err (its own cause), not a Detail")
	}
	msg := a.Err.Error()
	if !strings.Contains(msg, "NOT a DNS-over-TCP failure") {
		t.Fatalf("a pull failure must explicitly disclaim a DNS-over-TCP verdict; got %q", msg)
	}
	if strings.Contains(strings.ToLower(msg), "not answering over tcp") {
		t.Fatalf("a pull failure must NOT blame the forwarder; got %q", msg)
	}
}

// TestDNSOverTCPAssertion_RunErrorIsNotAForwarderVerdict: a jail/runtime error
// (podman/timeout) means the probe produced no verdict; report THAT, never a
// forwarder claim.
func TestDNSOverTCPAssertion_RunErrorIsNotAForwarderVerdict(t *testing.T) {
	a := dnsOverTCPAssertion("", errors.New("context deadline exceeded"), nil)
	if a.Ok {
		t.Fatal("a jail-run error must FAIL the assertion")
	}
	if a.Err == nil {
		t.Fatal("a jail-run error must be surfaced as an Err, not a Detail")
	}
	msg := a.Err.Error()
	if !strings.Contains(msg, "NOT necessarily a DNS-over-TCP failure") {
		t.Fatalf("a jail-run error must disclaim a definite DNS-over-TCP verdict; got %q", msg)
	}
	if strings.Contains(strings.ToLower(msg), "not answering over tcp") {
		t.Fatalf("a jail-run error must NOT blame the forwarder; got %q", msg)
	}
}

// TestDNSOverTCPAssertion_PullErrorTakesPrecedence: if the pull failed, the
// probe never ran, so pullErr is reported even if a runErr is also present.
func TestDNSOverTCPAssertion_PullErrorTakesPrecedence(t *testing.T) {
	a := dnsOverTCPAssertion("", errors.New("run err"), errors.New("pull err"))
	if a.Err == nil || !strings.Contains(a.Err.Error(), "pull err") {
		t.Fatalf("pull failure must be reported first (the probe never ran); got %+v", a)
	}
}

// --- split-tunnel: direct-reachability probe (pure orchestration) ---

func TestDirectReachableProbe_ReachedWhenMarkerPresent(t *testing.T) {
	reached, err := DirectReachableProbe(context.Background(), fakeRunner("LAN-HOST-OK answered", nil), jail.Config{}, "LAN-HOST-OK")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !reached {
		t.Fatal("marker present => the direct endpoint answered; got reached=false")
	}
}

func TestDirectReachableProbe_NotReachedWhenMarkerAbsent(t *testing.T) {
	reached, err := DirectReachableProbe(context.Background(), fakeRunner("nc: connection timed out", nil), jail.Config{}, "LAN-HOST-OK")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if reached {
		t.Fatal("marker absent => the direct endpoint did NOT answer; got reached=true")
	}
}

func TestDirectReachableProbe_JailErrorIsNotReached(t *testing.T) {
	// A jail-run error means the direct probe reached nothing: the direct is NOT
	// reachable (so an allowlist-active report would fail), never a false pass.
	reached, err := DirectReachableProbe(context.Background(), fakeRunner("", errors.New("probe failed")), jail.Config{}, "LAN-HOST-OK")
	if err == nil {
		t.Fatal("a jail-run error must propagate from DirectReachableProbe")
	}
	if reached {
		t.Fatal("a jail-run error must count as not-reached (an unreachable direct fails the report)")
	}
}

// --- split-tunnel: no-clear-LAN-DNS assertion (row 2, pure render) ---

// TestNoClearLANDNSAssertion_PassWhenDirectDroppedAndForwarderResolves is the
// row-2 pass: with --allow-direct active, a DIRECT clear-DNS query aimed at the
// allowed LAN resolver is NOT answered directly (dropped / no clear answer), AND
// the loopback DNS-over-SOCKS forwarder STILL resolves. The black-hole/counter
// shape (NOT "direct dig must time out"): the pass is "no direct clear answer
// from the LAN", proven alongside the forwarder still working.
func TestNoClearLANDNSAssertion_PassWhenDirectDroppedAndForwarderResolves(t *testing.T) {
	a := NoClearLANDNSAssertion(false /*directAnswered*/, true /*forwarderResolved*/, nil)
	if !a.Ok {
		t.Fatalf("direct DROPPED + forwarder resolves must PASS; got %+v", a)
	}
	if !strings.Contains(strings.ToLower(a.Detail), "forwarder") {
		t.Fatalf("pass detail should credit the forwarder path; got %q", a.Detail)
	}
}

// TestNoClearLANDNSAssertion_FailWhenDirectAnswered is the leak: a DIRECT clear
// query to the LAN resolver got an answer => --allow-direct opened a clear-DNS
// hole to the LAN (the exact Tails row-2 leak). Must FAIL and name the leak.
func TestNoClearLANDNSAssertion_FailWhenDirectAnswered(t *testing.T) {
	a := NoClearLANDNSAssertion(true /*directAnswered*/, true, nil)
	if a.Ok {
		t.Fatal("a direct clear-DNS answer from the LAN resolver is a LEAK; must FAIL")
	}
	if !strings.Contains(strings.ToLower(a.Detail), "clear") || !strings.Contains(strings.ToLower(a.Detail), "dns") {
		t.Fatalf("leak detail must name the clear-DNS hole; got %q", a.Detail)
	}
}

// TestNoClearLANDNSAssertion_FailWhenForwarderBroken guards the OTHER half: the
// direct is dropped (good) but the loopback forwarder does NOT resolve, so DNS
// is not actually served over the proxy path. That is not a pass: the assertion
// must FAIL (a jail whose DNS is simply dead is not proof the hole is closed the
// RIGHT way).
func TestNoClearLANDNSAssertion_FailWhenForwarderBroken(t *testing.T) {
	a := NoClearLANDNSAssertion(false, false /*forwarderResolved*/, nil)
	if a.Ok {
		t.Fatal("direct dropped but forwarder dead is NOT a pass; DNS must be served over the proxy path")
	}
}

// TestNoClearLANDNSAssertion_ProbeErrorIsNotAVerdict: a probe/jail error means we
// got no verdict on the hole; report it as an Err (a failure), never a false
// pass and never a false leak claim.
func TestNoClearLANDNSAssertion_ProbeErrorIsNotAVerdict(t *testing.T) {
	a := NoClearLANDNSAssertion(false, true, errors.New("context deadline exceeded"))
	if a.Ok {
		t.Fatal("a probe error must FAIL the assertion")
	}
	if a.Err == nil {
		t.Fatal("a probe error must be surfaced as an Err, not a silent Detail verdict")
	}
}

// --- IPv6 egress fails-closed (Tails row 3, pure render) ---

// TestIPv6EgressFailsClosedAssertion_PassWhenBothV6PathsDropped is the row-3
// pass: NEITHER a v6-literal TCP attempt NOR a v6 DNS/AAAA attempt from the jail
// reached the real network (both markers absent). netcage does not carry v6 (no
// v6 default route out of the netns; egress v6 UDP is hard-dropped), so both v6
// egress paths fail closed. PASS.
func TestIPv6EgressFailsClosedAssertion_PassWhenBothV6PathsDropped(t *testing.T) {
	a := IPv6EgressFailsClosedAssertion(false /*v6TCPReached*/, false /*v6DNSReached*/, nil)
	if !a.Ok {
		t.Fatalf("both v6 paths dropped must PASS; got %+v", a)
	}
	if !strings.Contains(strings.ToLower(a.Detail), "ipv6") && !strings.Contains(strings.ToLower(a.Detail), "v6") {
		t.Fatalf("pass detail should name the v6 property; got %q", a.Detail)
	}
}

// TestIPv6EgressFailsClosedAssertion_FailWhenV6TCPReached is the v6-TCP leak: a
// v6-literal TCP connect from the jail reached the real network => v6 is a
// bypass of the forced egress (the classic transparent-proxy leak). Must FAIL
// and name the v6 TCP leak.
func TestIPv6EgressFailsClosedAssertion_FailWhenV6TCPReached(t *testing.T) {
	a := IPv6EgressFailsClosedAssertion(true /*v6TCPReached*/, false, nil)
	if a.Ok {
		t.Fatal("a v6-literal TCP that reached the real network is a LEAK; must FAIL")
	}
	if !strings.Contains(strings.ToLower(a.Detail), "tcp") {
		t.Fatalf("leak detail must name the v6 TCP path; got %q", a.Detail)
	}
}

// TestIPv6EgressFailsClosedAssertion_FailWhenV6DNSReached is the v6-DNS leak: a
// v6 DNS/AAAA path from the jail reached the real network => v6 DNS bypassed the
// proxy-side resolver. Must FAIL and name the v6 DNS leak.
func TestIPv6EgressFailsClosedAssertion_FailWhenV6DNSReached(t *testing.T) {
	a := IPv6EgressFailsClosedAssertion(false, true /*v6DNSReached*/, nil)
	if a.Ok {
		t.Fatal("a v6 DNS/AAAA path that reached the real network is a LEAK; must FAIL")
	}
	if !strings.Contains(strings.ToLower(a.Detail), "dns") {
		t.Fatalf("leak detail must name the v6 DNS path; got %q", a.Detail)
	}
}

// TestIPv6EgressFailsClosedAssertion_ProbeErrorIsNotAVerdict: a probe/jail error
// means we got no verdict on the v6 drop; report it as an Err (a failure), never
// a false pass and never a false leak claim.
func TestIPv6EgressFailsClosedAssertion_ProbeErrorIsNotAVerdict(t *testing.T) {
	a := IPv6EgressFailsClosedAssertion(false, false, errors.New("context deadline exceeded"))
	if a.Ok {
		t.Fatal("a probe error must FAIL the assertion")
	}
	if a.Err == nil {
		t.Fatal("a probe error must be surfaced as an Err, not a silent Detail verdict")
	}
}

// --- split-tunnel: allowlist-aware report composition (pure orchestration) ---

// pass/fail check builders for composition tests.
func passCheck(name string) Check {
	return Check{Name: name, Run: func(ctx context.Context) Assertion { return Assertion{Ok: true} }}
}
func failCheck(name string) Check {
	return Check{Name: name, Run: func(ctx context.Context) Assertion { return Assertion{Ok: false} }}
}

// TestSplitTunnelChecks_NoAllowlistIsCoreOnlyUnchanged: with NO directs (empty
// allowlist), the composition is EXACTLY the three core checks, in order, and
// adds nothing. This is the no-allowlist-path-unchanged guarantee at the
// composition seam.
func TestSplitTunnelChecks_NoAllowlistIsCoreOnlyUnchanged(t *testing.T) {
	core := []Check{passCheck("exit-ip"), passCheck("dns"), passCheck("fail-closed")}
	got := SplitTunnelChecks(core, nil)
	if len(got) != 3 {
		t.Fatalf("empty allowlist must yield exactly the 3 core checks; got %d", len(got))
	}
	for i, want := range []string{"exit-ip", "dns", "fail-closed"} {
		if got[i].Name != want {
			t.Fatalf("core check %d = %q, want %q (order/identity must be unchanged)", i, got[i].Name, want)
		}
	}
	rep := Run(context.Background(), got)
	if !rep.Ok() {
		t.Fatalf("all-core-pass, no-allowlist report must be Ok:\n%s", rep.String())
	}
}

// TestSplitTunnelChecks_AllowlistGreenOnlyWhenDirectAndCoreBothPass: with an
// allowlist active, the report is green ONLY when the direct-reachability check
// AND all three core checks pass. A direct that works does NOT excuse a core
// leak, and a core-clean jail whose direct is unreachable is NOT green either.
func TestSplitTunnelChecks_AllowlistGreenOnlyWhenDirectAndCoreBothPass(t *testing.T) {
	corePass := []Check{passCheck("exit-ip"), passCheck("dns"), passCheck("fail-closed")}
	coreLeak := []Check{passCheck("exit-ip"), failCheck("dns"), passCheck("fail-closed")} // a leak on the non-allowlisted path
	directOk := []Check{passCheck("direct-reachable")}
	directDown := []Check{failCheck("direct-reachable")}

	// direct works AND core clean => green.
	if rep := Run(context.Background(), SplitTunnelChecks(corePass, directOk)); !rep.Ok() {
		t.Fatalf("direct reachable + core clean must be green:\n%s", rep.String())
	}
	// direct works BUT a core assertion leaks => the report FAILS (approve must
	// mean leak-tight-outside-allowlist, not merely "the direct host works").
	if rep := Run(context.Background(), SplitTunnelChecks(coreLeak, directOk)); rep.Ok() {
		t.Fatalf("a leak on the non-allowlisted path must FAIL the report even though the direct works:\n%s", rep.String())
	}
	// core clean BUT direct unreachable => the report FAILS (approve must also mean
	// the named directs are reachable).
	if rep := Run(context.Background(), SplitTunnelChecks(corePass, directDown)); rep.Ok() {
		t.Fatalf("an unreachable direct must FAIL the report even though the jail is leak-tight:\n%s", rep.String())
	}
}

// TestSplitTunnelChecks_DirectChecksRunAfterCore: the direct-reachability checks
// are appended AFTER the three core checks, so a report lists the core leak
// assertions first (they are the whole point) then the direct-reachability.
func TestSplitTunnelChecks_DirectChecksRunAfterCore(t *testing.T) {
	core := []Check{passCheck("exit-ip"), passCheck("dns"), passCheck("fail-closed")}
	direct := []Check{passCheck("direct-a"), passCheck("direct-b")}
	got := SplitTunnelChecks(core, direct)
	names := make([]string, len(got))
	for i, c := range got {
		names[i] = c.Name
	}
	want := []string{"exit-ip", "dns", "fail-closed", "direct-a", "direct-b"}
	if len(names) != len(want) {
		t.Fatalf("composed %d checks, want %d: %v", len(names), len(want), names)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("check %d = %q, want %q (core first, directs appended)", i, names[i], want[i])
		}
	}
}

// TestReport_HeaderStatesResolvedProxyAndSource: the report renders a header line
// stating the RESOLVED proxy AND which source supplied it, so `netcage verify`
// answers "which proxy am I on?" on demand. The source label is a pure resolution
// fact carried on the Report, so it is asserted WITHOUT podman (no jail run).
func TestReport_HeaderStatesResolvedProxyAndSource(t *testing.T) {
	proxy := cli.ProxyConfig{Host: "127.0.0.1", Port: "9050"}
	for _, src := range []cli.ProxySource{cli.ProxySourceFlag, cli.ProxySourceEnv, cli.ProxySourceConfig} {
		rep := Report{Proxy: proxy, Source: src}
		out := rep.String()
		wantProxy := "proxy: socks5h://127.0.0.1:9050"
		wantSource := "source: " + string(src)
		if !strings.Contains(out, wantProxy) {
			t.Fatalf("report header must state the resolved proxy %q; got:\n%s", wantProxy, out)
		}
		if !strings.Contains(out, wantSource) {
			t.Fatalf("report header must state %q; got:\n%s", wantSource, out)
		}
	}
}

// TestReport_HeaderOmitsCredentials: the report NEVER prints embedded proxy
// credentials (env/flag proxies may carry user:pass@); the header shows only
// socks5h://host:port, so a screen-share / log of `verify` leaks no secret.
func TestReport_HeaderOmitsCredentials(t *testing.T) {
	proxy := cli.ProxyConfig{Host: "127.0.0.1", Port: "9050", Username: "user", Password: "secret"}
	out := Report{Proxy: proxy, Source: cli.ProxySourceEnv}.String()
	if strings.Contains(out, "secret") || strings.Contains(out, "user") {
		t.Fatalf("report header must NOT print proxy credentials; got:\n%s", out)
	}
	if !strings.Contains(out, "proxy: socks5h://127.0.0.1:9050") {
		t.Fatalf("report header must still state the credential-free proxy; got:\n%s", out)
	}
}

func TestIsHostLoopback(t *testing.T) {
	for _, h := range []string{"127.0.0.1", "::1", "localhost"} {
		if !isHostLoopback(h) {
			t.Fatalf("%q should be host-loopback", h)
		}
	}
	for _, h := range []string{"bastion.example", "203.0.113.9", "10.0.0.5"} {
		if isHostLoopback(h) {
			t.Fatalf("%q should NOT be host-loopback", h)
		}
	}
}

func TestFirstIP(t *testing.T) {
	cases := map[string]string{
		"127.0.0.2":                        "127.0.0.2",
		"line1\n203.0.113.55\nline3":       "203.0.113.55",
		"no ip here":                       "",
		"999.1.1.1 is invalid 10.0.0.1":    "10.0.0.1",
		"HTTP/1.0 200\r\n\r\n198.51.100.7": "198.51.100.7",
	}
	for in, want := range cases {
		if got := firstIP(in); got != want {
			t.Fatalf("firstIP(%q) = %q, want %q", in, got, want)
		}
	}
}
