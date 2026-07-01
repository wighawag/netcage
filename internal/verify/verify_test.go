package verify

import (
	"context"
	"errors"
	"testing"

	"github.com/wighawag/tooljail/internal/jail"
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
