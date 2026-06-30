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
