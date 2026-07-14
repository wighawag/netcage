package cli_test

import (
	"strings"
	"testing"

	"github.com/wighawag/netcage/internal/cli"
)

// TestParse_ForwardParsesContainerPortAndDefaultBind asserts the happy path:
// `netcage forward <container> <port>` parses into a `forward` command carrying
// the container name, the numeric port, and the DEFAULT loopback bind
// (127.0.0.1), with no bind flag given (ADR-0014: loopback by default).
func TestParse_ForwardParsesContainerPortAndDefaultBind(t *testing.T) {
	cmd, err := cli.ParseWithEnv([]string{"forward", "netcage-run-abc-tool", "3001"}, noEnv)
	if err != nil {
		t.Fatalf("forward <container> <port> must parse: %v", err)
	}
	if cmd.Name != "forward" {
		t.Fatalf("Name = %q, want forward", cmd.Name)
	}
	if cmd.ForwardContainer != "netcage-run-abc-tool" {
		t.Fatalf("ForwardContainer = %q, want netcage-run-abc-tool", cmd.ForwardContainer)
	}
	if cmd.ForwardPort != 3001 {
		t.Fatalf("ForwardPort = %d, want 3001", cmd.ForwardPort)
	}
	if cmd.ForwardBind != "127.0.0.1" {
		t.Fatalf("ForwardBind = %q, want the loopback default 127.0.0.1", cmd.ForwardBind)
	}
}

// TestParse_ForwardRemapParsesHostAndJailPort asserts the remap form
// `netcage forward <container> <hostPort>:<jailPort>` binds the host port and
// connects to a DIFFERENT in-jail port: `8080:3001` => host 8080, jail 3001
// (ForwardHostPort is the host bind port, ForwardPort stays the jail/connect
// port). The bare single-port form defaults ForwardHostPort to the jail port, so
// downstream is uniform (host==jail is the zero-remap special case).
func TestParse_ForwardRemapParsesHostAndJailPort(t *testing.T) {
	// The bare form: host defaults to the jail port (backward compatible).
	bare, err := cli.ParseWithEnv([]string{"forward", "c", "3001"}, noEnv)
	if err != nil {
		t.Fatalf("bare form must parse: %v", err)
	}
	if bare.ForwardPort != 3001 || bare.ForwardHostPort != 3001 {
		t.Fatalf("bare 3001: ForwardHostPort=%d ForwardPort=%d, want both 3001 (host defaults to jail)", bare.ForwardHostPort, bare.ForwardPort)
	}
	// The remap form: host 8080 -> jail 3001.
	remap, err := cli.ParseWithEnv([]string{"forward", "c", "8080:3001"}, noEnv)
	if err != nil {
		t.Fatalf("remap form 8080:3001 must parse: %v", err)
	}
	if remap.ForwardHostPort != 8080 {
		t.Fatalf("8080:3001: ForwardHostPort = %d, want 8080", remap.ForwardHostPort)
	}
	if remap.ForwardPort != 3001 {
		t.Fatalf("8080:3001: ForwardPort (jail/connect) = %d, want 3001", remap.ForwardPort)
	}
}

// TestParse_ForwardRemapRejectsBadSides asserts BOTH sides of the remap are
// validated 1..65535 and that extra colons are refused loudly: a non-numeric or
// out-of-range host side, a bad jail side, or two-or-more colons (`1:2:3`) is a
// usage error. A bare bad port stays refused too (unchanged).
func TestParse_ForwardRemapRejectsBadSides(t *testing.T) {
	for _, p := range []string{"x:3001", "70000:3001", "0:3001", "8080:x", "8080:99999", "8080:0", "1:2:3", ":3001", "8080:"} {
		if _, err := cli.ParseWithEnv([]string{"forward", "c", p}, noEnv); err == nil {
			t.Fatalf("port spec %q accepted; want a loud usage error (both sides 1-65535, at most one colon)", p)
		}
	}
}

// TestParse_ForwardRemapWithBind asserts --bind still parses alongside the remap
// with unchanged semantics: `--bind 0.0.0.0 c 8080:3001` binds host 0.0.0.0:8080
// and connects to jail 3001.
func TestParse_ForwardRemapWithBind(t *testing.T) {
	cmd, err := cli.ParseWithEnv([]string{"forward", "--bind", "0.0.0.0", "c", "8080:3001"}, noEnv)
	if err != nil {
		t.Fatalf("--bind alongside remap must parse: %v", err)
	}
	if cmd.ForwardBind != "0.0.0.0" {
		t.Fatalf("ForwardBind = %q, want 0.0.0.0", cmd.ForwardBind)
	}
	if cmd.ForwardHostPort != 8080 || cmd.ForwardPort != 3001 {
		t.Fatalf("host/jail = %d/%d, want 8080/3001", cmd.ForwardHostPort, cmd.ForwardPort)
	}
}

// TestParse_ForwardCarriesNoProxy asserts `forward` is a NETCAGE-ONLY host-access
// verb that carries NO proxy at all: it stands up an INBOUND loopback forward,
// not an egress, so it needs neither --proxy nor a resolved proxy source (like
// detect-proxy / setup-default / the management verbs).
func TestParse_ForwardCarriesNoProxy(t *testing.T) {
	cmd, err := cli.ParseWithEnv([]string{"forward", "netcage-run-abc-tool", "3001"}, noEnv)
	if err != nil {
		t.Fatalf("forward should parse with no proxy at all: %v", err)
	}
	if cmd.Proxy.Host != "" || cmd.ProxySource != "" {
		t.Fatalf("forward must carry no proxy: got Proxy=%+v source=%q", cmd.Proxy, cmd.ProxySource)
	}
}

// TestParse_ForwardBindLoopbackAndAllInterfaces asserts both accepted binds parse
// (in --flag and --flag=value forms): the explicit loopback and the guardrailed
// all-interfaces opt-in (ADR-0014: 0.0.0.0 is the ONLY other accepted bind).
func TestParse_ForwardBindLoopbackAndAllInterfaces(t *testing.T) {
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"forward", "--bind", "127.0.0.1", "c", "80"}, "127.0.0.1"},
		{[]string{"forward", "--bind=127.0.0.1", "c", "80"}, "127.0.0.1"},
		{[]string{"forward", "--bind", "0.0.0.0", "c", "80"}, "0.0.0.0"},
		{[]string{"forward", "--bind=0.0.0.0", "c", "80"}, "0.0.0.0"},
	}
	for _, tc := range cases {
		cmd, err := cli.ParseWithEnv(tc.args, noEnv)
		if err != nil {
			t.Fatalf("%v must parse: %v", tc.args, err)
		}
		if cmd.ForwardBind != tc.want {
			t.Fatalf("%v: ForwardBind = %q, want %q", tc.args, cmd.ForwardBind, tc.want)
		}
	}
}

// TestParse_ForwardRejectsOtherBind asserts any bind other than 127.0.0.1 /
// 0.0.0.0 is refused loudly: a specific-interface bind is Out of Scope (spec), so
// the parse layer refuses it now rather than silently accepting a value the
// mechanism will not honour.
func TestParse_ForwardRejectsOtherBind(t *testing.T) {
	for _, v := range []string{"192.168.1.10", "::1", "localhost", "0.0.0.0:80", "not-an-ip"} {
		if _, err := cli.ParseWithEnv([]string{"forward", "--bind", v, "c", "80"}, noEnv); err == nil {
			t.Fatalf("--bind %q accepted; want a loud refusal (only 127.0.0.1 / 0.0.0.0)", v)
		}
	}
}

// TestParse_ForwardRejectsWrongPositionalCounts asserts zero / one / three
// positionals are usage errors: forward takes EXACTLY <container> <port>.
func TestParse_ForwardRejectsWrongPositionalCounts(t *testing.T) {
	for _, args := range [][]string{
		{"forward"},
		{"forward", "only-container"},
		{"forward", "c", "80", "extra"},
	} {
		if _, err := cli.ParseWithEnv(args, noEnv); err == nil {
			t.Fatalf("%v accepted; want a usage error (forward takes exactly <container> <port>)", args)
		}
	}
}

// TestParse_ForwardRejectsBadPort asserts a non-numeric or out-of-range port is
// refused loudly (mirroring the --allow port validation).
func TestParse_ForwardRejectsBadPort(t *testing.T) {
	for _, p := range []string{"abc", "0", "70000", "-1", "3.14"} {
		if _, err := cli.ParseWithEnv([]string{"forward", "c", p}, noEnv); err == nil {
			t.Fatalf("port %q accepted; want a loud refusal (expected 1-65535)", p)
		}
	}
}

// TestParse_ForwardRejectsProxyFlag asserts forward takes NO --proxy: it is an
// inbound host-access verb, not an egress, so a --proxy is a usage error (not a
// silently-ignored flag), like detect-proxy / setup-default.
func TestParse_ForwardRejectsProxyFlag(t *testing.T) {
	if _, err := cli.ParseWithEnv([]string{"forward", "--proxy", "socks5h://127.0.0.1:9050", "c", "80"}, noEnv); err == nil {
		t.Fatal("forward must reject --proxy (it does not egress)")
	}
}

// TestParse_ForwardRejectsUnknownFlag asserts forward fails closed on an unknown
// flag, like the rest of the surface.
func TestParse_ForwardRejectsUnknownFlag(t *testing.T) {
	if _, err := cli.ParseWithEnv([]string{"forward", "--bogus", "c", "80"}, noEnv); err == nil {
		t.Fatal("forward must reject an unknown flag (fail-closed on the unknown)")
	}
}

// TestPreflight_ForwardSkipsProxyPreflight asserts forward is NOT run through the
// proxy preflight (it carries no proxy): Preflight is a no-op for it, exactly
// like the management verbs / detect-proxy / setup-default.
func TestPreflight_ForwardSkipsProxyPreflight(t *testing.T) {
	cmd, err := cli.ParseWithEnv([]string{"forward", "c", "80"}, noEnv)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !cmd.IsProxyless() {
		t.Fatal("forward must be proxyless (no proxy resolution, no preflight)")
	}
	if err := cmd.Preflight(); err != nil {
		t.Fatalf("forward Preflight should be a no-op (no proxy to check), got: %v", err)
	}
}

// TestParse_PublishFlagPointsAtForward asserts the refused -p / --publish message
// now points the operator at the safe path (`netcage forward`), so they discover
// the verb instead of hitting a dead end (spec story 11).
func TestParse_PublishFlagPointsAtForward(t *testing.T) {
	for _, flag := range []string{"-p", "--publish"} {
		_, err := cli.ParseWithEnv([]string{"run", "--proxy", "socks5h://h:1", flag, "8080:8080", "img", "cmd"}, noEnv)
		if err == nil {
			t.Fatalf("%s must still be refused", flag)
		}
		if !strings.Contains(err.Error(), "netcage forward") {
			t.Fatalf("%s refusal %q should point at `netcage forward`", flag, err.Error())
		}
	}
}
