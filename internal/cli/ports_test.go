package cli_test

import (
	"testing"

	"github.com/wighawag/netcage/internal/cli"
)

// TestParse_PortsParsesContainer asserts the happy path: `netcage ports
// <container>` parses into a `ports` command carrying the container NAME, with
// the JSON flag unset (the human-table default) when no --json is given.
func TestParse_PortsParsesContainer(t *testing.T) {
	cmd, err := cli.ParseWithEnv([]string{"ports", "netcage-run-abc-tool"}, noEnv)
	if err != nil {
		t.Fatalf("ports <container> must parse: %v", err)
	}
	if cmd.Name != "ports" {
		t.Fatalf("Name = %q, want ports", cmd.Name)
	}
	if cmd.PortsContainer != "netcage-run-abc-tool" {
		t.Fatalf("PortsContainer = %q, want netcage-run-abc-tool", cmd.PortsContainer)
	}
	if cmd.JSON {
		t.Fatalf("JSON = true, want false (no --json given)")
	}
}

// TestParse_PortsJSONFlag asserts `--json` sets the machine-contract flag, reusing
// the existing Command.JSON field (one spelling for the machine contract, like
// detect-proxy --json).
func TestParse_PortsJSONFlag(t *testing.T) {
	for _, args := range [][]string{
		{"ports", "netcage-run-abc-tool", "--json"},
		{"ports", "--json", "netcage-run-abc-tool"},
	} {
		cmd, err := cli.ParseWithEnv(args, noEnv)
		if err != nil {
			t.Fatalf("%v must parse: %v", args, err)
		}
		if !cmd.JSON {
			t.Fatalf("%v: JSON = false, want true (--json given)", args)
		}
		if cmd.PortsContainer != "netcage-run-abc-tool" {
			t.Fatalf("%v: PortsContainer = %q, want netcage-run-abc-tool", args, cmd.PortsContainer)
		}
	}
}

// TestParse_PortsCarriesNoProxy asserts `ports` is a NETCAGE-ONLY read verb that
// carries NO proxy at all: it only reads /proc, it does not egress, so it needs
// neither --proxy nor a resolved proxy source (like forward / detect-proxy /
// setup-default / the management verbs).
func TestParse_PortsCarriesNoProxy(t *testing.T) {
	cmd, err := cli.ParseWithEnv([]string{"ports", "netcage-run-abc-tool"}, noEnv)
	if err != nil {
		t.Fatalf("ports should parse with no proxy at all: %v", err)
	}
	if cmd.Proxy.Host != "" || cmd.ProxySource != "" {
		t.Fatalf("ports must carry no proxy: got Proxy=%+v source=%q", cmd.Proxy, cmd.ProxySource)
	}
}

// TestParse_PortsRejectsWrongPositionalCounts asserts zero and two+ positionals
// are usage errors: ports takes EXACTLY one <container>.
func TestParse_PortsRejectsWrongPositionalCounts(t *testing.T) {
	for _, args := range [][]string{
		{"ports"},
		{"ports", "c1", "c2"},
		{"ports", "c1", "c2", "c3"},
	} {
		if _, err := cli.ParseWithEnv(args, noEnv); err == nil {
			t.Fatalf("%v accepted; want a usage error (ports takes exactly one <container>)", args)
		}
	}
}

// TestParse_PortsRejectsProxyFlag asserts ports takes NO --proxy: it only reads
// /proc, it does not egress, so a --proxy is a usage error (not a
// silently-ignored flag), like forward / detect-proxy / setup-default.
func TestParse_PortsRejectsProxyFlag(t *testing.T) {
	for _, args := range [][]string{
		{"ports", "--proxy", "socks5h://127.0.0.1:9050", "c"},
		{"ports", "--proxy=socks5h://127.0.0.1:9050", "c"},
	} {
		if _, err := cli.ParseWithEnv(args, noEnv); err == nil {
			t.Fatalf("%v accepted; ports must reject --proxy (it does not egress)", args)
		}
	}
}

// TestParse_PortsRejectsUnknownFlag asserts ports fails closed on an unknown flag,
// like the rest of the surface.
func TestParse_PortsRejectsUnknownFlag(t *testing.T) {
	if _, err := cli.ParseWithEnv([]string{"ports", "--bogus", "c"}, noEnv); err == nil {
		t.Fatal("ports must reject an unknown flag (fail-closed on the unknown)")
	}
}

// TestPreflight_PortsSkipsProxyPreflight asserts ports is NOT run through the proxy
// preflight (it carries no proxy): Preflight is a no-op for it, exactly like the
// management verbs / detect-proxy / setup-default / forward.
func TestPreflight_PortsSkipsProxyPreflight(t *testing.T) {
	cmd, err := cli.ParseWithEnv([]string{"ports", "c"}, noEnv)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !cmd.IsProxyless() {
		t.Fatal("ports must be proxyless (no proxy resolution, no preflight)")
	}
	if err := cmd.Preflight(); err != nil {
		t.Fatalf("ports Preflight should be a no-op (no proxy to check), got: %v", err)
	}
}
