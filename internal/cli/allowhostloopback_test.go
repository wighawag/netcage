package cli_test

import (
	"strings"
	"testing"

	"github.com/wighawag/netcage/internal/cli"
)

// This file is the CLI half of the host-loopback class of --allow (ADR-0019,
// task allow-host-loopback-reachback): a `--allow 127.0.0.1:<port>` names a
// same-host HOST-loopback service the jailed tool may reach via the pasta map,
// dispatched on the typed address. It is the SECOND class of the unified --allow
// (the LAN class is in allowdirect_test.go), guarded by a STRICTER port-blocklist
// (53 / the configured proxy port / 9050 / 9150 / 9051 / 1080). It stands up no
// jail and needs no podman; the map-address rewrite is proven at the jail-wiring
// seam (internal/jail), this proves the parse-time class-dispatch + blocklist.

// TestParse_AllowHostLoopback_AcceptsNonBlocklistedPort is the headline case: a
// host-loopback address (127.0.0.0/8) with a non-blocklisted TCP port parses
// into the typed allowlist, marked as the host-loopback CLASS, riding the SAME
// --allow flag as a LAN entry (no new flag, no new field). The Network stays the
// raw 127.0.0.1/32 (the map-address rewrite happens at rule-emit time).
func TestParse_AllowHostLoopback_AcceptsNonBlocklistedPort(t *testing.T) {
	for _, v := range []string{"127.0.0.1:11434", "127.0.0.1:8080", "127.0.0.5:3000"} {
		cmd, err := cli.ParseWithEnv(runArgs("--allow", v), noEnv)
		if err != nil {
			t.Fatalf("host-loopback allow %q rejected; want accepted: %v", v, err)
		}
		if len(cmd.AllowDirect) != 1 {
			t.Fatalf("%q: AllowDirect len = %d, want 1", v, len(cmd.AllowDirect))
		}
		e := cmd.AllowDirect[0]
		if !e.HostLoopback {
			t.Fatalf("%q must dispatch to the host-loopback CLASS (HostLoopback=true); got %+v", v, e)
		}
		if !strings.HasPrefix(e.Network.String(), "127.") {
			t.Fatalf("%q: Network %q must stay the raw host loopback (rewrite is at emit time)", v, e.Network.String())
		}
	}
}

// TestParse_AllowHostLoopback_RefusesWellKnownControlPorts is the load-bearing
// stricter blocklist (ADR-0019): the context-free well-known anonymizer/control
// ports (53 clear DNS, 9050/9150 Tor SOCKS, 9051 Tor CONTROL, 1080 generic SOCKS)
// are REFUSED LOUDLY at parse time on the host-loopback class, naming the port.
// These fire in the context-free parse (they do not need the proxy config).
func TestParse_AllowHostLoopback_RefusesWellKnownControlPorts(t *testing.T) {
	for _, tc := range []struct {
		port string
	}{
		{"53"}, {"9050"}, {"9150"}, {"9051"}, {"1080"},
	} {
		v := "127.0.0.1:" + tc.port
		_, err := cli.ParseWithEnv(runArgs("--allow", v), noEnv)
		if err == nil {
			t.Fatalf("host-loopback allow %q on a blocklisted port was accepted; want a loud refusal", v)
		}
		if !strings.Contains(err.Error(), tc.port) {
			t.Fatalf("refusal %q must name the offending port %q", err, tc.port)
		}
		if !strings.Contains(err.Error(), v) {
			t.Fatalf("refusal %q must name the offending value %q", err, v)
		}
	}
}

// TestParse_AllowHostLoopback_RefusesConfiguredProxyPort proves the proxy-port
// half of the blocklist: the CONFIGURED proxy port is refused on the
// host-loopback class where the proxy config is known (the run wiring), so the
// jailed tool can never dial the proxy's SOCKS surface directly and bypass the
// forced path. A DIFFERENT host-loopback port with the same proxy is fine.
func TestParse_AllowHostLoopback_RefusesConfiguredProxyPort(t *testing.T) {
	// Proxy on 127.0.0.1:7777; a --allow 127.0.0.1:7777 must be refused.
	_, err := cli.ParseWithEnv([]string{
		"run", "--proxy", "socks5h://127.0.0.1:7777",
		"--allow", "127.0.0.1:7777",
		"img:latest", "cmd",
	}, noEnv)
	if err == nil {
		t.Fatal("host-loopback allow on the configured proxy port was accepted; want a refusal (it would let the tool dial the SOCKS surface directly)")
	}
	if !strings.Contains(err.Error(), "7777") {
		t.Fatalf("refusal %q must name the proxy port 7777", err)
	}

	// A remote proxy on port 7777 does NOT reserve 7777 on host loopback (a
	// different socket): a host-loopback :7777 is fine when the proxy is remote.
	if _, err := cli.ParseWithEnv([]string{
		"run", "--proxy", "socks5h://bastion.example:7777",
		"--allow", "127.0.0.1:7777",
		"img:latest", "cmd",
	}, noEnv); err != nil {
		t.Fatalf("host-loopback :7777 with a REMOTE proxy on 7777 must be accepted (different socket): %v", err)
	}

	// A non-proxy host-loopback port with the loopback proxy is accepted.
	if _, err := cli.ParseWithEnv([]string{
		"run", "--proxy", "socks5h://127.0.0.1:7777",
		"--allow", "127.0.0.1:11434",
		"img:latest", "cmd",
	}, noEnv); err != nil {
		t.Fatalf("host-loopback :11434 with proxy on 7777 must be accepted: %v", err)
	}
}

// TestParse_AllowLAN_NotSubjectToLoopbackBlocklist pins that a LAN --allow is
// NEVER subject to the host-loopback blocklist: a LAN host's :9050/:9051/:1080
// is a DIFFERENT socket than host loopback, so it stays accepted (only the LAN
// clear-DNS reject applies to it). The two classes have distinct guardrails.
func TestParse_AllowLAN_NotSubjectToLoopbackBlocklist(t *testing.T) {
	for _, v := range []string{"192.168.1.150:9050", "10.0.0.5:9051", "172.16.5.5:1080", "192.168.1.1:9150"} {
		if _, err := cli.ParseWithEnv(runArgs("--allow", v), noEnv); err != nil {
			t.Fatalf("LAN allow %q must NOT be subject to the loopback blocklist: %v", v, err)
		}
	}
	// And a LAN allow on the configured proxy port is fine too (different socket).
	if _, err := cli.ParseWithEnv([]string{
		"run", "--proxy", "socks5h://127.0.0.1:7777",
		"--allow", "192.168.1.150:7777",
		"img:latest", "cmd",
	}, noEnv); err != nil {
		t.Fatalf("LAN allow on the proxy port (different socket) must be accepted: %v", err)
	}
}

// TestParse_AllowHostLoopback_ProxyPortRefusedFromConfigEntry proves the
// proxy-port blocklist also fires for a host-loopback entry that arrives via the
// CONFIG allow list (not just the flag), since the refusal is at the resolved
// run wiring where the proxy is known, applied to the final allowlist.
func TestParse_AllowHostLoopback_ProxyPortRefusedFromConfigEntry(t *testing.T) {
	xdg := writeConfig(t, `{"proxy":"socks5h://127.0.0.1:7777","allow":["127.0.0.1:7777"]}`)
	_, err := cli.ParseWithEnv([]string{"run", "img:latest", "cmd"}, envConfigHome(xdg, nil))
	if err == nil {
		t.Fatal("config host-loopback allow on the configured proxy port was accepted; want a refusal")
	}
	if !strings.Contains(err.Error(), "7777") {
		t.Fatalf("refusal %q must name the proxy port 7777", err)
	}
}
