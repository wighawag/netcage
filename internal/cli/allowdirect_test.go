package cli_test

import (
	"strings"
	"testing"

	"github.com/wighawag/netcage/internal/cli"
)

// The --allow flag is the CLI half of the split-tunnel LAN allowlist
// (spec split-tunnel-lan-allowlist, stories 3/4/9). It parses one or more
// IP/CIDR:port values into a validated typed allowlist on Command, accepting
// ONLY RFC1918 + link-local ranges WITH an exact port and rejecting
// port-omitted / public IPs / hostnames / malformed values LOUDLY at startup
// (the all-ports / bare-IP form was dropped as a deanonymization risk, ADR-0020).
// This file is the parse+validate contract; it stands up no jail and needs no
// podman.

// runArgs prefixes the required subcommand + proxy so each case names only the
// --allow values it exercises.
func runArgs(extra ...string) []string {
	base := []string{"run", "--proxy", "socks5h://127.0.0.1:9050"}
	base = append(base, extra...)
	return append(base, "img:latest", "cmd")
}

// TestParse_AllowDirect_PrivateEntriesBothForms is the headline case: private
// IP and CIDR values, each WITH an exact :port (mandatory since ADR-0020), in
// BOTH `--flag value` and `--flag=value` forms, parse into the typed allowlist
// on Command.
func TestParse_AllowDirect_PrivateEntriesBothForms(t *testing.T) {
	cmd, err := cli.ParseWithEnv(runArgs(
		"--allow", "192.168.1.150:8080", // IP + port, space form
		"--allow=10.0.0.0/24:443",  // CIDR + port, equals form
		"--allow", "172.16.5.5:22", // IP + port, space form
		"--allow=169.254.0.0/16:80", // link-local CIDR + port, equals form
	), noEnv)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(cmd.AllowDirect) != 4 {
		t.Fatalf("AllowDirect len = %d, want 4: %+v", len(cmd.AllowDirect), cmd.AllowDirect)
	}

	// 1: 192.168.1.150:8080 -> a /32 network at port 8080.
	e0 := cmd.AllowDirect[0]
	if e0.Network.String() != "192.168.1.150/32" {
		t.Fatalf("entry0 Network = %q, want 192.168.1.150/32", e0.Network.String())
	}
	if e0.Port != 8080 {
		t.Fatalf("entry0 Port = %d, want 8080", e0.Port)
	}

	// 2: 10.0.0.0/24:443 -> the /24 network at port 443.
	e1 := cmd.AllowDirect[1]
	if e1.Network.String() != "10.0.0.0/24" {
		t.Fatalf("entry1 Network = %q, want 10.0.0.0/24", e1.Network.String())
	}
	if e1.Port != 443 {
		t.Fatalf("entry1 Port = %d, want 443", e1.Port)
	}

	// 3: IP 172.16.5.5:22 -> /32 at port 22.
	e2 := cmd.AllowDirect[2]
	if e2.Network.String() != "172.16.5.5/32" {
		t.Fatalf("entry2 Network = %q, want 172.16.5.5/32", e2.Network.String())
	}
	if e2.Port != 22 {
		t.Fatalf("entry2 Port = %d, want 22", e2.Port)
	}

	// 4: link-local CIDR at port 80.
	e3 := cmd.AllowDirect[3]
	if e3.Network.String() != "169.254.0.0/16" {
		t.Fatalf("entry3 Network = %q, want 169.254.0.0/16", e3.Network.String())
	}
	if e3.Port != 80 {
		t.Fatalf("entry3 Port = %d, want 80", e3.Port)
	}
}

// TestParse_AllowDirect_PortOmittedRejected is the ADR-0020 security core: a
// port-omitted value (a bare IP or a CIDR with no :port) is REFUSED LOUDLY,
// naming the value and telling the user to add :port. The all-ports / bare-IP
// form is a deanonymization risk (a forwarding proxy on an unspecified port on
// the exempted host would let the jailed tool egress the whole internet from the
// real IP around the forced path), so a direct exemption MUST name an exact port.
func TestParse_AllowDirect_PortOmittedRejected(t *testing.T) {
	for _, v := range []string{
		"192.168.1.150",  // bare IP, no port
		"10.0.0.0/24",    // CIDR, no port
		"172.16.5.5",     // another bare IP
		"169.254.0.0/16", // link-local CIDR, no port
	} {
		_, err := cli.ParseWithEnv(runArgs("--allow", v), noEnv)
		if err == nil {
			t.Fatalf("port-omitted %q accepted; want a loud rejection (the all-ports form is a deanonymization risk)", v)
		}
		if !strings.Contains(err.Error(), v) {
			t.Fatalf("rejection %q should name the offending value %q", err, v)
		}
		if !strings.Contains(strings.ToLower(err.Error()), ":port") {
			t.Fatalf("rejection %q should instruct the user to add :port", err)
		}
	}
}

// TestParse_AllowDirect_EmptyByDefault checks story 2/off-by-default: no
// --allow yields an empty (nil) allowlist and does not change parsing.
func TestParse_AllowDirect_EmptyByDefault(t *testing.T) {
	cmd, err := cli.ParseWithEnv(runArgs(), noEnv)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(cmd.AllowDirect) != 0 {
		t.Fatalf("AllowDirect = %+v, want empty by default", cmd.AllowDirect)
	}
}

// TestParse_AllowDirect_RejectsPublicIP checks a public IP is refused loudly,
// naming the value and the reason (it would leak / deanonymize).
func TestParse_AllowDirect_RejectsPublicIP(t *testing.T) {
	_, err := cli.ParseWithEnv(runArgs("--allow", "8.8.8.8:8080"), noEnv)
	if err == nil {
		t.Fatal("public IP 8.8.8.8 accepted; want a loud rejection (it would leak)")
	}
	if !strings.Contains(err.Error(), "8.8.8.8") {
		t.Fatalf("rejection %q should name the offending value 8.8.8.8", err)
	}
	if !strings.Contains(strings.ToLower(err.Error()), "private") &&
		!strings.Contains(strings.ToLower(err.Error()), "public") {
		t.Fatalf("rejection %q should explain WHY (public/not-private would leak)", err)
	}
}

// TestParse_AllowDirect_RejectsPublicCIDR checks a public CIDR is refused too.
func TestParse_AllowDirect_RejectsPublicCIDR(t *testing.T) {
	_, err := cli.ParseWithEnv(runArgs("--allow", "1.2.3.0/24:443"), noEnv)
	if err == nil {
		t.Fatal("public CIDR 1.2.3.0/24 accepted; want rejection")
	}
	if !strings.Contains(err.Error(), "1.2.3.0/24") {
		t.Fatalf("rejection %q should name the offending value", err)
	}
}

// TestParse_AllowDirect_RejectsPartlyPublicCIDR checks a CIDR that STRADDLES a
// private range (so not fully contained in an accepted range) is refused: a
// too-wide prefix that includes public space must not be accepted.
func TestParse_AllowDirect_RejectsPartlyPublicCIDR(t *testing.T) {
	// 10.0.0.0/7 covers 10.0.0.0/8 (private) AND 11.0.0.0/8 (public), so it is
	// NOT fully within an accepted range.
	_, err := cli.ParseWithEnv(runArgs("--allow", "10.0.0.0/7:443"), noEnv)
	if err == nil {
		t.Fatal("10.0.0.0/7 (straddles public space) accepted; want rejection")
	}
	if !strings.Contains(err.Error(), "10.0.0.0/7") {
		t.Fatalf("rejection %q should name the offending value", err)
	}
}

// TestParse_AllowDirect_RejectsHostname checks a hostname (not an IP/CIDR
// literal) is refused, naming the value and that hostnames are unsupported.
func TestParse_AllowDirect_RejectsHostname(t *testing.T) {
	_, err := cli.ParseWithEnv(runArgs("--allow", "llama.local:8080"), noEnv)
	if err == nil {
		t.Fatal("hostname llama.local accepted; want rejection (hostnames unsupported)")
	}
	if !strings.Contains(err.Error(), "llama.local") {
		t.Fatalf("rejection %q should name the offending value", err)
	}
	if !strings.Contains(strings.ToLower(err.Error()), "hostname") &&
		!strings.Contains(strings.ToLower(err.Error()), "ip") {
		t.Fatalf("rejection %q should explain hostnames are unsupported (IP/CIDR only)", err)
	}
}

// TestParse_AllowDirect_RejectsMalformed checks a malformed value is refused.
func TestParse_AllowDirect_RejectsMalformed(t *testing.T) {
	for _, v := range []string{"not-an-ip:80", "192.168.1.999:80", "10.0.0.0/33:80", "192.168.1.1/:80"} {
		_, err := cli.ParseWithEnv(runArgs("--allow", v), noEnv)
		if err == nil {
			t.Fatalf("malformed value %q accepted; want rejection", v)
		}
		if !strings.Contains(err.Error(), v) {
			t.Fatalf("rejection %q should name the offending value %q", err, v)
		}
	}
}

// TestParse_AllowDirect_RejectsBadPort checks an out-of-range / non-numeric port
// is refused, naming the value.
func TestParse_AllowDirect_RejectsBadPort(t *testing.T) {
	for _, v := range []string{"192.168.1.150:70000", "192.168.1.150:0", "192.168.1.150:abc", "192.168.1.150:-1"} {
		_, err := cli.ParseWithEnv(runArgs("--allow", v), noEnv)
		if err == nil {
			t.Fatalf("bad port in %q accepted; want rejection", v)
		}
		if !strings.Contains(err.Error(), v) {
			t.Fatalf("rejection %q should name the offending value %q", err, v)
		}
		if !strings.Contains(strings.ToLower(err.Error()), "port") {
			t.Fatalf("rejection %q should mention the port being the problem", err)
		}
	}
}

// TestParse_AllowDirect_RejectsClearDNSPort checks the row-2 Tails guardrail
// (learning-from-anonctl-tails-leak-catalogue.md): an explicit clear-DNS port is
// refused LOUDLY, naming the value + why (a LAN DNS resolver can reveal the
// local network's public IP, a deanonymization vector; DNS must stay on the
// proxy-side socks5h path). At minimum 53; 853 (DoT) and 5353 (mDNS) are refused
// too so no clear-DNS-ish port can be opened directly to the LAN. This mirrors
// anonctl's sibling lan-exemption reject (kept consistent by design).
func TestParse_AllowDirect_RejectsClearDNSPort(t *testing.T) {
	for _, v := range []string{
		"192.168.1.1:53",   // clear TCP-DNS to a LAN resolver (the headline hole)
		"10.0.0.53:53",     // same, another private range
		"192.168.1.1:853",  // DoT
		"192.168.1.1:5353", // mDNS
	} {
		_, err := cli.ParseWithEnv(runArgs("--allow", v), noEnv)
		if err == nil {
			t.Fatalf("clear-DNS port in %q accepted; want a loud rejection (it can reveal the LAN's public IP)", v)
		}
		if !strings.Contains(err.Error(), v) {
			t.Fatalf("rejection %q should name the offending value %q", err, v)
		}
		if !strings.Contains(strings.ToLower(err.Error()), "dns") {
			t.Fatalf("rejection %q should explain WHY (a DNS hole reveals the LAN's public IP)", err)
		}
	}
}

// TestParse_AllowDirect_AllowsNonDNSPorts guards against over-rejection: ordinary
// service ports (8080, 443, 22, 5354) with an exact port still parse, so the
// clear-DNS reject is scoped to the DNS ports only.
func TestParse_AllowDirect_AllowsNonDNSPorts(t *testing.T) {
	for _, v := range []string{"192.168.1.1:80", "192.168.1.150:8080", "10.0.0.5:443", "172.16.5.5:22", "192.168.1.1:5354"} {
		if _, err := cli.ParseWithEnv(runArgs("--allow", v), noEnv); err != nil {
			t.Fatalf("non-DNS allow %q rejected; want accepted: %v", v, err)
		}
	}
}

// TestParse_AllowDirect_MissingValueRejected checks a trailing --allow
// with no value fails loud (matching the other value-taking flags).
func TestParse_AllowDirect_MissingValueRejected(t *testing.T) {
	_, err := cli.ParseWithEnv([]string{"run", "--proxy", "socks5h://h:1", "--allow"}, noEnv)
	if err == nil {
		t.Fatal("--allow with no value accepted; want rejection")
	}
	if !strings.Contains(err.Error(), "--allow") {
		t.Fatalf("rejection %q should name the flag", err)
	}
}

// TestParse_AllowDirect_DoesNotDisturbOtherParsing checks that adding an
// allowlist entry leaves the image, argv, and other flags untouched (story 2:
// the feature is additive).
func TestParse_AllowDirect_DoesNotDisturbOtherParsing(t *testing.T) {
	cmd, err := cli.ParseWithEnv([]string{
		"run",
		"--allow", "192.168.1.150:8080",
		"-v", "a:b",
		"--proxy", "socks5h://127.0.0.1:9050",
		"nuclei:latest", "nuclei", "-u", "https://target",
	}, noEnv)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cmd.Image != "nuclei:latest" {
		t.Fatalf("Image = %q, want nuclei:latest", cmd.Image)
	}
	if strings.Join(cmd.ToolArgv, " ") != "nuclei -u https://target" {
		t.Fatalf("ToolArgv = %v", cmd.ToolArgv)
	}
	if strings.Join(cmd.Mounts, " ") != "a:b" {
		t.Fatalf("Mounts = %v", cmd.Mounts)
	}
	if len(cmd.AllowDirect) != 1 {
		t.Fatalf("AllowDirect len = %d, want 1", len(cmd.AllowDirect))
	}
}
