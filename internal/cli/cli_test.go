package cli_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/wighawag/tooljail/internal/cli"
)

func TestParseProxy_FullSocks5hWithAuth(t *testing.T) {
	p, err := cli.ParseProxy("socks5h://user:pass@host.example:1080")
	if err != nil {
		t.Fatalf("ParseProxy: %v", err)
	}
	if p.Host != "host.example" || p.Port != "1080" {
		t.Fatalf("host:port = %s:%s, want host.example:1080", p.Host, p.Port)
	}
	if p.Username != "user" || p.Password != "pass" {
		t.Fatalf("auth = %s:%s, want user:pass", p.Username, p.Password)
	}
	if got := p.Address(); got != "host.example:1080" {
		t.Fatalf("Address() = %q, want host.example:1080", got)
	}
}

func TestParseProxy_NoAuth(t *testing.T) {
	p, err := cli.ParseProxy("socks5h://127.0.0.1:9050")
	if err != nil {
		t.Fatalf("ParseProxy: %v", err)
	}
	if p.Username != "" || p.Password != "" {
		t.Fatalf("expected no auth, got %s:%s", p.Username, p.Password)
	}
	if p.Address() != "127.0.0.1:9050" {
		t.Fatalf("Address() = %q", p.Address())
	}
}

func TestParseProxy_RejectsPlainSocks5AsLeak(t *testing.T) {
	_, err := cli.ParseProxy("socks5://127.0.0.1:9050")
	if err == nil {
		t.Fatal("plain socks5:// accepted; want rejection (it is a DNS leak)")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "socks5h") {
		t.Fatalf("error %q should mention socks5h (the required scheme)", err)
	}
}

func TestParseProxy_RejectsOtherSchemes(t *testing.T) {
	for _, raw := range []string{"http://h:1", "https://h:1", "socks4://h:1", "h:1", ""} {
		if _, err := cli.ParseProxy(raw); err == nil {
			t.Fatalf("scheme %q accepted; want rejection", raw)
		}
	}
}

func TestParse_RunCommand(t *testing.T) {
	cmd, err := cli.Parse([]string{
		"run",
		"--proxy", "socks5h://127.0.0.1:9050",
		"--image", "nuclei",
		"--", "nuclei", "-u", "https://target",
	})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cmd.Name != "run" {
		t.Fatalf("Name = %q, want run", cmd.Name)
	}
	if cmd.Image != "nuclei" {
		t.Fatalf("Image = %q, want nuclei", cmd.Image)
	}
	if cmd.Proxy.Address() != "127.0.0.1:9050" {
		t.Fatalf("Proxy = %q", cmd.Proxy.Address())
	}
	wantArgv := []string{"nuclei", "-u", "https://target"}
	if strings.Join(cmd.ToolArgv, " ") != strings.Join(wantArgv, " ") {
		t.Fatalf("ToolArgv = %v, want %v", cmd.ToolArgv, wantArgv)
	}
}

func TestParse_VerifyCommand(t *testing.T) {
	cmd, err := cli.Parse([]string{"verify", "--proxy", "socks5h://127.0.0.1:9050"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cmd.Name != "verify" {
		t.Fatalf("Name = %q, want verify", cmd.Name)
	}
	if cmd.Proxy.Address() != "127.0.0.1:9050" {
		t.Fatalf("Proxy = %q", cmd.Proxy.Address())
	}
}

func TestParse_UnknownCommandFailsLoud(t *testing.T) {
	if _, err := cli.Parse([]string{"frobnicate", "--proxy", "socks5h://h:1"}); err == nil {
		t.Fatal("unknown subcommand accepted; want failure")
	}
}

func TestParse_MissingProxyFailsLoud(t *testing.T) {
	if _, err := cli.Parse([]string{"run", "--image", "x", "--", "x"}); err == nil {
		t.Fatal("missing --proxy accepted; want failure")
	}
}

func TestParse_RunMissingImageFailsLoud(t *testing.T) {
	if _, err := cli.Parse([]string{"run", "--proxy", "socks5h://h:1", "--", "x"}); err == nil {
		t.Fatal("run without --image accepted; want failure")
	}
}

func TestParse_RejectsPlainSocks5(t *testing.T) {
	if _, err := cli.Parse([]string{"run", "--proxy", "socks5://h:1", "--image", "x", "--", "x"}); err == nil {
		t.Fatal("Parse accepted socks5://; want rejection")
	}
}

// errReachable is an injectable reachability checker that returns a fixed error.
type fakeReach struct{ err error }

func (f fakeReach) Check(address string) error { return f.err }

func TestRun_UnreachableProxyExitsNonZero(t *testing.T) {
	cmd := &cli.Command{
		Name:     "run",
		Image:    "x",
		ToolArgv: []string{"x"},
		Proxy:    cli.ProxyConfig{Host: "127.0.0.1", Port: "1"},
	}
	// With a reachability checker that reports the proxy down, startup must fail
	// loud (non-zero) rather than silently no-op or leak.
	err := cmd.PreflightWith(fakeReach{err: errors.New("connection refused")})
	if err == nil {
		t.Fatal("unreachable proxy did not fail; want a loud error (story 10)")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "proxy") {
		t.Fatalf("error %q should clearly mention the proxy being unreachable", err)
	}
}

func TestRun_ReachableProxyPreflightOK(t *testing.T) {
	cmd := &cli.Command{
		Name:  "verify",
		Proxy: cli.ProxyConfig{Host: "127.0.0.1", Port: "9050"},
	}
	if err := cmd.PreflightWith(fakeReach{err: nil}); err != nil {
		t.Fatalf("reachable proxy preflight failed: %v", err)
	}
}
