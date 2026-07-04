package cli_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wighawag/netcage/internal/cli"
)

// The config file is netcage's persisted, LOWEST-priority proxy source
// (`~/.config/netcage/config.json`, XDG-aware), making proxy resolution
// flag > env > config > refuse. This file owns the loader + precedence +
// allowDirect REPLACE + missing-file-no-op contract. It is pure parse/validate:
// no podman, no real $HOME mutation. Every test that materialises a config
// points the config location at a temp dir (via XDG_CONFIG_HOME) so the real
// ~/.config/netcage is never read or written.

// envConfigHome returns an env lookup that points XDG_CONFIG_HOME at dir (and,
// optionally, sets NETCAGE_PROXY too), so a test drives the config path against a
// scratch dir and never the real user config.
func envConfigHome(dir string, extra map[string]string) func(string) (string, bool) {
	vars := map[string]string{"XDG_CONFIG_HOME": dir}
	for k, v := range extra {
		vars[k] = v
	}
	return envWith(vars)
}

// writeConfig materialises a netcage config.json under a temp XDG_CONFIG_HOME and
// returns that XDG dir. It also asserts the real ~/.config/netcage is untouched
// before returning, anchoring the shared-write isolation guarantee.
func writeConfig(t *testing.T, body string) string {
	t.Helper()
	xdg := t.TempDir()
	dir := filepath.Join(xdg, "netcage")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir config dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return xdg
}

// realConfigSnapshot records whether the real ~/.config/netcage/config.json
// exists (and its bytes) so a test can assert the loader never touched it.
func realConfigSnapshot(t *testing.T) (existed bool, data []byte) {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		return false, nil
	}
	p := filepath.Join(home, ".config", "netcage", "config.json")
	b, err := os.ReadFile(p)
	if err != nil {
		return false, nil
	}
	return true, b
}

func assertRealConfigUntouched(t *testing.T, existed bool, data []byte) {
	t.Helper()
	nowExisted, nowData := realConfigSnapshot(t)
	if existed != nowExisted || string(data) != string(nowData) {
		t.Fatalf("the real ~/.config/netcage/config.json was modified by the test run (must be untouched)")
	}
}

// TestParse_ConfigProxyResolvesWhenNoFlagOrEnv is the headline case: with a
// config file holding a valid socks5h proxy and NEITHER --proxy NOR NETCAGE_PROXY,
// `netcage run <img>` resolves the config proxy and records source=config.
func TestParse_ConfigProxyResolvesWhenNoFlagOrEnv(t *testing.T) {
	existed, data := realConfigSnapshot(t)
	xdg := writeConfig(t, `{"proxy":"socks5h://127.0.0.1:9050"}`)

	cmd, err := cli.ParseWithEnv([]string{"run", "alpine", "sh"}, envConfigHome(xdg, nil))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cmd.Proxy.Address() != "127.0.0.1:9050" {
		t.Fatalf("Proxy = %q, want 127.0.0.1:9050 (from config)", cmd.Proxy.Address())
	}
	if cmd.ProxySource != cli.ProxySourceConfig {
		t.Fatalf("ProxySource = %q, want config", cmd.ProxySource)
	}
	assertRealConfigUntouched(t, existed, data)
}

// TestParse_ProxySourceRecordedForEachSource asserts the resolution RECORDS which
// source won (flag | env | config), so tasks 2/4 can report it.
func TestParse_ProxySourceRecordedForEachSource(t *testing.T) {
	xdg := writeConfig(t, `{"proxy":"socks5h://127.0.0.1:9050"}`)

	// flag wins over env AND config.
	cmd, err := cli.ParseWithEnv(
		[]string{"run", "--proxy", "socks5h://flag.host:1111", "img"},
		envConfigHome(xdg, map[string]string{"NETCAGE_PROXY": "socks5h://env.host:2222"}))
	if err != nil {
		t.Fatalf("Parse (flag): %v", err)
	}
	if cmd.ProxySource != cli.ProxySourceFlag || cmd.Proxy.Address() != "flag.host:1111" {
		t.Fatalf("flag: source=%q addr=%q, want flag / flag.host:1111", cmd.ProxySource, cmd.Proxy.Address())
	}

	// env wins over config.
	cmd, err = cli.ParseWithEnv(
		[]string{"run", "img"},
		envConfigHome(xdg, map[string]string{"NETCAGE_PROXY": "socks5h://env.host:2222"}))
	if err != nil {
		t.Fatalf("Parse (env): %v", err)
	}
	if cmd.ProxySource != cli.ProxySourceEnv || cmd.Proxy.Address() != "env.host:2222" {
		t.Fatalf("env: source=%q addr=%q, want env / env.host:2222", cmd.ProxySource, cmd.Proxy.Address())
	}

	// config is the lowest-priority default.
	cmd, err = cli.ParseWithEnv([]string{"run", "img"}, envConfigHome(xdg, nil))
	if err != nil {
		t.Fatalf("Parse (config): %v", err)
	}
	if cmd.ProxySource != cli.ProxySourceConfig || cmd.Proxy.Address() != "127.0.0.1:9050" {
		t.Fatalf("config: source=%q addr=%q, want config / 127.0.0.1:9050", cmd.ProxySource, cmd.Proxy.Address())
	}
}

// TestParse_ConfigProxySocks5hValidatedSameAsFlag checks the config proxy goes
// through the SAME socks5h-enforcing ParseProxy: a plain socks5:// in config is
// rejected as a leak, exactly as on the flag (the config path is NOT laxer).
func TestParse_ConfigProxySocks5hValidatedSameAsFlag(t *testing.T) {
	xdg := writeConfig(t, `{"proxy":"socks5://127.0.0.1:9050"}`)
	_, err := cli.ParseWithEnv([]string{"run", "img"}, envConfigHome(xdg, nil))
	if err == nil {
		t.Fatal("socks5:// in config accepted; want the same leak rejection as the flag")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "socks5h") {
		t.Fatalf("config-proxy rejection %q should mention socks5h", err)
	}
}

// TestParse_ConfigProxyMalformedRejected checks a structurally-malformed config
// proxy is rejected loudly, not silently ignored.
func TestParse_ConfigProxyMalformedRejected(t *testing.T) {
	xdg := writeConfig(t, `{"proxy":"http://h:1"}`)
	if _, err := cli.ParseWithEnv([]string{"run", "img"}, envConfigHome(xdg, nil)); err == nil {
		t.Fatal("malformed config proxy accepted; want rejection")
	}
}

// TestParse_ConfigAllowDirectListValidated checks each config allowDirect entry
// is validated by the SAME parseAllowDirect (private-only), and applies when NO
// --allow-direct is on the CLI.
func TestParse_ConfigAllowDirectListValidated(t *testing.T) {
	xdg := writeConfig(t, `{"proxy":"socks5h://127.0.0.1:9050","allowDirect":["192.168.1.0/24","10.0.0.5:8080"]}`)
	cmd, err := cli.ParseWithEnv([]string{"run", "img"}, envConfigHome(xdg, nil))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(cmd.AllowDirect) != 2 {
		t.Fatalf("AllowDirect len = %d, want 2 (from config): %+v", len(cmd.AllowDirect), cmd.AllowDirect)
	}
	if cmd.AllowDirect[0].Raw != "192.168.1.0/24" || cmd.AllowDirect[1].Raw != "10.0.0.5:8080" {
		t.Fatalf("AllowDirect = %+v, want the two config entries in order", cmd.AllowDirect)
	}
}

// TestParse_ConfigAllowDirectPublicRejected checks a PUBLIC allowDirect entry in
// config is rejected by the same guardrail as the flag (a config hole cannot be
// wider than a flag hole).
func TestParse_ConfigAllowDirectPublicRejected(t *testing.T) {
	xdg := writeConfig(t, `{"proxy":"socks5h://127.0.0.1:9050","allowDirect":["8.8.8.8"]}`)
	if _, err := cli.ParseWithEnv([]string{"run", "img"}, envConfigHome(xdg, nil)); err == nil {
		t.Fatal("public allowDirect in config accepted; want the same private-only rejection as the flag")
	}
}

// TestParse_ExplicitAllowDirectReplacesConfigList is the REPLACE contract: an
// explicit --allow-direct on the CLI supplies the COMPLETE allowlist and fully
// overrides the config list (config directs are NOT carried along).
func TestParse_ExplicitAllowDirectReplacesConfigList(t *testing.T) {
	xdg := writeConfig(t, `{"proxy":"socks5h://127.0.0.1:9050","allowDirect":["192.168.1.0/24","10.0.0.5:8080"]}`)
	cmd, err := cli.ParseWithEnv(
		[]string{"run", "--allow-direct", "172.16.9.9:22", "img"},
		envConfigHome(xdg, nil))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(cmd.AllowDirect) != 1 || cmd.AllowDirect[0].Raw != "172.16.9.9:22" {
		t.Fatalf("AllowDirect = %+v, want ONLY the CLI entry (REPLACE, config list dropped)", cmd.AllowDirect)
	}
}

// TestParse_MissingConfigIsNoOp checks a MISSING config file is a clean no-op:
// with no config AND no flag/env, netcage still refuses with the existing
// fail-closed "no proxy" message. XDG points at an empty temp dir (no file).
func TestParse_MissingConfigIsNoOp(t *testing.T) {
	xdg := t.TempDir() // no netcage/config.json under it
	_, err := cli.ParseWithEnv([]string{"run", "img"}, envConfigHome(xdg, nil))
	if err == nil {
		t.Fatal("missing config + no flag/env accepted; want the existing fail-closed refusal")
	}
	low := strings.ToLower(err.Error())
	if !strings.Contains(low, "proxy") || !strings.Contains(low, "netcage_proxy") {
		t.Fatalf("refusal %q should be today's no-proxy message (mentioning NETCAGE_PROXY)", err)
	}
}

// TestParse_ConfigCredentialsAccepted checks a hand-edited credentialed config
// proxy LOADS (the restriction is on what setup-default WRITES, task 4; the
// loader accepts credentials, matching env/flag). See ADR-0012.
func TestParse_ConfigCredentialsAccepted(t *testing.T) {
	xdg := writeConfig(t, `{"proxy":"socks5h://user:pass@127.0.0.1:9050"}`)
	cmd, err := cli.ParseWithEnv([]string{"run", "img"}, envConfigHome(xdg, nil))
	if err != nil {
		t.Fatalf("Parse: %v (a hand-edited credentialed config proxy should load)", err)
	}
	if cmd.Proxy.Username != "user" || cmd.Proxy.Password != "pass" {
		t.Fatalf("auth = %s:%s, want user:pass (credentials loaded from config)", cmd.Proxy.Username, cmd.Proxy.Password)
	}
}

// TestParse_ConfigInvalidJSONRejected checks a corrupt config.json is a loud
// error, not a silent no-op (a broken config the user meant to use must not
// silently fall through to refuse as if absent).
func TestParse_ConfigInvalidJSONRejected(t *testing.T) {
	xdg := writeConfig(t, `{"proxy": not json}`)
	if _, err := cli.ParseWithEnv([]string{"run", "img"}, envConfigHome(xdg, nil)); err == nil {
		t.Fatal("corrupt config.json accepted; want a loud parse error")
	}
}

// TestParse_ConfigProxyStillPreflighted proves fail-closed is intact: a proxy
// resolved from config is still subject to the SAME preflight reachability check
// as a flag/env proxy (a down config proxy refuses loudly).
func TestParse_ConfigProxyStillPreflighted(t *testing.T) {
	xdg := writeConfig(t, `{"proxy":"socks5h://127.0.0.1:9050"}`)
	cmd, err := cli.ParseWithEnv([]string{"run", "img"}, envConfigHome(xdg, nil))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	// A reachability checker that always fails stands in for a down proxy; the
	// config-sourced proxy must be refused loudly, never leaked past.
	if err := cmd.PreflightWith(alwaysUnreachable{}); err == nil {
		t.Fatal("a down config proxy passed preflight; fail-closed requires a loud refusal")
	}
}

// alwaysUnreachable is a Reachability that reports every address unreachable, so a
// test can assert the fail-closed refusal without real network I/O.
type alwaysUnreachable struct{}

func (alwaysUnreachable) Check(string) error { return errTestUnreachable }

var errTestUnreachable = errTestUnreach("proxy down (test)")

type errTestUnreach string

func (e errTestUnreach) Error() string { return string(e) }
