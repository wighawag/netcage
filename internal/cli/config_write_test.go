package cli_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wighawag/netcage/internal/cli"
)

// WriteConfig is netcage's SINGLE config writer (setup-default's persist step).
// These tests own its invariants (ADR-0012): credential-free by construction,
// same strict socks5h/allowDirect validation as the flag, 0600, and the
// XDG-scoped location so the real ~/.config/netcage is never written. Every test
// points the config location at a temp dir via XDG_CONFIG_HOME and asserts the
// real user config is untouched.

// TestWriteConfig_PersistsCredentialFreeProxy is the headline case: a plain
// socks5h proxy is written to the XDG-scoped config.json and round-trips through
// the loader (so a subsequent bare `netcage run` resolves it).
func TestWriteConfig_PersistsCredentialFreeProxy(t *testing.T) {
	existed, data := realConfigSnapshot(t)
	xdg := t.TempDir()
	env := envConfigHome(xdg, nil)

	if err := cli.WriteConfig(env, "socks5h://127.0.0.1:9050", nil); err != nil {
		t.Fatalf("WriteConfig: %v", err)
	}

	// The persisted default resolves for a bare run (loader round-trip).
	cmd, err := cli.ParseWithEnv([]string{"run", "img"}, env)
	if err != nil {
		t.Fatalf("Parse after WriteConfig: %v", err)
	}
	if cmd.Proxy.Address() != "127.0.0.1:9050" || cmd.ProxySource != cli.ProxySourceConfig {
		t.Fatalf("after WriteConfig, resolved proxy=%q source=%q, want 127.0.0.1:9050 / config", cmd.Proxy.Address(), cmd.ProxySource)
	}
	assertRealConfigUntouched(t, existed, data)
}

// TestWriteConfig_RefusesCredentialedProxy is the credential-free invariant: a
// user:pass@ proxy is REFUSED (ErrCredentialedProxyNotPersisted) and NO file is
// written, so the config never holds secrets at rest.
func TestWriteConfig_RefusesCredentialedProxy(t *testing.T) {
	existed, data := realConfigSnapshot(t)
	xdg := t.TempDir()
	env := envConfigHome(xdg, nil)

	err := cli.WriteConfig(env, "socks5h://user:pass@127.0.0.1:9050", nil)
	if err == nil {
		t.Fatal("WriteConfig persisted a credentialed proxy; the config must be credential-free by construction")
	}
	if !errors.Is(err, cli.ErrCredentialedProxyNotPersisted) {
		t.Fatalf("error = %v, want ErrCredentialedProxyNotPersisted", err)
	}
	// The message must redirect the user to the transient env/flag paths.
	low := strings.ToLower(err.Error())
	if !strings.Contains(low, "netcage_proxy") && !strings.Contains(low, "--proxy") {
		t.Fatalf("refusal %q should point at NETCAGE_PROXY / --proxy for authed proxies", err)
	}
	// NO file was written.
	if _, statErr := os.Stat(filepath.Join(xdg, "netcage", "config.json")); !os.IsNotExist(statErr) {
		t.Fatalf("a config file was written despite the credentialed refusal (stat err: %v)", statErr)
	}
	assertRealConfigUntouched(t, existed, data)
}

// TestWriteConfig_RejectsNonSocks5h checks the writer is not laxer than the flag:
// a socks5:// (DNS leak) proxy is rejected exactly as ParseProxy rejects it.
func TestWriteConfig_RejectsNonSocks5h(t *testing.T) {
	xdg := t.TempDir()
	err := cli.WriteConfig(envConfigHome(xdg, nil), "socks5://127.0.0.1:9050", nil)
	if err == nil {
		t.Fatal("WriteConfig accepted a socks5:// proxy; the writer must enforce socks5h like the flag")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "socks5h") {
		t.Fatalf("rejection %q should mention socks5h", err)
	}
}

// TestWriteConfig_RejectsPublicAllowDirect checks each persisted allowDirect
// entry round-trips the SAME private-only validator; a public entry is refused.
func TestWriteConfig_RejectsPublicAllowDirect(t *testing.T) {
	xdg := t.TempDir()
	err := cli.WriteConfig(envConfigHome(xdg, nil), "socks5h://127.0.0.1:9050", []string{"8.8.8.8"})
	if err == nil {
		t.Fatal("WriteConfig accepted a public allowDirect entry; a persisted direct must be private-only like the flag")
	}
}

// TestWriteConfig_WritesAllowDirectList checks a valid private allowDirect list is
// persisted and round-trips through the loader as the run's allowlist.
func TestWriteConfig_WritesAllowDirectList(t *testing.T) {
	xdg := t.TempDir()
	env := envConfigHome(xdg, nil)
	if err := cli.WriteConfig(env, "socks5h://127.0.0.1:9050", []string{"192.168.1.0/24", "10.0.0.5:8080"}); err != nil {
		t.Fatalf("WriteConfig: %v", err)
	}
	cmd, err := cli.ParseWithEnv([]string{"run", "img"}, env)
	if err != nil {
		t.Fatalf("Parse after WriteConfig: %v", err)
	}
	if len(cmd.AllowDirect) != 2 || cmd.AllowDirect[0].Raw != "192.168.1.0/24" || cmd.AllowDirect[1].Raw != "10.0.0.5:8080" {
		t.Fatalf("AllowDirect = %+v, want the two persisted entries in order", cmd.AllowDirect)
	}
}

// TestWriteConfig_FileMode0600 asserts the written file is 0600 (owner-only)
// regardless, so nothing at rest is world-readable.
func TestWriteConfig_FileMode0600(t *testing.T) {
	xdg := t.TempDir()
	if err := cli.WriteConfig(envConfigHome(xdg, nil), "socks5h://127.0.0.1:9050", nil); err != nil {
		t.Fatalf("WriteConfig: %v", err)
	}
	info, err := os.Stat(filepath.Join(xdg, "netcage", "config.json"))
	if err != nil {
		t.Fatalf("stat config: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("config mode = %o, want 600 (owner-only)", perm)
	}
}

// TestWriteConfig_ReRunNormalisesLooseModeTo0600 checks a reconfigure re-write
// normalises an existing looser-mode file down to 0600 (a re-run must not leave a
// world-readable config behind if a prior/hand-edited file was 0644).
func TestWriteConfig_ReRunNormalisesLooseModeTo0600(t *testing.T) {
	xdg := t.TempDir()
	dir := filepath.Join(xdg, "netcage")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{"proxy":"socks5h://127.0.0.1:1080"}`), 0o644); err != nil {
		t.Fatalf("seed loose-mode config: %v", err)
	}
	if err := cli.WriteConfig(envConfigHome(xdg, nil), "socks5h://127.0.0.1:9050", nil); err != nil {
		t.Fatalf("WriteConfig (re-run): %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("after re-run, config mode = %o, want 600 (a re-run must normalise a loose mode down)", perm)
	}
}

// TestReadConfigView_PrefillFromExisting checks the reconfigure PRE-FILL read
// surfaces the current proxy + allowDirect exactly as persisted, so setup-default
// can show "current: ...".
func TestReadConfigView_PrefillFromExisting(t *testing.T) {
	xdg := writeConfig(t, `{"proxy":"socks5h://127.0.0.1:1080","allowDirect":["10.0.0.0/8"]}`)
	view, err := cli.ReadConfigView(envConfigHome(xdg, nil))
	if err != nil {
		t.Fatalf("ReadConfigView: %v", err)
	}
	if !view.Present || view.ProxyURL != "socks5h://127.0.0.1:1080" {
		t.Fatalf("view = %+v, want present with the persisted proxy", view)
	}
	if len(view.AllowDirect) != 1 || view.AllowDirect[0] != "10.0.0.0/8" {
		t.Fatalf("view.AllowDirect = %v, want [10.0.0.0/8]", view.AllowDirect)
	}
}

// TestReadConfigView_MissingIsNotPresent checks a first-time setup (no file) reads
// as not-present, nil error (so setup-default treats it as a fresh install).
func TestReadConfigView_MissingIsNotPresent(t *testing.T) {
	xdg := t.TempDir()
	view, err := cli.ReadConfigView(envConfigHome(xdg, nil))
	if err != nil {
		t.Fatalf("ReadConfigView: %v", err)
	}
	if view.Present {
		t.Fatalf("view.Present = true for a missing file, want false")
	}
}
