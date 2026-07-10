package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ConfigFileMode is the permission the config file is written with: 0600,
// owner-only. The persisted default is credential-free by construction (see
// WriteConfig), but the file is written owner-only REGARDLESS, so nothing at
// rest is world-readable. It is exported so a test can assert the mode.
const ConfigFileMode os.FileMode = 0o600

// ErrCredentialedProxyNotPersisted is the sentinel WriteConfig returns when asked
// to persist a proxy carrying embedded user:pass@ credentials. The persisted
// default is credential-free by construction (ADR-0012 section 2): authed proxies
// stay in NETCAGE_PROXY / --proxy (transient), so ~/.config/netcage/config.json
// never accumulates secrets at rest. WriteConfig is the ONE writer, so this is
// the ONE place the invariant is enforced.
var ErrCredentialedProxyNotPersisted = errors.New("refusing to persist a proxy with embedded credentials: the netcage config file is credential-free by construction; keep an authed proxy in NETCAGE_PROXY or --proxy (transient) instead")

// ProxySource records which of the three proxy sources supplied the resolved
// proxy for a run, so downstream verbs can REPORT it (verify prints
// `source: ...`; setup-default reads it) without retrofitting the signal. It is
// owned HERE, at the one resolution point, so every consumer reads the same
// value rather than re-deriving it.
type ProxySource string

const (
	// ProxySourceFlag means the proxy came from the explicit --proxy flag.
	ProxySourceFlag ProxySource = "flag"
	// ProxySourceEnv means the proxy came from the NETCAGE_PROXY environment var.
	ProxySourceEnv ProxySource = "env"
	// ProxySourceConfig means the proxy came from the persisted config file
	// (~/.config/netcage/config.json), the lowest-priority default.
	ProxySourceConfig ProxySource = "config"
)

// configFileName is the fixed leaf name of the netcage config file under the
// netcage config directory.
const configFileName = "config.json"

// fileConfig is the on-disk shape of ~/.config/netcage/config.json. It is a
// NEW proxy SOURCE for the same strict proxy, never a bypass: the proxy string
// still round-trips the socks5h-enforcing ParseProxy and each allow entry
// still round-trips parseAllowDirect on load (see ADR-0012). Fields are pointers
// / slices so "absent" is distinguishable from "present but empty" and an empty
// file is a clean no-op.
type fileConfig struct {
	// Proxy is the full socks5h URL STRING (socks5h://host:port), handed to the
	// SAME ParseProxy the flag/env paths use (one validator, no laxer path).
	Proxy string `json:"proxy"`
	// AllowDirect is a JSON array of raw --allow strings (RFC1918 / link-local
	// WITH an exact :port), each validated by the SAME parseAllowDirect on load.
	// omitempty so the SINGLE writer emits no `"allow": null` for the common
	// case (a bare default proxy with no split-tunnel list); a present array still
	// round-trips the loader unchanged.
	AllowDirect []string `json:"allow,omitempty"`
}

// netcageConfigDir returns the netcage config directory
// (`$XDG_CONFIG_HOME/netcage`, else `$HOME/.config/netcage`), resolved from the
// injectable env lookup so tests point it at a scratch dir and the real
// ~/.config/netcage is never read/written. It returns ok=false when no base
// directory can be resolved (no XDG_CONFIG_HOME and no HOME), which the loader
// treats as "no config" (a clean no-op), matching the missing-file case.
func netcageConfigDir(lookupEnv func(string) (string, bool)) (dir string, ok bool) {
	if x, has := lookupEnv("XDG_CONFIG_HOME"); has && x != "" {
		return filepath.Join(x, "netcage"), true
	}
	if h, has := lookupEnv("HOME"); has && h != "" {
		return filepath.Join(h, ".config", "netcage"), true
	}
	return "", false
}

// loadedConfig is the parsed, VALIDATED config a run consumes: a resolved proxy
// URL string (still to be handed to ParseProxy at the resolution point) and the
// already-validated allow entries. present=false means no config file
// (missing file OR no resolvable config dir): a clean no-op, not an error.
type loadedConfig struct {
	present     bool
	proxyURL    string        // the config proxy URL string, "" if the file set no proxy
	allowDirect []DirectAllow // validated config allow entries (may be empty)
}

// loadConfig reads and VALIDATES the netcage config file resolved from the given
// env lookup. A MISSING file (or no resolvable config dir) is a clean no-op
// (present=false, nil error): a user with no config still hits today's
// fail-closed refusal. A PRESENT-but-broken file (corrupt JSON, a non-socks5h /
// malformed proxy, a public/malformed allow entry) is a LOUD error, never
// silently ignored: the config path is not laxer than the flag/env path.
//
// The proxy is NOT parsed here into ProxyConfig (the resolution point decides
// whether config even wins before validating), but the allow entries ARE
// validated here through the SAME parseAllowDirect the flag uses, so a bad config
// direct is rejected on load exactly like a bad --allow.
func loadConfig(lookupEnv func(string) (string, bool)) (loadedConfig, error) {
	dir, ok := netcageConfigDir(lookupEnv)
	if !ok {
		return loadedConfig{}, nil // no config dir resolvable => no-op
	}
	path := filepath.Join(dir, configFileName)

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return loadedConfig{}, nil // missing file => clean no-op
		}
		return loadedConfig{}, fmt.Errorf("reading netcage config %s: %w", path, err)
	}

	var fc fileConfig
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&fc); err != nil {
		return loadedConfig{}, fmt.Errorf("parsing netcage config %s: %w (expected {\"proxy\":\"socks5h://host:port\",\"allow\":[\"192.168.1.150:8080\"]})", path, err)
	}

	out := loadedConfig{present: true, proxyURL: fc.Proxy}

	// Validate each allow entry through the SAME parseAllowDirect as the
	// flag, so a port-omitted/public/hostname/malformed config direct is rejected on
	// load and the config hole can never be wider than a flag hole.
	for _, raw := range fc.AllowDirect {
		entry, aerr := parseAllowDirect(raw)
		if aerr != nil {
			return loadedConfig{}, fmt.Errorf("in netcage config %s: %w", path, aerr)
		}
		out.allowDirect = append(out.allowDirect, entry)
	}

	return out, nil
}

// ConfigView is the current persisted config, surfaced for the setup-default
// reconfigure PRE-FILL: the raw proxy URL string and the raw allow strings
// exactly as they sit on disk (so the interactive flow can show "current: ...").
// Present=false means no config file yet (a first-time setup). It is the READ
// side of the single-writer seam; setup-default reads it to pre-fill and writes
// through WriteConfig.
type ConfigView struct {
	Present     bool
	ProxyURL    string
	AllowDirect []string
}

// ReadConfigView returns the current persisted config (raw, un-parsed) for the
// reconfigure pre-fill, resolved from the injectable env lookup so tests point it
// at a scratch dir and the real ~/.config/netcage is never read. A missing file
// (or no resolvable config dir) is Present=false, nil error. A present-but-corrupt
// file is a loud error (setup-default should not silently pre-fill from garbage).
// It reads the RAW strings (not the validated loadedConfig) because the pre-fill
// only needs to DISPLAY what is there, and a hand-edited credentialed proxy should
// still be shown so the user sees what they are replacing.
func ReadConfigView(lookupEnv func(string) (string, bool)) (ConfigView, error) {
	dir, ok := netcageConfigDir(lookupEnv)
	if !ok {
		return ConfigView{}, nil
	}
	path := filepath.Join(dir, configFileName)
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ConfigView{}, nil
		}
		return ConfigView{}, fmt.Errorf("reading netcage config %s: %w", path, err)
	}
	var fc fileConfig
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&fc); err != nil {
		return ConfigView{}, fmt.Errorf("parsing netcage config %s: %w", path, err)
	}
	return ConfigView{Present: true, ProxyURL: fc.Proxy, AllowDirect: fc.AllowDirect}, nil
}

// ConfigPath returns the absolute path of the netcage config file resolved from
// the injectable env lookup (`$XDG_CONFIG_HOME/netcage/config.json`, else
// `$HOME/.config/netcage/config.json`). ok=false when no base dir resolves (no
// XDG_CONFIG_HOME and no HOME). It is exported so setup-default can NAME the file
// it is about to write in its prompts/warnings. It performs no I/O.
func ConfigPath(lookupEnv func(string) (string, bool)) (path string, ok bool) {
	dir, ok := netcageConfigDir(lookupEnv)
	if !ok {
		return "", false
	}
	return filepath.Join(dir, configFileName), true
}

// WriteConfig persists the netcage default config (`~/.config/netcage/config.json`,
// XDG-aware, resolved from the injectable env lookup so tests write to a scratch
// dir and the real config is untouched). It is the SINGLE config writer
// (setup-default's persist step); no other code writes this file.
//
// It ENFORCES the two ADR-0012 invariants at this one seam:
//
//   - Credential-free by construction: a proxy carrying embedded user:pass@
//     credentials is REFUSED (ErrCredentialedProxyNotPersisted), so the file
//     never accumulates secrets at rest. The caller directs the user to keep an
//     authed proxy in NETCAGE_PROXY / --proxy instead.
//   - Same strict validation as every other path: the proxy round-trips the SAME
//     socks5h-enforcing ParseProxy (a socks5:// or malformed proxy is rejected
//     exactly as on the flag), and each allow entry round-trips the SAME
//     parseAllowDirect (RFC1918 / link-local WITH an exact port). The config path is never
//     laxer than the flag.
//
// The file is written 0600 (owner-only) regardless. The parent directory is
// created 0700 if absent. proxyURL is required (an empty proxy is refused: the
// config exists to persist a DEFAULT proxy). allowDirectRaw may be nil/empty.
func WriteConfig(lookupEnv func(string) (string, bool), proxyURL string, allowDirectRaw []string) error {
	if strings.TrimSpace(proxyURL) == "" {
		return errors.New("refusing to persist an empty proxy: setup-default installs a DEFAULT proxy, so a socks5h://host:port is required")
	}
	// Round-trip the SAME socks5h-enforcing validator the flag/env paths use, so a
	// socks5:// (DNS leak) or malformed proxy is rejected here exactly as on the
	// flag. This is also where the credential refusal fires: a persisted default
	// is credential-free by construction.
	proxy, err := ParseProxy(proxyURL)
	if err != nil {
		return err
	}
	if proxy.Username != "" || proxy.Password != "" {
		return ErrCredentialedProxyNotPersisted
	}
	// Validate each allow entry through the SAME parseAllowDirect the flag
	// uses, so a persisted direct can never be wider than a flag direct.
	for _, raw := range allowDirectRaw {
		if _, aerr := parseAllowDirect(raw); aerr != nil {
			return fmt.Errorf("refusing to persist allow entry %q: %w", raw, aerr)
		}
	}

	dir, ok := netcageConfigDir(lookupEnv)
	if !ok {
		return errors.New("cannot resolve a config directory (no XDG_CONFIG_HOME and no HOME); set one to persist a default proxy")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("creating netcage config dir %s: %w", dir, err)
	}

	fc := fileConfig{Proxy: proxyURL, AllowDirect: allowDirectRaw}
	blob, err := json.MarshalIndent(fc, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding netcage config: %w", err)
	}
	blob = append(blob, '\n')

	path := filepath.Join(dir, configFileName)
	// Write 0600 (owner-only) regardless. WriteFile applies the mode only when it
	// CREATES the file, so also Chmod to normalise an existing file's mode down to
	// 0600 on a reconfigure (a re-run must not leave a looser mode behind).
	if err := os.WriteFile(path, blob, ConfigFileMode); err != nil {
		return fmt.Errorf("writing netcage config %s: %w", path, err)
	}
	if err := os.Chmod(path, ConfigFileMode); err != nil {
		return fmt.Errorf("setting netcage config mode on %s: %w", path, err)
	}
	return nil
}
