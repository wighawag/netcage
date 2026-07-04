package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

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
// still round-trips the socks5h-enforcing ParseProxy and each allowDirect entry
// still round-trips parseAllowDirect on load (see ADR-0012). Fields are pointers
// / slices so "absent" is distinguishable from "present but empty" and an empty
// file is a clean no-op.
type fileConfig struct {
	// Proxy is the full socks5h URL STRING (socks5h://host:port), handed to the
	// SAME ParseProxy the flag/env paths use (one validator, no laxer path).
	Proxy string `json:"proxy"`
	// AllowDirect is a JSON array of raw --allow-direct strings (RFC1918 /
	// link-local only), each validated by the SAME parseAllowDirect on load.
	AllowDirect []string `json:"allowDirect"`
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
// already-validated allowDirect entries. present=false means no config file
// (missing file OR no resolvable config dir): a clean no-op, not an error.
type loadedConfig struct {
	present     bool
	proxyURL    string        // the config proxy URL string, "" if the file set no proxy
	allowDirect []DirectAllow // validated config allowDirect entries (may be empty)
}

// loadConfig reads and VALIDATES the netcage config file resolved from the given
// env lookup. A MISSING file (or no resolvable config dir) is a clean no-op
// (present=false, nil error): a user with no config still hits today's
// fail-closed refusal. A PRESENT-but-broken file (corrupt JSON, a non-socks5h /
// malformed proxy, a public/malformed allowDirect entry) is a LOUD error, never
// silently ignored: the config path is not laxer than the flag/env path.
//
// The proxy is NOT parsed here into ProxyConfig (the resolution point decides
// whether config even wins before validating), but the allowDirect entries ARE
// validated here through the SAME parseAllowDirect the flag uses, so a bad config
// direct is rejected on load exactly like a bad --allow-direct.
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
		return loadedConfig{}, fmt.Errorf("parsing netcage config %s: %w (expected {\"proxy\":\"socks5h://host:port\",\"allowDirect\":[...]})", path, err)
	}

	out := loadedConfig{present: true, proxyURL: fc.Proxy}

	// Validate each allowDirect entry through the SAME parseAllowDirect as the
	// flag, so a public/hostname/malformed config direct is rejected on load and
	// the config hole can never be wider than a flag hole.
	for _, raw := range fc.AllowDirect {
		entry, aerr := parseAllowDirect(raw)
		if aerr != nil {
			return loadedConfig{}, fmt.Errorf("in netcage config %s: %w", path, aerr)
		}
		out.allowDirect = append(out.allowDirect, entry)
	}

	return out, nil
}
