// Package cli implements netcage's command-line surface: the `run` and `verify`
// subcommands, the socks5h proxy-URL contract, and the fail-loud startup
// preflight. It deliberately does NOT stand up the jail (sidecar/netns/firewall);
// that is the jail-run-forced-egress task. This package is pure parsing +
// validation + a reachability seam, so it is unit-testable without any system
// mutation.
package cli

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/wighawag/netcage/internal/devimage"
)

// DefaultMountTarget is the container path a repo mount defaults to (and the
// workdir defaults to) when the user does not spell one out, so a repo dropped in
// with `-v <repo>` (or `-v <repo>:/work`) is worked in without hand-writing -w
// (prd story 10, repo-mount ergonomics).
const DefaultMountTarget = "/work"

// ProxyEnvVar is the environment variable an agent can set instead of passing
// --proxy, so the netcage command line carries nothing netcage-specific and is
// pure `podman run` vocabulary (prd story 8). Precedence is flag > env > refuse.
const ProxyEnvVar = "NETCAGE_PROXY"

// ProxyConfig is a parsed, validated socks5h proxy endpoint.
type ProxyConfig struct {
	Host     string
	Port     string
	Username string // optional
	Password string // optional
}

// Address returns "host:port".
func (p ProxyConfig) Address() string { return net.JoinHostPort(p.Host, p.Port) }

// ParseProxy parses a proxy URL and ENFORCES the socks5h scheme. A plain
// socks5:// (local DNS resolution) is rejected because it is a DNS leak by
// definition: with socks5 the client resolves hostnames on the host resolver,
// which is exactly what netcage exists to prevent. Only socks5h (remote,
// proxy-side resolution) is the target.
func ParseProxy(raw string) (ProxyConfig, error) {
	if strings.TrimSpace(raw) == "" {
		return ProxyConfig{}, errors.New("empty --proxy: a socks5h:// URL is required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ProxyConfig{}, fmt.Errorf("invalid --proxy URL %q: %w", raw, err)
	}
	switch u.Scheme {
	case "socks5h":
		// ok
	case "socks5":
		return ProxyConfig{}, fmt.Errorf("--proxy uses socks5:// (local DNS) which LEAKS hostnames to the host resolver; use socks5h:// (remote, proxy-side resolution)")
	default:
		return ProxyConfig{}, fmt.Errorf("--proxy scheme %q unsupported; netcage requires socks5h://", u.Scheme)
	}

	host := u.Hostname()
	port := u.Port()
	if host == "" || port == "" {
		return ProxyConfig{}, fmt.Errorf("--proxy %q must include host and port (socks5h://host:port)", raw)
	}

	p := ProxyConfig{Host: host, Port: port}
	if u.User != nil {
		p.Username = u.User.Username()
		if pw, ok := u.User.Password(); ok {
			p.Password = pw
		}
	}
	return p, nil
}

// Command is a parsed netcage invocation.
//
// The `run` grammar is podman-native and POSITIONAL: `run [flags] <image>
// [<cmd> <args...>]`, mirroring `podman run [flags] IMAGE [CMD...]`. The FIRST
// positional is ALWAYS the image (no image-vs-command guessing, so `run alpine
// sh` just works) and the tool argv is the remaining positionals. If NO
// positional image is given, the pinned default dev image is used. There is no
// --image flag; a standalone `--` is accepted only as an optional end-of-flags
// marker (a podman nicety) and is not load-bearing. Flags outside the curated
// allow-list are rejected: jail-breaching flags with an explanatory message,
// anything else as an unknown flag.
type Command struct {
	Name     string // "run" or "verify"
	Proxy    ProxyConfig
	Image    string   // required for run (first positional); unused for verify
	ToolArgv []string // the tool command + args (positionals after the image)
	Mounts   []string // -v/--volume pass-through values (run)

	// Interactive / TTY record the -i / -t (and -it/-ti) booleans. This package
	// only PARSES them; `main.go`'s runRun consumes them to run the jailed tool
	// with `podman run -it` (raw stdio passthrough, terminal in raw mode) via
	// jail.Config.Interactive, so a human/agent can shell into the jail.
	Interactive bool // -i / --interactive
	TTY         bool // -t / --tty

	Workdir    string   // -w/--workdir pass-through (run)
	Env        []string // -e/--env pass-through values, repeatable (run)
	User       string   // -u/--user pass-through (run)
	Entrypoint string   // --entrypoint pass-through (run)

	// AllowDirect is the validated split-tunnel LAN allowlist: --allow-direct
	// values (repeatable) parsed into private-only DirectAllow entries (network +
	// optional port). EMPTY by default (no flag) == today's strict jail. This
	// package only PARSES + VALIDATES the allowlist (accepting only RFC1918 /
	// link-local, rejecting public/hostname/malformed loudly at startup); the
	// split-tunnel-jail-wiring task consumes it to open the narrow direct path.
	AllowDirect []DirectAllow // --allow-direct entries, repeatable (run)
}

// ProxyOnHostLoopback reports whether the proxy listens on the host's loopback
// (the local Tor / ssh -D case), so the jail reaches it via the pasta map with
// reachback narrowing (ADR-0002). A remote proxy is a normal routable host the
// sidecar dials directly and needs neither.
func (c Command) ProxyOnHostLoopback() bool {
	switch c.Proxy.Host {
	case "127.0.0.1", "::1", "localhost":
		return true
	}
	return false
}

// Reachability checks whether a proxy address is reachable at startup. It is an
// interface so tests can inject a result without real network I/O.
type Reachability interface {
	Check(address string) error
}

// DialReachability checks reachability by attempting a TCP dial to the proxy.
type DialReachability struct{ Timeout time.Duration }

// Check dials the address and returns an error if it cannot connect.
func (d DialReachability) Check(address string) error {
	to := d.Timeout
	if to <= 0 {
		to = 3 * time.Second
	}
	c, err := net.DialTimeout("tcp", address, to)
	if err != nil {
		return err
	}
	return c.Close()
}

// Preflight runs the startup checks with a real TCP dial.
func (c *Command) Preflight() error {
	return c.PreflightWith(DialReachability{})
}

// PreflightWith runs the startup checks using the given reachability checker.
// It FAILS LOUD if the proxy is unreachable: netcage must never silently no-op
// or fall back to the host network when the proxy is down (story 10 / the
// fail-closed invariant).
func (c *Command) PreflightWith(r Reachability) error {
	if err := r.Check(c.Proxy.Address()); err != nil {
		return fmt.Errorf("proxy %s is unreachable at startup: %w (refusing to run: netcage fails closed, it never leaks to the host network)", c.Proxy.Address(), err)
	}
	return nil
}

// denyReasons maps each jail-breaching flag to WHY netcage refuses it. netcage
// OWNS the container's network and isolation (it sets `--network
// container:<sidecar>`, a run-attributable `--name`, `--rm`, and the in-netns DNS
// forwarder), so honouring a user/agent-supplied one would either collide with
// what netcage sets or open a leak path around the forced-egress jail. The
// message is part of the agent-facing interface: a self-correcting nudge.
var denyReasons = map[string]string{
	"--network":    "netcage owns the container network (it sets --network container:<sidecar> so all egress is forced through the socks5h proxy); overriding it would breach the jail and leak",
	"-p":           "publishing ports (-p/--publish) would open an inbound path around the jail; netcage owns the container's networking to keep it leak-proof",
	"--publish":    "publishing ports (-p/--publish) would open an inbound path around the jail; netcage owns the container's networking to keep it leak-proof",
	"--dns":        "netcage owns DNS (it forces resolution through the socks5h proxy via the in-netns forwarder); a user --dns would leak DNS to a host-reachable resolver, defeating the jail",
	"--privileged": "a privileged container can escape the network jail and the isolation netcage depends on; refused to keep the jail leak-proof",
	"--cap-add":    "added capabilities (e.g. NET_ADMIN) let the tool re-route around the forced-egress jail; netcage owns the container's capabilities to keep it leak-proof",
	"--device":     "passing host devices can bypass the network namespace the jail relies on; netcage owns device access to keep the jail leak-proof",
	"--name":       "netcage owns the container --name (it uses a run-attributable name for teardown); a user --name would collide with the jail's lifecycle management",
	"--rm":         "netcage owns the container lifecycle (--rm and teardown); a user --rm would collide with the jail's no-residue teardown",
}

// Parse parses argv (without the program name) into a Command, reading the
// NETCAGE_PROXY fallback from the real process environment.
func Parse(args []string) (*Command, error) {
	return ParseWithEnv(args, os.LookupEnv)
}

// ParseWithEnv is Parse with an injectable environment lookup (os.LookupEnv in
// production) so the NETCAGE_PROXY precedence and env-validation paths are
// unit-testable without mutating the real process environment.
func ParseWithEnv(args []string, lookupEnv func(string) (string, bool)) (*Command, error) {
	if len(args) == 0 {
		return nil, errors.New("no subcommand: expected `run` or `verify`")
	}
	name := args[0]
	switch name {
	case "run", "verify":
	default:
		return nil, fmt.Errorf("unknown subcommand %q: expected `run` or `verify`", name)
	}

	rest := args[1:]
	cmd := &Command{Name: name}

	var proxyRaw string
	var proxyFromFlag bool
	var positionals []string
	endOfFlags := false

	for i := 0; i < len(rest); i++ {
		a := rest[i]

		// Once we are past the flags (either a standalone `--` marker or the first
		// positional image), everything else is positional: the image and the tool
		// argv. A `-t` here is a tool arg, not netcage's TTY flag.
		if endOfFlags {
			positionals = append(positionals, a)
			continue
		}
		if a == "--" {
			// Optional explicit end-of-flags marker (a podman nicety). The image and
			// argv follow it; the marker itself is not a positional. It is no longer
			// load-bearing: the first positional is the image with or without it.
			endOfFlags = true
			continue
		}

		// A jail-breaching flag: reject loudly, in both --flag and --flag=value forms.
		if reason, denied := denyFlag(a); denied {
			flag := denyFlagName(a)
			return nil, fmt.Errorf("flag %s is not allowed: %s", flag, reason)
		}

		switch {
		case a == "--proxy":
			v, ok := next(rest, &i)
			if !ok {
				return nil, errors.New("--proxy requires a value")
			}
			proxyRaw, proxyFromFlag = v, true
		case strings.HasPrefix(a, "--proxy="):
			proxyRaw, proxyFromFlag = strings.TrimPrefix(a, "--proxy="), true

		case a == "-i" || a == "--interactive":
			cmd.Interactive = true
		case a == "-t" || a == "--tty":
			cmd.TTY = true
		case a == "-it" || a == "-ti":
			cmd.Interactive, cmd.TTY = true, true

		case a == "-v" || a == "--volume":
			v, ok := next(rest, &i)
			if !ok {
				return nil, errors.New("-v/--volume requires a value (host:container[:opts])")
			}
			cmd.Mounts = append(cmd.Mounts, v)
		case strings.HasPrefix(a, "--volume="):
			cmd.Mounts = append(cmd.Mounts, strings.TrimPrefix(a, "--volume="))
		case strings.HasPrefix(a, "-v="):
			cmd.Mounts = append(cmd.Mounts, strings.TrimPrefix(a, "-v="))

		case a == "-w" || a == "--workdir":
			v, ok := next(rest, &i)
			if !ok {
				return nil, errors.New("-w/--workdir requires a value")
			}
			cmd.Workdir = v
		case strings.HasPrefix(a, "--workdir="):
			cmd.Workdir = strings.TrimPrefix(a, "--workdir=")
		case strings.HasPrefix(a, "-w="):
			cmd.Workdir = strings.TrimPrefix(a, "-w=")

		case a == "-e" || a == "--env":
			v, ok := next(rest, &i)
			if !ok {
				return nil, errors.New("-e/--env requires a value (KEY=VALUE)")
			}
			cmd.Env = append(cmd.Env, v)
		case strings.HasPrefix(a, "--env="):
			cmd.Env = append(cmd.Env, strings.TrimPrefix(a, "--env="))
		case strings.HasPrefix(a, "-e="):
			cmd.Env = append(cmd.Env, strings.TrimPrefix(a, "-e="))

		case a == "-u" || a == "--user":
			v, ok := next(rest, &i)
			if !ok {
				return nil, errors.New("-u/--user requires a value")
			}
			cmd.User = v
		case strings.HasPrefix(a, "--user="):
			cmd.User = strings.TrimPrefix(a, "--user=")
		case strings.HasPrefix(a, "-u="):
			cmd.User = strings.TrimPrefix(a, "-u=")

		case a == "--entrypoint":
			v, ok := next(rest, &i)
			if !ok {
				return nil, errors.New("--entrypoint requires a value")
			}
			cmd.Entrypoint = v
		case strings.HasPrefix(a, "--entrypoint="):
			cmd.Entrypoint = strings.TrimPrefix(a, "--entrypoint=")

		case a == "--allow-direct":
			v, ok := next(rest, &i)
			if !ok {
				return nil, errors.New("--allow-direct requires a value (an RFC1918/link-local IP or CIDR, optionally with :port)")
			}
			entry, aerr := parseAllowDirect(v)
			if aerr != nil {
				return nil, aerr
			}
			cmd.AllowDirect = append(cmd.AllowDirect, entry)
		case strings.HasPrefix(a, "--allow-direct="):
			entry, aerr := parseAllowDirect(strings.TrimPrefix(a, "--allow-direct="))
			if aerr != nil {
				return nil, aerr
			}
			cmd.AllowDirect = append(cmd.AllowDirect, entry)

		case strings.HasPrefix(a, "-") && a != "-":
			// An unlisted/unaudited flag: reject by default (fail-closed on the CLI)
			// so it cannot silently ride through into the tool container. "-" alone
			// (stdin) is treated as a positional, not a flag.
			return nil, fmt.Errorf("unknown flag %q: netcage accepts only a curated allow-list of podman flags (-i, -t, -it, -v/--volume, -w/--workdir, -e/--env, -u/--user, --entrypoint) plus --proxy and --allow-direct", a)

		default:
			// The first non-flag positional ends the flags: it is the image, and
			// everything after it is the tool argv (mirroring podman/docker).
			endOfFlags = true
			positionals = append(positionals, a)
		}
	}

	// Proxy resolution: flag > env > refuse. Both paths go through the SAME
	// socks5h-enforcing ParseProxy (the env path is NOT laxer).
	if !proxyFromFlag {
		if v, ok := lookupEnv(ProxyEnvVar); ok && strings.TrimSpace(v) != "" {
			proxyRaw = v
		}
	}
	if strings.TrimSpace(proxyRaw) == "" {
		return nil, fmt.Errorf("no proxy: pass --proxy socks5h://host:port or set %s (netcage refuses to run without a proxy; it fails closed and never leaks to the host network)", ProxyEnvVar)
	}
	proxy, err := ParseProxy(proxyRaw)
	if err != nil {
		return nil, err
	}
	cmd.Proxy = proxy

	if name == "run" {
		resolveRunPositionals(cmd, positionals)
		resolveRepoMountDefaults(cmd)
	} else if len(positionals) > 0 {
		return nil, fmt.Errorf("verify takes no positional arguments, got %v", positionals)
	}

	return cmd, nil
}

// resolveRunPositionals splits the run positionals into the image and the tool
// argv, following podman's grammar exactly: `run [flags] IMAGE [CMD...]`.
//
//   - The FIRST positional is ALWAYS the image, just like `podman run IMAGE
//     [CMD...]`. So `run -it alpine sh` => image `alpine`, argv `[sh]`, with no
//     `--` marker and no image-vs-command guessing. A bare-token image (`alpine`,
//     `ubuntu`) needs nothing special: it is the first positional, so it is the
//     image.
//   - NO positionals at all => the pinned DEFAULT dev image with an EMPTY argv,
//     so `netcage run -it -v <repo>:/work` drops into the default image's own
//     shell out of the box (prd story 10). This is the ONLY case the default
//     image applies: a default is used solely when the user supplied no image.
//
// The `--` end-of-flags marker is still accepted (a podman nicety) but is no
// longer load-bearing: because the first positional is unconditionally the
// image, `run alpine sh` and `run -- alpine sh` mean the same thing.
func resolveRunPositionals(cmd *Command, positionals []string) {
	if len(positionals) == 0 {
		cmd.Image = defaultImageReference()
		return
	}
	cmd.Image = positionals[0]
	cmd.ToolArgv = positionals[1:]
}

// resolveRepoMountDefaults applies the repo-mount ergonomics (prd story 10): a
// bare `-v <repo>` value with no :container part defaults its target to /work,
// and if the user gave no explicit -w but there is a mount targeting /work, the
// workdir defaults to /work, so a repo dropped in is worked in without
// hand-writing -w. An explicit -w always wins (it is left untouched here).
func resolveRepoMountDefaults(cmd *Command) {
	mountsAtDefaultTarget := false
	for i, m := range cmd.Mounts {
		if mountHasNoContainerTarget(m) {
			cmd.Mounts[i] = m + ":" + DefaultMountTarget
			mountsAtDefaultTarget = true
			continue
		}
		if mountContainerTarget(m) == DefaultMountTarget {
			mountsAtDefaultTarget = true
		}
	}
	if cmd.Workdir == "" && mountsAtDefaultTarget {
		cmd.Workdir = DefaultMountTarget
	}
}

// defaultImageReference is the pinned, digest-immutable default dev image the CLI
// injects when no positional image is given. It is a var (not a direct call) only
// so the reference is resolved in one place; it always returns the pinned
// devimage reference.
func defaultImageReference() string { return devimage.ImageReference() }

// mountHasNoContainerTarget reports whether a -v value is a bare host path with no
// :container target (so its target should default to /work). A Windows-style
// drive letter (`C:\...`) is not a target separator, but netcage's mounts are
// host paths on a Linux host, so a lone `:` here means an explicit target.
func mountHasNoContainerTarget(m string) bool {
	return !strings.Contains(m, ":")
}

// mountContainerTarget returns the container-target segment of a `host:container`
// (or `host:container:opts`) -v value, or "" if there is none.
func mountContainerTarget(m string) string {
	parts := strings.SplitN(m, ":", 3)
	if len(parts) < 2 {
		return ""
	}
	return parts[1]
}

// denyFlag reports whether a is a jail-breaching flag (in --flag or --flag=value
// form) and, if so, the reason it is refused.
func denyFlag(a string) (reason string, denied bool) {
	name := denyFlagName(a)
	r, ok := denyReasons[name]
	return r, ok
}

// denyFlagName strips a `=value` suffix so `--network=host` maps to `--network`.
func denyFlagName(a string) string {
	if i := strings.IndexByte(a, '='); i >= 0 {
		return a[:i]
	}
	return a
}

// next returns the value following the flag at *i and advances *i past it.
func next(args []string, i *int) (string, bool) {
	if *i+1 >= len(args) {
		return "", false
	}
	*i++
	return args[*i], true
}
