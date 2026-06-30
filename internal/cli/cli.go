// Package cli implements tooljail's command-line surface: the `run` and `verify`
// subcommands, the socks5h proxy-URL contract, and the fail-loud startup
// preflight. It deliberately does NOT stand up the jail (sidecar/netns/nft);
// that is the jail-run-forced-egress task. This package is pure parsing +
// validation + a reachability seam, so it is unit-testable without any system
// mutation.
package cli

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

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
// which is exactly what tooljail exists to prevent. Only socks5h (remote,
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
		return ProxyConfig{}, fmt.Errorf("--proxy scheme %q unsupported; tooljail requires socks5h://", u.Scheme)
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

// Command is a parsed tooljail invocation.
type Command struct {
	Name     string // "run" or "verify"
	Proxy    ProxyConfig
	Image    string   // required for run; unused for verify
	ToolArgv []string // the post-"--" tool argv (run)
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
// It FAILS LOUD if the proxy is unreachable: tooljail must never silently no-op
// or fall back to the host network when the proxy is down (story 10 / the
// fail-closed invariant).
func (c *Command) PreflightWith(r Reachability) error {
	if err := r.Check(c.Proxy.Address()); err != nil {
		return fmt.Errorf("proxy %s is unreachable at startup: %w (refusing to run: tooljail fails closed, it never leaks to the host network)", c.Proxy.Address(), err)
	}
	return nil
}

// Parse parses argv (without the program name) into a Command.
func Parse(args []string) (*Command, error) {
	if len(args) == 0 {
		return nil, errors.New("no subcommand: expected `run` or `verify`")
	}
	name := args[0]
	switch name {
	case "run", "verify":
	default:
		return nil, fmt.Errorf("unknown subcommand %q: expected `run` or `verify`", name)
	}

	rest, toolArgv := splitDoubleDash(args[1:])

	var proxyRaw, image string
	for i := 0; i < len(rest); i++ {
		a := rest[i]
		switch {
		case a == "--proxy":
			v, ok := next(rest, &i)
			if !ok {
				return nil, errors.New("--proxy requires a value")
			}
			proxyRaw = v
		case strings.HasPrefix(a, "--proxy="):
			proxyRaw = strings.TrimPrefix(a, "--proxy=")
		case a == "--image":
			v, ok := next(rest, &i)
			if !ok {
				return nil, errors.New("--image requires a value")
			}
			image = v
		case strings.HasPrefix(a, "--image="):
			image = strings.TrimPrefix(a, "--image=")
		default:
			return nil, fmt.Errorf("unknown flag or argument %q", a)
		}
	}

	if proxyRaw == "" {
		return nil, errors.New("--proxy is required (socks5h://host:port)")
	}
	proxy, err := ParseProxy(proxyRaw)
	if err != nil {
		return nil, err
	}

	cmd := &Command{Name: name, Proxy: proxy, ToolArgv: toolArgv}

	if name == "run" {
		if image == "" {
			return nil, errors.New("run requires --image <image>")
		}
		cmd.Image = image
		if len(toolArgv) == 0 {
			return nil, errors.New("run requires a tool command after `--` (e.g. -- nuclei -u https://target)")
		}
	}
	return cmd, nil
}

// splitDoubleDash splits args at the first standalone "--": everything before is
// flags, everything after is the tool argv.
func splitDoubleDash(args []string) (before, after []string) {
	for i, a := range args {
		if a == "--" {
			return args[:i], args[i+1:]
		}
	}
	return args, nil
}

// next returns the value following the flag at *i and advances *i past it.
func next(args []string, i *int) (string, bool) {
	if *i+1 >= len(args) {
		return "", false
	}
	*i++
	return args[*i], true
}
