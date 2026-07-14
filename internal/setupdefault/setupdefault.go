// Package setupdefault implements `netcage setup-default`: the interactive,
// re-runnable onboarding that detects a SOCKS proxy, lets the user choose or
// enter one, verifies it (shows the exit IP as evidence it differs from the
// host), WARNS about the silent-default tradeoff, and PERSISTS the choice
// (credential-free) into ~/.config/netcage/config.json so a bare `netcage run`
// needs no --proxy. It is the ONLY config writer (it composes cli.WriteConfig).
//
// The honesty model (settled in the netcage-config-and-proxy-setup spec) is
// load-bearing and lives HERE at write time, once: the verb NAME carries the
// weight (`setup-default`, not an innocent `setup`), the tradeoff warning fires
// ONCE here (no per-run chatter), and the persisted default is CREDENTIAL-FREE by
// construction (cli.WriteConfig refuses a user:pass@ proxy; authed proxies stay
// in env/flag). It NEVER labels the exit provider (the exit IP is evidence only,
// inherited from detect-proxy's evidence-only output).
//
// The DECISION logic is pure and testable: NormalizeProxyInput, the
// credential-refusal, the reconfigure pre-fill formatting, the candidate list,
// and WarningText are pure functions; the impure prompt / detect / verify / write
// I/O is behind the small injectable seams (Prompter, Detector, Verifier, Writer,
// Console). Run wires them; a test drives Run with fakes and no real podman.
package setupdefault

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"

	"github.com/wighawag/netcage/internal/cli"
	"github.com/wighawag/netcage/internal/detectproxy"
)

// Prompter is the impure interactive INPUT seam: Ask returns a line of user input
// for a prompt (with a default shown), and Confirm returns a yes/no answer. A
// test injects scripted answers; production reads the real stdin. Returning an
// error lets a closed/EOF stdin abort cleanly rather than loop.
type Prompter interface {
	// Ask shows prompt (and, if non-empty, the current/default value) and returns
	// the trimmed user input. An empty return means "accept the default".
	Ask(prompt, def string) (string, error)
	// Confirm shows prompt and returns whether the user answered yes. def is the
	// answer used on an empty (bare-Enter) reply.
	Confirm(prompt string, def bool) (bool, error)
}

// Detector is the impure DETECTION seam: it runs the detect-proxy engine and
// returns its evidence-only Report (which ports are open / confirmed SOCKS5, weak
// process hints). setup-default drives it to offer detected candidates. It is an
// interface so a test supplies a fixed Report with no real socket probe.
type Detector interface {
	Detect() detectproxy.Report
}

// Verifier is the impure VERIFY seam: given a resolved proxy it returns the exit
// IP observed through the jail (evidence the egress is not the host IP), reusing
// verify's exit-IP machinery. It NEVER labels the provider. An error means the
// evidence could not be gathered (no podman / offline / unreachable), which the
// flow surfaces as "could not verify" rather than a false claim.
type Verifier interface {
	ExitIP(proxy cli.ProxyConfig) (string, error)
}

// Writer is the impure PERSIST seam: it writes the chosen credential-free proxy
// (+ optional allow list) to the config file 0600. In production it is
// cli.WriteConfig bound to the process env; a test injects a fake to assert what
// would be persisted without touching disk. It returns
// cli.ErrCredentialedProxyNotPersisted when asked to persist a credentialed
// proxy (the single-writer invariant).
type Writer interface {
	Write(proxyURL string, allowDirect []string) error
}

// Console is the impure OUTPUT seam: setup-default's human-facing lines (the
// findings, the exit-IP evidence, the tradeoff WARNING, the done line). A test
// captures them to assert the warning text and the never-label-the-provider
// guarantee. Kept separate from Prompter so output is testable independently of
// scripted input.
type Console interface {
	Printf(format string, args ...any)
}

// Options carries the impure seams Run composes. All are required; ConfigPath is
// the human path shown in prompts/warnings (e.g. ~/.config/netcage/config.json),
// and Existing is the current persisted config for the reconfigure pre-fill
// (Present=false for a first-time setup).
type Options struct {
	Prompter   Prompter
	Detector   Detector
	Verifier   Verifier
	Writer     Writer
	Console    Console
	ConfigPath string
	Existing   cli.ConfigView
}

// NormalizeProxyInput turns a user's proxy input into a validated socks5h URL
// STRING. It accepts either a full socks5h://host:port URL or a bare host:port
// (the common case a user types after detection), defaulting a bare entry to the
// socks5h scheme, then round-trips the SAME socks5h-enforcing cli.ParseProxy so a
// socks5:// (DNS leak) or malformed entry is rejected exactly as on the flag. It
// is PURE (no I/O) so the input-handling decision is unit-testable. It returns
// the canonical socks5h://host:port string to persist (credentials, if any,
// preserved here so the WRITER can refuse them with a precise message rather than
// this step silently dropping them).
func NormalizeProxyInput(raw string) (proxyURL string, err error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", errors.New("empty proxy: enter a socks5h://host:port or a host:port")
	}
	// A bare host:port (no scheme) is defaulted to socks5h:// (the only scheme
	// netcage persists). A value that already carries a scheme is left as-is so a
	// wrong scheme (socks5://, http://) is rejected by ParseProxy, not masked.
	if !strings.Contains(s, "://") {
		s = "socks5h://" + s
	}
	p, perr := cli.ParseProxy(s)
	if perr != nil {
		return "", perr
	}
	// Rebuild the canonical URL from the parsed parts so the persisted string is
	// normalised (scheme + host:port, plus credentials if the user supplied them;
	// the writer refuses credentials with a precise redirect).
	u := &url.URL{Scheme: "socks5h", Host: net.JoinHostPort(p.Host, p.Port)}
	if p.Username != "" || p.Password != "" {
		if p.Password != "" {
			u.User = url.UserPassword(p.Username, p.Password)
		} else {
			u.User = url.User(p.Username)
		}
	}
	return u.String(), nil
}

// candidateProxyURL is the socks5h URL for a confirmed detect-proxy candidate
// (always loopback, always credential-free: a detected local proxy has no
// embedded auth). It is the value offered when the user picks a detected proxy.
func candidateProxyURL(port int) string {
	return fmt.Sprintf("socks5h://127.0.0.1:%d", port)
}

// confirmedPorts returns the ports of the candidates that CONFIRMED SOCKS5, in
// the report's order, deduplicated. These are the only sensible defaults to offer
// (an open-but-unconfirmed port is not a proxy). It is pure.
func confirmedPorts(rep detectproxy.Report) []int {
	var ports []int
	seen := map[int]bool{}
	for _, c := range rep.Candidates {
		if c.SOCKS5 && !seen[c.Port] {
			ports = append(ports, c.Port)
			seen[c.Port] = true
		}
	}
	return ports
}

// WarningText is the ONE-TIME tradeoff WARNING setup-default prints at write time
// (the honesty model: the warning fires ONCE here, never per run). It states that
// from now on a bare `netcage run` uses this proxy with no per-run reminder and
// points at `netcage verify` as the on-demand proof of which proxy you are on and
// that your exit IP is not the host's. It is PURE so a test asserts its content.
func WarningText(proxyURL string) string {
	return "" +
		"WARNING: this installs " + proxyURL + " as netcage's DEFAULT proxy.\n" +
		"From now on a bare `netcage run` uses this proxy with NO per-run reminder.\n" +
		"Run `netcage verify` any time to confirm which proxy you are on and that\n" +
		"your exit IP is not your host's."
}

// prefillProxy returns the proxy value to pre-fill the prompt with on a
// reconfigure: the current persisted proxy URL if one exists, else empty (a
// first-time setup). It is pure. The current value is SHOWN so the user sees what
// they are replacing (the re-runnable / reconfigure contract).
func prefillProxy(existing cli.ConfigView) string {
	if existing.Present {
		return existing.ProxyURL
	}
	return ""
}

// sortedInts returns a sorted copy (small helper for deterministic candidate
// display / tests).
func sortedInts(in []int) []int {
	out := append([]int(nil), in...)
	sort.Ints(out)
	return out
}

// Run drives the interactive, re-runnable onboarding to completion and returns an
// error only if the flow could not finish (a closed stdin, a persist failure). A
// user who declines to overwrite an existing config, or aborts, is a clean
// no-error return (nothing was written). It composes the injected seams:
//
//  1. DETECT: run detect-proxy and print its evidence-only findings.
//  2. CHOOSE: offer the confirmed detected proxies (or let the user type a
//     host:port), pre-filling the current value on a reconfigure. The input is
//     normalised + socks5h-validated (NormalizeProxyInput).
//  3. VERIFY: best-effort exit-IP EVIDENCE (never a provider label); a failure is
//     surfaced as "could not verify" and the user is asked whether to proceed.
//  4. WARN: the ONE-TIME tradeoff warning (WarningText).
//  5. CONFIRM + WRITE: on a reconfigure, CONFIRM before overwriting (never clobber
//     silently); then persist credential-free via the Writer (0600). A
//     credentialed proxy is REFUSED at persist with a clear redirect to env/flag,
//     and the user may re-enter.
func Run(o Options) error {
	c := o.Console

	// 1. DETECT: present the evidence-only findings (never a provider label; the
	// text is detect-proxy's own evidence-only rendering).
	rep := o.Detector.Detect()
	c.Printf("%s", rep.Human())

	ports := confirmedPorts(rep)

	// 2. CHOOSE + 3. VERIFY + 5. WRITE, looping so a rejected (e.g. credentialed)
	// entry lets the user try again rather than aborting the whole onboarding.
	for {
		proxyURL, err := o.chooseProxy(ports)
		if err != nil {
			return err
		}
		if proxyURL == "" {
			c.Printf("setup-default: aborted, nothing was written.\n")
			return nil
		}

		// 3. VERIFY: best-effort exit-IP EVIDENCE. A parse of proxyURL cannot fail
		// here (NormalizeProxyInput already validated it), but guard anyway.
		if proxy, perr := cli.ParseProxy(proxyURL); perr == nil {
			if ip, verr := o.Verifier.ExitIP(proxy); verr == nil && ip != "" {
				c.Printf("verified: exit IP %s (evidence the egress is not your host IP)\n", ip)
			} else {
				c.Printf("could not verify the exit IP (no podman / offline / proxy unreachable); no evidence gathered.\n")
				proceed, cerr := o.Prompter.Confirm("persist this proxy anyway?", false)
				if cerr != nil {
					return cerr
				}
				if !proceed {
					continue // let the user re-choose / re-enter
				}
			}
		}

		// 4. WARN: the one-time tradeoff warning, at write time, once.
		c.Printf("%s\n", WarningText(proxyURL))

		// 5. CONFIRM before overwriting an EXISTING config (never clobber silently);
		// a first-time setup still confirms the write.
		prompt := "write this default proxy to " + o.ConfigPath + "?"
		if o.Existing.Present {
			prompt = "overwrite the existing config at " + o.ConfigPath + " with this default proxy?"
		}
		ok, cerr := o.Prompter.Confirm(prompt, false)
		if cerr != nil {
			return cerr
		}
		if !ok {
			c.Printf("setup-default: left the existing config unchanged.\n")
			return nil
		}

		// PERSIST credential-free (0600). The writer is the single enforcement point
		// for the credential-free invariant: a user:pass@ proxy is refused with a
		// redirect to env/flag, and we loop so the user can re-enter a clean one.
		if werr := o.Writer.Write(proxyURL, existingAllowDirect(o.Existing)); werr != nil {
			if errors.Is(werr, cli.ErrCredentialedProxyNotPersisted) {
				c.Printf("%v\n", werr)
				continue // let the user enter a credential-free proxy instead
			}
			return werr
		}
		c.Printf("saved: %s is now netcage's default proxy (%s, 0600).\n", proxyURL, o.ConfigPath)
		return nil
	}
}

// existingAllowDirect carries the current persisted allow list through a
// reconfigure unchanged (setup-default reconfigures the PROXY; it does not
// silently drop the user's existing split-tunnel list). It is empty for a
// first-time setup. Each entry is re-validated by the writer, so a stale/invalid
// hand-edited entry is caught at persist rather than carried blindly.
func existingAllowDirect(existing cli.ConfigView) []string {
	if !existing.Present {
		return nil
	}
	return existing.AllowDirect
}

// chooseProxy is the CHOICE decision: it offers the confirmed detected proxies as
// numbered options and lets the user pick one or type a host:port, pre-filling
// the current persisted proxy on a reconfigure. It returns the normalised,
// socks5h-validated proxy URL to persist, or "" if the user chose to abort. A
// malformed manual entry re-prompts (it does not abort the onboarding). The
// candidate list is shown sorted for a deterministic display.
func (o Options) chooseProxy(confirmed []int) (string, error) {
	ports := sortedInts(confirmed)
	for _, p := range ports {
		o.Console.Printf("  detected: %s (confirmed SOCKS5)\n", candidateProxyURL(p))
	}
	def := prefillProxy(o.Existing)
	for {
		hint := "enter a proxy host:port (or a full socks5h://host:port)"
		if len(ports) > 0 {
			hint = "enter a proxy host:port, or accept a detected one above"
		}
		if def != "" {
			hint += " [current: " + def + "]"
		}
		raw, err := o.Prompter.Ask(hint, def)
		if err != nil {
			return "", err
		}
		raw = strings.TrimSpace(raw)
		if raw == "" {
			if def != "" {
				raw = def // bare Enter accepts the current value on a reconfigure
			} else if len(ports) == 1 {
				raw = candidateProxyURL(ports[0]) // bare Enter accepts the sole detected proxy
			} else {
				return "", nil // nothing to default to: treat empty as abort
			}
		}
		proxyURL, nerr := NormalizeProxyInput(raw)
		if nerr != nil {
			o.Console.Printf("invalid proxy: %v\n", nerr)
			continue // re-prompt rather than abort the onboarding
		}
		return proxyURL, nil
	}
}
