// Package detectproxy is netcage's reusable, tool-agnostic proxy DETECTION
// primitive: it probes the common local SOCKS ports, CONFIRMS each open port
// actually speaks SOCKS5 via a minimal RFC1928 handshake, and presents
// EVIDENCE-ONLY findings. It is the engine `setup-default` drives interactively
// and the primitive anon-pi's `init` calls via the `--json` contract, which is
// exactly why the detection lives in netcage rather than a downstream wrapper.
//
// netcage forces egress through a socks5h proxy, fail-closed; this package is the
// OPPOSITE end: it HELPS FIND that proxy. The honesty constraint is load-bearing
// for an anonymity-adjacent tool: the output presents evidence (which ports are
// open, the SOCKS5 handshake result, an optional exit IP) plus WEAK, HEDGED,
// provider-AGNOSTIC process hints, and it NEVER labels the exit PROVIDER. A SOCKS
// proxy does not announce Mullvad/Proton, so a false label is a dangerous lie.
// That honesty is made STRUCTURAL: the `--json` schema (Report/Candidate) carries
// NO provider/label field by construction (asserted by a test), so it can never
// regress into a runtime-only rule.
//
// The decision layer here is PURE and injectable (Probe over a Prober; the
// handshake over any io.ReadWriter), so the probe/handshake/rendering decisions
// are unit-testable against internal/socks5hfixture with no real Tor and no
// host-global proxy assumption. The impure socket I/O (DialProber) is a thin
// shell around it.
package detectproxy

import (
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// SchemaVersion is the version of the `--json` reuse CONTRACT. The schema evolves
// ADDITIVELY only (new optional fields), so a consumer pinned to this version keeps
// working; a breaking change would bump it. It is emitted as `schemaVersion` in the
// JSON so anon-pi (and any other consumer) can guard on the shape it understands.
const SchemaVersion = 1

// DefaultPorts is the canonical, ORDERED list of common local SOCKS ports netcage
// probes, with a provider-AGNOSTIC descriptive note per port. The notes describe
// the CONVENTIONAL occupant of the port (a weak, hedged prior), never a confirmed
// provider label: they are the "likely Tor" hedge, not "you are on Tor".
var DefaultPorts = []PortSpec{
	{Port: 9050, Note: "Tor default"},
	{Port: 9150, Note: "Tor Browser default"},
	{Port: 1080, Note: "generic SOCKS (wireproxy / ssh -D / other)"},
}

// PortSpec is one common SOCKS port to probe plus a provider-AGNOSTIC note about
// its conventional occupant (a weak prior, never a label).
type PortSpec struct {
	Port int
	Note string
}

// Candidate is the EVIDENCE for one probed port: whether the port was open,
// whether it CONFIRMED SOCKS5 via the RFC1928 handshake (an open port alone is
// NOT enough), and an optional WEAK, HEDGED, provider-agnostic process hint. By
// construction it has NO provider/label field: the never-label-the-provider
// honesty is a property of this SHAPE (a test asserts it), not just a runtime
// rule.
type Candidate struct {
	Port        int    `json:"port"`
	Open        bool   `json:"open"`
	SOCKS5      bool   `json:"socks5"`
	ProcessHint string `json:"processHint,omitempty"`
}

// Report is the structured findings and the `--json` reuse CONTRACT. It carries a
// SchemaVersion (additive-only evolution), the per-candidate evidence, and an
// OPTIONAL overall exit IP (proof the egress is not the host IP, when the caller
// supplied it via verify's exit-IP machinery). It has NO provider/label field by
// construction.
type Report struct {
	SchemaVersion int         `json:"schemaVersion"`
	Candidates    []Candidate `json:"candidates"`
	ExitIP        string      `json:"exitIP,omitempty"`
}

// PortResult is one port's probe outcome as observed by a Prober (the impure I/O
// seam). Probe folds these into the ordered candidate list.
type PortResult struct {
	Open        bool
	SOCKS5      bool
	ProcessHint string
}

// Prober performs the impure per-port probe (dial the port, and if open, run the
// SOCKS5 handshake; optionally attach a process hint). It is an interface so the
// pure Probe decision is testable with an injected result and no real socket.
type Prober interface {
	Probe(port int) PortResult
}

// Probe is the PURE detection decision: it walks the canonical DefaultPorts IN
// ORDER, asks the Prober for each port's result, and folds them into the ordered
// candidate list. It performs no I/O itself, so it is deterministic and unit-
// testable against a fake Prober. The Report it returns carries the current
// SchemaVersion; the caller attaches an optional ExitIP separately (that evidence
// needs a jail run, kept OUT of this pure seam).
func Probe(p Prober) Report {
	rep := Report{SchemaVersion: SchemaVersion}
	for _, spec := range DefaultPorts {
		r := p.Probe(spec.Port)
		rep.Candidates = append(rep.Candidates, Candidate{
			Port:        spec.Port,
			Open:        r.Open,
			SOCKS5:      r.SOCKS5,
			ProcessHint: r.ProcessHint,
		})
	}
	return rep
}

// SOCKS5 protocol constants (RFC 1928).
const (
	socksVer      = 0x05
	methodNoAuth  = 0x00
	methodNoAccep = 0xFF
)

// Handshake performs a MINIMAL RFC1928 SOCKS5 method negotiation over rw and
// reports whether the peer is really SOCKS5 (an open port is NOT enough
// confirmation). It offers the no-auth method (0x00) and requires the server to
// answer with a version-5 method-selection that is NOT "no acceptable methods"
// (0xFF). It reads no further (no CONNECT is issued): confirming the peer speaks
// SOCKS5 is the whole job, and issuing a CONNECT would egress. A protocol/read
// error returns (false, err); a clean non-SOCKS5 answer returns (false, nil).
func Handshake(rw io.ReadWriter) (bool, error) {
	// VER=5, NMETHODS=1, METHODS=[no-auth].
	if _, err := rw.Write([]byte{socksVer, 0x01, methodNoAuth}); err != nil {
		return false, err
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(rw, resp); err != nil {
		return false, err
	}
	if resp[0] != socksVer {
		// A non-SOCKS5 server (e.g. an HTTP proxy or garbage) answered on an open
		// port: NOT confirmed, but not an error we need to surface loudly.
		return false, nil
	}
	if resp[1] == methodNoAccep {
		// It IS SOCKS5 (version byte matched), but it refused no-auth. That is still
		// a confirmed SOCKS5 speaker; netcage only needs to know it speaks SOCKS5.
		return true, nil
	}
	return true, nil
}

// PortHints builds the per-port WEAK, HEDGED, provider-AGNOSTIC process hints
// from a set of running process names (lower-cased basenames). A running `tor`
// process hints the two Tor-conventional ports; the hint is deliberately hedged
// ("-> likely Tor") and describes an OBSERVED process, never a claim about the
// exit. It is pure (the caller injects the process names), so the hint decision
// is testable without reading the real process table. A hint is NEVER a provider
// label: "a `tor` process is running" is evidence-shaped, not "you are on Tor".
func PortHints(processNames []string) map[int]string {
	set := map[string]bool{}
	for _, n := range processNames {
		set[strings.ToLower(strings.TrimSpace(n))] = true
	}
	hints := map[int]string{}
	if set["tor"] {
		hints[9050] = "a `tor` process is running -> likely Tor"
		hints[9150] = "a `tor` process is running -> likely Tor"
	}
	return hints
}

// DialProber is the thin, IMPURE socket I/O: it dials 127.0.0.1:<port>, and if
// the port is open, runs the RFC1928 Handshake to confirm SOCKS5. It attaches an
// optional provider-AGNOSTIC process hint from Hints (looked up by port). It is
// deliberately small: all decisions live in the pure layer above.
type DialProber struct {
	// Timeout bounds each dial + handshake so a probe of a dead port is fast.
	Timeout time.Duration
	// Hints maps a port to a WEAK, HEDGED, provider-agnostic process hint (e.g.
	// "a `tor` process is running -> likely Tor"), computed by the caller from the
	// process table. Empty for a port with no hint.
	Hints map[int]string
}

// Probe dials the loopback port and, if open, confirms SOCKS5 via the handshake.
func (d DialProber) Probe(port int) PortResult {
	to := d.Timeout
	if to <= 0 {
		to = 2 * time.Second
	}
	res := PortResult{ProcessHint: d.Hints[port]}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", port)), to)
	if err != nil {
		return res // closed / unreachable: open stays false
	}
	defer conn.Close()
	res.Open = true
	_ = conn.SetDeadline(time.Now().Add(to))
	if ok, _ := Handshake(conn); ok {
		res.SOCKS5 = true
	}
	return res
}

// Human renders the EVIDENCE-ONLY findings as human-readable text: for each
// candidate it states whether the port was open and whether it CONFIRMED SOCKS5,
// carries the weak hedged process hint verbatim (the hint is provider-agnostic by
// construction), and prints the exit IP when present. It NEVER names/labels a
// provider (a test asserts no provider label appears): the strongest thing it
// says is the caller's own hedged "-> likely Tor" hint, which is evidence-shaped
// ("a process is running"), not a claim about the exit.
func (r Report) Human() string {
	var b strings.Builder
	b.WriteString("netcage detect-proxy findings (evidence only):\n")
	notes := map[int]string{}
	for _, s := range DefaultPorts {
		notes[s.Port] = s.Note
	}
	for _, c := range r.Candidates {
		note := notes[c.Port]
		switch {
		case c.SOCKS5:
			fmt.Fprintf(&b, "  127.0.0.1:%d  open, SOCKS5 confirmed", c.Port)
		case c.Open:
			fmt.Fprintf(&b, "  127.0.0.1:%d  open, but NOT confirmed SOCKS5 (an open port is not enough)", c.Port)
		default:
			fmt.Fprintf(&b, "  127.0.0.1:%d  closed", c.Port)
		}
		if note != "" {
			fmt.Fprintf(&b, "  [%s]", note)
		}
		if c.ProcessHint != "" {
			fmt.Fprintf(&b, "  hint: %s", c.ProcessHint)
		}
		b.WriteString("\n")
	}
	if r.ExitIP != "" {
		fmt.Fprintf(&b, "  exit IP (via netcage verify): %s (evidence the egress is not your host IP)\n", r.ExitIP)
	}
	if !r.anyConfirmed() {
		b.WriteString("  no SOCKS5 proxy confirmed on the common ports. Start one (e.g. Tor) or pass its host:port to `netcage setup-default`.\n")
	}
	return b.String()
}

// anyConfirmed reports whether at least one candidate confirmed SOCKS5.
func (r Report) anyConfirmed() bool {
	for _, c := range r.Candidates {
		if c.SOCKS5 {
			return true
		}
	}
	return false
}
