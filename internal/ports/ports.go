// This file is the WIRING half of the `netcage ports` verb (the pure enumeration
// core is procnet.go). It executes the parsed `netcage ports <container>
// [--json]` read verb: it resolves the named container to a netcage-managed run
// (label-scoped, ADR-0009), reads the in-jail TCP LISTEN sockets IMAGE-
// INDEPENDENTLY via the netns-sharing SIDECAR's /proc/net/tcp* (podman exec,
// ADR-0006), feeds both bodies to the pure parser, and renders either a human
// table or the --json reuse contract.
//
// Load-bearing guardrails (all from the prd + reused from forward/manage):
//
//   - Label-scoped. Only a netcage-managed run is enumerated (ResolveManagedRun);
//     a non-netcage or unknown container is refused loudly, and a STOPPED jail is
//     refused loudly (nothing to enumerate), same shape as forward.
//   - Image-independent. The listeners are read from /proc/net/tcp* via the
//     SIDECAR (netcage-pinned redirector image, shares the tool's netns), NOT the
//     arbitrary tool image, so it works for a tool image with no ss/netstat/nc
//     (the exact forward-connector lesson). The read never depends on a tool in
//     the user image (ADR-0006: podman is the only host dependency, no host
//     nsenter).
//   - Proxyless / no egress. The verb only READS /proc: it sends no traffic and
//     adds NO firewall rule. It must NEVER emit a socat relay / iptables / publish.
//   - netcage's own 127.0.0.1:53 DNS forwarder is SHOWN, not filtered: the human
//     table annotates it as netcage-internal, but the data never lies by omission
//     (prd story 8).
//
// The orchestration goes through the injectable jail.Runner and the render is a
// pure function, so the wiring is unit-testable without executing podman or a real
// container (fixture /proc/net/tcp* bodies), mirroring internal/forward.
package ports

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/wighawag/netcage/internal/jail"
)

// Config is a resolved `ports` invocation: the user-named container to enumerate
// and whether to emit the --json machine contract instead of the human table.
type Config struct {
	Container string // the user-supplied container name (guarded by label)
	JSON      bool   // emit the machine-readable listener contract instead of the table
}

// IO carries the sinks the verb writes to: Stdout receives the human table OR the
// --json array (the machine output goes to stdout so a caller can capture it
// cleanly); Stderr is available for diagnostics. In production these are
// os.Stdout/os.Stderr; a unit test injects buffers.
type IO struct {
	Stdout io.Writer
	Stderr io.Writer
}

// dnsForwarderNote annotates netcage's own in-jail DNS forwarder in the human
// table: it listens on 127.0.0.1:53 and is netcage plumbing, not a user server.
// It is SHOWN (never filtered) so the list cannot hide a real listener that
// happens to sit on :53 (prd story 8); the annotation is presentation-only and
// is NOT emitted in the --json contract (the machine array reports raw sockets).
const dnsForwarderNote = "netcage DNS forwarder"

// Run executes the ports verb: it resolves + guards the container, reads the
// in-jail listeners via the sidecar, and renders them. It:
//
//  1. RESOLVES the named container to a netcage-managed run (ResolveManagedRun),
//     refusing a non-netcage/unknown container loudly and reading NOTHING.
//  2. REFUSES a stopped jail loudly (the sidecar that shares the netns is not up,
//     so there is nothing to enumerate), pointing the user at `netcage start`.
//  3. READS /proc/net/tcp + /proc/net/tcp6 via `podman exec <sidecar> cat ...`
//     (image-independent: the sidecar shares the tool's netns and is the pinned
//     image, so its /proc/net/tcp* sees the tool's listeners and the read never
//     depends on a tool in the user image), and feeds both to the pure parser.
//  4. RENDERS the human table (default) or the --json reuse contract.
//
// It adds NO firewall rule and sends NO traffic (it only reads /proc): a `ports`
// call is a pure read, like detect-proxy.
func Run(ctx context.Context, r jail.Runner, cfg Config, out IO) error {
	runID, err := jail.ResolveManagedRun(ctx, r, cfg.Container)
	if err != nil {
		return err
	}
	sidecar := jail.SidecarNameFor(runID)
	// The SIDECAR owns the shared netns; if it is not running there is nothing to
	// read. Refuse loudly (pointing at `netcage start`) rather than exec into a
	// down container and report an empty/failed read as "no listeners".
	if err := requireSidecarRunning(ctx, r, sidecar, cfg.Container); err != nil {
		return err
	}

	v4, err := readProc(ctx, r, sidecar, "/proc/net/tcp")
	if err != nil {
		return err
	}
	v6, err := readProc(ctx, r, sidecar, "/proc/net/tcp6")
	if err != nil {
		return err
	}
	listeners := parseProcNetTCP(v4, v6)

	if cfg.JSON {
		return renderJSON(writerOrDiscard(out.Stdout), listeners)
	}
	renderTable(writerOrDiscard(out.Stdout), listeners)
	return nil
}

// requireSidecarRunning REFUSES the enumeration unless the run's SIDECAR (which
// owns the shared netns whose /proc/net/tcp* the listeners live in) is running: a
// stopped jail has nothing to enumerate, so failing loud beats reporting an empty
// list as if the tool had no listeners. One `.State.Running` inspect through the
// Runner seam (the run is already confirmed netcage-managed by the resolver).
func requireSidecarRunning(ctx context.Context, r jail.Runner, sidecar, named string) error {
	out, _, err := r.Run(ctx, jail.RunSpec{Name: "podman", Args: []string{"inspect", "--format", "{{ .State.Running }}", sidecar}})
	if err != nil {
		return fmt.Errorf("cannot list ports for %q: its jail is unavailable (inspect failed): %w; run `netcage start %s` first", named, err, named)
	}
	if strings.TrimSpace(out) != "true" {
		return fmt.Errorf("cannot list ports for %q: its forced-egress jail is not running (the jail is stopped, nothing to enumerate); run `netcage start %s` first to revive it", named, named)
	}
	return nil
}

// readProc reads one /proc/net/tcp* file from inside the shared netns via `podman
// exec <sidecar> cat <path>`. The SIDECAR (not the tool) is exec'd so the read is
// image-independent (the pinned image ships cat / busybox; the arbitrary tool
// image may not). A read failure is surfaced with the captured stderr.
func readProc(ctx context.Context, r jail.Runner, sidecar, path string) (string, error) {
	body, serr, err := r.Run(ctx, jail.RunSpec{Name: "podman", Args: []string{"exec", sidecar, "cat", path}})
	if err != nil {
		if strings.TrimSpace(serr) != "" {
			return "", fmt.Errorf("reading %s via the sidecar %q failed: %w: %s", path, sidecar, err, serr)
		}
		return "", fmt.Errorf("reading %s via the sidecar %q failed: %w", path, sidecar, err)
	}
	return body, nil
}

// renderJSON writes the documented reuse contract: a stable JSON array of
// {address, port, loopbackOnly}, IPv4 + IPv6 in the SAME array (the parser
// already emits v4 then v6 in one slice). A nil/empty result marshals as `[]`
// (never `null`), so a consumer always parses an array. This is the machine
// contract a caller (e.g. anon-pi) consumes to pick a forward target, documented
// like detect-proxy --json.
func renderJSON(w io.Writer, listeners []Listener) error {
	if listeners == nil {
		listeners = []Listener{}
	}
	sortListeners(listeners)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(listeners); err != nil {
		return fmt.Errorf("encoding the ports json contract: %w", err)
	}
	return nil
}

// renderTable writes the human table: ADDRESS / PORT / SCOPE columns, sorted
// stably (by port, then address), with SCOPE reading `loopback` or
// `all-interfaces` and netcage's own 127.0.0.1:53 DNS forwarder ANNOTATED (shown,
// never filtered). An empty result prints a clear "no listeners" line rather than
// a bare header, so the user knows the read succeeded and found nothing.
func renderTable(w io.Writer, listeners []Listener) {
	sortListeners(listeners)
	if len(listeners) == 0 {
		fmt.Fprintln(w, "no TCP listeners in the jail")
		return
	}
	// Compute the address column width so the table aligns.
	addrWidth := len("ADDRESS")
	for _, l := range listeners {
		if len(l.Address) > addrWidth {
			addrWidth = len(l.Address)
		}
	}
	fmt.Fprintf(w, "%-*s  %-5s  %-14s  %s\n", addrWidth, "ADDRESS", "PORT", "SCOPE", "")
	for _, l := range listeners {
		scope := "all-interfaces"
		if l.LoopbackOnly {
			scope = "loopback"
		}
		note := ""
		if l.Address == "127.0.0.1" && l.Port == 53 {
			note = "(" + dnsForwarderNote + ")"
		}
		fmt.Fprintf(w, "%-*s  %-5d  %-14s  %s\n", addrWidth, l.Address, l.Port, scope, note)
	}
}

// sortListeners orders the listeners STABLY for a deterministic table + json: by
// port first (the operator scans for a port), then by address, so the output is
// reproducible regardless of the kernel's /proc row order.
func sortListeners(listeners []Listener) {
	sort.SliceStable(listeners, func(i, j int) bool {
		if listeners[i].Port != listeners[j].Port {
			return listeners[i].Port < listeners[j].Port
		}
		return listeners[i].Address < listeners[j].Address
	})
}

// writerOrDiscard returns w, or io.Discard when w is nil, so Run never panics on
// a nil sink (a test may leave one unset).
func writerOrDiscard(w io.Writer) io.Writer {
	if w == nil {
		return io.Discard
	}
	return w
}
