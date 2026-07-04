package forward_test

import (
	"context"
	"strings"
	"testing"

	"github.com/wighawag/netcage/internal/forward"
	"github.com/wighawag/netcage/internal/jail"
)

// recordRunner records every podman invocation the forward orchestration makes
// and answers label/role/run-id + .State.Running inspect queries from a scripted
// table, so the guard-by-label + running check is unit-testable WITHOUT a real
// podman (mirrors manage's recordRunner). It also records the RunSpec of the
// socat listener so a test can assert its argv WITHOUT ever binding a real host
// socket.
type recordRunner struct {
	calls   [][]string
	labels  map[string]map[string]string // container name -> label key -> value
	running map[string]bool              // container name -> .State.Running
	specs   []jail.RunSpec
}

func (r *recordRunner) Run(_ context.Context, spec jail.RunSpec) (string, string, error) {
	// Record the invocation keyed by its binary NAME as the first token, so a test
	// can tell a `podman inspect` guard from the `socat` relay (jail.RunSpec keeps
	// the binary in Name and its args in Args).
	r.calls = append(r.calls, append([]string{spec.Name}, spec.Args...))
	r.specs = append(r.specs, spec)
	if len(spec.Args) >= 3 && spec.Args[0] == "inspect" && spec.Args[1] == "--format" {
		format := spec.Args[2]
		name := spec.Args[len(spec.Args)-1]
		if strings.Contains(format, ".State.Running") {
			if r.running != nil && r.running[name] {
				return "true", "", nil
			}
			return "false", "", nil
		}
		lbls, ok := r.labels[name]
		if !ok {
			return "", "no such container", errNotFound
		}
		return lbls[jail.LabelManaged] + "\t" + lbls[jail.LabelRole] + "\t" + lbls[jail.LabelRunID], "", nil
	}
	// Any other call (the socat listener) succeeds cleanly.
	return "", "", nil
}

var errNotFound = &notFoundErr{}

type notFoundErr struct{}

func (*notFoundErr) Error() string { return "no such container" }

func joinAll(calls [][]string) string {
	var b strings.Builder
	for _, c := range calls {
		b.WriteString(strings.Join(c, " "))
		b.WriteString("\n")
	}
	return b.String()
}

// managedTool is the healthy-jail label+state table for a netcage-managed tool.
func managedTool(runID string) *recordRunner {
	tool := "netcage-run-" + runID + "-tool"
	sidecar := "netcage-run-" + runID + "-sidecar"
	return &recordRunner{
		labels: map[string]map[string]string{
			tool: {jail.LabelManaged: "true", jail.LabelRole: jail.RoleTool, jail.LabelRunID: runID},
		},
		running: map[string]bool{tool: true, sidecar: true},
	}
}

// TestListenArgs_IsHostSocatLoopbackListenerIntoNetnsConnect pins the spike's
// proven recipe (Shape B): a HOST socat listener binding <bind> whose EXEC connect
// side reaches the in-jail server via `podman --root <graphroot> exec -i <tool>
// <connector> ... <port>`. It must NEVER add a firewall rule, be TCP only, name
// exactly the one port, and bind the DEFAULT loopback when bind is 127.0.0.1.
func TestListenArgs_IsHostSocatLoopbackListenerIntoNetnsConnect(t *testing.T) {
	args := forward.ListenArgs(forward.Config{ToolContainer: "netcage-run-abc-tool", Port: 3001, Bind: "127.0.0.1"})
	joined := strings.Join(args, " ")

	if args[0] != "socat" {
		t.Fatalf("the forward is a host socat relay; argv must start with socat. got: %s", joined)
	}
	// Host-side listener binds the given host address, TCP, on the named host port.
	if !strings.Contains(joined, "TCP-LISTEN:3001") {
		t.Fatalf("the listener must be a TCP listener on the named port 3001; got: %s", joined)
	}
	if !strings.Contains(joined, "bind=127.0.0.1") {
		t.Fatalf("the DEFAULT bind must be loopback 127.0.0.1; got: %s", joined)
	}
	// Connect side enters the netns via podman exec into the netcage-managed TOOL,
	// carrying the graphroot so it reads the same store the jail wrote.
	if !strings.Contains(joined, "podman") || !strings.Contains(joined, "--root "+jail.GraphRoot()) {
		t.Fatalf("the connect side must be `podman --root <graphroot> exec`; got: %s", joined)
	}
	if !strings.Contains(joined, "exec -i netcage-run-abc-tool") {
		t.Fatalf("the connect side must `podman exec -i` into the tool container; got: %s", joined)
	}
	if !strings.Contains(joined, "127.0.0.1 3001") {
		t.Fatalf("the connect side must reach the in-jail server at 127.0.0.1:<port>; got: %s", joined)
	}
	// Load-bearing: the socat EXEC address must be SOCAT-PARSEABLE. socat's `EXEC:`
	// does NOT invoke a shell and does NOT honour quotes: it whitespace-splits the
	// address and execvp's the raw tokens. So a nested `sh -c '...'`, a single-quote,
	// a `||`, or a shell redirection in the connector would be passed LITERALLY to
	// podman and the connector would die (the host reaches nothing). This guard is
	// exactly what the earlier broken `EXEC:...sh -c 'nc || socat'` connector needed
	// and lacked; the connector must be a single, shell-free command
	// (work/notes/observations/forward-socat-exec-nested-quote-connector-broken.md).
	for _, unparseable := range []string{"sh -c", "'", "||", "2>", "&&"} {
		if strings.Contains(joined, unparseable) {
			t.Fatalf("the socat EXEC connector must be a single shell-free command (socat EXEC does not run a shell / honour quotes); found %q in: %s", unparseable, joined)
		}
	}
	// Load-bearing: the forward NEVER touches the egress firewall.
	for _, forbidden := range []string{"iptables", "OUTPUT", "--network", "-p ", "--publish", "nft"} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("the forward must add NO firewall/OUTPUT/publish rule; found %q in: %s", forbidden, joined)
		}
	}
	// UDP is hard-dropped (ADR-0003): the forward is TCP-only.
	if strings.Contains(joined, "UDP") || strings.Contains(joined, "udp") {
		t.Fatalf("the forward must be TCP-only (UDP stays hard-dropped, ADR-0003); got: %s", joined)
	}
}

// TestListenArgs_BindDefaultVsAllInterfaces pins the guardrailed opt-in: the
// resolved bind is written verbatim into the listener, so 0.0.0.0 binds all
// interfaces and 127.0.0.1 (the default) binds loopback only.
func TestListenArgs_BindDefaultVsAllInterfaces(t *testing.T) {
	loop := strings.Join(forward.ListenArgs(forward.Config{ToolContainer: "netcage-run-abc-tool", Port: 8080, Bind: "127.0.0.1"}), " ")
	if !strings.Contains(loop, "bind=127.0.0.1") || strings.Contains(loop, "bind=0.0.0.0") {
		t.Fatalf("default must bind loopback only; got: %s", loop)
	}
	lan := strings.Join(forward.ListenArgs(forward.Config{ToolContainer: "netcage-run-abc-tool", Port: 8080, Bind: "0.0.0.0"}), " ")
	if !strings.Contains(lan, "bind=0.0.0.0") {
		t.Fatalf("--bind 0.0.0.0 must bind all interfaces; got: %s", lan)
	}
}

// TestRun_RefusesNonNetcageContainer proves the label-scoping refusal: a named
// container that does NOT carry the netcage.managed label is REFUSED loudly, and
// NO socat listener is ever stood up (no host state touched).
func TestRun_RefusesNonNetcageContainer(t *testing.T) {
	r := &recordRunner{labels: map[string]map[string]string{
		"some-random-container": {}, // exists but NOT netcage-managed
	}}
	var out strings.Builder
	err := forward.Run(context.Background(), r,
		forward.Config{Container: "some-random-container", Port: 3001, Bind: "127.0.0.1"},
		forward.IO{Stdout: &out, Stderr: &out})
	if err == nil {
		t.Fatal("forwarding into a non-netcage container must be REFUSED")
	}
	if !strings.Contains(err.Error(), "not a netcage-managed container") {
		t.Fatalf("the refusal must name the reason; got: %v", err)
	}
	for _, c := range r.calls {
		if len(c) > 0 && c[0] == "socat" {
			t.Fatalf("a refused forward must NOT stand up a socat listener; calls:\n%s", joinAll(r.calls))
		}
	}
}

// TestRun_RefusesStoppedJail proves a non-running jail is refused loudly (the
// server cannot be reached, so failing loud beats appearing to work), and no
// listener is stood up.
func TestRun_RefusesStoppedJail(t *testing.T) {
	r := managedTool("abc")
	r.running["netcage-run-abc-tool"] = false // tool stopped (kept pair at rest)
	var out strings.Builder
	err := forward.Run(context.Background(), r,
		forward.Config{Container: "netcage-run-abc-tool", Port: 3001, Bind: "127.0.0.1"},
		forward.IO{Stdout: &out, Stderr: &out})
	if err == nil {
		t.Fatal("forwarding into a stopped jail must be REFUSED loudly")
	}
	if !strings.Contains(err.Error(), "netcage start") {
		t.Fatalf("the refusal must point the user at `netcage start`; got: %v", err)
	}
	for _, c := range r.calls {
		if len(c) > 0 && c[0] == "socat" {
			t.Fatalf("a refused forward must NOT stand up a socat listener; calls:\n%s", joinAll(r.calls))
		}
	}
}

// TestRun_LoopbackDefaultPrintsStartLineNoWarning proves the bare verb (loopback
// default) prints the start line and does NOT warn (nothing is exposed off-box),
// and stands up exactly ONE socat listener bound to 127.0.0.1.
func TestRun_LoopbackDefaultPrintsStartLineNoWarning(t *testing.T) {
	r := managedTool("abc")
	var out strings.Builder
	err := forward.Run(context.Background(), r,
		forward.Config{Container: "netcage-run-abc-tool", Port: 3001, Bind: "127.0.0.1"},
		forward.IO{Stdout: &out, Stderr: &out})
	if err != nil {
		t.Fatalf("loopback forward into a healthy jail: %v", err)
	}
	printed := out.String()
	if !strings.Contains(printed, "forwarding") || !strings.Contains(printed, "127.0.0.1:3001") {
		t.Fatalf("must print a clear start line naming the loopback bind + port; got: %s", printed)
	}
	if !strings.Contains(printed, "Ctrl-C") {
		t.Fatalf("the start line must tell the user how to stop it (Ctrl-C); got: %s", printed)
	}
	if strings.Contains(strings.ToUpper(printed), "WARNING") {
		t.Fatalf("the loopback default exposes nothing off-box, so it must NOT warn; got: %s", printed)
	}
	// Exactly one socat listener, bound to loopback.
	var socatCalls int
	for _, c := range r.calls {
		if len(c) > 0 && c[0] == "socat" {
			socatCalls++
			if !strings.Contains(strings.Join(c, " "), "bind=127.0.0.1") {
				t.Fatalf("the listener must bind loopback; got: %s", strings.Join(c, " "))
			}
		}
	}
	if socatCalls != 1 {
		t.Fatalf("a healthy forward stands up exactly one socat listener; got %d\ncalls:\n%s", socatCalls, joinAll(r.calls))
	}
}

// TestRun_AllInterfacesWarnsNamingExposure proves the guardrailed anonymity
// opt-in (ADR-0013/ADR-0014): `--bind 0.0.0.0` prints a WARNING naming the
// container, the port, and that ANY LAN host can reach the jailed tool's server,
// BEFORE the forward is stood up.
func TestRun_AllInterfacesWarnsNamingExposure(t *testing.T) {
	r := managedTool("abc")
	var out strings.Builder
	err := forward.Run(context.Background(), r,
		forward.Config{Container: "netcage-run-abc-tool", Port: 3001, Bind: "0.0.0.0"},
		forward.IO{Stdout: &out, Stderr: &out})
	if err != nil {
		t.Fatalf("0.0.0.0 forward into a healthy jail: %v", err)
	}
	printed := out.String()
	if !strings.Contains(strings.ToUpper(printed), "WARNING") {
		t.Fatalf("--bind 0.0.0.0 must print a WARNING; got: %s", printed)
	}
	// The warning must name what it exposes: the container, the port, and the LAN.
	for _, want := range []string{"netcage-run-abc-tool", "3001", "0.0.0.0"} {
		if !strings.Contains(printed, want) {
			t.Fatalf("the warning must name what it exposes (%q); got: %s", want, printed)
		}
	}
	if !strings.Contains(strings.ToUpper(printed), "LAN") {
		t.Fatalf("the warning must say any LAN host can reach the jailed server; got: %s", printed)
	}
}

// TestRun_TeardownLeavesNoResidue proves the lifetime bound: the forward is a
// host process run through the Runner; when Run returns (the socat call
// completes, standing in for Ctrl-C cancelling ctx) there is nothing to unwind -
// no firewall rule was added and no persistent state was written. This asserts
// the ONLY podman calls are the label guard + the running probe + the socat
// relay; no rm/rule/persist call is made on teardown.
func TestRun_TeardownLeavesNoResidue(t *testing.T) {
	r := managedTool("abc")
	var out strings.Builder
	if err := forward.Run(context.Background(), r,
		forward.Config{Container: "netcage-run-abc-tool", Port: 3001, Bind: "127.0.0.1"},
		forward.IO{Stdout: &out, Stderr: &out}); err != nil {
		t.Fatalf("forward: %v", err)
	}
	for _, c := range r.calls {
		if len(c) == 0 {
			continue
		}
		joined := strings.Join(c, " ")
		switch {
		case c[0] == "socat":
			// the relay itself
		case c[0] == "podman" && len(c) > 1 && c[1] == "inspect":
			// the label guard + running probe
		default:
			t.Fatalf("the forward must add no persistent state / firewall rule / rm; unexpected call: %s", joined)
		}
		// Belt-and-braces: no forward call may ever add a firewall/publish rule.
		for _, forbidden := range []string{"iptables", "nft", "--publish", " -p ", "rm "} {
			if strings.Contains(joined, forbidden) {
				t.Fatalf("the forward must add no firewall/publish/rm state; found %q in: %s", forbidden, joined)
			}
		}
	}
}
