package ports_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/wighawag/netcage/internal/jail"
	"github.com/wighawag/netcage/internal/ports"
)

// recordRunner records every podman invocation the ports orchestration makes and
// answers the label/role/run-id + .State.Running inspects from a scripted table,
// and returns fixture /proc/net/tcp* bodies for the `cat` reads, so the whole
// wiring (label guard, running check, SIDECAR-exec target, rendering) is
// unit-testable WITHOUT a real podman or a real container (mirrors forward's
// recordRunner). procV4/procV6 are the bodies the `podman exec <sidecar> cat
// /proc/net/tcp{,6}` calls return.
type recordRunner struct {
	calls   [][]string
	labels  map[string]map[string]string
	running map[string]bool
	procV4  string
	procV6  string
}

func (r *recordRunner) Run(_ context.Context, spec jail.RunSpec) (string, string, error) {
	r.calls = append(r.calls, append([]string{spec.Name}, spec.Args...))
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
	// The `podman exec <sidecar> cat /proc/net/tcp*` reads: return the fixture body
	// matching the requested file.
	if len(spec.Args) >= 1 && spec.Args[0] == "exec" {
		joined := strings.Join(spec.Args, " ")
		switch {
		case strings.HasSuffix(joined, "/proc/net/tcp6"):
			return r.procV6, "", nil
		case strings.HasSuffix(joined, "/proc/net/tcp"):
			return r.procV4, "", nil
		}
	}
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

// The two live-observed jail rows: the netcage DNS forwarder on 127.0.0.1:53
// (loopback) and a server on 0.0.0.0:3001 (wildcard).
const v4Header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode"
const v6Header = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode"

func v4Row(sl, localAddr, st string) string {
	return "   " + sl + ": " + localAddr + " 00000000:0000 " + st + " 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0"
}

func fixtureV4() string {
	return v4Header + "\n" +
		v4Row("0", "0100007F:0035", "0A") + "\n" + // 127.0.0.1:53   LISTEN (netcage DNS)
		v4Row("1", "00000000:0BB9", "0A") + "\n" // 0.0.0.0:3001   LISTEN
}

// managedTool builds a healthy-jail label+state table for a netcage-managed tool
// run, wired with fixture /proc/net/tcp bodies.
func managedTool(runID, procV4, procV6 string) *recordRunner {
	tool := "netcage-run-" + runID + "-tool"
	sidecar := "netcage-run-" + runID + "-sidecar"
	return &recordRunner{
		labels: map[string]map[string]string{
			tool: {jail.LabelManaged: "true", jail.LabelRole: jail.RoleTool, jail.LabelRunID: runID},
		},
		running: map[string]bool{tool: true, sidecar: true},
		procV4:  procV4,
		procV6:  procV6,
	}
}

// TestRun_RefusesNonNetcageContainer: a container without the netcage.managed
// label is REFUSED loudly and NO /proc read is ever attempted.
func TestRun_RefusesNonNetcageContainer(t *testing.T) {
	r := &recordRunner{labels: map[string]map[string]string{"some-random-container": {}}}
	var out strings.Builder
	err := ports.Run(context.Background(), r,
		ports.Config{Container: "some-random-container"},
		ports.IO{Stdout: &out, Stderr: &out})
	if err == nil {
		t.Fatal("enumerating a non-netcage container must be REFUSED")
	}
	if !strings.Contains(err.Error(), "not a netcage-managed container") {
		t.Fatalf("the refusal must name the reason; got: %v", err)
	}
	for _, c := range r.calls {
		if strings.Contains(strings.Join(c, " "), "/proc/net/tcp") {
			t.Fatalf("a refused ports must NOT read /proc; calls:\n%s", joinAll(r.calls))
		}
	}
}

// TestRun_RefusesStoppedJail: a stopped jail is refused loudly (nothing to
// enumerate), pointing the user at `netcage start`, and no /proc read is made.
func TestRun_RefusesStoppedJail(t *testing.T) {
	r := managedTool("abc", fixtureV4(), "")
	r.running["netcage-run-abc-tool"] = false
	r.running["netcage-run-abc-sidecar"] = false
	var out strings.Builder
	err := ports.Run(context.Background(), r,
		ports.Config{Container: "netcage-run-abc-tool"},
		ports.IO{Stdout: &out, Stderr: &out})
	if err == nil {
		t.Fatal("enumerating a stopped jail must be REFUSED loudly")
	}
	if !strings.Contains(err.Error(), "netcage start") {
		t.Fatalf("the refusal must point the user at `netcage start`; got: %v", err)
	}
	for _, c := range r.calls {
		if strings.Contains(strings.Join(c, " "), "/proc/net/tcp") {
			t.Fatalf("a refused ports must NOT read /proc; calls:\n%s", joinAll(r.calls))
		}
	}
}

// TestRun_ReadsProcViaSidecarNotTool: the /proc/net/tcp* reads exec into the
// SIDECAR (netcage-pinned image, shares the netns), NEVER the arbitrary tool
// image (which may lack cat / any userspace tool). This is the image-independence
// guarantee (ADR-0006, the forward-connector lesson).
func TestRun_ReadsProcViaSidecarNotTool(t *testing.T) {
	r := managedTool("abc", fixtureV4(), "")
	var out strings.Builder
	if err := ports.Run(context.Background(), r,
		ports.Config{Container: "netcage-run-abc-tool"},
		ports.IO{Stdout: &out, Stderr: &out}); err != nil {
		t.Fatalf("ports into a healthy jail: %v", err)
	}
	var readV4, readV6 bool
	for _, c := range r.calls {
		joined := strings.Join(c, " ")
		if strings.Contains(joined, "/proc/net/tcp") {
			if !strings.Contains(joined, "exec netcage-run-abc-sidecar") {
				t.Fatalf("the /proc read must exec into the SIDECAR, not the tool; got: %s", joined)
			}
			if strings.Contains(joined, "netcage-run-abc-tool") {
				t.Fatalf("the /proc read must NOT exec into the tool image (may lack cat); got: %s", joined)
			}
			if strings.HasSuffix(joined, "/proc/net/tcp6") {
				readV6 = true
			} else if strings.HasSuffix(joined, "/proc/net/tcp") {
				readV4 = true
			}
		}
	}
	if !readV4 || !readV6 {
		t.Fatalf("ports must read BOTH /proc/net/tcp and /proc/net/tcp6 via the sidecar; v4=%v v6=%v\ncalls:\n%s", readV4, readV6, joinAll(r.calls))
	}
}

// TestRun_HumanTableShowsListenersIncludingDNS: the default output is a human
// table naming ADDRESS / PORT / SCOPE, and netcage's own 127.0.0.1:53 DNS
// forwarder is SHOWN (not filtered), so the list never hides a real listener.
func TestRun_HumanTableShowsListenersIncludingDNS(t *testing.T) {
	r := managedTool("abc", fixtureV4(), "")
	var out strings.Builder
	if err := ports.Run(context.Background(), r,
		ports.Config{Container: "netcage-run-abc-tool"},
		ports.IO{Stdout: &out, Stderr: &out}); err != nil {
		t.Fatalf("ports: %v", err)
	}
	printed := out.String()
	for _, want := range []string{"ADDRESS", "PORT", "SCOPE", "127.0.0.1", "53", "0.0.0.0", "3001"} {
		if !strings.Contains(printed, want) {
			t.Fatalf("the human table must contain %q; got:\n%s", want, printed)
		}
	}
	// The DNS :53 listener is netcage-internal; it must be shown, not omitted.
	if !strings.Contains(printed, "53") {
		t.Fatalf("netcage's own DNS forwarder on :53 must be shown, not filtered; got:\n%s", printed)
	}
}

// TestRun_JSONEmitsReuseContract: --json emits the documented array
// [{address, port, loopbackOnly}] with IPv4 + IPv6 in ONE array, and nothing
// else on stdout (no human table), so a consumer can parse it directly.
func TestRun_JSONEmitsReuseContract(t *testing.T) {
	v6 := v6Header + "\n" +
		"   0: 00000000000000000000000001000000:0035 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1 0000000000000000 100 0 0 10 0" + "\n"
	r := managedTool("abc", fixtureV4(), v6)
	var out strings.Builder
	if err := ports.Run(context.Background(), r,
		ports.Config{Container: "netcage-run-abc-tool", JSON: true},
		ports.IO{Stdout: &out, Stderr: &out}); err != nil {
		t.Fatalf("ports --json: %v", err)
	}
	printed := strings.TrimSpace(out.String())
	if strings.Contains(printed, "ADDRESS") || strings.Contains(printed, "SCOPE") {
		t.Fatalf("--json must emit ONLY the machine array, not the human table; got:\n%s", printed)
	}
	var got []map[string]any
	if err := json.Unmarshal([]byte(printed), &got); err != nil {
		t.Fatalf("--json output must be a valid JSON array; err=%v; got:\n%s", err, printed)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 listeners (v4 x2 + v6 x1) in one array; got %d: %s", len(got), printed)
	}
	// The documented field names must be exactly address / port / loopbackOnly.
	for _, o := range got {
		for _, key := range []string{"address", "port", "loopbackOnly"} {
			if _, ok := o[key]; !ok {
				t.Fatalf("each entry must carry %q (the reuse contract); got: %v", key, o)
			}
		}
	}
	// IPv4 and IPv6 must appear in the SAME array (v4 127.0.0.1:53 and v6 ::1:53 are
	// both present alongside the v4 0.0.0.0:3001).
	var sawV4Loopback, sawV6Loopback, sawWildcard bool
	for _, o := range got {
		switch o["address"] {
		case "127.0.0.1":
			sawV4Loopback = true
		case "::1":
			sawV6Loopback = true
		case "0.0.0.0":
			sawWildcard = true
		}
	}
	if !sawV4Loopback || !sawV6Loopback || !sawWildcard {
		t.Fatalf("v4 + v6 must share one array (127.0.0.1, ::1, 0.0.0.0 all present); got: %s", printed)
	}
}

// TestRun_NoEgressNoFirewallRule: ports only READS /proc via the sidecar; it must
// never run socat / add a firewall/publish rule / egress.
func TestRun_NoEgressNoFirewallRule(t *testing.T) {
	r := managedTool("abc", fixtureV4(), "")
	var out strings.Builder
	if err := ports.Run(context.Background(), r,
		ports.Config{Container: "netcage-run-abc-tool"},
		ports.IO{Stdout: &out, Stderr: &out}); err != nil {
		t.Fatalf("ports: %v", err)
	}
	for _, c := range r.calls {
		joined := strings.Join(c, " ")
		for _, forbidden := range []string{"socat", "iptables", "nft", "--publish", " -p ", "OUTPUT", "TCP-LISTEN"} {
			if strings.Contains(joined, forbidden) {
				t.Fatalf("ports must do NO egress / add NO rule; found %q in: %s", forbidden, joined)
			}
		}
	}
}
