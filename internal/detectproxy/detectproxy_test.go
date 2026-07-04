package detectproxy_test

import (
	"encoding/json"
	"net"
	"reflect"
	"strings"
	"testing"

	"github.com/wighawag/netcage/internal/detectproxy"
	"github.com/wighawag/netcage/internal/socks5hfixture"
)

// The provider-label words a false detection must NEVER emit. netcage is an
// anonymity-adjacent tool: a SOCKS proxy does not announce its exit provider, so
// labelling one is a dangerous lie. These are asserted absent from BOTH the human
// text and the JSON contract.
var forbiddenProviderLabels = []string{
	"mullvad", "proton", "protonvpn", "nordvpn", "expressvpn",
	"provider", "label", "vendor", "brand",
}

// TestHandshake_ConfirmsRealSOCKS5AgainstFixture drives the RFC1928 no-auth
// negotiation against the in-process socks5hfixture (NO real Tor): an open port
// that actually speaks SOCKS5 must confirm. This is the "an open port is not
// enough" guarantee at its seam.
func TestHandshake_ConfirmsRealSOCKS5AgainstFixture(t *testing.T) {
	fx := socks5hfixture.New(socks5hfixture.Options{ExitIP: "127.0.0.2"})
	if err := fx.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("fixture start: %v", err)
	}
	defer fx.Close()

	conn, err := net.Dial("tcp", fx.Addr())
	if err != nil {
		t.Fatalf("dial fixture: %v", err)
	}
	defer conn.Close()

	ok, err := detectproxy.Handshake(conn)
	if err != nil {
		t.Fatalf("Handshake against a real SOCKS5 fixture errored: %v", err)
	}
	if !ok {
		t.Fatal("Handshake did not confirm SOCKS5 against the real fixture; an RFC1928 no-auth negotiation should succeed")
	}
}

// TestHandshake_RejectsNonSOCKS5 confirms an open port that answers with garbage
// (a non-SOCKS5 server) is NOT confirmed as SOCKS5: an open port alone is not
// enough.
func TestHandshake_RejectsNonSOCKS5(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		// Read the client's method-negotiation, then reply with a NON-SOCKS5
		// version byte (an HTTP-ish / garbage server), which must not be accepted.
		buf := make([]byte, 8)
		_, _ = c.Read(buf)
		_, _ = c.Write([]byte("HTTP/1.1"))
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	ok, _ := detectproxy.Handshake(conn)
	if ok {
		t.Fatal("Handshake confirmed SOCKS5 against a non-SOCKS5 server; want rejection")
	}
}

// fakeProber is an injected probe result so the pure Probe decision (port list ->
// candidates) is testable without any real socket I/O.
type fakeProber struct {
	open   map[int]bool
	socks5 map[int]bool
	hints  map[int]string
}

func (f fakeProber) Probe(port int) detectproxy.PortResult {
	return detectproxy.PortResult{
		Open:        f.open[port],
		SOCKS5:      f.socks5[port],
		ProcessHint: f.hints[port],
	}
}

// TestProbe_PortListToCandidates asserts the pure decision maps the injected
// per-port probe results onto the canonical candidate list (the three default
// ports, in order), independent of any real socket.
func TestProbe_PortListToCandidates(t *testing.T) {
	pr := fakeProber{
		open:   map[int]bool{9050: true, 9150: false, 1080: true},
		socks5: map[int]bool{9050: true, 9150: false, 1080: false},
		hints:  map[int]string{9050: "a `tor` process is running -> likely Tor"},
	}
	rep := detectproxy.Probe(pr)

	wantPorts := []int{9050, 9150, 1080}
	if len(rep.Candidates) != len(wantPorts) {
		t.Fatalf("got %d candidates, want %d", len(rep.Candidates), len(wantPorts))
	}
	for i, c := range rep.Candidates {
		if c.Port != wantPorts[i] {
			t.Fatalf("candidate %d port = %d, want %d (canonical order)", i, c.Port, wantPorts[i])
		}
	}
	// 9050: open + socks5 + a hedged hint.
	if !rep.Candidates[0].Open || !rep.Candidates[0].SOCKS5 {
		t.Fatalf("9050 candidate = %+v, want open+socks5", rep.Candidates[0])
	}
	if rep.Candidates[0].ProcessHint == "" {
		t.Fatal("9050 hint dropped; the process hint should be carried onto the candidate")
	}
	// 1080: open but NOT confirmed SOCKS5 (an open port alone is not enough).
	if !rep.Candidates[2].Open || rep.Candidates[2].SOCKS5 {
		t.Fatalf("1080 candidate = %+v, want open+not-socks5", rep.Candidates[2])
	}
}

// TestPortHints_HedgedProviderAgnostic asserts a running `tor` process yields a
// WEAK, HEDGED hint on the Tor-conventional ports, and that the hint is
// provider-agnostic (evidence-shaped, never a provider label). No tor process =>
// no hint.
func TestPortHints_HedgedProviderAgnostic(t *testing.T) {
	hints := detectproxy.PortHints([]string{"bash", "tor", "sshd"})
	h, ok := hints[9050]
	if !ok {
		t.Fatal("a running `tor` process should hint port 9050")
	}
	low := strings.ToLower(h)
	if !strings.Contains(low, "likely") {
		t.Fatalf("hint %q should be HEDGED (contain \"likely\"), never a definite claim", h)
	}
	for _, bad := range forbiddenProviderLabels {
		if strings.Contains(low, bad) {
			t.Fatalf("hint %q contains the forbidden provider-label word %q", h, bad)
		}
	}
	if len(detectproxy.PortHints([]string{"bash", "sshd"})) != 0 {
		t.Fatal("no tor process => no hint")
	}
}

// TestReport_SchemaVersionAndJSONShape asserts the --json reuse CONTRACT: a
// versioned envelope with per-candidate {port, open, socks5, processHint?} and an
// overall exitIP?. This is the cross-repo shape anon-pi reuses.
func TestReport_SchemaVersionAndJSONShape(t *testing.T) {
	rep := detectproxy.Report{
		SchemaVersion: detectproxy.SchemaVersion,
		Candidates: []detectproxy.Candidate{
			{Port: 9050, Open: true, SOCKS5: true, ProcessHint: "a `tor` process is running -> likely Tor"},
			{Port: 9150, Open: false, SOCKS5: false},
		},
		ExitIP: "203.0.113.7",
	}
	data, err := json.Marshal(rep)
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	var generic map[string]any
	if err := json.Unmarshal(data, &generic); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	if _, ok := generic["schemaVersion"]; !ok {
		t.Fatalf("JSON missing schemaVersion; got keys %v", keysOf(generic))
	}
	if _, ok := generic["candidates"]; !ok {
		t.Fatalf("JSON missing candidates; got keys %v", keysOf(generic))
	}
	if _, ok := generic["exitIP"]; !ok {
		t.Fatalf("JSON missing exitIP when set; got keys %v", keysOf(generic))
	}

	cands, _ := generic["candidates"].([]any)
	if len(cands) != 2 {
		t.Fatalf("got %d candidates in JSON, want 2", len(cands))
	}
	c0, _ := cands[0].(map[string]any)
	for _, k := range []string{"port", "open", "socks5", "processHint"} {
		if _, ok := c0[k]; !ok {
			t.Fatalf("candidate JSON missing %q; got keys %v", k, keysOf(c0))
		}
	}
	// A candidate with no hint OMITS processHint (it is optional).
	c1, _ := cands[1].(map[string]any)
	if _, ok := c1["processHint"]; ok {
		t.Fatalf("candidate with no hint should OMIT processHint, got %v", keysOf(c1))
	}
}

// TestReport_ExitIPOmittedWhenAbsent confirms exitIP is optional: with no exit-IP
// evidence it is absent from the JSON, not an empty string.
func TestReport_ExitIPOmittedWhenAbsent(t *testing.T) {
	rep := detectproxy.Report{SchemaVersion: detectproxy.SchemaVersion}
	data, err := json.Marshal(rep)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var generic map[string]any
	if err := json.Unmarshal(data, &generic); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := generic["exitIP"]; ok {
		t.Fatal("exitIP should be OMITTED when there is no exit-IP evidence")
	}
}

// TestSchema_HasNoProviderFieldByConstruction is the STRUCTURAL honesty
// guarantee: the JSON schema has NO provider/label field. It walks the Go struct
// types (the contract's source of truth) and asserts no field name or JSON tag is
// a provider label. This makes never-labelling-the-provider a property of the
// SHAPE, not merely a runtime rule.
func TestSchema_HasNoProviderFieldByConstruction(t *testing.T) {
	for _, typ := range []reflect.Type{
		reflect.TypeOf(detectproxy.Report{}),
		reflect.TypeOf(detectproxy.Candidate{}),
	} {
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			name := strings.ToLower(f.Name)
			tag := strings.ToLower(f.Tag.Get("json"))
			for _, bad := range forbiddenProviderLabels {
				if strings.Contains(name, bad) || strings.Contains(tag, bad) {
					t.Fatalf("%s has a provider-label field %q (json %q); the schema must NEVER carry a provider/label field", typ.Name(), f.Name, f.Tag.Get("json"))
				}
			}
		}
	}
}

// TestHuman_EvidenceOnlyNeverLabelsProvider asserts the human-readable findings
// present EVIDENCE ONLY (ports, handshake result, exit IP, weak hedged hints) and
// NEVER a provider label, across a representative report.
func TestHuman_EvidenceOnlyNeverLabelsProvider(t *testing.T) {
	rep := detectproxy.Report{
		SchemaVersion: detectproxy.SchemaVersion,
		Candidates: []detectproxy.Candidate{
			{Port: 9050, Open: true, SOCKS5: true, ProcessHint: "a `tor` process is running -> likely Tor"},
			{Port: 9150, Open: false, SOCKS5: false},
			{Port: 1080, Open: true, SOCKS5: false},
		},
		ExitIP: "203.0.113.7",
	}
	out := strings.ToLower(rep.Human())
	for _, bad := range forbiddenProviderLabels {
		if strings.Contains(out, bad) {
			t.Fatalf("human findings contain the forbidden provider-label word %q; detection must present evidence only:\n%s", bad, rep.Human())
		}
	}
	// It DOES present the evidence.
	if !strings.Contains(out, "9050") || !strings.Contains(out, "203.0.113.7") {
		t.Fatalf("human findings should present the evidence (ports, exit IP):\n%s", rep.Human())
	}
}

// keysOf is a small helper for readable failure messages.
func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
