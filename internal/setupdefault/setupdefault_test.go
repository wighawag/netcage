package setupdefault_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/wighawag/netcage/internal/cli"
	"github.com/wighawag/netcage/internal/detectproxy"
	"github.com/wighawag/netcage/internal/setupdefault"
)

// These tests own the PURE decision logic of setup-default (choice handling, the
// credential-refusal, the reconfigure pre-fill, the warning text) with the impure
// prompt / detect / verify / write I/O behind injectable fakes: NO real podman,
// NO real stdin, NO disk write. The credential-free and 0600 file invariants at
// the writer are covered in internal/cli's config_write_test.go (the single
// writer); here we prove setup-default DRIVES them correctly.

// --- fakes -------------------------------------------------------------------

// scriptPrompter replays scripted Ask / Confirm answers in order, so a test drives
// the interactive flow deterministically. Overrun (more prompts than scripted)
// returns io-EOF-shaped errors so a test notices an unexpected extra prompt.
type scriptPrompter struct {
	asks     []string
	confirms []bool
	askI     int
	confI    int
	askLog   []string
	confLog  []string
}

func (s *scriptPrompter) Ask(prompt, def string) (string, error) {
	s.askLog = append(s.askLog, prompt)
	if s.askI >= len(s.asks) {
		return "", errors.New("unexpected extra Ask (stdin exhausted)")
	}
	a := s.asks[s.askI]
	s.askI++
	return a, nil
}

func (s *scriptPrompter) Confirm(prompt string, def bool) (bool, error) {
	s.confLog = append(s.confLog, prompt)
	if s.confI >= len(s.confirms) {
		return false, errors.New("unexpected extra Confirm (stdin exhausted)")
	}
	c := s.confirms[s.confI]
	s.confI++
	return c, nil
}

// fixedDetector returns a canned detect-proxy Report (no real socket probe).
type fixedDetector struct{ rep detectproxy.Report }

func (f fixedDetector) Detect() detectproxy.Report { return f.rep }

// fakeVerifier returns a fixed exit IP (or an error) for any proxy, so the verify
// step is exercised with no podman. It records the proxy it was asked to verify.
type fakeVerifier struct {
	ip    string
	err   error
	asked []string
}

func (f *fakeVerifier) ExitIP(proxy cli.ProxyConfig) (string, error) {
	f.asked = append(f.asked, proxy.Address())
	return f.ip, f.err
}

// recordingWriter captures what would be persisted (no disk). It can be
// configured to REFUSE (returning ErrCredentialedProxyNotPersisted) for the first
// N calls, to exercise the credential-refusal loop.
type recordingWriter struct {
	refuseCredentialed bool
	writes             []writeCall
}

type writeCall struct {
	proxyURL    string
	allowDirect []string
}

func (w *recordingWriter) Write(proxyURL string, allowDirect []string) error {
	// Mirror the real writer's credential refusal so the flow's loop is exercised
	// end-to-end without touching cli.WriteConfig's disk path.
	if w.refuseCredentialed {
		if p, err := cli.ParseProxy(proxyURL); err == nil && (p.Username != "" || p.Password != "") {
			return cli.ErrCredentialedProxyNotPersisted
		}
	}
	w.writes = append(w.writes, writeCall{proxyURL: proxyURL, allowDirect: allowDirect})
	return nil
}

// captureConsole collects printed output for assertions.
type captureConsole struct{ b strings.Builder }

func (c *captureConsole) Printf(format string, args ...any) {
	c.b.WriteString(fmt.Sprintf(format, args...))
}

// confirmedReport builds a detect-proxy Report with the given ports marked
// confirmed SOCKS5.
func confirmedReport(ports ...int) detectproxy.Report {
	rep := detectproxy.Report{SchemaVersion: detectproxy.SchemaVersion}
	for _, p := range ports {
		rep.Candidates = append(rep.Candidates, detectproxy.Candidate{Port: p, Open: true, SOCKS5: true})
	}
	return rep
}

// --- NormalizeProxyInput (pure) ----------------------------------------------

func TestNormalizeProxyInput_BareHostPortDefaultsSocks5h(t *testing.T) {
	got, err := setupdefault.NormalizeProxyInput("127.0.0.1:9050")
	if err != nil {
		t.Fatalf("NormalizeProxyInput: %v", err)
	}
	if got != "socks5h://127.0.0.1:9050" {
		t.Fatalf("got %q, want socks5h://127.0.0.1:9050 (a bare host:port defaults to socks5h)", got)
	}
}

func TestNormalizeProxyInput_FullSocks5hURLAccepted(t *testing.T) {
	got, err := setupdefault.NormalizeProxyInput("  socks5h://10.0.0.1:1080  ")
	if err != nil {
		t.Fatalf("NormalizeProxyInput: %v", err)
	}
	if got != "socks5h://10.0.0.1:1080" {
		t.Fatalf("got %q, want the trimmed socks5h URL", got)
	}
}

func TestNormalizeProxyInput_RejectsSocks5(t *testing.T) {
	_, err := setupdefault.NormalizeProxyInput("socks5://127.0.0.1:9050")
	if err == nil {
		t.Fatal("socks5:// accepted; the input path must enforce socks5h like the flag")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "socks5h") {
		t.Fatalf("rejection %q should mention socks5h", err)
	}
}

func TestNormalizeProxyInput_EmptyRejected(t *testing.T) {
	if _, err := setupdefault.NormalizeProxyInput("   "); err == nil {
		t.Fatal("empty input accepted; want a rejection")
	}
}

// --- WarningText (pure) ------------------------------------------------------

func TestWarningText_StatesTheSilentDefaultTradeoff(t *testing.T) {
	w := setupdefault.WarningText("socks5h://127.0.0.1:9050")
	low := strings.ToLower(w)
	// It must name the proxy, warn that a bare run uses it silently, and point at
	// verify as the on-demand proof.
	if !strings.Contains(w, "socks5h://127.0.0.1:9050") {
		t.Fatalf("warning must name the proxy being installed:\n%s", w)
	}
	if !strings.Contains(low, "default") || !strings.Contains(low, "no per-run") {
		t.Fatalf("warning must state the silent-default (no per-run reminder) tradeoff:\n%s", w)
	}
	if !strings.Contains(low, "netcage verify") {
		t.Fatalf("warning must point at `netcage verify` for the on-demand proof:\n%s", w)
	}
	// Honesty: it must NEVER name a provider.
	assertNoProviderLabel(t, w)
}

// --- Run: the driven decision flow -------------------------------------------

// TestRun_DetectChooseVerifyWarnWrite is the headline happy path: detect a proxy,
// accept the detected one, verify shows an exit IP, the warning fires, and the
// choice is persisted credential-free.
func TestRun_DetectChooseVerifyWarnWrite(t *testing.T) {
	pr := &scriptPrompter{
		asks:     []string{"127.0.0.1:9050"}, // choose/enter the proxy
		confirms: []bool{true},               // confirm the write
	}
	ver := &fakeVerifier{ip: "203.0.113.9"}
	w := &recordingWriter{}
	con := &captureConsole{}
	err := setupdefault.Run(setupdefault.Options{
		Prompter:   pr,
		Detector:   fixedDetector{rep: confirmedReport(9050)},
		Verifier:   ver,
		Writer:     w,
		Console:    con,
		ConfigPath: "/tmp/x/netcage/config.json",
		Existing:   cli.ConfigView{}, // first-time setup
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(w.writes) != 1 || w.writes[0].proxyURL != "socks5h://127.0.0.1:9050" {
		t.Fatalf("writes = %+v, want one write of socks5h://127.0.0.1:9050", w.writes)
	}
	out := con.b.String()
	if !strings.Contains(out, "203.0.113.9") {
		t.Fatalf("output should show the verified exit IP as evidence:\n%s", out)
	}
	if !strings.Contains(strings.ToLower(out), "default") || !strings.Contains(strings.ToLower(out), "no per-run") {
		t.Fatalf("output should include the one-time tradeoff warning:\n%s", out)
	}
	assertNoProviderLabel(t, out)
}

// TestRun_RefusesCredentialedProxyThenAcceptsCleanOne proves the credential
// refusal loop: a user:pass@ entry is refused with a redirect, then a clean
// re-entry persists.
func TestRun_RefusesCredentialedProxyThenAcceptsCleanOne(t *testing.T) {
	pr := &scriptPrompter{
		asks: []string{
			"socks5h://user:pass@127.0.0.1:9050", // refused at persist
			"127.0.0.1:9050",                     // clean re-entry
		},
		confirms: []bool{true, true}, // confirm-write for each attempt
	}
	w := &recordingWriter{refuseCredentialed: true}
	con := &captureConsole{}
	err := setupdefault.Run(setupdefault.Options{
		Prompter:   pr,
		Detector:   fixedDetector{rep: confirmedReport(9050)},
		Verifier:   &fakeVerifier{ip: "203.0.113.9"},
		Writer:     w,
		Console:    con,
		ConfigPath: "/tmp/x/netcage/config.json",
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Only the clean proxy was persisted; the credentialed one never reached disk.
	if len(w.writes) != 1 || w.writes[0].proxyURL != "socks5h://127.0.0.1:9050" {
		t.Fatalf("writes = %+v, want ONLY the clean socks5h://127.0.0.1:9050", w.writes)
	}
	out := con.b.String()
	if !strings.Contains(strings.ToLower(out), "credential") {
		t.Fatalf("output should surface the credential refusal:\n%s", out)
	}
	if !strings.Contains(strings.ToLower(out), "netcage_proxy") && !strings.Contains(out, "--proxy") {
		t.Fatalf("credential refusal should redirect to env/flag:\n%s", out)
	}
}

// TestRun_ReconfigurePrefillsCurrentAndConfirmsOverwrite proves the re-runnable /
// reconfigure path: the current proxy is pre-filled (bare Enter accepts it), and
// the flow CONFIRMS before overwriting an existing config (never clobbers
// silently).
func TestRun_ReconfigurePrefillsCurrentAndConfirmsOverwrite(t *testing.T) {
	pr := &scriptPrompter{
		asks:     []string{""}, // bare Enter => accept the pre-filled current proxy
		confirms: []bool{true}, // confirm the overwrite
	}
	w := &recordingWriter{}
	con := &captureConsole{}
	err := setupdefault.Run(setupdefault.Options{
		Prompter:   pr,
		Detector:   fixedDetector{rep: confirmedReport()}, // nothing detected this time
		Verifier:   &fakeVerifier{ip: "203.0.113.9"},
		Writer:     w,
		Console:    con,
		ConfigPath: "/tmp/x/netcage/config.json",
		Existing:   cli.ConfigView{Present: true, ProxyURL: "socks5h://127.0.0.1:1080", AllowDirect: []string{"10.0.0.0/8:443"}},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(w.writes) != 1 || w.writes[0].proxyURL != "socks5h://127.0.0.1:1080" {
		t.Fatalf("writes = %+v, want the pre-filled current proxy persisted", w.writes)
	}
	// The existing allow list is carried through a proxy reconfigure.
	if len(w.writes[0].allowDirect) != 1 || w.writes[0].allowDirect[0] != "10.0.0.0/8:443" {
		t.Fatalf("allow list = %v, want the existing list carried through", w.writes[0].allowDirect)
	}
	// The overwrite confirm prompt must have fired (never clobber silently).
	joined := strings.ToLower(strings.Join(pr.confLog, " | "))
	if !strings.Contains(joined, "overwrite") {
		t.Fatalf("confirm prompts = %v, want an overwrite confirmation before clobbering", pr.confLog)
	}
	// The current value was shown for pre-fill.
	if !strings.Contains(strings.Join(pr.askLog, " "), "current: socks5h://127.0.0.1:1080") {
		t.Fatalf("ask prompts = %v, want the current value shown for pre-fill", pr.askLog)
	}
}

// TestRun_DeclineOverwriteWritesNothing proves the never-clobber-silently
// guarantee: declining the overwrite confirm leaves the existing config unchanged
// (no write).
func TestRun_DeclineOverwriteWritesNothing(t *testing.T) {
	pr := &scriptPrompter{
		asks:     []string{"127.0.0.1:9050"},
		confirms: []bool{false}, // decline the overwrite
	}
	w := &recordingWriter{}
	con := &captureConsole{}
	err := setupdefault.Run(setupdefault.Options{
		Prompter:   pr,
		Detector:   fixedDetector{rep: confirmedReport(9050)},
		Verifier:   &fakeVerifier{ip: "203.0.113.9"},
		Writer:     w,
		Console:    con,
		ConfigPath: "/tmp/x/netcage/config.json",
		Existing:   cli.ConfigView{Present: true, ProxyURL: "socks5h://127.0.0.1:1080"},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(w.writes) != 0 {
		t.Fatalf("writes = %+v, want NONE (declined overwrite must not clobber)", w.writes)
	}
}

// TestRun_VerifyFailureAsksBeforePersisting proves an unverifiable proxy (no
// podman / offline) surfaces "could not verify" and asks before persisting,
// rather than silently claiming a false exit IP.
func TestRun_VerifyFailureAsksBeforePersisting(t *testing.T) {
	pr := &scriptPrompter{
		asks:     []string{"127.0.0.1:9050"},
		confirms: []bool{true, true}, // (1) persist anyway despite no verify, (2) confirm write
	}
	w := &recordingWriter{}
	con := &captureConsole{}
	err := setupdefault.Run(setupdefault.Options{
		Prompter:   pr,
		Detector:   fixedDetector{rep: confirmedReport(9050)},
		Verifier:   &fakeVerifier{err: errors.New("no podman")},
		Writer:     w,
		Console:    con,
		ConfigPath: "/tmp/x/netcage/config.json",
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !strings.Contains(strings.ToLower(con.b.String()), "could not verify") {
		t.Fatalf("output should surface the unverifiable evidence, not a false exit IP:\n%s", con.b.String())
	}
	if len(w.writes) != 1 {
		t.Fatalf("writes = %+v, want one write after the user opted to persist anyway", w.writes)
	}
}

// assertNoProviderLabel asserts the output never names a concrete exit PROVIDER
// (the load-bearing honesty constraint: detection is evidence-only). "likely Tor"
// is an allowed HEDGED process hint from detect-proxy, not a provider claim, so we
// only forbid the un-hedged provider brand names.
func assertNoProviderLabel(t *testing.T, out string) {
	t.Helper()
	for _, brand := range []string{"Mullvad", "Proton", "NordVPN", "you are on Tor", "you are on Mullvad"} {
		if strings.Contains(out, brand) {
			t.Fatalf("output labels a provider (%q); detection must be evidence-only:\n%s", brand, out)
		}
	}
}
