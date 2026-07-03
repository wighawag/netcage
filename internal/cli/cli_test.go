package cli_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/wighawag/netcage/internal/cli"
)

func TestParseProxy_FullSocks5hWithAuth(t *testing.T) {
	p, err := cli.ParseProxy("socks5h://user:pass@host.example:1080")
	if err != nil {
		t.Fatalf("ParseProxy: %v", err)
	}
	if p.Host != "host.example" || p.Port != "1080" {
		t.Fatalf("host:port = %s:%s, want host.example:1080", p.Host, p.Port)
	}
	if p.Username != "user" || p.Password != "pass" {
		t.Fatalf("auth = %s:%s, want user:pass", p.Username, p.Password)
	}
	if got := p.Address(); got != "host.example:1080" {
		t.Fatalf("Address() = %q, want host.example:1080", got)
	}
}

func TestParseProxy_NoAuth(t *testing.T) {
	p, err := cli.ParseProxy("socks5h://127.0.0.1:9050")
	if err != nil {
		t.Fatalf("ParseProxy: %v", err)
	}
	if p.Username != "" || p.Password != "" {
		t.Fatalf("expected no auth, got %s:%s", p.Username, p.Password)
	}
	if p.Address() != "127.0.0.1:9050" {
		t.Fatalf("Address() = %q", p.Address())
	}
}

func TestParseProxy_RejectsPlainSocks5AsLeak(t *testing.T) {
	_, err := cli.ParseProxy("socks5://127.0.0.1:9050")
	if err == nil {
		t.Fatal("plain socks5:// accepted; want rejection (it is a DNS leak)")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "socks5h") {
		t.Fatalf("error %q should mention socks5h (the required scheme)", err)
	}
}

func TestParseProxy_RejectsOtherSchemes(t *testing.T) {
	for _, raw := range []string{"http://h:1", "https://h:1", "socks4://h:1", "h:1", ""} {
		if _, err := cli.ParseProxy(raw); err == nil {
			t.Fatalf("scheme %q accepted; want rejection", raw)
		}
	}
}

// noEnv is an env lookup that reports every variable unset, so a test drives the
// flag-only path deterministically regardless of the real process environment.
func noEnv(string) (string, bool) { return "", false }

// envWith returns an env lookup that resolves exactly the given variables.
func envWith(vars map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) {
		v, ok := vars[k]
		return v, ok
	}
}

// TestParse_RunPositionalPodmanGrammar is the headline acceptance case: pure
// podman-native positional grammar with a curated allow-list of flags, NO
// --image flag and NO -- separator. The image is the first positional; the tool
// argv is the remaining positionals.
func TestParse_RunPositionalPodmanGrammar(t *testing.T) {
	cmd, err := cli.ParseWithEnv([]string{
		"run",
		"-it",
		"-v", "a:b",
		"-w", "/work",
		"-e", "K=V",
		"-u", "1000",
		"--proxy", "socks5h://127.0.0.1:9050",
		"nuclei:latest",
		"nuclei", "-u", "https://target",
	}, noEnv)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cmd.Name != "run" {
		t.Fatalf("Name = %q, want run", cmd.Name)
	}
	// A tagged reference (nuclei:latest) is recognised as the image; the remaining
	// positionals are the tool argv. A BARE token (`nuclei`) would instead be taken
	// as a command with the default image injected (the default-dev-image
	// disambiguation; see internal/cli/defaults_test.go).
	if cmd.Image != "nuclei:latest" {
		t.Fatalf("Image = %q, want nuclei:latest (first positional, image-form)", cmd.Image)
	}
	if cmd.Proxy.Address() != "127.0.0.1:9050" {
		t.Fatalf("Proxy = %q", cmd.Proxy.Address())
	}
	if !cmd.Interactive || !cmd.TTY {
		t.Fatalf("-it should set Interactive=%v TTY=%v, want both true", cmd.Interactive, cmd.TTY)
	}
	if strings.Join(cmd.Mounts, " ") != "a:b" {
		t.Fatalf("Mounts = %v, want [a:b]", cmd.Mounts)
	}
	if cmd.Workdir != "/work" {
		t.Fatalf("Workdir = %q, want /work", cmd.Workdir)
	}
	if strings.Join(cmd.Env, " ") != "K=V" {
		t.Fatalf("Env = %v, want [K=V]", cmd.Env)
	}
	if cmd.User != "1000" {
		t.Fatalf("User = %q, want 1000", cmd.User)
	}
	wantArgv := []string{"nuclei", "-u", "https://target"}
	if strings.Join(cmd.ToolArgv, " ") != strings.Join(wantArgv, " ") {
		t.Fatalf("ToolArgv = %v, want %v", cmd.ToolArgv, wantArgv)
	}
}

// TestParse_SeparateInteractiveTTYFlags checks -i and -t as separate flags, and
// -ti as the combined alias.
func TestParse_SeparateInteractiveTTYFlags(t *testing.T) {
	cmd, err := cli.ParseWithEnv([]string{
		"run", "-i", "-t", "--proxy", "socks5h://h:1", "img", "sh",
	}, noEnv)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !cmd.Interactive || !cmd.TTY {
		t.Fatalf("-i -t should set both, got Interactive=%v TTY=%v", cmd.Interactive, cmd.TTY)
	}
	cmd2, err := cli.ParseWithEnv([]string{
		"run", "-ti", "--proxy", "socks5h://h:1", "img", "sh",
	}, noEnv)
	if err != nil {
		t.Fatalf("Parse -ti: %v", err)
	}
	if !cmd2.Interactive || !cmd2.TTY {
		t.Fatalf("-ti should set both, got Interactive=%v TTY=%v", cmd2.Interactive, cmd2.TTY)
	}
}

// TestParse_AllowListEqualsForms checks that every value-taking allow-list flag
// accepts both `--flag value` and `--flag=value` forms.
func TestParse_AllowListEqualsForms(t *testing.T) {
	cmd, err := cli.ParseWithEnv([]string{
		"run",
		"--volume=a:b",
		"--workdir=/w",
		"--env=K=V",
		"--user=42",
		"--entrypoint=/bin/sh",
		"--proxy=socks5h://h:1",
		"img:latest", "cmd",
	}, noEnv)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if strings.Join(cmd.Mounts, " ") != "a:b" {
		t.Fatalf("Mounts = %v", cmd.Mounts)
	}
	if cmd.Workdir != "/w" {
		t.Fatalf("Workdir = %q", cmd.Workdir)
	}
	if strings.Join(cmd.Env, " ") != "K=V" {
		t.Fatalf("Env = %v", cmd.Env)
	}
	if cmd.User != "42" {
		t.Fatalf("User = %q", cmd.User)
	}
	if cmd.Entrypoint != "/bin/sh" {
		t.Fatalf("Entrypoint = %q", cmd.Entrypoint)
	}
	if cmd.Image != "img:latest" {
		t.Fatalf("Image = %q", cmd.Image)
	}
	if strings.Join(cmd.ToolArgv, " ") != "cmd" {
		t.Fatalf("ToolArgv = %v", cmd.ToolArgv)
	}
}

// TestParse_MultipleEnvAndVolume checks the repeatable flags accumulate.
func TestParse_MultipleEnvAndVolume(t *testing.T) {
	cmd, err := cli.ParseWithEnv([]string{
		"run",
		"-v", "/host/out:/out",
		"--volume", "/host/words:/words:ro",
		"-e", "A=1",
		"--env", "B=2",
		"--proxy", "socks5h://127.0.0.1:9050",
		"ffuf:latest", "ffuf", "-o", "/out/r.json",
	}, noEnv)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	wantMounts := []string{"/host/out:/out", "/host/words:/words:ro"}
	if strings.Join(cmd.Mounts, " ") != strings.Join(wantMounts, " ") {
		t.Fatalf("Mounts = %v, want %v", cmd.Mounts, wantMounts)
	}
	wantEnv := []string{"A=1", "B=2"}
	if strings.Join(cmd.Env, " ") != strings.Join(wantEnv, " ") {
		t.Fatalf("Env = %v, want %v", cmd.Env, wantEnv)
	}
	wantArgv := []string{"ffuf", "-o", "/out/r.json"}
	if strings.Join(cmd.ToolArgv, " ") != strings.Join(wantArgv, " ") {
		t.Fatalf("ToolArgv = %v, want %v", cmd.ToolArgv, wantArgv)
	}
}

// TestParse_OptionalDoubleDashEndOfFlags checks that a standalone `--` before the
// image is accepted as an optional end-of-flags marker (a podman nicety), with
// the image and argv taken from the positionals after it.
func TestParse_OptionalDoubleDashEndOfFlags(t *testing.T) {
	cmd, err := cli.ParseWithEnv([]string{
		"run", "--proxy", "socks5h://h:1", "--", "img", "cmd", "-t",
	}, noEnv)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cmd.Image != "img" {
		t.Fatalf("Image = %q, want img", cmd.Image)
	}
	// A `-t` AFTER the end-of-flags marker is a tool arg, not a netcage flag.
	wantArgv := []string{"cmd", "-t"}
	if strings.Join(cmd.ToolArgv, " ") != strings.Join(wantArgv, " ") {
		t.Fatalf("ToolArgv = %v, want %v", cmd.ToolArgv, wantArgv)
	}
	if cmd.TTY {
		t.Fatal("-t after -- should be a tool arg, not netcage's TTY flag")
	}
}

// TestParse_DenyListFlagsRejectedWithReason checks EACH jail-breaching flag is
// rejected with a message that names the flag and says WHY (netcage owns the
// network/isolation to keep the jail leak-proof).
func TestParse_DenyListFlagsRejectedWithReason(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"--network", []string{"--network", "host"}},
		{"-p", []string{"-p", "8080:8080"}},
		{"--publish", []string{"--publish", "8080:8080"}},
		{"--dns", []string{"--dns", "1.1.1.1"}},
		{"--privileged", []string{"--privileged"}},
		{"--cap-add", []string{"--cap-add", "NET_ADMIN"}},
		{"--device", []string{"--device", "/dev/net/tun"}},
		{"--name", []string{"--name", "x"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{"run", "--proxy", "socks5h://h:1"}, tc.args...)
			args = append(args, "img", "cmd")
			_, err := cli.ParseWithEnv(args, noEnv)
			if err == nil {
				t.Fatalf("jail-breaching flag %s accepted; want a loud rejection", tc.name)
			}
			msg := err.Error()
			if !strings.Contains(msg, tc.name) {
				t.Fatalf("rejection %q should name the flag %s", msg, tc.name)
			}
			if !strings.Contains(strings.ToLower(msg), "jail") && !strings.Contains(strings.ToLower(msg), "netcage owns") {
				t.Fatalf("rejection %q should explain WHY (netcage owns network/isolation to keep the jail leak-proof)", msg)
			}
		})
	}
}

// TestParse_RmIsNetcageOwnedFlagNotDenied proves the podman-fidelity split: --rm
// is NO LONGER in the deny-set. It is a NETCAGE-owned flag meaning "ephemeral
// this run" (remove both tool + sidecar on exit); netcage interprets it and does
// NOT smuggle it to podman's raw --rm. Without it a run is KEPT (Command.Rm
// false, the stopped pair is left behind). --name STAYS denied (netcage owns the
// run-attributable name).
func TestParse_RmIsNetcageOwnedFlagNotDenied(t *testing.T) {
	t.Run("--rm is accepted and sets Command.Rm", func(t *testing.T) {
		cmd, err := cli.ParseWithEnv([]string{"run", "--proxy", "socks5h://h:1", "--rm", "img", "cmd"}, noEnv)
		if err != nil {
			t.Fatalf("--rm must be accepted (netcage-owned ephemeral flag), got error: %v", err)
		}
		if !cmd.Rm {
			t.Fatal("--rm must set Command.Rm true (ephemeral run)")
		}
	})
	t.Run("no --rm means a kept run (Command.Rm false)", func(t *testing.T) {
		cmd, err := cli.ParseWithEnv([]string{"run", "--proxy", "socks5h://h:1", "img", "cmd"}, noEnv)
		if err != nil {
			t.Fatalf("plain run must parse, got error: %v", err)
		}
		if cmd.Rm {
			t.Fatal("a run without --rm must leave Command.Rm false (kept run)")
		}
	})
	t.Run("--name stays denied", func(t *testing.T) {
		_, err := cli.ParseWithEnv([]string{"run", "--proxy", "socks5h://h:1", "--name", "x", "img", "cmd"}, noEnv)
		if err == nil {
			t.Fatal("--name must still be rejected (netcage owns the run-attributable name)")
		}
	})
}

// TestParse_EqualsFormDenyListRejected checks a deny-list flag in --flag=value
// form is rejected too (not slipped through by the = spelling).
func TestParse_EqualsFormDenyListRejected(t *testing.T) {
	_, err := cli.ParseWithEnv([]string{
		"run", "--proxy", "socks5h://h:1", "--network=host", "img", "cmd",
	}, noEnv)
	if err == nil {
		t.Fatal("--network=host accepted; want rejection")
	}
	if !strings.Contains(err.Error(), "--network") {
		t.Fatalf("rejection %q should name --network", err)
	}
}

// TestParse_UnknownFlagRejectedByDefault checks an unaudited/unlisted flag is
// rejected rather than silently forwarded into the tool container. --frobnicate
// is used deliberately: a flag netcage does NOT (and should never) recognise, so
// this stays a genuine unknown-flag case even as the allow-list widens.
func TestParse_UnknownFlagRejectedByDefault(t *testing.T) {
	_, err := cli.ParseWithEnv([]string{
		"run", "--proxy", "socks5h://h:1", "--frobnicate", "1g", "img", "cmd",
	}, noEnv)
	if err == nil {
		t.Fatal("unknown flag --frobnicate accepted; want fail-closed rejection")
	}
	if !strings.Contains(err.Error(), "--frobnicate") {
		t.Fatalf("rejection %q should name the unknown flag", err)
	}
	// The refusal message must LIST the accepted flags (a self-correcting nudge),
	// so the agent can see what IS allowed.
	if !strings.Contains(err.Error(), "allow-list") {
		t.Fatalf("rejection %q should mention the curated allow-list", err)
	}
}

// TestParse_WidenedAllowListFlagsAccepted proves each newly-vetted,
// network/isolation-IRRELEVANT flag is ACCEPTED by the parser (both `--flag
// value` and, where applicable, `--flag=value`) and recorded on the command's
// ordered pass-through slice so it can reach the tool container's podman run
// args. These flags cannot alter the network/netns, add caps/devices/privilege,
// publish ports, affect DNS, or collide with a netcage-owned name/lifecycle
// field, so they are safe to pass through (the vetting checklist, ADR-0010).
func TestParse_WidenedAllowListFlagsAccepted(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want []string // the tokens expected on PassThroughFlags, in order
	}{
		{"--memory", []string{"--memory", "512m"}, []string{"--memory", "512m"}},
		{"--memory=", []string{"--memory=512m"}, []string{"--memory", "512m"}},
		{"--cpus", []string{"--cpus", "1.5"}, []string{"--cpus", "1.5"}},
		{"--cpus=", []string{"--cpus=1.5"}, []string{"--cpus", "1.5"}},
		{"--memory-swap", []string{"--memory-swap", "1g"}, []string{"--memory-swap", "1g"}},
		{"--memory-swap=", []string{"--memory-swap=1g"}, []string{"--memory-swap", "1g"}},
		{"-l", []string{"-l", "a=b"}, []string{"--label", "a=b"}},
		{"--label", []string{"--label", "a=b"}, []string{"--label", "a=b"}},
		{"--label=", []string{"--label=a=b"}, []string{"--label", "a=b"}},
		{"--tmpfs", []string{"--tmpfs", "/scratch"}, []string{"--tmpfs", "/scratch"}},
		{"--tmpfs=", []string{"--tmpfs=/scratch"}, []string{"--tmpfs", "/scratch"}},
		{"--read-only", []string{"--read-only"}, []string{"--read-only"}},
		{"--hostname", []string{"--hostname", "box"}, []string{"--hostname", "box"}},
		{"--hostname=", []string{"--hostname=box"}, []string{"--hostname", "box"}},
		{"--pull", []string{"--pull", "always"}, []string{"--pull", "always"}},
		{"--pull=", []string{"--pull=always"}, []string{"--pull", "always"}},
		{"--platform", []string{"--platform", "linux/amd64"}, []string{"--platform", "linux/amd64"}},
		{"--platform=", []string{"--platform=linux/amd64"}, []string{"--platform", "linux/amd64"}},
		{"--env-file", []string{"--env-file", "/env"}, []string{"--env-file", "/env"}},
		{"--env-file=", []string{"--env-file=/env"}, []string{"--env-file", "/env"}},
		{"--ulimit", []string{"--ulimit", "nofile=1024:2048"}, []string{"--ulimit", "nofile=1024:2048"}},
		{"--ulimit=", []string{"--ulimit=nofile=1024:2048"}, []string{"--ulimit", "nofile=1024:2048"}},
		{"--shm-size", []string{"--shm-size", "256m"}, []string{"--shm-size", "256m"}},
		{"--shm-size=", []string{"--shm-size=256m"}, []string{"--shm-size", "256m"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{"run", "--proxy", "socks5h://h:1"}, tc.args...)
			args = append(args, "img:latest", "cmd")
			cmd, err := cli.ParseWithEnv(args, noEnv)
			if err != nil {
				t.Fatalf("newly-allowed flag %s must be accepted, got error: %v", tc.name, err)
			}
			if strings.Join(cmd.PassThroughFlags, " ") != strings.Join(tc.want, " ") {
				t.Fatalf("PassThroughFlags = %v, want %v", cmd.PassThroughFlags, tc.want)
			}
			// The image and tool argv must NOT be swallowed by a value-taking flag
			// (the value is parsed as the flag's value, not mis-scanned as the image).
			if cmd.Image != "img:latest" {
				t.Fatalf("Image = %q, want img:latest (value-taking flag must consume its value)", cmd.Image)
			}
		})
	}
}

// TestParse_WidenedAllowListRepeatableAndOrdered checks the pass-through flags
// accumulate in argv ORDER and are repeatable (e.g. multiple --label / --ulimit),
// so they reach podman exactly as the user wrote them.
func TestParse_WidenedAllowListRepeatableAndOrdered(t *testing.T) {
	cmd, err := cli.ParseWithEnv([]string{
		"run", "--proxy", "socks5h://h:1",
		"--label", "a=1",
		"--memory", "256m",
		"-l", "b=2",
		"--read-only",
		"img:latest", "cmd",
	}, noEnv)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	want := []string{"--label", "a=1", "--memory", "256m", "--label", "b=2", "--read-only"}
	if strings.Join(cmd.PassThroughFlags, " ") != strings.Join(want, " ") {
		t.Fatalf("PassThroughFlags = %v, want %v (ordered + repeatable)", cmd.PassThroughFlags, want)
	}
}

// TestParse_AddHostRefusedAsDNSsidestep proves --add-host is in the DENY-set: it
// can pin a hostname->IP that sidesteps proxy-side DNS, so netcage refuses it
// with a message saying WHY (ADR-0010). It is refused in both --flag value and
// --flag=value forms.
func TestParse_AddHostRefusedAsDNSsidestep(t *testing.T) {
	for _, args := range [][]string{
		{"--add-host", "evil.example:1.2.3.4"},
		{"--add-host=evil.example:1.2.3.4"},
	} {
		full := append([]string{"run", "--proxy", "socks5h://h:1"}, args...)
		full = append(full, "img", "cmd")
		_, err := cli.ParseWithEnv(full, noEnv)
		if err == nil {
			t.Fatalf("--add-host (%v) accepted; want a loud refusal (it sidesteps proxy-side DNS)", args)
		}
		if !strings.Contains(err.Error(), "--add-host") {
			t.Fatalf("refusal %q should name --add-host", err)
		}
		if !strings.Contains(strings.ToLower(err.Error()), "dns") {
			t.Fatalf("refusal %q should explain the DNS-sidestep reason", err)
		}
	}
}

// TestParse_ProxyFromEnv checks NETCAGE_PROXY is honoured when --proxy is absent.
func TestParse_ProxyFromEnv(t *testing.T) {
	cmd, err := cli.ParseWithEnv([]string{
		"run", "img", "cmd",
	}, envWith(map[string]string{"NETCAGE_PROXY": "socks5h://127.0.0.1:9050"}))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cmd.Proxy.Address() != "127.0.0.1:9050" {
		t.Fatalf("Proxy from env = %q, want 127.0.0.1:9050", cmd.Proxy.Address())
	}
}

// TestParse_ProxyFlagWinsOverEnv checks the flag takes precedence over the env.
func TestParse_ProxyFlagWinsOverEnv(t *testing.T) {
	cmd, err := cli.ParseWithEnv([]string{
		"run", "--proxy", "socks5h://flag.host:1111", "img", "cmd",
	}, envWith(map[string]string{"NETCAGE_PROXY": "socks5h://env.host:2222"}))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cmd.Proxy.Address() != "flag.host:1111" {
		t.Fatalf("Proxy = %q, want flag.host:1111 (flag wins over env)", cmd.Proxy.Address())
	}
}

// TestParse_NoProxyNoEnvRefuses checks neither flag nor env => fail-closed refusal.
func TestParse_NoProxyNoEnvRefuses(t *testing.T) {
	_, err := cli.ParseWithEnv([]string{"run", "img", "cmd"}, noEnv)
	if err == nil {
		t.Fatal("run with no --proxy and no NETCAGE_PROXY accepted; want fail-closed refusal")
	}
	low := strings.ToLower(err.Error())
	if !strings.Contains(low, "proxy") {
		t.Fatalf("refusal %q should mention the proxy", err)
	}
	if !strings.Contains(low, "netcage_proxy") {
		t.Fatalf("refusal %q should mention the NETCAGE_PROXY env var as an option", err)
	}
}

// TestParse_EnvProxyMalformedRejectedBySameValidation checks a bad env proxy is
// rejected by the SAME socks5h validation as the flag (the env path is NOT laxer).
func TestParse_EnvProxyMalformedRejectedBySameValidation(t *testing.T) {
	// socks5:// (local DNS) from the env must be rejected as a leak, exactly like
	// the flag.
	_, err := cli.ParseWithEnv([]string{"run", "img", "cmd"},
		envWith(map[string]string{"NETCAGE_PROXY": "socks5://127.0.0.1:9050"}))
	if err == nil {
		t.Fatal("socks5:// from NETCAGE_PROXY accepted; want the same leak rejection as the flag")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "socks5h") {
		t.Fatalf("env-proxy rejection %q should mention socks5h", err)
	}

	// A structurally-malformed env proxy is rejected too.
	_, err = cli.ParseWithEnv([]string{"run", "img", "cmd"},
		envWith(map[string]string{"NETCAGE_PROXY": "http://h:1"}))
	if err == nil {
		t.Fatal("malformed NETCAGE_PROXY accepted; want rejection")
	}
}

func TestCommand_ProxyOnHostLoopback(t *testing.T) {
	loopback := []string{"127.0.0.1", "::1", "localhost"}
	for _, h := range loopback {
		c := cli.Command{Proxy: cli.ProxyConfig{Host: h, Port: "9050"}}
		if !c.ProxyOnHostLoopback() {
			t.Fatalf("%q should be detected as host-loopback", h)
		}
	}
	for _, h := range []string{"bastion.example", "203.0.113.9", "10.0.0.5"} {
		c := cli.Command{Proxy: cli.ProxyConfig{Host: h, Port: "1080"}}
		if c.ProxyOnHostLoopback() {
			t.Fatalf("%q should NOT be host-loopback (remote proxy)", h)
		}
	}
}

func TestParse_VerifyCommand(t *testing.T) {
	cmd, err := cli.ParseWithEnv([]string{"verify", "--proxy", "socks5h://127.0.0.1:9050"}, noEnv)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cmd.Name != "verify" {
		t.Fatalf("Name = %q, want verify", cmd.Name)
	}
	if cmd.Proxy.Address() != "127.0.0.1:9050" {
		t.Fatalf("Proxy = %q", cmd.Proxy.Address())
	}
}

// TestParse_VerifyProxyFromEnv checks verify also accepts the env-provided proxy.
func TestParse_VerifyProxyFromEnv(t *testing.T) {
	cmd, err := cli.ParseWithEnv([]string{"verify"},
		envWith(map[string]string{"NETCAGE_PROXY": "socks5h://127.0.0.1:9050"}))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cmd.Proxy.Address() != "127.0.0.1:9050" {
		t.Fatalf("Proxy from env = %q", cmd.Proxy.Address())
	}
}

func TestParse_UnknownCommandFailsLoud(t *testing.T) {
	if _, err := cli.ParseWithEnv([]string{"frobnicate", "--proxy", "socks5h://h:1"}, noEnv); err == nil {
		t.Fatal("unknown subcommand accepted; want failure")
	}
}

// TestParse_RunNoPositionalsUsesDefaultImage checks that `run` with NO
// positionals no longer fails: the default-dev-image ergonomic injects the pinned
// default image and leaves the command empty (the image's own default command
// runs). This REPLACES the old "image is a required positional" contract, which
// the default-dev-image-and-repo-mount task deliberately relaxes.
func TestParse_RunNoPositionalsUsesDefaultImage(t *testing.T) {
	cmd, err := cli.ParseWithEnv([]string{"run", "--proxy", "socks5h://h:1"}, noEnv)
	if err != nil {
		t.Fatalf("run with no positionals should inject the default image, not fail: %v", err)
	}
	if !strings.Contains(cmd.Image, "@sha256:") {
		t.Fatalf("Image = %q, want the pinned default dev image", cmd.Image)
	}
}

// TestParse_SingleBarePositionalIsTheImage checks the podman-native rule for a
// single bare positional: it is the IMAGE (with the image's own default command),
// exactly like `podman run bash` => image `bash`. This REPLACES the old
// heuristic that treated a bare command-shaped token as the command + default
// image; the default image now applies only when NO positional is given.
func TestParse_SingleBarePositionalIsTheImage(t *testing.T) {
	cmd, err := cli.ParseWithEnv([]string{"run", "--proxy", "socks5h://h:1", "bash"}, noEnv)
	if err != nil {
		t.Fatalf("run <image>: %v", err)
	}
	if cmd.Image != "bash" {
		t.Fatalf("Image = %q, want bash (the first positional is always the image)", cmd.Image)
	}
	if len(cmd.ToolArgv) != 0 {
		t.Fatalf("ToolArgv = %v, want empty (the image's own default command runs)", cmd.ToolArgv)
	}
}

// TestParse_ExplicitImageNoCommandRunsImageDefault checks that an explicit image
// with no command no longer fails: the image's own default command runs (like
// `podman run <image>`). netcage no longer forces a trailing command.
func TestParse_ExplicitImageNoCommandRunsImageDefault(t *testing.T) {
	cmd, err := cli.ParseWithEnv([]string{"run", "--proxy", "socks5h://h:1", "docker.io/library/alpine:latest"}, noEnv)
	if err != nil {
		t.Fatalf("run <image> with no command should run the image default, not fail: %v", err)
	}
	if cmd.Image != "docker.io/library/alpine:latest" {
		t.Fatalf("Image = %q, want the explicit image", cmd.Image)
	}
	if len(cmd.ToolArgv) != 0 {
		t.Fatalf("ToolArgv = %v, want empty", cmd.ToolArgv)
	}
}

func TestParse_RejectsPlainSocks5(t *testing.T) {
	if _, err := cli.ParseWithEnv([]string{"run", "--proxy", "socks5://h:1", "img", "cmd"}, noEnv); err == nil {
		t.Fatal("Parse accepted socks5://; want rejection")
	}
}

// TestParse_TopLevelUsesProcessEnv checks the exported Parse (no env arg) reads
// the real process environment for NETCAGE_PROXY.
func TestParse_TopLevelUsesProcessEnv(t *testing.T) {
	t.Setenv("NETCAGE_PROXY", "socks5h://127.0.0.1:9050")
	cmd, err := cli.Parse([]string{"run", "img", "cmd"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cmd.Proxy.Address() != "127.0.0.1:9050" {
		t.Fatalf("Proxy = %q, want the env value via the real environment", cmd.Proxy.Address())
	}
}

// errReachable is an injectable reachability checker that returns a fixed error.
type fakeReach struct{ err error }

func (f fakeReach) Check(address string) error { return f.err }

func TestRun_UnreachableProxyExitsNonZero(t *testing.T) {
	cmd := &cli.Command{
		Name:     "run",
		Image:    "x",
		ToolArgv: []string{"x"},
		Proxy:    cli.ProxyConfig{Host: "127.0.0.1", Port: "1"},
	}
	// With a reachability checker that reports the proxy down, startup must fail
	// loud (non-zero) rather than silently no-op or leak.
	err := cmd.PreflightWith(fakeReach{err: errors.New("connection refused")})
	if err == nil {
		t.Fatal("unreachable proxy did not fail; want a loud error (story 10)")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "proxy") {
		t.Fatalf("error %q should clearly mention the proxy being unreachable", err)
	}
}

func TestRun_ReachableProxyPreflightOK(t *testing.T) {
	cmd := &cli.Command{
		Name:  "verify",
		Proxy: cli.ProxyConfig{Host: "127.0.0.1", Port: "9050"},
	}
	if err := cmd.PreflightWith(fakeReach{err: nil}); err != nil {
		t.Fatalf("reachable proxy preflight failed: %v", err)
	}
}

// TestParse_ManagementVerbsNeedNoProxy proves the management verbs
// (ps/logs/inspect/exec/stop/rm/images) parse WITHOUT a proxy: they are thin
// podman pass-throughs that do not egress, so requiring --proxy to `ps`/`logs`
// would be wrong. Their positionals pass through verbatim as ManageArgv.
func TestParse_ManagementVerbsNeedNoProxy(t *testing.T) {
	cases := []struct {
		args     []string
		wantName string
		wantArgv []string
	}{
		{[]string{"ps"}, "ps", nil},
		{[]string{"images"}, "images", nil},
		{[]string{"logs", "netcage-run-abc-tool"}, "logs", []string{"netcage-run-abc-tool"}},
		{[]string{"inspect", "netcage-run-abc-tool"}, "inspect", []string{"netcage-run-abc-tool"}},
		{[]string{"stop", "netcage-run-abc-tool"}, "stop", []string{"netcage-run-abc-tool"}},
		{[]string{"rm", "netcage-run-abc-tool"}, "rm", []string{"netcage-run-abc-tool"}},
		{[]string{"exec", "netcage-run-abc-tool", "sh", "-c", "id"}, "exec", []string{"netcage-run-abc-tool", "sh", "-c", "id"}},
	}
	for _, tc := range cases {
		t.Run(tc.wantName, func(t *testing.T) {
			cmd, err := cli.ParseWithEnv(tc.args, noEnv)
			if err != nil {
				t.Fatalf("management verb %v must parse without a proxy: %v", tc.args, err)
			}
			if cmd.Name != tc.wantName {
				t.Fatalf("Name = %q, want %q", cmd.Name, tc.wantName)
			}
			if !cmd.IsManagement() {
				t.Fatalf("%q must be recognised as a management verb", cmd.Name)
			}
			if strings.Join(cmd.ManageArgv, " ") != strings.Join(tc.wantArgv, " ") {
				t.Fatalf("ManageArgv = %v, want %v", cmd.ManageArgv, tc.wantArgv)
			}
			// A management command must NOT require a proxy preflight.
			if err := cmd.Preflight(); err != nil {
				t.Fatalf("management verb preflight must be a no-op (no proxy needed); got %v", err)
			}
		})
	}
}

// TestParse_StartIsNotAManagementPassThrough guards the deliberate exclusion:
// `netcage start` is the jail-aware revive verb (its own task), NOT a thin
// pass-through, so it must not parse as a management verb here.
func TestParse_StartIsNotAManagementPassThrough(t *testing.T) {
	if cli.IsManagementVerb("start") {
		t.Fatal("`start` must NOT be a pass-through management verb (it is the jail-aware verb built separately)")
	}
}
