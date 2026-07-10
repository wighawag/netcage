package jail

import (
	"strings"
	"testing"

	"github.com/wighawag/netcage/internal/cli"
)

func cfg() Config {
	return Config{
		Proxy:    cli.ProxyConfig{Host: "127.0.0.1", Port: "9050"},
		Image:    "nuclei",
		ToolArgv: []string{"nuclei", "-u", "https://target"},
		RunID:    "abc123",
	}
}

func TestSidecarProxyURL_TranslatesSocks5hToSocks5(t *testing.T) {
	c := cfg()
	got := c.sidecarProxyURL()
	if strings.HasPrefix(got, "socks5h://") {
		t.Fatalf("sidecar proxy URL %q still uses socks5h; tun2socks rejects it, must be socks5://", got)
	}
	if !strings.HasPrefix(got, "socks5://") {
		t.Fatalf("sidecar proxy URL %q is not socks5://", got)
	}
}

func TestSidecarProxyURL_HostLoopbackUsesMappedAddr(t *testing.T) {
	c := cfg()
	c.ProxyOnHostLoopback = true
	got := c.sidecarProxyURL()
	if !strings.Contains(got, mappedHostLoopback) {
		t.Fatalf("host-loopback proxy URL %q must use the pasta-mapped addr %s", got, mappedHostLoopback)
	}
}

func TestSidecarProxyURL_RemoteProxyKeepsHostAndAuth(t *testing.T) {
	c := cfg()
	c.Proxy = cli.ProxyConfig{Host: "bastion.example", Port: "1080", Username: "u", Password: "p"}
	got := c.sidecarProxyURL()
	if !strings.Contains(got, "bastion.example:1080") {
		t.Fatalf("remote proxy URL %q lost host:port", got)
	}
	if !strings.Contains(got, "u:p@") {
		t.Fatalf("remote proxy URL %q lost user:pass auth", got)
	}
}

func TestSidecarRunArgs_ForcedEgressShape(t *testing.T) {
	c := cfg()
	c.ProxyOnHostLoopback = true
	args := strings.Join(c.SidecarRunArgs(), " ")
	for _, want := range []string{
		"--cap-add NET_ADMIN", "--device /dev/net/tun",
		"--network pasta:-I," + pastaIfName + ",--map-host-loopback," + mappedHostLoopback,
		"PROXY=socks5://" + mappedHostLoopback + ":9050",
		"netcage-run-abc123-sidecar",
	} {
		if !strings.Contains(args, want) {
			t.Fatalf("sidecar args missing %q\ngot: %s", want, args)
		}
	}
	// Must consume the pinned redirector digest, never a mutable tag.
	if !strings.Contains(args, "@sha256:") {
		t.Fatalf("sidecar must run the digest-pinned redirector; got: %s", args)
	}
}

// TestSidecarRunArgs_CloneMainOffAndExcludesProxyRoute pins the two sidecar-env
// settings the forced-egress spike proved are load-bearing
// (work/notes/findings/spike-jail-forced-egress-clone-main-and-excluded-route.md):
//
//   - CLONE_MAIN=0 so the TUN routing table is exactly `default dev tun0` and
//     does NOT clone the pasta-copied real-NIC routes (which caused a routing
//     loop / packet storm).
//   - TUN_EXCLUDED_ROUTES=<proxy-reachback-addr>/32 so tun2socks's own dialer
//     reaches the proxy over the real NIC (the pasta map) instead of looping
//     back through the TUN (which pasta reset). For a host-loopback proxy the
//     excluded address is the pasta map; for a remote proxy it is the remote
//     host so the bastion is reached over the real outbound.
func TestSidecarRunArgs_CloneMainOffAndExcludesProxyRoute(t *testing.T) {
	t.Run("host-loopback proxy excludes the pasta map address", func(t *testing.T) {
		c := cfg()
		c.ProxyOnHostLoopback = true
		args := strings.Join(c.SidecarRunArgs(), " ")
		if !strings.Contains(args, "CLONE_MAIN=0") {
			t.Fatalf("sidecar must set CLONE_MAIN=0 (else the TUN table clones the real NIC and storms); got: %s", args)
		}
		if !strings.Contains(args, "TUN_EXCLUDED_ROUTES="+mappedHostLoopback+"/32") {
			t.Fatalf("host-loopback sidecar must exclude the pasta map %s/32 from the TUN; got: %s", mappedHostLoopback, args)
		}
	})
	t.Run("remote proxy excludes the remote host address", func(t *testing.T) {
		c := cfg()
		c.Proxy = cli.ProxyConfig{Host: "203.0.113.9", Port: "1080"}
		c.ProxyOnHostLoopback = false
		args := strings.Join(c.SidecarRunArgs(), " ")
		if !strings.Contains(args, "CLONE_MAIN=0") {
			t.Fatalf("remote sidecar must set CLONE_MAIN=0; got: %s", args)
		}
		if !strings.Contains(args, "TUN_EXCLUDED_ROUTES=203.0.113.9/32") {
			t.Fatalf("remote sidecar must exclude the bastion 203.0.113.9/32 from the TUN; got: %s", args)
		}
		if strings.Contains(args, mappedHostLoopback) {
			t.Fatalf("remote sidecar must not reference the host-loopback map addr; got: %s", args)
		}
	})
}

func TestSidecarRunArgs_RemoteProxyNoHostLoopbackMap(t *testing.T) {
	c := cfg()
	c.Proxy = cli.ProxyConfig{Host: "bastion.example", Port: "1080"}
	c.ProxyOnHostLoopback = false
	args := strings.Join(c.SidecarRunArgs(), " ")
	if strings.Contains(args, "map-host-loopback") {
		t.Fatalf("remote proxy must NOT use --map-host-loopback; got: %s", args)
	}
}

// TestSidecarRunArgs_RenamesPastaInterface pins the NIC-name leak fix (Leak 5,
// ADR-0013): the pasta network arg carries `-I,<fixed-name>` so the in-netns
// interface is renamed to a fixed neutral name instead of inheriting the host
// default-route NIC's name (which under systemd `enx<MAC>` naming re-exposes the
// host MAC). It is present in BOTH proxy modes (the interface exists regardless
// of how the sidecar reaches the proxy), and composes alongside the existing
// --map-host-loopback opt for the host-loopback case. The route out is still the
// TUN, so renaming the interface does not touch forced egress (live-verified in
// the observation).
func TestSidecarRunArgs_RenamesPastaInterface(t *testing.T) {
	t.Run("host-loopback proxy: -I composes alongside --map-host-loopback", func(t *testing.T) {
		c := cfg()
		c.ProxyOnHostLoopback = true
		args := strings.Join(c.SidecarRunArgs(), " ")
		want := "--network pasta:-I," + pastaIfName + ",--map-host-loopback," + mappedHostLoopback
		if !strings.Contains(args, want) {
			t.Fatalf("host-loopback sidecar must rename the pasta interface: want %q\ngot: %s", want, args)
		}
	})
	t.Run("remote proxy: -I is the only pasta opt", func(t *testing.T) {
		c := cfg()
		c.Proxy = cli.ProxyConfig{Host: "bastion.example", Port: "1080"}
		c.ProxyOnHostLoopback = false
		args := strings.Join(c.SidecarRunArgs(), " ")
		want := "--network pasta:-I," + pastaIfName
		if !strings.Contains(args, want) {
			t.Fatalf("remote sidecar must rename the pasta interface: want %q\ngot: %s", want, args)
		}
		if strings.Contains(args, "map-host-loopback") {
			t.Fatalf("remote proxy must NOT use --map-host-loopback; got: %s", args)
		}
	})
}

func TestToolRunArgs_SharesNetnsAndPassesThrough(t *testing.T) {
	c := cfg()
	c.Mounts = []string{"/host/out:/out", "/host/words:/words:ro"}
	args := strings.Join(c.ToolRunArgs(), " ")
	for _, want := range []string{
		"--network container:netcage-run-abc123-sidecar",
		"-v /host/out:/out", "-v /host/words:/words:ro",
		"nuclei -u https://target",
	} {
		if !strings.Contains(args, want) {
			t.Fatalf("tool args missing %q\ngot: %s", want, args)
		}
	}
}

// TestToolRunArgs_SanitizesHostsAndFixesHostname pins the host-machine-name leak
// fix (Leak 1, ADR-0013): the tool container mounts a synthesized localhost-only
// /etc/hosts read-only (mirroring the resolv.conf mount) so it no longer inherits
// podman's default /etc/hosts carrying the host's `127.0.1.1 <hostname>` line, and
// carries a fixed neutral --hostname so /etc/hostname and the container name do
// not mirror the host. Both are accepted under --network container: (unlike --dns;
// live-verified). The hosts mount appears only when Run has synthesized the file
// (hostsPath set), like the resolv.conf mount.
func TestToolRunArgs_SanitizesHostsAndFixesHostname(t *testing.T) {
	c := cfg()
	c.hostsPath = "/tmp/netcage-hosts-abc123"
	args := c.ToolRunArgs()
	joined := strings.Join(args, " ")
	if want := "-v /tmp/netcage-hosts-abc123:/etc/hosts:ro"; !strings.Contains(joined, want) {
		t.Fatalf("tool args must mount the sanitized /etc/hosts read-only: want %q\ngot: %s", want, joined)
	}
	if want := "--hostname " + fixedHostname; !strings.Contains(joined, want) {
		t.Fatalf("tool args must set the fixed neutral hostname: want %q\ngot: %s", want, joined)
	}
	// The hostname flag must precede the image (a run flag), else podman mis-reads it
	// as the tool argv.
	imgIdx := indexOf(args, c.Image)
	if i := indexOf(args, "--hostname"); i < 0 || i > imgIdx {
		t.Fatalf("--hostname must appear as a run flag BEFORE the image; args: %s", joined)
	}
	// The netcage-owned --hostname must precede PassThroughFlags so an explicit user
	// --hostname (a vetted ADR-0010 pass-through) wins under podman's last-flag-wins
	// semantics; the netcage value is only the neutral DEFAULT.
	c2 := cfg()
	c2.hostsPath = "/tmp/netcage-hosts-abc123"
	c2.PassThroughFlags = []string{"--hostname", "userbox"}
	args2 := c2.ToolRunArgs()
	first := indexOf(args2, "--hostname")
	if first < 0 || args2[first+1] != fixedHostname {
		t.Fatalf("the FIRST --hostname must be netcage's neutral default %q; args: %s", fixedHostname, strings.Join(args2, " "))
	}
	// and the user's override appears AFTER it (last wins in podman)
	if last := lastIndexOf(args2, "userbox"); last <= first {
		t.Fatalf("a user --hostname override must appear AFTER netcage's default so it wins; args: %s", strings.Join(args2, " "))
	}
}

// TestToolRunArgs_OmitsHostsMountWhenUnsynthesized checks the hosts mount is
// conditional on Run having written the file (like resolv.conf): with no
// hostsPath set, no /etc/hosts mount is emitted (the arg-builder alone does not
// fabricate a source path). The fixed --hostname is unconditional (it needs no
// host file).
func TestToolRunArgs_OmitsHostsMountWhenUnsynthesized(t *testing.T) {
	c := cfg()
	joined := strings.Join(c.ToolRunArgs(), " ")
	if strings.Contains(joined, ":/etc/hosts:ro") {
		t.Fatalf("tool args must NOT mount /etc/hosts when Run has not synthesized it; got: %s", joined)
	}
}

// TestToolRunArgs_BindsEtcIdentityFixturesEgressNeutral is the ADR-0021 wiring +
// egress-neutral assertion: with the synthesized /etc-identity fixtures set (as
// Run does), the tool container mounts a minimal /etc/passwd, /etc/group, and
// /etc/machine-id READ-ONLY, mirroring the /etc/hosts mount. It also asserts these
// binds are EGRESS-NEUTRAL exactly as the host-identity-hardening work asserted the
// /etc/hosts mount was: they must introduce NOTHING that alters name resolution or
// pins a hostname->IP (nothing --add-host / --dns-like), and must not touch the
// --network container: topology. The three-point leak-test (exit IP is the
// proxy's, DNS resolves proxy-side, proxy-killed fails closed) is proven unchanged
// by the integration/verify suite; this unit test proves the binds are present and
// carry no egress-affecting arg.
func TestToolRunArgs_BindsEtcIdentityFixturesEgressNeutral(t *testing.T) {
	c := cfg()
	c.passwdPath = "/tmp/netcage-passwd-abc123"
	c.groupPath = "/tmp/netcage-group-abc123"
	c.machineIDPath = "/tmp/netcage-machine-id-abc123"
	args := c.ToolRunArgs()
	joined := strings.Join(args, " ")
	for _, want := range []string{
		"-v /tmp/netcage-passwd-abc123:/etc/passwd:ro",
		"-v /tmp/netcage-group-abc123:/etc/group:ro",
		"-v /tmp/netcage-machine-id-abc123:/etc/machine-id:ro",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("tool args must mount the ADR-0021 /etc-identity fixture read-only: want %q\ngot: %s", want, joined)
		}
	}
	// Egress-neutral: the new binds must not smuggle any name-resolution / hostname-IP
	// pin. --add-host and --dns are the flags netcage owns/refuses precisely because
	// they sidestep proxy-side DNS; the /etc-identity binds must add NEITHER.
	for _, forbidden := range []string{"--add-host", "--dns"} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("the /etc-identity binds must be egress-neutral: they must NOT introduce %q; got: %s", forbidden, joined)
		}
	}
	// The topology stays exactly the shared-netns --network container: edge; the binds
	// do not change it.
	if !strings.Contains(joined, "--network container:"+c.sidecarName()) {
		t.Fatalf("the /etc-identity binds must not alter the --network container: topology; got: %s", joined)
	}
	// The machine-id bind is /etc/machine-id ONLY (NOT /var/lib/dbus/machine-id, which
	// would break on minimal images lacking /var/lib/dbus/, e.g. the alpine the verify
	// leak-test uses); the residual is documented in ADR-0021.
	if strings.Contains(joined, "/var/lib/dbus/machine-id") {
		t.Fatalf("netcage must bind /etc/machine-id only, not /var/lib/dbus/machine-id (breaks minimal images); got: %s", joined)
	}
	// Each bind is a run flag, so it must precede the image (else podman reads it as
	// the tool argv).
	imgIdx := indexOf(args, c.Image)
	for _, mount := range []string{
		"/tmp/netcage-passwd-abc123:/etc/passwd:ro",
		"/tmp/netcage-group-abc123:/etc/group:ro",
		"/tmp/netcage-machine-id-abc123:/etc/machine-id:ro",
	} {
		if i := indexOf(args, mount); i < 0 || i > imgIdx {
			t.Fatalf("the %q bind must appear as a run flag BEFORE the image; args: %s", mount, joined)
		}
	}
}

// TestToolRunArgs_OmitsEtcIdentityMountsWhenUnsynthesized checks the ADR-0021
// binds are conditional on Run having synthesized the fixtures (like /etc/hosts):
// with no fixture paths set, no /etc/passwd, /etc/group, or /etc/machine-id mount
// is emitted (the arg-builder alone does not fabricate a source path).
func TestToolRunArgs_OmitsEtcIdentityMountsWhenUnsynthesized(t *testing.T) {
	c := cfg()
	joined := strings.Join(c.ToolRunArgs(), " ")
	for _, forbidden := range []string{":/etc/passwd:ro", ":/etc/group:ro", ":/etc/machine-id:ro"} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("tool args must NOT mount %q when Run has not synthesized the fixture; got: %s", forbidden, joined)
		}
	}
}

// TestToolRunArgs_RmOnlyWhenEphemeral pins the podman-fidelity split: the tool
// container's --rm follows netcage's Ephemeral flag, NOT a hard-coded default.
// A KEPT run (Ephemeral=false, a plain `netcage run` with no --rm) must NOT pass
// --rm, so podman leaves the stopped tool container behind (inspectable,
// restartable) like `podman run`. An EPHEMERAL run (Ephemeral=true: the netcage
// `--rm` flag and every internal one-shot) DOES pass --rm so the tool container
// is removed on exit as before.
func TestToolRunArgs_RmOnlyWhenEphemeral(t *testing.T) {
	t.Run("kept run omits --rm (leaves the stopped tool container)", func(t *testing.T) {
		c := cfg()
		c.Ephemeral = false
		args := c.ToolRunArgs()
		for _, a := range args {
			if a == "--rm" {
				t.Fatalf("kept run (Ephemeral=false) must NOT force --rm; got: %s", strings.Join(args, " "))
			}
		}
	})
	t.Run("ephemeral run keeps --rm (removes the tool container)", func(t *testing.T) {
		c := cfg()
		c.Ephemeral = true
		if !strings.Contains(strings.Join(c.ToolRunArgs(), " "), "--rm") {
			t.Fatalf("ephemeral run (Ephemeral=true) must pass --rm; got: %s", strings.Join(c.ToolRunArgs(), " "))
		}
	})
}

// TestCreateArgs_CarryNetcageManagedLabel pins the netcage.managed (+ role + run
// id) label INTRODUCED here on BOTH create paths: it is the stable discriminator
// a left-behind pair carries so the pass-through verbs can scope to
// netcage-managed containers (a label, not the name convention). The tool gets
// role=tool, the sidecar role=sidecar; both carry the run id.
func TestCreateArgs_CarryNetcageManagedLabel(t *testing.T) {
	c := cfg()
	c.ProxyOnHostLoopback = true

	tool := strings.Join(c.ToolRunArgs(), " ")
	for _, want := range []string{
		"--label netcage.managed=true",
		"--label netcage.role=tool",
		"--label netcage.run-id=abc123",
	} {
		if !strings.Contains(tool, want) {
			t.Fatalf("tool create args missing label %q\ngot: %s", want, tool)
		}
	}

	sidecar := strings.Join(c.SidecarRunArgs(), " ")
	for _, want := range []string{
		"--label netcage.managed=true",
		"--label netcage.role=sidecar",
		"--label netcage.run-id=abc123",
	} {
		if !strings.Contains(sidecar, want) {
			t.Fatalf("sidecar create args missing label %q\ngot: %s", want, sidecar)
		}
	}
}

func TestToolRunArgs_SetsWorkdirWhenGiven(t *testing.T) {
	c := cfg()
	c.Mounts = []string{"/host/repo:/work"}
	c.Workdir = "/work"
	args := strings.Join(c.ToolRunArgs(), " ")
	if !strings.Contains(args, "-w /work") {
		t.Fatalf("tool args should set the container workdir with -w /work (repo-mount ergonomic)\ngot: %s", args)
	}
}

func TestToolRunArgs_OmitsWorkdirWhenEmpty(t *testing.T) {
	c := cfg()
	c.Workdir = ""
	args := strings.Join(c.ToolRunArgs(), " ")
	if strings.Contains(args, " -w ") {
		t.Fatalf("tool args must NOT set -w when no workdir is given (leave the image's own workdir)\ngot: %s", args)
	}
}

// TestToolRunArgs_WiresEnvUserEntrypoint pins the drift-bug fix: -e/--env,
// -u/--user and --entrypoint were PARSED into the CLI command but never reached
// the tool container (silently dropped). They must now appear in the podman run
// args so the env is set, the tool runs as that user, and the entrypoint is
// overridden. Repeatable -e accumulates in order.
func TestToolRunArgs_WiresEnvUserEntrypoint(t *testing.T) {
	c := cfg()
	c.Env = []string{"KEY=VALUE", "OTHER=2"}
	c.User = "1000:1000"
	c.Entrypoint = "/bin/sh"
	args := c.ToolRunArgs()
	joined := strings.Join(args, " ")
	for _, want := range []string{
		"-e KEY=VALUE", "-e OTHER=2",
		"-u 1000:1000",
		"--entrypoint /bin/sh",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("tool args must wire the parsed-but-dropped flag %q\ngot: %s", want, joined)
		}
	}
	// The env/user/entrypoint flags must precede the image (podman run flags come
	// before the positional IMAGE), else they are mis-read as the tool argv.
	imgIdx := indexOf(args, c.Image)
	for _, flag := range []string{"-e", "-u", "--entrypoint"} {
		if i := indexOf(args, flag); i < 0 || i > imgIdx {
			t.Fatalf("%s must appear as a run flag BEFORE the image; args: %s", flag, joined)
		}
	}
}

// TestToolRunArgs_OmitsEnvUserEntrypointWhenUnset checks the drift-fix wiring is
// conditional: with no env/user/entrypoint set, none of those flags appears (the
// image's own env/user/entrypoint are left intact, like plain `podman run`).
func TestToolRunArgs_OmitsEnvUserEntrypointWhenUnset(t *testing.T) {
	c := cfg()
	args := c.ToolRunArgs()
	// Only the RUN-FLAG region (before the image) may contain these flags; the tool
	// argv after the image legitimately carries its own -u (nuclei -u https://...),
	// so scan the flag region, not the whole joined string.
	imgIdx := indexOf(args, c.Image)
	for _, flag := range []string{"-e", "-u", "--entrypoint"} {
		if i := indexOf(args, flag); i >= 0 && i < imgIdx {
			t.Fatalf("unset env/user/entrypoint must add no %s run flag\ngot: %s", flag, strings.Join(args, " "))
		}
	}
}

// TestToolRunArgs_PassesThroughVettedFlags proves the widened, vetted allow-list
// flags (Config.PassThroughFlags, populated from cli.Command.PassThroughFlags)
// reach the tool container's podman run args verbatim, in order, BEFORE the image
// (ADR-0010). These flags cannot touch network/netns/caps/devices/privilege/
// ports/DNS, so passing them through does not weaken forced egress.
func TestToolRunArgs_PassesThroughVettedFlags(t *testing.T) {
	c := cfg()
	c.PassThroughFlags = []string{"--memory", "512m", "--label", "a=b", "--read-only"}
	args := c.ToolRunArgs()
	joined := strings.Join(args, " ")
	for _, want := range []string{"--memory 512m", "--label a=b", "--read-only"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("tool args must pass through vetted flag %q\ngot: %s", want, joined)
		}
	}
	// Every pass-through token must precede the image (they are run flags).
	imgIdx := indexOf(args, c.Image)
	if i := indexOf(args, "--memory"); i < 0 || i > imgIdx {
		t.Fatalf("pass-through flags must appear BEFORE the image; args: %s", joined)
	}
}

// indexOf returns the first index of tok in args, or -1.
func indexOf(args []string, tok string) int {
	for i, a := range args {
		if a == tok {
			return i
		}
	}
	return -1
}

func lastIndexOf(args []string, tok string) int {
	last := -1
	for i, a := range args {
		if a == tok {
			last = i
		}
	}
	return last
}

// The firewall is baked into the sidecar's create-time `EXTRA_COMMANDS` env
// (ADR-0008, refining ADR-0006) so it re-applies on every (re)start, so the
// ruleset is an iptables/ip6tables shell script (the pinned redirector image
// ships iptables, not nft), not an nft ruleset piped through host nsenter.
func TestFirewallScript_DropsUDPExceptLocalDNSAndNarrowsReachback(t *testing.T) {
	c := cfg()
	c.ProxyOnHostLoopback = true
	rs := c.firewallScript("9050")
	for _, want := range []string{
		"iptables -A OUTPUT -p udp -d 127.0.0.0/8 -j ACCEPT",                             // tool<->forwarder loopback DNS (query + reply)
		"iptables -A OUTPUT -p udp -j DROP",                                              // all other IPv4 UDP dropped (ADR-0003)
		"ip6tables -A OUTPUT -p udp -j DROP",                                             // ... and IPv6 UDP (the nft `inet` table covered both)
		"iptables -A OUTPUT -p tcp -d " + mappedHostLoopback + " --dport 9050 -j ACCEPT", // exactly the proxy port
		"iptables -A OUTPUT -d " + mappedHostLoopback + " -j DROP",                       // nothing else on the host
	} {
		if !strings.Contains(rs, want) {
			t.Fatalf("firewall script missing %q\ngot:\n%s", want, rs)
		}
	}
	// The reachback accept must precede the reachback drop (else the proxy port
	// itself is dropped and the jail fails closed against its own proxy).
	accept := strings.Index(rs, "--dport 9050 -j ACCEPT")
	drop := strings.Index(rs, "iptables -A OUTPUT -d "+mappedHostLoopback+" -j DROP")
	if accept < 0 || drop < 0 || accept > drop {
		t.Fatalf("reachback accept must precede the reachback drop\ngot:\n%s", rs)
	}
	// The script must fail loudly if any rule fails to apply (a silently
	// half-applied firewall is a leak).
	if !strings.HasPrefix(rs, "set -e\n") {
		t.Fatalf("firewall script must start with `set -e` so a failed rule aborts the run\ngot:\n%s", rs)
	}
}

func TestFirewallScript_RemoteProxyHasNoReachbackNarrowing(t *testing.T) {
	c := cfg()
	c.ProxyOnHostLoopback = false
	rs := c.firewallScript("1080")
	if strings.Contains(rs, mappedHostLoopback) {
		t.Fatalf("remote proxy ruleset must not reference the host-loopback map addr\ngot:\n%s", rs)
	}
	// UDP still hard-dropped (both families).
	for _, want := range []string{"iptables -A OUTPUT -p udp -j DROP", "ip6tables -A OUTPUT -p udp -j DROP"} {
		if !strings.Contains(rs, want) {
			t.Fatalf("UDP must still be dropped for a remote proxy (missing %q)\ngot:\n%s", want, rs)
		}
	}
}

// TestFirewallScript_DropFirstOrdering pins the DROP-first ordering the spike
// proved bounds the partial-apply residual on the one unguarded path (a raw
// `podman start` outside netcage): the broad DROPs (all-egress-UDP drop, the
// reachback drop, the RFC1918/link-local drops) come BEFORE the narrow trailing
// ... wait: the CONSTRAINT is the opposite for the accepts that ENABLE the
// proxy/direct hop. So this test pins BOTH halves at once:
//
//   - every broad DROP precedes the NEXT accept it does not need to gate (there
//     is no trailing accept after the drop block); concretely the UDP drop and
//     the RFC1918/reachback drops are all emitted in one contiguous DROP block
//     that comes AFTER the required enabling accepts, so a mid-script failure in
//     the DROP block leaves MORE dropped, not more open; and
//   - the ENABLING accepts (loopback-UDP, the proxy-port reachback ACCEPT, each
//     split-tunnel direct ACCEPT) still precede their corresponding broad drops
//     (the UDP drop, the link-local drop, the RFC1918 drops), else the sidecar's
//     own dial to the pasta-mapped proxy or an allowlisted direct is caught by a
//     broad drop.
func TestFirewallScript_DropFirstOrdering(t *testing.T) {
	c := cfg()
	c.ProxyOnHostLoopback = true
	c.AllowDirect = []cli.DirectAllow{
		allow(t, "192.168.1.150", 8080),
	}
	rs := c.firewallScript("9050")

	idx := func(sub string) int {
		i := strings.Index(rs, sub)
		if i < 0 {
			t.Fatalf("firewall script missing %q\ngot:\n%s", sub, rs)
		}
		return i
	}

	// The enabling accepts.
	loopUDPAccept := idx("iptables -A OUTPUT -p udp -d 127.0.0.0/8 -j ACCEPT")
	proxyAccept := idx("iptables -A OUTPUT -p tcp -d " + mappedHostLoopback + " --dport 9050 -j ACCEPT")
	directAccept := idx("iptables -A OUTPUT -p tcp -d 192.168.1.150/32 --dport 8080 -j ACCEPT")

	// The broad drops.
	udpDrop := idx("iptables -A OUTPUT -p udp -j DROP")
	reachbackDrop := idx("iptables -A OUTPUT -d " + mappedHostLoopback + " -j DROP")
	linkLocalDrop := idx("iptables -A OUTPUT -d 169.254.0.0/16 -j DROP")
	rfc1918Drop := idx("iptables -A OUTPUT -d 192.168.0.0/16 -j DROP")

	// The enabling accepts must precede the drops that would otherwise catch them.
	if loopUDPAccept > udpDrop {
		t.Fatalf("loopback-UDP accept must precede the UDP drop (else DNS fails closed)\n%s", rs)
	}
	if proxyAccept > reachbackDrop || proxyAccept > linkLocalDrop {
		t.Fatalf("proxy-port reachback accept must precede the reachback/link-local drops (else the sidecar cannot reach its own proxy)\n%s", rs)
	}
	if directAccept > rfc1918Drop {
		t.Fatalf("split-tunnel direct accept must precede the RFC1918 drops (else the allowed direct is dropped)\n%s", rs)
	}

	// DROP-first: the broad DROP block is CONTIGUOUS and comes AFTER all the
	// enabling accepts, so a mid-script failure inside the drop block leaves MORE
	// dropped, not more open. Concretely: every enabling accept precedes every
	// broad drop.
	lastAccept := loopUDPAccept
	for _, a := range []int{proxyAccept, directAccept} {
		if a > lastAccept {
			lastAccept = a
		}
	}
	firstDrop := udpDrop
	for _, d := range []int{reachbackDrop, linkLocalDrop, rfc1918Drop} {
		if d < firstDrop {
			firstDrop = d
		}
	}
	if lastAccept > firstDrop {
		t.Fatalf("DROP-first violated: an enabling accept (at %d) comes AFTER a broad drop (first at %d); the broad drops must all follow the enabling accepts so a partial apply is MORE closed\n%s", lastAccept, firstDrop, rs)
	}
}

// TestSidecarRunArgs_FirewallInExtraCommands: the firewall now rides in the
// sidecar's create-time EXTRA_COMMANDS env (so it self-heals on every restart),
// NOT a post-start `podman exec`. The env value must equal the firewall script
// exactly, built without executing podman.
func TestSidecarRunArgs_FirewallInExtraCommands(t *testing.T) {
	c := cfg()
	c.ProxyOnHostLoopback = true
	args := c.SidecarRunArgs()

	var extra string
	found := false
	for i := 0; i < len(args)-1; i++ {
		if args[i] == "-e" && strings.HasPrefix(args[i+1], "EXTRA_COMMANDS=") {
			extra = strings.TrimPrefix(args[i+1], "EXTRA_COMMANDS=")
			found = true
		}
	}
	if !found {
		t.Fatalf("sidecar args must set EXTRA_COMMANDS with the firewall script; got: %s", strings.Join(args, " "))
	}
	if extra != c.firewallScript(c.Proxy.Port) {
		t.Fatalf("EXTRA_COMMANDS value must equal firewallScript(proxyPort)\ngot:\n%s\nwant:\n%s", extra, c.firewallScript(c.Proxy.Port))
	}
}

// TestFirewallVerifyRules_MatchExpectedIptablesOutput pins the seam the
// post-start VERIFICATION uses: firewallVerifyRules returns the exact set of
// `iptables -S OUTPUT`-shaped rule lines netcage asserts are present after the
// sidecar is up (the fail-loud layer, since EXTRA_COMMANDS cannot abort the
// sidecar). Each expected rule must be a substring of what the baked script's
// own `-A OUTPUT ...` lines would produce, using iptables' /32 normalisation for
// a bare host address.
func TestFirewallVerifyRules_MatchExpectedIptablesOutput(t *testing.T) {
	c := cfg()
	c.ProxyOnHostLoopback = true
	c.AllowDirect = []cli.DirectAllow{allow(t, "192.168.1.150", 8080)}

	v4, v6 := c.firewallVerifyRules(c.Proxy.Port)
	if len(v4) == 0 || len(v6) == 0 {
		t.Fatalf("firewallVerifyRules must return both v4 and v6 expected rules; got v4=%v v6=%v", v4, v6)
	}
	for _, want := range []string{
		// The canonical `iptables -S` form: -d before -p, /32-normalised host, and
		// -m tcp for a --dport match.
		"-A OUTPUT -d 127.0.0.0/8 -p udp -j ACCEPT",
		"-A OUTPUT -p udp -j DROP",
		"-A OUTPUT -d " + mappedHostLoopback + "/32 -j DROP",
		"-A OUTPUT -d " + mappedHostLoopback + "/32 -p tcp -m tcp --dport 9050 -j ACCEPT",
		"-A OUTPUT -d 192.168.1.150/32 -p tcp -m tcp --dport 8080 -j ACCEPT",
		"-A OUTPUT -d 192.168.0.0/16 -j DROP",
	} {
		if !containsRule(v4, want) {
			t.Fatalf("firewallVerifyRules (v4) missing expected rule %q\ngot: %v", want, v4)
		}
	}
	if !containsRule(v6, "-A OUTPUT -p udp -j DROP") {
		t.Fatalf("firewallVerifyRules (v6) must assert the IPv6 UDP drop; got: %v", v6)
	}
}

func containsRule(rules []string, want string) bool {
	for _, r := range rules {
		if r == want {
			return true
		}
	}
	return false
}

// TestVerifyFirewallOutput_FailsOnMissingRule proves the fail-loud check: given
// captured `iptables -S` output that is MISSING an expected rule, the verifier
// reports the jail as NOT fully firewalled (so Run can abort loudly). A raw
// half-applied firewall must fail, never silently run.
func TestVerifyFirewallOutput_FailsOnMissingRule(t *testing.T) {
	c := cfg()
	c.ProxyOnHostLoopback = true
	v4, _ := c.firewallVerifyRules(c.Proxy.Port)

	// Full output: every expected rule present -> ok.
	full := strings.Join(v4, "\n")
	if err := checkRulesPresent(v4, full); err != nil {
		t.Fatalf("full ruleset must verify clean; got %v", err)
	}

	// Drop one rule -> the verifier must flag it as missing.
	partial := strings.Join(v4[1:], "\n")
	if err := checkRulesPresent(v4, partial); err == nil {
		t.Fatalf("a missing rule must fail verification (fail-loud); got nil err for partial:\n%s", partial)
	}
}

// TestSidecarRunArgs_MountsDNSHelper: when Run has resolved the netcage-dns
// helper's host path, the sidecar args mount it read-only at the in-container
// path the jail execs it from (ADR-0006: the forwarder runs INSIDE the sidecar
// via podman exec, not on the host via nsenter).
func TestSidecarRunArgs_MountsDNSHelper(t *testing.T) {
	c := cfg()
	c.dnsHelperPath = "/opt/bin/netcage-dns"
	args := strings.Join(c.SidecarRunArgs(), " ")
	want := "-v /opt/bin/netcage-dns:" + sidecarDNSHelperPath + ":ro"
	if !strings.Contains(args, want) {
		t.Fatalf("sidecar args missing the DNS-helper mount %q\ngot: %s", want, args)
	}
}
