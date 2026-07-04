package ports

import (
	"testing"
)

// parseProcNetTCP is the pure, image-independent CORE of `netcage ports`: it
// turns raw /proc/net/tcp + /proc/net/tcp6 text into the ordered list of TCP
// LISTEN sockets, each with a human-readable bind address, its port, and whether
// it is loopback-only. Because /proc/net/tcp* exists in ANY Linux container
// regardless of installed userspace, this is where enumeration correctness lives
// and it is fully unit-testable with fixture strings (no podman, no container).
//
// The fixtures below are real-shaped rows: the kernel emits a header line, then
// one row per socket with a space-separated `sl  local_address rem_address st ...`
// layout. IPv4 local_address is `HEXIP:HEXPORT` with the IP LITTLE-ENDIAN
// (0100007F -> 127.0.0.1) and the port BIG-ENDIAN (0BB9 -> 3001); IPv6 uses a
// 32-hex-char address. `st == 0A` is LISTEN.

// v4Header / v6Header are the exact column headers the kernel prints; the parser
// must skip them (they are not data rows) without treating them as sockets.
const v4Header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode"
const v6Header = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode"

// v4Row builds a /proc/net/tcp data row with the given local hex address and
// state, padding out the trailing columns the parser ignores.
func v4Row(sl, localAddr, st string) string {
	return "   " + sl + ": " + localAddr + " 00000000:0000 " + st + " 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0"
}

// v6Row builds a /proc/net/tcp6 data row (32-hex-char address).
func v6Row(sl, localAddr, st string) string {
	return "   " + sl + ": " + localAddr + " 00000000000000000000000000000000:0000 " + st + " 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0"
}

func joinLines(lines ...string) string {
	out := ""
	for _, l := range lines {
		out += l + "\n"
	}
	return out
}

// TestParseProcNetTCP_IPv4LoopbackAndWildcard is the headline case: the two
// live-observed jail rows. 0100007F:0035 (LISTEN) is the netcage in-jail DNS
// forwarder on 127.0.0.1:53, loopback-only; 00000000:0BB9 (LISTEN) is a server
// on 0.0.0.0:3001, wildcard (not loopback-only). Both must decode faithfully.
func TestParseProcNetTCP_IPv4LoopbackAndWildcard(t *testing.T) {
	v4 := joinLines(
		v4Header,
		v4Row("0", "0100007F:0035", "0A"), // 127.0.0.1:53  LISTEN
		v4Row("1", "00000000:0BB9", "0A"), // 0.0.0.0:3001  LISTEN
	)

	got := parseProcNetTCP(v4, "")

	want := []Listener{
		{Address: "127.0.0.1", Port: 53, LoopbackOnly: true},
		{Address: "0.0.0.0", Port: 3001, LoopbackOnly: false},
	}
	assertListeners(t, got, want)
}

// TestParseProcNetTCP_IPv4LittleEndianDecode pins the little-endian IP decode and
// the big-endian port decode independently, so a byte-order regression is caught.
func TestParseProcNetTCP_IPv4LittleEndianDecode(t *testing.T) {
	cases := []struct {
		name      string
		localAddr string
		wantAddr  string
		wantPort  int
		wantLoop  bool
	}{
		{"loopback 127.0.0.1:53", "0100007F:0035", "127.0.0.1", 53, true},
		{"wildcard 0.0.0.0:3001", "00000000:0BB9", "0.0.0.0", 3001, false},
		{"loopback range 127.1.2.3:80", "0302017F:0050", "127.1.2.3", 80, true},
		{"routable 10.0.0.5:8080", "0500000A:1F90", "10.0.0.5", 8080, false},
		{"high port 65535", "00000000:FFFF", "0.0.0.0", 65535, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseProcNetTCP(joinLines(v4Header, v4Row("0", tc.localAddr, "0A")), "")
			if len(got) != 1 {
				t.Fatalf("got %d listeners, want 1: %+v", len(got), got)
			}
			if got[0].Address != tc.wantAddr {
				t.Fatalf("Address = %q, want %q", got[0].Address, tc.wantAddr)
			}
			if got[0].Port != tc.wantPort {
				t.Fatalf("Port = %d, want %d", got[0].Port, tc.wantPort)
			}
			if got[0].LoopbackOnly != tc.wantLoop {
				t.Fatalf("LoopbackOnly = %v, want %v", got[0].LoopbackOnly, tc.wantLoop)
			}
		})
	}
}

// TestParseProcNetTCP_IPv6LoopbackAndWildcard checks the 32-hex-char v6 decode:
// ::1 is loopback-only, :: (wildcard) is not, and a routable v6 is not.
func TestParseProcNetTCP_IPv6LoopbackAndWildcard(t *testing.T) {
	v6 := joinLines(
		v6Header,
		// ::1  -> loopback. Kernel stores v6 as 4 little-endian 32-bit words; the
		// canonical loopback appears as 00000000000000000000000001000000.
		v6Row("0", "00000000000000000000000001000000:0035", "0A"),
		// ::   -> wildcard, all zeroes.
		v6Row("1", "00000000000000000000000000000000:0BB9", "0A"),
	)

	got := parseProcNetTCP("", v6)

	want := []Listener{
		{Address: "::1", Port: 53, LoopbackOnly: true},
		{Address: "::", Port: 3001, LoopbackOnly: false},
	}
	assertListeners(t, got, want)
}

// TestParseProcNetTCP_FiltersNonListen checks that only st==0A rows survive:
// ESTABLISHED (01), TIME_WAIT (06), and any other state are dropped.
func TestParseProcNetTCP_FiltersNonListen(t *testing.T) {
	v4 := joinLines(
		v4Header,
		v4Row("0", "0100007F:0035", "0A"), // LISTEN  -> kept
		v4Row("1", "0100007F:1F90", "01"), // ESTABLISHED -> dropped
		v4Row("2", "00000000:0BB9", "06"), // TIME_WAIT -> dropped
		v4Row("3", "00000000:0050", "0A"), // LISTEN  -> kept
	)

	got := parseProcNetTCP(v4, "")

	want := []Listener{
		{Address: "127.0.0.1", Port: 53, LoopbackOnly: true},
		{Address: "0.0.0.0", Port: 80, LoopbackOnly: false},
	}
	assertListeners(t, got, want)
}

// TestParseProcNetTCP_SkipsMalformedWithoutPanic checks robustness: a blank
// input, blank lines, short/truncated rows, and rows with an unparseable
// local_address are skipped rather than crashing, while valid rows still parse.
func TestParseProcNetTCP_SkipsMalformedWithoutPanic(t *testing.T) {
	// Empty input yields no listeners (and no panic).
	if got := parseProcNetTCP("", ""); len(got) != 0 {
		t.Fatalf("empty input: got %d listeners, want 0", len(got))
	}

	v4 := joinLines(
		v4Header,
		"",              // blank line
		"   4: garbage", // too few columns
		"   5: ZZZZZZZZ:0035 00000000:0000 0A rest...", // non-hex IP
		"   6: 0100007F:ZZZZ 00000000:0000 0A rest...", // non-hex port
		v4Row("7", "0100007F:0035", "0A"),              // the one valid LISTEN row
		"partial",                                      // junk trailing line
	)

	got := parseProcNetTCP(v4, "")
	want := []Listener{{Address: "127.0.0.1", Port: 53, LoopbackOnly: true}}
	assertListeners(t, got, want)
}

// TestParseProcNetTCP_MergesV4AndV6InOrder checks the combined output: v4 rows
// first (in file order) then v6 rows, in one slice, as the --json contract emits.
func TestParseProcNetTCP_MergesV4AndV6InOrder(t *testing.T) {
	v4 := joinLines(v4Header, v4Row("0", "00000000:0BB9", "0A"))                         // 0.0.0.0:3001
	v6 := joinLines(v6Header, v6Row("0", "00000000000000000000000001000000:0035", "0A")) // ::1:53

	got := parseProcNetTCP(v4, v6)
	want := []Listener{
		{Address: "0.0.0.0", Port: 3001, LoopbackOnly: false},
		{Address: "::1", Port: 53, LoopbackOnly: true},
	}
	assertListeners(t, got, want)
}

// assertListeners compares the parsed listeners to the expected slice, field by
// field, failing with a readable diff.
func assertListeners(t *testing.T, got, want []Listener) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d listeners, want %d\n got: %+v\nwant: %+v", len(got), len(want), got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("listener[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
}
