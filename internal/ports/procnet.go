// Package ports is the pure, image-independent CORE of the `netcage ports` verb:
// it decodes raw /proc/net/tcp + /proc/net/tcp6 text into the list of TCP LISTEN
// sockets, each with a human-readable bind address, its port, and whether it is
// loopback-only. /proc/net/tcp* exists in ANY Linux container regardless of the
// installed userspace (the real anon-pi image ships no ss/netstat/nc), so it is
// the portable source of truth: netcage reads it via the netns-sharing SIDECAR
// (podman exec, ADR-0006) rather than depending on tools inside the arbitrary
// tool image. That "don't depend on in-image tools" lesson is the same one the
// forward connector learned (work/notes/findings/forward-connector-must-use-
// sidecar-nc-not-tool.md). This file is PURE parsing: no podman, no Runner; the
// wiring verb reads the two file bodies and hands them to parseProcNetTCP.
package ports

import (
	"encoding/binary"
	"encoding/hex"
	"net"
	"strconv"
	"strings"
)

// Listener is one decoded TCP LISTEN socket, the settled shape the `ports`
// wiring + `--json` contract consume (spec ports-verb-list-jail-listeners, story
// 7). It is deliberately minimal and JSON-tagged so the wiring layer can marshal
// it directly as the documented reuse array `[{address, port, loopbackOnly}]`
// (IPv4 and IPv6 in the same slice).
//
//   - Address is the rendered bind address: 127.0.0.1 / 0.0.0.0 / ::1 / :: or a
//     full specific v6 form. It is NEVER a hostname; the parser only decodes what
//     the kernel reports.
//   - Port is the TCP port (1..65535).
//   - LoopbackOnly is true when the bind address is in 127.0.0.0/8 (v4) or is ::1
//     (v6): a server reachable ONLY from inside the netns, the exact `forward`
//     use case. A wildcard bind (0.0.0.0 / ::) or any routable address is false.
//     Annotating / filtering (e.g. netcage's own :53 DNS forwarder) is the
//     presentation layer's job, not the parser's: this reports every LISTEN
//     socket faithfully.
type Listener struct {
	Address      string `json:"address"`
	Port         int    `json:"port"`
	LoopbackOnly bool   `json:"loopbackOnly"`
}

// tcpStateListen is the /proc/net/tcp* `st` (state) column value for LISTEN.
// Every other state (ESTABLISHED 01, TIME_WAIT 06, etc.) is filtered out: `ports`
// answers "what could be forwarded", not "what is connected".
const tcpStateListen = "0A"

// parseProcNetTCP decodes the two file bodies (v4 = /proc/net/tcp, v6 =
// /proc/net/tcp6) into the ordered slice of LISTEN sockets: all v4 listeners in
// file order first, then all v6 listeners, in one slice (the --json contract puts
// both families in a single array). Either body may be empty.
//
// It is defensive by construction: the kernel's header line, blank lines, short
// or truncated rows, and rows with an unparseable local_address are SKIPPED
// rather than causing a panic (a `ports` read must never crash on a surprising
// /proc layout). Only rows whose `st` column equals 0A survive.
func parseProcNetTCP(v4, v6 string) []Listener {
	var out []Listener
	out = append(out, parseBody(v4, false)...)
	out = append(out, parseBody(v6, true)...)
	return out
}

// parseBody parses one /proc/net/tcp* body. isV6 selects the 32-hex-char IPv6
// address decode (vs the 8-hex-char IPv4 decode).
func parseBody(body string, isV6 bool) []Listener {
	var out []Listener
	for _, line := range strings.Split(body, "\n") {
		l, ok := parseRow(line, isV6)
		if ok {
			out = append(out, l)
		}
	}
	return out
}

// parseRow decodes a single line into a Listener, returning ok=false for the
// header, blanks, non-LISTEN rows, and any malformed row (so callers just skip).
//
// A data row's columns are whitespace-separated:
//
//	sl  local_address rem_address  st  tx_queue ...
//	 0: 0100007F:0035 00000000:0000 0A ...
//
// so field[1] is the local_address (HEXIP:HEXPORT) and field[3] is the state.
func parseRow(line string, isV6 bool) (Listener, bool) {
	fields := strings.Fields(line)
	if len(fields) < 4 {
		return Listener{}, false // header, blank, or truncated
	}
	// The header's second field is the literal "local_address", never a
	// hex:hex token; skip it (and any other non-colon field defensively).
	local := fields[1]
	if fields[3] != tcpStateListen {
		return Listener{}, false // not a LISTEN socket (or the header's "st")
	}

	colon := strings.LastIndexByte(local, ':')
	if colon < 0 {
		return Listener{}, false
	}
	addrHex := local[:colon]
	portHex := local[colon+1:]

	port, ok := decodePort(portHex)
	if !ok {
		return Listener{}, false
	}

	var ip net.IP
	if isV6 {
		ip, ok = decodeV6(addrHex)
	} else {
		ip, ok = decodeV4(addrHex)
	}
	if !ok {
		return Listener{}, false
	}

	return Listener{
		Address:      renderIP(ip),
		Port:         port,
		LoopbackOnly: ip.IsLoopback(),
	}, true
}

// decodePort decodes the 4-hex-char BIG-ENDIAN port (0BB9 -> 3001, 0035 -> 53).
func decodePort(portHex string) (int, bool) {
	if len(portHex) != 4 {
		return 0, false
	}
	v, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return 0, false
	}
	return int(v), true
}

// decodeV4 decodes the 8-hex-char LITTLE-ENDIAN IPv4 address (0100007F ->
// 127.0.0.1, 00000000 -> 0.0.0.0). The kernel prints the 32-bit address in host
// (little-endian on the x86/arm64 hosts netcage targets) byte order, so the hex
// bytes are reversed relative to dotted-quad.
func decodeV4(addrHex string) (net.IP, bool) {
	if len(addrHex) != 8 {
		return nil, false
	}
	raw, err := hex.DecodeString(addrHex)
	if err != nil {
		return nil, false
	}
	// raw is little-endian; reverse to network (big-endian) order.
	ip := net.IPv4(raw[3], raw[2], raw[1], raw[0])
	return ip, true
}

// decodeV6 decodes the 32-hex-char IPv6 address. The kernel stores it as FOUR
// 32-bit words in host (little-endian) byte order, so each 8-hex-char word must
// be byte-reversed to recover the network-order address (e.g. ::1 appears as
// 00000000000000000000000001000000, and :: as all zeroes).
func decodeV6(addrHex string) (net.IP, bool) {
	if len(addrHex) != 32 {
		return nil, false
	}
	raw, err := hex.DecodeString(addrHex)
	if err != nil {
		return nil, false
	}
	out := make(net.IP, net.IPv6len)
	for word := 0; word < 4; word++ {
		// Read the word as little-endian, write it back big-endian.
		v := binary.LittleEndian.Uint32(raw[word*4 : word*4+4])
		binary.BigEndian.PutUint32(out[word*4:word*4+4], v)
	}
	return out, true
}

// renderIP renders the decoded address human-readably: 127.0.0.1 / 0.0.0.0 for
// IPv4, and the canonical compressed form (::1 / :: / a full specific address)
// for IPv6. net.IP.String already produces exactly these forms.
func renderIP(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}
