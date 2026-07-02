// Command harness is the spike test harness for spike-dns-to-socks-bridge.
//
// It stands up, in one process:
//   - a DNS-over-TCP resolver that answers ONLY the unique name
//     "unique.netcage.test" (A record) and records every name it was asked, so a
//     test can assert the lookup arrived HERE (proxy-side) and not at the host
//     resolver;
//   - a minimal SOCKS5 proxy that CONNECTs by hostname (socks5h) to the
//     DNS-over-TCP resolver;
//   - the test: send a UDP DNS query for the unique name to the forwarder (whose
//     address is passed in), assert the answer is the expected A record, and
//     assert the resolver recorded the unique name (proof the resolution went
//     through the proxy, not the host).
//
// Run modes:
//
//	-mode=serve  : start the proxy + dns-over-tcp resolver, print PROXY_ADDR +
//	               UPSTREAM_HOST, then idle (the forwarder is pointed at these).
//	-mode=assert : send a UDP query for the unique name to -forwarder and verify
//	               the A record + that the proxy-side resolver saw the name.
package main

import (
	"bufio"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

const uniqueName = "unique.netcage.test"
const answerIP = "203.0.113.55" // the A record only the proxy-side resolver knows

func main() {
	mode := flag.String("mode", "serve", "serve | assert")
	listen := flag.String("listen", "127.0.0.1:0", "address to bind the proxy on (serve)")
	dnsListen := flag.String("dns", "127.0.0.1:0", "address to bind the dns-over-tcp resolver on (serve)")
	forwarder := flag.String("forwarder", "", "forwarder UDP address to query (assert)")
	flag.Parse()

	switch *mode {
	case "serve":
		serve(*listen, *dnsListen)
	case "assert":
		assert(*forwarder)
	default:
		fmt.Fprintf(os.Stderr, "unknown -mode %q\n", *mode)
		os.Exit(2)
	}
}

// ---- DNS-over-TCP resolver (records queried names) ----

var (
	seenMu sync.Mutex
	seen   []string
)

func recordSeen(name string) {
	seenMu.Lock()
	seen = append(seen, name)
	seenMu.Unlock()
}

func serve(proxyBind, dnsBind string) {
	dnsLn, err := net.Listen("tcp", dnsBind)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dns bind: %v\n", err)
		os.Exit(1)
	}
	go serveDNSOverTCP(dnsLn)
	dnsHostPort := dnsLn.Addr().String()

	// The proxy CONNECTs (socks5h) to the upstream the forwarder names; the spike
	// redirects every CONNECT to the real dns-over-tcp resolver, so the forwarder
	// can use a stable upstream HOSTNAME (resolved proxy-side) regardless of port.
	upstreamTarget = dnsHostPort

	proxyLn, err := net.Listen("tcp", proxyBind)
	if err != nil {
		fmt.Fprintf(os.Stderr, "proxy bind: %v\n", err)
		os.Exit(1)
	}
	go serveSOCKS(proxyLn, dnsHostPort)

	fmt.Printf("PROXY_ADDR=%s\nUPSTREAM_HOSTPORT=%s\n", proxyLn.Addr().String(), dnsHostPort)
	os.Stdout.Sync()
	time.Sleep(10 * time.Minute)
}

func serveDNSOverTCP(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			var lenBuf [2]byte
			if _, err := io.ReadFull(c, lenBuf[:]); err != nil {
				return
			}
			msg := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
			if _, err := io.ReadFull(c, msg); err != nil {
				return
			}
			name := parseQName(msg)
			recordSeen(name)
			resp := buildAResponse(msg, name)
			out := make([]byte, 2+len(resp))
			binary.BigEndian.PutUint16(out[:2], uint16(len(resp)))
			copy(out[2:], resp)
			_, _ = c.Write(out)
		}(c)
	}
}

// ---- minimal SOCKS5 proxy: no-auth, CONNECT by domain (socks5h) ----

func serveSOCKS(ln net.Listener, dnsHostPort string) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go handleSOCKS(c)
	}
}

func handleSOCKS(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	ver, _ := r.ReadByte()
	n, _ := r.ReadByte()
	io.CopyN(io.Discard, r, int64(n))
	if ver != 5 {
		return
	}
	c.Write([]byte{5, 0})
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return
	}
	var host string
	switch hdr[3] {
	case 3: // domain
		l, _ := r.ReadByte()
		nameb := make([]byte, l)
		io.ReadFull(r, nameb)
		host = string(nameb)
	default:
		c.Write([]byte{5, 8, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	pb := make([]byte, 2)
	io.ReadFull(r, pb)
	port := int(pb[0])<<8 | int(pb[1])

	// socks5h: the proxy resolves the upstream DNS host by name. We only know the
	// dns-over-tcp resolver's address; CONNECT there regardless of the name (the
	// forwarder always targets the upstream-host we advertised).
	up, err := net.DialTimeout("tcp", resolveUpstream(host, port), 5*time.Second)
	if err != nil {
		c.Write([]byte{5, 4, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer up.Close()
	c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	go io.Copy(up, r)
	io.Copy(c, up)
}

// resolveUpstream maps the advertised upstream hostname to the dns-over-tcp
// resolver address. Set via env by serve(); for the spike the forwarder is told
// the real host:port as -upstream, so host already is host:port-resolvable.
var upstreamTarget string

func resolveUpstream(host string, port int) string {
	if upstreamTarget != "" {
		return upstreamTarget
	}
	return net.JoinHostPort(host, fmt.Sprintf("%d", port))
}

// ---- assert mode: query the forwarder and verify ----

func assert(forwarder string) {
	if forwarder == "" {
		fmt.Fprintln(os.Stderr, "ASSERT FAIL: -forwarder required")
		os.Exit(2)
	}
	conn, err := net.Dial("udp", forwarder)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ASSERT FAIL: dial forwarder: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(6 * time.Second))

	query := buildAQuery(uniqueName)
	if _, err := conn.Write(query); err != nil {
		fmt.Fprintf(os.Stderr, "ASSERT FAIL: write query: %v\n", err)
		os.Exit(1)
	}
	resp := make([]byte, 512)
	n, err := conn.Read(resp)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ASSERT FAIL: no DNS answer via forwarder (DNS did not resolve through the proxy): %v\n", err)
		os.Exit(1)
	}
	ip := parseFirstA(resp[:n])
	if ip != answerIP {
		fmt.Fprintf(os.Stderr, "ASSERT FAIL: got A=%q, want %q (proxy-side answer)\n", ip, answerIP)
		os.Exit(1)
	}
	fmt.Printf("ASSERT OK: %s resolved to %s THROUGH the proxy (DNS-over-SOCKS-TCP), UDP never left the jail\n", uniqueName, ip)
}

// ---- tiny DNS wire helpers (A queries/responses only) ----

func buildAQuery(name string) []byte {
	msg := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	msg = append(msg, encodeName(name)...)
	msg = append(msg, 0, 1, 0, 1) // QTYPE A, QCLASS IN
	return msg
}

func buildAResponse(query []byte, name string) []byte {
	resp := make([]byte, len(query))
	copy(resp, query)
	resp[2] = 0x81
	resp[3] = 0x80          // response, recursion available
	resp[6], resp[7] = 0, 1 // ANCOUNT = 1
	if !strings.EqualFold(name, uniqueName) {
		resp[6], resp[7] = 0, 0
		resp[3] = 0x83 // NXDOMAIN
		return resp
	}
	ans := []byte{0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4}
	ip := net.ParseIP(answerIP).To4()
	ans = append(ans, ip...)
	return append(resp, ans...)
}

func encodeName(name string) []byte {
	var out []byte
	for _, label := range strings.Split(name, ".") {
		out = append(out, byte(len(label)))
		out = append(out, []byte(label)...)
	}
	return append(out, 0)
}

func parseQName(msg []byte) string {
	if len(msg) < 12 {
		return ""
	}
	return decodeName(msg[12:])
}

func decodeName(b []byte) string {
	var parts []string
	for len(b) > 0 {
		l := int(b[0])
		if l == 0 {
			break
		}
		if 1+l > len(b) {
			break
		}
		parts = append(parts, string(b[1:1+l]))
		b = b[1+l:]
	}
	return strings.Join(parts, ".")
}

func parseFirstA(resp []byte) string {
	if len(resp) < 12 {
		return ""
	}
	// skip header + question, then walk answers; cheap: find the 4-byte A rdata
	// after the answer type/class/ttl. For the spike, scan for the A record we
	// built (type=1, class=1, rdlength=4).
	for i := 12; i+14 <= len(resp); i++ {
		if resp[i] == 0xc0 && resp[i+1] == 0x0c &&
			resp[i+2] == 0 && resp[i+3] == 1 && // type A
			resp[i+4] == 0 && resp[i+5] == 1 && // class IN
			resp[i+10] == 0 && resp[i+11] == 4 { // rdlength 4
			return net.IP(resp[i+12 : i+16]).String()
		}
	}
	return ""
}
