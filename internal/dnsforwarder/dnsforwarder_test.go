package dnsforwarder_test

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wighawag/netcage/internal/dnsforwarder"
)

const uniqueName = "unique.netcage.test"
const answerIP = "203.0.113.55"

// TestForwarder_ResolvesThroughProxyNotHost proves the DNS-to-SOCKS-TCP bridge:
// a UDP query to the forwarder is resolved via the SOCKS proxy over TCP, the
// proxy-side resolver answers, and the host resolver is never consulted.
func TestForwarder_ResolvesThroughProxyNotHost(t *testing.T) {
	resolver := startDNSOverTCP(t)
	proxyAddr := startSOCKS(t, resolver.addr)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fwd, err := dnsforwarder.Start(ctx, dnsforwarder.Config{
		Listen:    "127.0.0.1:0",
		ProxyAddr: proxyAddr,
		Upstream:  "dns.netcage.test:53", // a hostname resolved proxy-side
	})
	if err != nil {
		t.Fatalf("start forwarder: %v", err)
	}
	defer fwd.Close()

	ip := queryA(t, fwd.Addr(), uniqueName)
	if ip != answerIP {
		t.Fatalf("resolved %s to %q, want %q (proxy-side answer)", uniqueName, ip, answerIP)
	}
	// The proxy-side resolver must have seen the name (proof it went through the proxy).
	if !resolver.saw(uniqueName) {
		t.Fatalf("proxy-side resolver never saw %q; it did not resolve through the proxy", uniqueName)
	}
}

// TestForwarder_ResolvesOverTCP proves the TCP listener (RFC 7766 DNS-over-TCP):
// a glibc client honouring resolv.conf's `use-vc` queries the forwarder over TCP
// and gets the proxy-side answer. This is the path a UDP-only forwarder missed,
// leaving glibc images (node/debian) with EAI_AGAIN.
func TestForwarder_ResolvesOverTCP(t *testing.T) {
	resolver := startDNSOverTCP(t)
	proxyAddr := startSOCKS(t, resolver.addr)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fwd, err := dnsforwarder.Start(ctx, dnsforwarder.Config{
		Listen:    "127.0.0.1:0",
		ProxyAddr: proxyAddr,
		Upstream:  "dns.netcage.test:53",
	})
	if err != nil {
		t.Fatalf("start forwarder: %v", err)
	}
	defer fwd.Close()

	conn, err := net.Dial("tcp", fwd.TCPAddr())
	if err != nil {
		t.Fatalf("dial forwarder tcp: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	q := buildAQuery(uniqueName)
	framed := make([]byte, 2+len(q))
	binary.BigEndian.PutUint16(framed[:2], uint16(len(q)))
	copy(framed[2:], q)
	if _, err := conn.Write(framed); err != nil {
		t.Fatalf("write tcp query: %v", err)
	}

	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		t.Fatalf("read tcp resp length: %v", err)
	}
	resp := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("read tcp resp: %v", err)
	}
	if ip := parseFirstA(resp); ip != answerIP {
		t.Fatalf("TCP resolved %s to %q, want %q (proxy-side answer)", uniqueName, ip, answerIP)
	}
	if !resolver.saw(uniqueName) {
		t.Fatalf("proxy-side resolver never saw %q over the TCP path", uniqueName)
	}
}

// TestForwarder_FailsClosedWhenProxyDown asserts that with the proxy unreachable,
// the forwarder gives NO answer (no fallback to a host resolver).
func TestForwarder_FailsClosedWhenProxyDown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fwd, err := dnsforwarder.Start(ctx, dnsforwarder.Config{
		Listen:    "127.0.0.1:0",
		ProxyAddr: "127.0.0.1:1", // nothing listening
		Upstream:  "dns.netcage.test:53",
	})
	if err != nil {
		t.Fatalf("start forwarder: %v", err)
	}
	defer fwd.Close()

	conn, err := net.Dial("udp", fwd.Addr())
	if err != nil {
		t.Fatalf("dial forwarder: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write(buildAQuery(uniqueName)); err != nil {
		t.Fatalf("write query: %v", err)
	}
	buf := make([]byte, 512)
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("got a DNS answer with the proxy down; want fail-closed (no answer)")
	}
}

// ---- in-test SOCKS5 proxy + DNS-over-TCP resolver ----

type dnsResolver struct {
	addr   string
	mu     sync.Mutex
	seened []string
}

func (r *dnsResolver) record(n string) { r.mu.Lock(); r.seened = append(r.seened, n); r.mu.Unlock() }
func (r *dnsResolver) saw(n string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range r.seened {
		if strings.EqualFold(s, n) {
			return true
		}
	}
	return false
}

func startDNSOverTCP(t *testing.T) *dnsResolver {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("dns resolver listen: %v", err)
	}
	r := &dnsResolver{addr: ln.Addr().String()}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				var l [2]byte
				if _, err := io.ReadFull(c, l[:]); err != nil {
					return
				}
				msg := make([]byte, binary.BigEndian.Uint16(l[:]))
				if _, err := io.ReadFull(c, msg); err != nil {
					return
				}
				name := decodeName(msg[12:])
				r.record(name)
				resp := buildAResponse(msg, name)
				out := make([]byte, 2+len(resp))
				binary.BigEndian.PutUint16(out[:2], uint16(len(resp)))
				copy(out[2:], resp)
				_, _ = c.Write(out)
			}(c)
		}
	}()
	return r
}

func startSOCKS(t *testing.T, upstream string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("socks listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				ver, _ := br.ReadByte()
				n, _ := br.ReadByte()
				io.CopyN(io.Discard, br, int64(n))
				if ver != 5 {
					return
				}
				c.Write([]byte{5, 0})
				hdr := make([]byte, 4)
				if _, err := io.ReadFull(br, hdr); err != nil {
					return
				}
				if hdr[3] != 3 { // require domain (socks5h)
					c.Write([]byte{5, 8, 0, 1, 0, 0, 0, 0, 0, 0})
					return
				}
				l, _ := br.ReadByte()
				nameb := make([]byte, l)
				io.ReadFull(br, nameb)
				pb := make([]byte, 2)
				io.ReadFull(br, pb)
				// socks5h: resolve the upstream name proxy-side -> the test resolver.
				up, err := net.DialTimeout("tcp", upstream, 3*time.Second)
				if err != nil {
					c.Write([]byte{5, 4, 0, 1, 0, 0, 0, 0, 0, 0})
					return
				}
				defer up.Close()
				c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
				go io.Copy(up, br)
				io.Copy(c, up)
			}(c)
		}
	}()
	return ln.Addr().String()
}

// ---- tiny DNS wire helpers (A only) ----

func buildAQuery(name string) []byte {
	msg := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	msg = append(msg, encodeName(name)...)
	return append(msg, 0, 1, 0, 1)
}

func buildAResponse(query []byte, name string) []byte {
	resp := make([]byte, len(query))
	copy(resp, query)
	resp[2], resp[3] = 0x81, 0x80
	if !strings.EqualFold(name, uniqueName) {
		resp[3] = 0x83
		return resp
	}
	resp[6], resp[7] = 0, 1
	ans := []byte{0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4}
	ans = append(ans, net.ParseIP(answerIP).To4()...)
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

func decodeName(b []byte) string {
	var parts []string
	for len(b) > 0 {
		l := int(b[0])
		if l == 0 || 1+l > len(b) {
			break
		}
		parts = append(parts, string(b[1:1+l]))
		b = b[1+l:]
	}
	return strings.Join(parts, ".")
}

func queryA(t *testing.T, forwarder, name string) string {
	t.Helper()
	conn, err := net.Dial("udp", forwarder)
	if err != nil {
		t.Fatalf("dial forwarder: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
	if _, err := conn.Write(buildAQuery(name)); err != nil {
		t.Fatalf("write query: %v", err)
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read answer (DNS did not resolve through the proxy): %v", err)
	}
	return parseFirstA(buf[:n])
}

func parseFirstA(resp []byte) string {
	for i := 12; i+16 <= len(resp); i++ {
		if resp[i] == 0xc0 && resp[i+1] == 0x0c &&
			resp[i+2] == 0 && resp[i+3] == 1 &&
			resp[i+4] == 0 && resp[i+5] == 1 &&
			resp[i+10] == 0 && resp[i+11] == 4 {
			return net.IP(resp[i+12 : i+16]).String()
		}
	}
	return ""
}
