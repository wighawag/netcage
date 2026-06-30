// Command tun-probe is the spike probe for spike-rootless-tun-routing.
//
// It proves the load-bearing assumption behind ADR-0001 (tun2socks sidecar):
// that under rootless Podman a container given /dev/net/tun + CAP_NET_ADMIN can
// stand up a TUN interface, make it the default route, and have a process's
// traffic actually go THROUGH the TUN (observed as raw IP packets readable off
// the TUN fd) rather than out a real gateway.
//
// It is deliberately test-first: the single assertion is "a packet emitted by a
// process in this netns is observed arriving at the TUN fd". The probe exits 0
// only when that holds. Run with -mode=assert-only (no wiring) it is RED
// (exits non-zero) because nothing routes to a TUN; run with -mode=wire it sets
// up the TUN + default route first, then asserts, and goes GREEN iff the kernel
// really delivered the packet to the TUN.
//
// No external `ip` binary is used: the TUN device, address, link-up, and
// default route are all done via the /dev/net/tun ioctl + netlink (raw syscalls
// + golang.org/x/sys/unix would be ideal, but to keep the spike dependency-free
// it uses only the standard library plus the minimal ioctl/netlink wire format).
package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"time"
)

// mode selects whether the probe wires the TUN+route before asserting.
//
//	-mode=assert-only : do NOT set up the TUN/route; just try to observe a packet
//	                    on a TUN fd. This is the RED baseline (no route => nothing
//	                    arrives => non-zero exit), proving the assertion can fail.
//	-mode=wire        : set up the TUN, address, link-up, default route, THEN
//	                    assert. GREEN iff the packet is delivered to the TUN fd.
var mode = flag.String("mode", "wire", "assert-only | wire")

// readResult carries the outcome of one blocking TUN read.
type readResult struct {
	n   int
	err error
}

// offLinkTarget is an address that is NOT on any local subnet, so a packet to it
// must follow the default route. If the default route is the TUN, the packet
// shows up on the TUN fd.
const offLinkTarget = "203.0.113.7:9" // TEST-NET-3 (RFC 5737), guaranteed off-link

func main() {
	flag.Parse()

	// Hard watchdog: under no circumstances should the probe hang. If run() has
	// not returned within 20s, fail loudly so the container exits and --rm cleans
	// up (a hung spike that leaks a container is itself the footgun we are wary
	// of). This is a backstop on top of the per-read select timeout.
	go func() {
		time.Sleep(20 * time.Second)
		fmt.Fprintln(os.Stderr, "PROBE FAIL: watchdog timeout (probe hung)")
		os.Exit(2)
	}()

	msg, err := run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "PROBE FAIL: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(msg)
}

// run returns a human-readable success message, or an error.
//
// The single assertion is "a packet to the off-link target is observed on OUR
// TUN fd". The two modes prove that assertion is meaningful (can both pass when
// wired and FAIL when not):
//
//	-mode=assert-only : open the TUN but do NOT route to it. The off-link packet
//	                    must NOT arrive on the TUN fd. Seeing one is a FAIL (the
//	                    test would be tautological). Seeing none is the expected
//	                    baseline -> distinct "BASELINE" success.
//	-mode=wire        : route the default via the TUN, THEN the packet MUST arrive
//	                    on the TUN fd -> "WIRED" success; absence is a FAIL.
func run() (string, error) {
	tun, err := openTUN("tun-probe0")
	if err != nil {
		return "", fmt.Errorf("open TUN: %w", err)
	}
	defer tun.Close()

	switch *mode {
	case "assert-only":
		arrived, err := packetArrivesOnTUN(tun)
		if err != nil {
			return "", err
		}
		if arrived {
			return "", errors.New("BASELINE BROKEN: a packet reached the TUN fd WITHOUT routing to it (the assertion is tautological and cannot be trusted)")
		}
		return "PROBE BASELINE OK: with no route to the TUN, no off-link packet reached the TUN fd (the assertion is falsifiable; now run -mode=wire)", nil
	case "wire":
		if err := bringUpAndRoute(tun.Name()); err != nil {
			return "", fmt.Errorf("wire TUN+route: %w", err)
		}
		arrived, err := packetArrivesOnTUN(tun)
		if err != nil {
			return "", err
		}
		if !arrived {
			return "", errors.New("no packet observed at TUN fd after wiring the default route: rootless TUN routing did NOT work")
		}
		return "PROBE WIRED OK: with the default route via the TUN, an off-link packet from an in-netns process was observed at the TUN fd (rootless TUN routing works, ADR-0001 confirmed)", nil
	default:
		return "", fmt.Errorf("unknown -mode %q", *mode)
	}
}

// packetArrivesOnTUN sends UDP datagrams to the off-link target and reports
// whether a matching IP packet (destination == off-link target) is observed on
// the TUN fd within the timeout.
//
// The read is raced against a timeout in a select rather than relying on an fd
// read deadline: a TUN char device is not pollable, so we use a raw blocking
// unix.Read in a goroutine bounded by select.
func packetArrivesOnTUN(tun *tunDevice) (bool, error) {
	// Fire traffic to the off-link target in the background, repeatedly, so a
	// late route setup still gets hit.
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			if conn, err := net.DialTimeout("udp", offLinkTarget, 500*time.Millisecond); err == nil {
				_, _ = conn.Write([]byte("tooljail-tun-probe"))
				_ = conn.Close()
			}
			time.Sleep(200 * time.Millisecond)
		}
	}()

	got := make(chan readResult, 1)
	readBuf := make([]byte, 65535)
	go func() {
		n, err := tun.Read(readBuf) // may block; the select bounds us
		got <- readResult{n: n, err: err}
	}()

	dst := net.ParseIP("203.0.113.7").To4()
	deadline := time.After(4 * time.Second)
	for {
		select {
		case r := <-got:
			if r.err != nil {
				return false, fmt.Errorf("reading TUN fd: %w", r.err)
			}
			if isIPv4To(readBuf[:r.n], dst) {
				return true, nil // a packet to OUR off-link target reached the TUN
			}
			// Some other packet (e.g. a stray); keep waiting by re-arming the read.
			go func() {
				n, err := tun.Read(readBuf)
				got <- readResult{n: n, err: err}
			}()
		case <-deadline:
			return false, nil // nothing matching arrived in time
		}
	}
}

// isIPv4To reports whether b is an IPv4 packet whose destination is dst.
func isIPv4To(b []byte, dst net.IP) bool {
	if len(b) < 20 || b[0]>>4 != 4 {
		return false
	}
	return net.IP(b[16:20]).Equal(dst)
}
