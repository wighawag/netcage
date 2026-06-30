// Command dialer is the in-container probe client for the pasta reachback spike.
// It attempts a short TCP connect+read to a target and reports REACHED:<banner>
// or UNREACHABLE, exiting 0 on reach and non-zero on failure to connect.
//
// It is run INSIDE the container (the sidecar netns or a --network none netns)
// against the host-loopback proxy/control ports (translated by pasta's
// --map-host-loopback to refer to the host). The -want flag makes the probe
// self-asserting so the spike's expectation is encoded in the probe itself:
//
//	-want=reach   : exit 0 iff the target is reached (else fail)
//	-want=blocked : exit 0 iff the target is NOT reached (else fail) -- the
//	                leak-proof negative assertion
package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
	"time"
)

func main() {
	target := flag.String("target", "", "host:port to dial (the pasta-mapped host loopback addr)")
	want := flag.String("want", "reach", "reach | blocked")
	flag.Parse()

	reached, banner := tryDial(*target)

	switch *want {
	case "reach":
		if reached {
			fmt.Printf("OK reach %s -> %s\n", *target, banner)
			os.Exit(0)
		}
		fmt.Fprintf(os.Stderr, "FAIL: wanted to REACH %s but it was unreachable\n", *target)
		os.Exit(1)
	case "blocked":
		if !reached {
			fmt.Printf("OK blocked %s (correctly unreachable)\n", *target)
			os.Exit(0)
		}
		fmt.Fprintf(os.Stderr, "LEAK: wanted %s BLOCKED but it was reachable (-> %s)\n", *target, banner)
		os.Exit(1)
	default:
		fmt.Fprintf(os.Stderr, "unknown -want %q\n", *want)
		os.Exit(2)
	}
}

func tryDial(target string) (reached bool, banner string) {
	c, err := net.DialTimeout("tcp", target, 2*time.Second)
	if err != nil {
		return false, ""
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		// Connected but no banner; still counts as reached (TCP handshake done).
		return true, "(connected, no banner)"
	}
	return true, line[:len(line)-1]
}
