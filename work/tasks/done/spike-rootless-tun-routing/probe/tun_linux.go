//go:build linux

package main

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

// tunDevice is an open TUN interface (the /dev/net/tun fd) plus its kernel name.
//
// Reads go through the RAW fd (unix.Read), not an *os.File, because a TUN char
// device is "not pollable": wrapping it in *os.File makes the Go runtime register
// it with the netpoller, and the read then fails immediately with
// "read /dev/net/tun: not pollable". A raw blocking unix.Read is the correct path
// (the caller bounds it with a select+timeout, since the fd cannot be polled).
type tunDevice struct {
	fd   int
	name string
}

func (t *tunDevice) Name() string { return t.name }
func (t *tunDevice) Close() error { return unix.Close(t.fd) }
func (t *tunDevice) Read(p []byte) (int, error) {
	return unix.Read(t.fd, p)
}

// ifreq layout for the TUNSETIFF ioctl (name[16] + flags).
type ifreqFlags struct {
	name  [unix.IFNAMSIZ]byte
	flags uint16
	_     [22]byte
}

// openTUN opens /dev/net/tun and creates a TUN (IFF_TUN | IFF_NO_PI) interface
// with the requested name. Requires the device to be present and CAP_NET_ADMIN.
func openTUN(name string) (*tunDevice, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/net/tun (is --device /dev/net/tun passed in?): %w", err)
	}

	var req ifreqFlags
	copy(req.name[:], name)
	req.flags = unix.IFF_TUN | unix.IFF_NO_PI

	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(unix.TUNSETIFF),
		uintptr(unsafe.Pointer(&req)),
	)
	if errno != 0 {
		unix.Close(fd)
		return nil, fmt.Errorf("TUNSETIFF ioctl (is CAP_NET_ADMIN present in the userns?): %w", errno)
	}

	// The kernel may have picked the final name (e.g. if %d was used).
	finalName := string(req.name[:])
	if i := indexZero(req.name[:]); i >= 0 {
		finalName = string(req.name[:i])
	}

	return &tunDevice{fd: fd, name: finalName}, nil
}

func indexZero(b []byte) int {
	for i, c := range b {
		if c == 0 {
			return i
		}
	}
	return -1
}

// bringUpAndRoute assigns 10.255.255.1/30 to the TUN, brings the link up, and
// installs a default route via the TUN, all via netlink (no `ip` binary).
func bringUpAndRoute(ifName string) error {
	link, err := netlinkLinkByName(ifName)
	if err != nil {
		return fmt.Errorf("find link %q: %w", ifName, err)
	}
	if err := netlinkAddrAdd(link, "10.255.255.1", 30); err != nil {
		return fmt.Errorf("add addr: %w", err)
	}
	if err := netlinkLinkUp(link); err != nil {
		return fmt.Errorf("link up: %w", err)
	}
	if err := netlinkDefaultRoute(link); err != nil {
		return fmt.Errorf("default route: %w", err)
	}
	return nil
}
