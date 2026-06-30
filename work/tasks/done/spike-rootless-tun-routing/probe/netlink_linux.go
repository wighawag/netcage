//go:build linux

// Minimal netlink (RTNETLINK) helpers using only golang.org/x/sys/unix.
//
// These do the equivalent of:
//
//	ip addr add 10.255.255.1/30 dev <tun>
//	ip link set <tun> up
//	ip route add default dev <tun>
//
// without shelling out to `ip`, so the spike's container image needs no
// iproute2. Kept deliberately small: enough to wire one TUN for the spike, not a
// general netlink library.
package main

import (
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/unix"
)

type nlLink struct {
	index int
}

// netlinkLinkByName resolves an interface name to its index.
func netlinkLinkByName(name string) (*nlLink, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	return &nlLink{index: iface.Index}, nil
}

// nlConn is a single-use netlink socket.
type nlConn struct {
	fd  int
	seq uint32
}

func dialNetlink() (*nlConn, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, fmt.Errorf("netlink socket: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("netlink bind: %w", err)
	}
	return &nlConn{fd: fd}, nil
}

func (c *nlConn) close() { unix.Close(c.fd) }

// execute sends one RTNETLINK request (with ACK requested) and waits for the ACK.
func (c *nlConn) execute(msgType int, flags int, payload []byte, attrs []byte) error {
	c.seq++
	body := append(append([]byte{}, payload...), attrs...)
	total := unix.NLMSG_HDRLEN + len(body)

	hdr := make([]byte, unix.NLMSG_HDRLEN)
	*(*uint32)(unsafe.Pointer(&hdr[0])) = uint32(total)
	*(*uint16)(unsafe.Pointer(&hdr[4])) = uint16(msgType)
	*(*uint16)(unsafe.Pointer(&hdr[6])) = uint16(unix.NLM_F_REQUEST | unix.NLM_F_ACK | flags)
	*(*uint32)(unsafe.Pointer(&hdr[8])) = c.seq
	*(*uint32)(unsafe.Pointer(&hdr[12])) = 0

	msg := append(hdr, body...)
	if err := unix.Sendto(c.fd, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return fmt.Errorf("netlink send: %w", err)
	}

	resp := make([]byte, 4096)
	n, _, err := unix.Recvfrom(c.fd, resp, 0)
	if err != nil {
		return fmt.Errorf("netlink recv: %w", err)
	}
	if n < unix.NLMSG_HDRLEN {
		return fmt.Errorf("short netlink response (%d bytes)", n)
	}
	// NLMSG_ERROR carries the errno at offset NLMSG_HDRLEN (0 == ACK).
	mtype := *(*uint16)(unsafe.Pointer(&resp[4]))
	if mtype == unix.NLMSG_ERROR {
		errno := *(*int32)(unsafe.Pointer(&resp[unix.NLMSG_HDRLEN]))
		if errno != 0 {
			return fmt.Errorf("netlink ack errno %d (%s)", -errno, unix.Errno(-errno))
		}
	}
	return nil
}

func attr(typ uint16, data []byte) []byte {
	const hdr = 4
	l := hdr + len(data)
	out := make([]byte, (l+3)&^3) // align to 4
	*(*uint16)(unsafe.Pointer(&out[0])) = uint16(l)
	*(*uint16)(unsafe.Pointer(&out[2])) = typ
	copy(out[hdr:], data)
	return out
}

// netlinkAddrAdd adds ipv4/prefix to the link.
func netlinkAddrAdd(link *nlLink, ip string, prefix int) error {
	c, err := dialNetlink()
	if err != nil {
		return err
	}
	defer c.close()

	v4 := net.ParseIP(ip).To4()
	if v4 == nil {
		return fmt.Errorf("not an IPv4 address: %s", ip)
	}

	// struct ifaddrmsg { family, prefixlen, flags, scope, index }
	ifa := make([]byte, 8)
	ifa[0] = unix.AF_INET
	ifa[1] = byte(prefix)
	*(*uint32)(unsafe.Pointer(&ifa[4])) = uint32(link.index)

	attrs := append(attr(unix.IFA_LOCAL, v4), attr(unix.IFA_ADDRESS, v4)...)
	return c.execute(unix.RTM_NEWADDR, unix.NLM_F_CREATE|unix.NLM_F_REPLACE, ifa, attrs)
}

// netlinkLinkUp sets IFF_UP on the link.
func netlinkLinkUp(link *nlLink) error {
	c, err := dialNetlink()
	if err != nil {
		return err
	}
	defer c.close()

	// struct ifinfomsg { family, _, type, index, flags, change }
	ifi := make([]byte, 16)
	ifi[0] = unix.AF_UNSPEC
	*(*int32)(unsafe.Pointer(&ifi[4])) = int32(link.index)
	*(*uint32)(unsafe.Pointer(&ifi[8])) = unix.IFF_UP  // flags
	*(*uint32)(unsafe.Pointer(&ifi[12])) = unix.IFF_UP // change mask
	return c.execute(unix.RTM_NEWLINK, 0, ifi, nil)
}

// netlinkDefaultRoute installs `default dev <link>` (no gateway; point-to-point TUN).
func netlinkDefaultRoute(link *nlLink) error {
	c, err := dialNetlink()
	if err != nil {
		return err
	}
	defer c.close()

	// struct rtmsg { family, dst_len, src_len, tos, table, protocol, scope, type, flags }
	rtm := make([]byte, 12)
	rtm[0] = unix.AF_INET
	rtm[1] = 0 // dst_len 0 == default
	rtm[4] = unix.RT_TABLE_MAIN
	rtm[5] = unix.RTPROT_BOOT
	rtm[6] = unix.RT_SCOPE_UNIVERSE
	rtm[7] = unix.RTN_UNICAST

	oif := make([]byte, 4)
	*(*uint32)(unsafe.Pointer(&oif[0])) = uint32(link.index)
	attrs := attr(unix.RTA_OIF, oif)

	return c.execute(unix.RTM_NEWROUTE, unix.NLM_F_CREATE|unix.NLM_F_REPLACE, rtm, attrs)
}
