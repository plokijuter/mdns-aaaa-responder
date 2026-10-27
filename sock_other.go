//go:build !windows && !linux

package main

import (
	"errors"
	"net"
	"syscall"
)

// regler : TTL IP 255 et retour local du multicast. Plate-forme non prise en
// charge officiellement (seuls Windows et Linux le sont).
func regler(c *net.UDPConn) error {
	rc, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var errs []error
	err = rc.Control(func(fd uintptr) {
		f := int(fd)
		errs = append(errs,
			syscall.SetsockoptInt(f, syscall.IPPROTO_IP, syscall.IP_TTL, ttlIP),
			syscall.SetsockoptInt(f, syscall.IPPROTO_IP, syscall.IP_MULTICAST_TTL, ttlIP))
	})
	if err != nil {
		return err
	}
	return errors.Join(errs...)
}

func carteArrivee(oob []byte) (int, bool) { return 0, false }
