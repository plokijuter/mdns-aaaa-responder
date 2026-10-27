package main

import (
	"net"
	"syscall"
)

// regler impose le TTL IP 255 exige pour le mDNS (RFC 6762 §11) et
// retablit le retour local du multicast.
func regler(c *net.UDPConn) error {
	rc, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var e error
	err = rc.Control(func(fd uintptr) {
		e = syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IP, syscall.IP_MULTICAST_TTL, 255)
		if e == nil {
			// Go coupe le retour local du multicast ; sous Windows cela empeche
			// aussi de RECEVOIR ce que la machine elle-meme emet. Or il faut voir
			// une vraie AAAA annoncee par Windows.
			e = syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IP, syscall.IP_MULTICAST_LOOP, 1)
		}
	})
	if err != nil {
		return err
	}
	return e
}
