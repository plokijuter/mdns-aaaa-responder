package main

import (
	"errors"
	"net"
	"syscall"
)

// regler impose le TTL IP 255 a tout envoi, unicast comme multicast (RFC 6762
// §11 : SHOULD, certains clients ignorent les reponses d'un autre TTL), et
// retablit le retour local du multicast : Go le coupe, et sous Windows cela
// empeche aussi de RECEVOIR ce que la machine elle-meme emet (une vraie AAAA
// annoncee par Windows doit etre vue).
func regler(c *net.UDPConn) error {
	rc, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var errs []error
	err = rc.Control(func(fd uintptr) {
		h := syscall.Handle(fd)
		errs = append(errs,
			syscall.SetsockoptInt(h, syscall.IPPROTO_IP, syscall.IP_TTL, ttlIP),
			syscall.SetsockoptInt(h, syscall.IPPROTO_IP, syscall.IP_MULTICAST_TTL, ttlIP),
			syscall.SetsockoptInt(h, syscall.IPPROTO_IP, syscall.IP_MULTICAST_LOOP, 1))
	})
	if err != nil {
		return err
	}
	return errors.Join(errs...)
}

// carteArrivee : non disponible ici ; le filtrage se fait par le sous-reseau de
// la source, et Windows ne livre le multicast que pour le groupe rejoint sur
// la carte choisie.
func carteArrivee(oob []byte) (int, bool) { return 0, false }
