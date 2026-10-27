package main

import (
	"encoding/binary"
	"errors"
	"net"
	"syscall"
)

// IP_MULTICAST_ALL (linux/in.h) : absent du paquet syscall.
const ipMulticastAll = 49

// regler impose le TTL IP 255 a tout envoi, unicast comme multicast (RFC 6762
// §11 : SHOULD), retablit le retour local du multicast, et isole la reception
// sur la carte choisie : IP_MULTICAST_ALL=0 (sinon Linux livre au socket le
// multicast rejoint par n'importe quel autre service, sur n'importe quelle
// carte) et IP_PKTINFO pour verifier la carte d'arrivee de chaque paquet.
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
			syscall.SetsockoptInt(f, syscall.IPPROTO_IP, syscall.IP_MULTICAST_TTL, ttlIP),
			syscall.SetsockoptInt(f, syscall.IPPROTO_IP, syscall.IP_MULTICAST_LOOP, 1),
			syscall.SetsockoptInt(f, syscall.IPPROTO_IP, ipMulticastAll, 0),
			syscall.SetsockoptInt(f, syscall.IPPROTO_IP, syscall.IP_PKTINFO, 1))
	})
	if err != nil {
		return err
	}
	return errors.Join(errs...)
}

// carteArrivee lit l'index de la carte d'arrivee dans IP_PKTINFO (struct
// in_pktinfo : ipi_ifindex en tete, ordre de la machine).
func carteArrivee(oob []byte) (int, bool) {
	msgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return 0, false
	}
	for _, m := range msgs {
		if m.Header.Level == syscall.IPPROTO_IP && m.Header.Type == syscall.IP_PKTINFO && len(m.Data) >= 4 {
			return int(int32(binary.NativeEndian.Uint32(m.Data[:4]))), true
		}
	}
	return 0, false
}
