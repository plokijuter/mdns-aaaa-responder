package main

import (
	"net"
	"syscall"
	"testing"
	"time"
)

func TestOptionsSocketLinux(t *testing.T) {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skip(err)
	}
	defer c.Close()
	if err := regler(c); err != nil {
		t.Fatal(err)
	}
	rc, _ := c.SyscallConn()
	rc.Control(func(fd uintptr) {
		for nom, o := range map[string]struct{ opt, attendu int }{
			"IP_TTL":            {syscall.IP_TTL, 255},
			"IP_MULTICAST_TTL":  {syscall.IP_MULTICAST_TTL, 255},
			"IP_MULTICAST_LOOP": {syscall.IP_MULTICAST_LOOP, 1},
			"IP_MULTICAST_ALL":  {ipMulticastAll, 0},
			"IP_PKTINFO":        {syscall.IP_PKTINFO, 1},
		} {
			v, err := syscall.GetsockoptInt(int(fd), syscall.IPPROTO_IP, o.opt)
			if err != nil || v != o.attendu {
				t.Errorf("%s = %d (%v), attendu %d", nom, v, err, o.attendu)
			}
		}
	})
	// Carte d'arrivee lue sur un vrai paquet (boucle locale).
	e, err := net.DialUDP("udp4", nil, c.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	e.Write([]byte("x"))
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf, oob := make([]byte, 16), make([]byte, 256)
	_, oobn, _, _, err := c.ReadMsgUDP(buf, oob)
	if err != nil {
		t.Fatal(err)
	}
	lo, _ := net.InterfaceByName("lo")
	idx, ok := carteArrivee(oob[:oobn])
	if !ok || lo == nil || idx != lo.Index {
		t.Fatalf("carte d'arrivee %d (%v), attendu lo=%v", idx, ok, lo)
	}
}
