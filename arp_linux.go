package main

import (
	"bufio"
	"net"
	"os"
	"strings"
)

// macDe lit l'adresse MAC de ip dans /proc/net/arp, pour la carte d'index
// carte seulement (nil si absente).
func macDe(ip net.IP, carte int) net.HardwareAddr {
	ifi, err := net.InterfaceByIndex(carte)
	if err != nil {
		return nil
	}
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return nil
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		c := strings.Fields(s.Text())
		if len(c) >= 6 && c[5] == ifi.Name && net.ParseIP(c[0]).Equal(ip) {
			if mac, err := net.ParseMAC(c[3]); err == nil && mac.String() != "00:00:00:00:00:00" {
				return mac
			}
		}
	}
	return nil
}
