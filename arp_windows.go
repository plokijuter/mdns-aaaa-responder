package main

import (
	"net"
	"syscall"
	"unsafe"
)

var getIpNetTable = syscall.NewLazyDLL("iphlpapi.dll").NewProc("GetIpNetTable")

// MIB_IPNETROW (iprtrmib.h).
type ligneARP struct {
	index    uint32
	longueur uint32
	mac      [8]byte
	adresse  [4]byte
	genre    uint32
}

// macDe lit l'adresse MAC de ip dans la table ARP de Windows, pour la carte
// d'index carte seulement (nil si absente).
func macDe(ip net.IP, carte int) net.HardwareAddr {
	v4 := ip.To4()
	if v4 == nil {
		return nil
	}
	var taille uint32
	getIpNetTable.Call(0, uintptr(unsafe.Pointer(&taille)), 0)
	if taille == 0 {
		return nil
	}
	buf := make([]byte, taille+1024)
	taille = uint32(len(buf))
	if r, _, _ := getIpNetTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&taille)), 0); r != 0 {
		return nil
	}
	n := *(*uint32)(unsafe.Pointer(&buf[0]))
	lignes := unsafe.Slice((*ligneARP)(unsafe.Pointer(&buf[4])), n)
	for _, l := range lignes {
		// genre 2 = entree invalide.
		if l.genre != 2 && l.longueur == 6 && int(l.index) == carte && net.IP(l.adresse[:]).Equal(v4) {
			return net.HardwareAddr(append([]byte(nil), l.mac[:6]...))
		}
	}
	return nil
}
