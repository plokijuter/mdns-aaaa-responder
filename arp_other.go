//go:build !windows && !linux

package main

import "net"

// macDe : table ARP non lue sur cette plate-forme (seuls Windows et Linux sont
// pris en charge) ; la detection Amazon par MAC est alors inactive.
func macDe(ip net.IP, carte int) net.HardwareAddr { return nil }
