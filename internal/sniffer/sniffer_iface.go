// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package sniffer

import (
	"fmt"
	"net"
)

// localInterfaceByIP returns the first network interface that owns the given
// IP address. Returns an error if the IP is not assigned to any interface.
// The comparison is exact (host-part only, not CIDR prefix match).
// Works for both IPv4 and IPv6, including zone-stripped IPv6 addresses.
func localInterfaceByIP(ip net.IP) (*net.Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("enumerate interfaces: %w", err)
	}
	for i := range ifaces {
		addrs, err := ifaces[i].Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ifaceIP net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ifaceIP = v.IP
			case *net.IPAddr:
				ifaceIP = v.IP
			}
			if ifaceIP != nil && ip.Equal(ifaceIP) {
				return &ifaces[i], nil
			}
		}
	}
	return nil, fmt.Errorf("address %s not assigned to any local interface", ip)
}

// localIPsOnInterface returns all IPv4 and IPv6 addresses assigned to iface.
func localIPsOnInterface(iface *net.Interface) ([]net.IP, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		switch v := a.(type) {
		case *net.IPNet:
			ips = append(ips, v.IP)
		case *net.IPAddr:
			ips = append(ips, v.IP)
		}
	}
	return ips, nil
}

// isWildcardAddr reports whether addr is a wildcard/listen-all address
// (IPv4 0.0.0.0 or IPv6 ::). An empty string is also treated as wildcard.
func isWildcardAddr(addr string) bool {
	if addr == "" {
		return true
	}
	ip := net.ParseIP(addr)
	return ip != nil && ip.IsUnspecified()
}

// hasAnyWildcard returns true if any address in the list is a wildcard.
func hasAnyWildcard(addresses []string) bool {
	for _, a := range addresses {
		if isWildcardAddr(a) {
			return true
		}
	}
	return false
}

// validateListenAddresses checks that each non-wildcard address in the list
// is assigned to a local network interface. Returns a descriptive error on
// the first address that cannot be resolved. Wildcards (0.0.0.0, ::) and
// empty strings are silently accepted.
//
// Call this before creating sniffers so the server fails fast with a clear
// message instead of silently capturing on the wrong interface.
func validateListenAddresses(addresses []string) error {
	for _, addr := range addresses {
		if isWildcardAddr(addr) {
			continue
		}
		ip := net.ParseIP(addr)
		if ip == nil {
			return fmt.Errorf("invalid listen_address %q: not a valid IP address", addr)
		}
		if _, err := localInterfaceByIP(ip); err != nil {
			return fmt.Errorf(
				"listen_address %s is not assigned to any local interface "+
					"(use 0.0.0.0 for all IPv4 interfaces, :: for all IPv6): %w",
				addr, err,
			)
		}
	}
	return nil
}

// listLocalAddresses returns all non-loopback IPv4 and IPv6 addresses on
// the machine -- useful for diagnostic error messages.
func listLocalAddresses() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []string
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
				out = append(out, fmt.Sprintf("%s (%s)", ip, iface.Name))
			}
		}
	}
	return out
}
