// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package client

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"net"
	"time"
)

// DefaultStunServers are the built-in STUN servers written into new client configs.
// They are NOT used as a runtime fallback -- if stunServers is nil or empty, STUN is
// disabled and a warning is printed instead.
var DefaultStunServers = []string{
	"stun.cloudflare.com:3478",
	"stun.l.google.com:19302",
	"stun1.l.google.com:19302",
}

// stunMagicCookie is the STUN protocol magic cookie (RFC 5389).
var stunMagicCookie = []byte{0x21, 0x12, 0xA4, 0x42}

// detectWANIP tries to determine the client's public (WAN) IP address.
// Uses STUN Binding Request - a lightweight, no-dependency UDP protocol.
// Returns empty string and error if all servers fail or none are provided.
func detectWANIP(servers []string) (string, error) {
	if len(servers) == 0 {
		return "", fmt.Errorf("no STUN servers configured")
	}
	var lastErr error
	for _, server := range servers {
		ip, err := stunBindingRequest(server)
		if err == nil {
			return ip, nil
		}
		lastErr = err
	}
	return "", fmt.Errorf("WAN IP detection failed (tried %d STUN servers): %w", len(servers), lastErr)
}

// stunBindingRequest sends a STUN Binding Request and parses the response.
// Returns the XOR-MAPPED-ADDRESS (client's public IP as seen by the server).
func stunBindingRequest(server string) (string, error) {
	conn, err := net.DialTimeout("udp", server, 3*time.Second)
	if err != nil {
		return "", fmt.Errorf("dial %s: %w", server, err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(3 * time.Second))

	// Build STUN Binding Request (RFC 5389 Sec.6)
	// Header: type(2) + length(2) + magic_cookie(4) + transaction_id(12) = 20 bytes
	var txID [12]byte
	if _, err := rand.Read(txID[:]); err != nil {
		return "", fmt.Errorf("generate transaction ID: %w", err)
	}

	req := make([]byte, 20)
	req[0], req[1] = 0x00, 0x01 // Type: Binding Request
	req[2], req[3] = 0x00, 0x00 // Length: 0 (no attributes)
	copy(req[4:8], stunMagicCookie)
	copy(req[8:20], txID[:])

	if _, err := conn.Write(req); err != nil {
		return "", fmt.Errorf("send STUN request: %w", err)
	}

	// Read response
	resp := make([]byte, 128)
	n, err := conn.Read(resp)
	if err != nil {
		return "", fmt.Errorf("read STUN response: %w", err)
	}

	return parseSTUNResponse(resp[:n], txID)
}

// parseSTUNResponse extracts the mapped address from a STUN Binding Response.
func parseSTUNResponse(data []byte, txID [12]byte) (string, error) {
	if len(data) < 20 {
		return "", fmt.Errorf("STUN response too short: %d bytes", len(data))
	}

	// Verify Binding Success Response (0x0101)
	if data[0] != 0x01 || data[1] != 0x01 {
		return "", fmt.Errorf("unexpected STUN response type: 0x%02x%02x", data[0], data[1])
	}

	// Verify magic cookie
	if !bytes.Equal(data[4:8], stunMagicCookie) {
		return "", fmt.Errorf("STUN magic cookie mismatch")
	}

	// Verify transaction ID
	if !bytes.Equal(data[8:20], txID[:]) {
		return "", fmt.Errorf("STUN transaction ID mismatch")
	}

	// Parse message length and attributes
	msgLen := int(data[2])<<8 | int(data[3])
	if len(data) < 20+msgLen {
		return "", fmt.Errorf("STUN response truncated")
	}

	attrs := data[20 : 20+msgLen]
	for len(attrs) >= 4 {
		attrType := int(attrs[0])<<8 | int(attrs[1])
		attrLen := int(attrs[2])<<8 | int(attrs[3])

		if len(attrs) < 4+attrLen {
			break
		}

		attrData := attrs[4 : 4+attrLen]

		// XOR-MAPPED-ADDRESS (0x0020) - preferred
		// MAPPED-ADDRESS (0x0001) - fallback
		if (attrType == 0x0020 || attrType == 0x0001) && attrLen >= 8 {
			family := attrData[1]
			if family == 0x01 { // IPv4
				var ip [4]byte
				copy(ip[:], attrData[4:8])

				if attrType == 0x0020 {
					// XOR with magic cookie (RFC 5389 Sec.15.2)
					ip[0] ^= 0x21
					ip[1] ^= 0x12
					ip[2] ^= 0xA4
					ip[3] ^= 0x42
				}

				return fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]), nil
			}
			if family == 0x02 && attrLen >= 20 { // IPv6
				var ip [16]byte
				copy(ip[:], attrData[4:20])

				if attrType == 0x0020 {
					// XOR with magic cookie + transaction ID
					xor := make([]byte, 16)
					copy(xor[0:4], stunMagicCookie)
					copy(xor[4:16], txID[:])
					for i := 0; i < 16; i++ {
						ip[i] ^= xor[i]
					}
				}

				return net.IP(ip[:]).String(), nil
			}
		}

		// Advance to next attribute (padded to 4-byte boundary)
		padded := attrLen
		if padded%4 != 0 {
			padded += 4 - padded%4
		}
		attrs = attrs[4+padded:]
	}

	return "", fmt.Errorf("no mapped address found in STUN response")
}

// reservedIPv4Ranges contains non-public IPv4 ranges beyond what Go's
// ip.IsPrivate/IsLoopback/IsLinkLocal cover. Traffic to these should
// never trigger STUN.
var reservedIPv4Ranges = []net.IPNet{
	// CGNAT (RFC 6598)
	{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)},
	// Documentation/TEST-NET (RFC 5737) -- not routable on the internet
	{IP: net.IPv4(192, 0, 2, 0), Mask: net.CIDRMask(24, 32)},
	{IP: net.IPv4(198, 51, 100, 0), Mask: net.CIDRMask(24, 32)},
	{IP: net.IPv4(203, 0, 113, 0), Mask: net.CIDRMask(24, 32)},
	// Benchmarking (RFC 2544)
	{IP: net.IPv4(198, 18, 0, 0), Mask: net.CIDRMask(15, 32)},
}

// isPrivateTarget checks if a host/IP is a private (LAN) address.
// Returns true for RFC1918, loopback, link-local, carrier-grade NAT (100.64/10),
// RFC 5737 documentation ranges, and IPv6 unique-local (fc00::/7) and
// link-local (fe80::/10) addresses.
func isPrivateTarget(host string) bool {
	// Resolve hostname to IP if needed
	ips, err := net.LookupIP(host)
	if err != nil {
		// If we can't resolve, try parsing as IP directly
		ip := net.ParseIP(host)
		if ip == nil {
			return false // Unknown, assume WAN
		}
		return isPrivateIP(ip)
	}

	for _, ip := range ips {
		if isPrivateIP(ip) {
			return true
		}
	}
	return false
}

// isPrivateIP checks if an IP address is private/non-public.
func isPrivateIP(ip net.IP) bool {
	// Standard private ranges (RFC1918 + IPv6 ULA fc00::/7)
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	// Check additional reserved IPv4 ranges
	if ip4 := ip.To4(); ip4 != nil {
		for _, r := range reservedIPv4Ranges {
			if r.Contains(ip4) {
				return true
			}
		}
	}
	return false
}

// resolveClientIP determines the correct client IP for the given server.
// For LAN/private targets: uses the OS routing table to pick the right local
// interface. For WAN targets: tries STUN to detect the client's public IP.
// The manualIP override takes priority over auto-detection.
// If manualIP is a non-public address, the local interface IP is used
// instead and STUN is never contacted.
// stunServers nil or empty disables STUN; the OS-selected local interface IP
// is used instead and a warning is printed.
func resolveClientIP(host string, port int, manualIP string, stunServers []string) (string, error) {
	// Manual override always wins
	if manualIP != "" {
		// If the manual IP is private/non-public, use it directly without STUN
		if ip := net.ParseIP(manualIP); ip != nil && isPrivateIP(ip) {
			return manualIP, nil
		}
		return manualIP, nil
	}

	// For private/LAN targets, the local interface IP is correct -- skip STUN entirely
	if isPrivateTarget(host) {
		return getLocalIPForHost(host, port)
	}

	// If no STUN servers are configured (nil or empty), respect that decision:
	// use the local interface IP selected by the OS routing table and warn the user.
	// getLocalIPForHost uses a UDP dial so the kernel picks the right adapter even
	// with multiple physical NICs, virtual adapters (VMware/Docker/Hyper-V), etc.
	if len(stunServers) == 0 {
		localIP, err := getLocalIPForHost(host, port)
		if err != nil {
			return "", fmt.Errorf("cannot determine local IP: %w", err)
		}
		fmt.Printf("[WARN] No STUN servers configured. Using local network interface IP %s.\n", localIP)
		fmt.Printf("[WARN] If connecting over the internet, add stun_servers to your config or use the --ip flag.\n")
		return localIP, nil
	}

	// For WAN targets, try STUN to detect the public IP
	wanIP, err := detectWANIP(stunServers)
	if err != nil {
		// Fall back to local IP with a warning
		localIP, localErr := getLocalIPForHost(host, port)
		if localErr != nil {
			return "", fmt.Errorf("cannot determine client IP: WAN detection failed (%v), local detection failed (%v)", err, localErr)
		}
		fmt.Printf("[WARN] Could not detect WAN IP (%v). Using local IP %s.\n", err, localIP)
		fmt.Printf("[WARN] If server rejects with 'IP mismatch', use --ip flag or set match_incoming_ip=false on server.\n")
		return localIP, nil
	}

	return wanIP, nil
}
