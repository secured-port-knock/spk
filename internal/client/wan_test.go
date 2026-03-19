// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package client

import (
	"net"
	"testing"
)

func TestIsPrivateTarget(t *testing.T) {
	tests := []struct {
		host    string
		private bool
	}{
		// Private (RFC 1918)
		{"192.168.1.1", true},
		{"10.0.0.1", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},

		// Loopback
		{"127.0.0.1", true},
		{"localhost", true},

		// Public
		{"8.8.8.8", false},
		{"1.1.1.1", false},

		// RFC 5737 documentation/TEST-NET ranges (not routable)
		{"192.0.2.1", true},
		{"198.51.100.1", true},
		{"203.0.113.1", true},
		{"203.0.113.50", true},

		// Benchmarking (RFC 2544)
		{"198.18.0.1", true},

		// Link-local
		{"169.254.1.1", true},

		// IPv6 loopback
		{"::1", true},

		// Invalid / unresolvable (should return false = treat as WAN)
		{"definitely.not.a.real.host.invalid", false},
	}

	for _, tt := range tests {
		got := isPrivateTarget(tt.host)
		if got != tt.private {
			t.Errorf("isPrivateTarget(%q) = %v, want %v", tt.host, got, tt.private)
		}
	}
}

func TestResolveClientIPManualOverride(t *testing.T) {
	// Manual IP override should always be returned
	ip, err := resolveClientIP("8.8.8.8", 12345, "203.0.113.50", nil)
	if err != nil {
		t.Fatalf("resolveClientIP: %v", err)
	}
	if ip != "203.0.113.50" {
		t.Errorf("got %q, want %q", ip, "203.0.113.50")
	}
}

func TestResolveClientIPLANTarget(t *testing.T) {
	// For LAN targets, should return a local interface IP
	ip, err := resolveClientIP("127.0.0.1", 12345, "", nil)
	if err != nil {
		t.Fatalf("resolveClientIP for LAN: %v", err)
	}
	// Should get 127.0.0.1 when connecting to loopback
	if ip != "127.0.0.1" {
		t.Logf("NOTE: resolveClientIP(127.0.0.1) = %q (expected 127.0.0.1 but may vary)", ip)
	}
	if ip == "" {
		t.Error("resolveClientIP should return non-empty for loopback")
	}
}

func TestGetLocalIPForHost(t *testing.T) {
	// Should return a valid local IP for loopback target
	ip, err := getLocalIPForHost("127.0.0.1", 12345)
	if err != nil {
		t.Fatalf("getLocalIPForHost: %v", err)
	}
	if ip == "" {
		t.Error("should return non-empty IP")
	}
}

func TestResolveClientIPNoSTUN_WANTarget(t *testing.T) {
	// When stun_servers is nil or empty, resolveClientIP must NOT contact STUN,
	// must return the local interface IP chosen by the OS routing table, and
	// must not error. This covers the case where a user comments out stun_servers.
	for _, stunServers := range [][]string{nil, {}} {
		ip, err := resolveClientIP("8.8.8.8", 12345, "", stunServers)
		if err != nil {
			t.Fatalf("resolveClientIP (no STUN, stunServers=%v): %v", stunServers, err)
		}
		if ip == "" {
			t.Error("resolveClientIP should return non-empty IP when STUN is disabled")
		}
		parsed := net.ParseIP(ip)
		if parsed == nil {
			t.Errorf("resolveClientIP returned non-IP string %q", ip)
		}
	}
}

func TestDetectWANIPNoServersReturnsError(t *testing.T) {
	// detectWANIP must return an error when called with no servers instead of
	// silently falling back to built-in defaults.
	_, err := detectWANIP(nil)
	if err == nil {
		t.Error("detectWANIP(nil) should return error, not fall back to defaults")
	}
	_, err = detectWANIP([]string{})
	if err == nil {
		t.Error("detectWANIP([]) should return error, not fall back to defaults")
	}
}

func TestParseSTUNResponseValid(t *testing.T) {
	// Build a valid STUN Binding Success Response with XOR-MAPPED-ADDRESS
	txID := [12]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C}

	// Header: type(2)=0x0101 + length(2)=12 + magic(4) + txID(12) = 20 bytes
	// Attribute: XOR-MAPPED-ADDRESS (type=0x0020, len=8)
	// Value: reserved(1)=0 + family(1)=0x01(IPv4) + port(2) + ip(4)
	// IP: 203.0.113.1 = 0xCB, 0x00, 0x71, 0x01
	// XOR'd with magic 0x2112A442: 0xCB^0x21=0xEA, 0x00^0x12=0x12, 0x71^0xA4=0xD5, 0x01^0x42=0x43

	resp := make([]byte, 32)
	resp[0], resp[1] = 0x01, 0x01 // Binding Success Response
	resp[2], resp[3] = 0x00, 0x0C // Length: 12 (attr header 4 + attr data 8)
	copy(resp[4:8], stunMagicCookie)
	copy(resp[8:20], txID[:])

	// XOR-MAPPED-ADDRESS attribute
	resp[20], resp[21] = 0x00, 0x20 // Type: XOR-MAPPED-ADDRESS
	resp[22], resp[23] = 0x00, 0x08 // Length: 8
	resp[24] = 0x00                 // Reserved
	resp[25] = 0x01                 // Family: IPv4
	resp[26], resp[27] = 0x00, 0x00 // Port (XOR'd, we don't use it)
	resp[28] = 0xCB ^ 0x21          // 203 XOR 0x21
	resp[29] = 0x00 ^ 0x12          // 0 XOR 0x12
	resp[30] = 0x71 ^ 0xA4          // 113 XOR 0xA4
	resp[31] = 0x01 ^ 0x42          // 1 XOR 0x42

	ip, err := parseSTUNResponse(resp, txID)
	if err != nil {
		t.Fatalf("parseSTUNResponse: %v", err)
	}
	if ip != "203.0.113.1" {
		t.Errorf("got %q, want %q", ip, "203.0.113.1")
	}
}

func TestParseSTUNResponseMappedAddress(t *testing.T) {
	// Test with MAPPED-ADDRESS (0x0001) instead of XOR-MAPPED-ADDRESS
	txID := [12]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C}

	resp := make([]byte, 32)
	resp[0], resp[1] = 0x01, 0x01
	resp[2], resp[3] = 0x00, 0x0C
	copy(resp[4:8], stunMagicCookie)
	copy(resp[8:20], txID[:])

	// MAPPED-ADDRESS (not XOR'd)
	resp[20], resp[21] = 0x00, 0x01 // Type: MAPPED-ADDRESS
	resp[22], resp[23] = 0x00, 0x08
	resp[24] = 0x00
	resp[25] = 0x01 // IPv4
	resp[26], resp[27] = 0x00, 0x00
	resp[28] = 10
	resp[29] = 20
	resp[30] = 30
	resp[31] = 40

	ip, err := parseSTUNResponse(resp, txID)
	if err != nil {
		t.Fatalf("parseSTUNResponse: %v", err)
	}
	if ip != "10.20.30.40" {
		t.Errorf("got %q, want %q", ip, "10.20.30.40")
	}
}

func TestParseSTUNResponseTooShort(t *testing.T) {
	txID := [12]byte{}
	_, err := parseSTUNResponse([]byte{0x01, 0x01}, txID)
	if err == nil {
		t.Error("expected error for too-short response")
	}
}

func TestParseSTUNResponseWrongType(t *testing.T) {
	txID := [12]byte{}
	resp := make([]byte, 20)
	resp[0], resp[1] = 0x01, 0x11 // Binding Error Response
	copy(resp[4:8], stunMagicCookie)

	_, err := parseSTUNResponse(resp, txID)
	if err == nil {
		t.Error("expected error for wrong response type")
	}
}

func TestParseSTUNResponseWrongTxID(t *testing.T) {
	txID := [12]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C}
	wrongTxID := [12]byte{0xFF, 0xFE, 0xFD}

	resp := make([]byte, 32)
	resp[0], resp[1] = 0x01, 0x01
	resp[2], resp[3] = 0x00, 0x0C
	copy(resp[4:8], stunMagicCookie)
	copy(resp[8:20], wrongTxID[:])

	_, err := parseSTUNResponse(resp, txID)
	if err == nil {
		t.Error("expected error for mismatched transaction ID")
	}
}

func TestParseSTUNResponseNoMappedAddress(t *testing.T) {
	txID := [12]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C}

	// Response with an unknown attribute type (no mapped address)
	resp := make([]byte, 32)
	resp[0], resp[1] = 0x01, 0x01
	resp[2], resp[3] = 0x00, 0x0C
	copy(resp[4:8], stunMagicCookie)
	copy(resp[8:20], txID[:])

	// Unknown attribute
	resp[20], resp[21] = 0x80, 0x22 // SOFTWARE attribute (not mapped address)
	resp[22], resp[23] = 0x00, 0x04
	resp[24], resp[25], resp[26], resp[27] = 't', 'e', 's', 't'

	_, err := parseSTUNResponse(resp, txID)
	if err == nil {
		t.Error("expected error when no mapped address found")
	}
}

func TestParseSTUNResponseIPv6(t *testing.T) {
	txID := [12]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C}

	// Build response with XOR-MAPPED-ADDRESS for IPv6
	// IPv6 address: 2001:db8::1
	// In bytes: 20 01 0d b8 00 00 00 00 00 00 00 00 00 00 00 01
	ipv6 := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}

	// XOR with magic cookie + txID
	xored := make([]byte, 16)
	xorKey := make([]byte, 16)
	copy(xorKey[0:4], stunMagicCookie)
	copy(xorKey[4:16], txID[:])
	for i := 0; i < 16; i++ {
		xored[i] = ipv6[i] ^ xorKey[i]
	}

	resp := make([]byte, 44)
	resp[0], resp[1] = 0x01, 0x01 // Success
	resp[2], resp[3] = 0x00, 0x18 // Length: 24 (attr hdr 4 + attr data 20)
	copy(resp[4:8], stunMagicCookie)
	copy(resp[8:20], txID[:])

	resp[20], resp[21] = 0x00, 0x20 // XOR-MAPPED-ADDRESS
	resp[22], resp[23] = 0x00, 0x14 // Length: 20 (1+1+2+16)
	resp[24] = 0x00                 // Reserved
	resp[25] = 0x02                 // Family: IPv6
	resp[26], resp[27] = 0x00, 0x00 // Port (unused)
	copy(resp[28:44], xored)

	ip, err := parseSTUNResponse(resp, txID)
	if err != nil {
		t.Fatalf("parseSTUNResponse IPv6: %v", err)
	}
	if ip != "2001:db8::1" {
		t.Errorf("got %q, want %q", ip, "2001:db8::1")
	}
}

func TestIsPrivateIPCGNAT(t *testing.T) {
	// Carrier-grade NAT (100.64.0.0/10, RFC 6598) should be private
	tests := []struct {
		ip      string
		private bool
	}{
		{"100.64.0.1", true},
		{"100.127.255.254", true},
		{"100.63.255.255", false}, // Just below CGNAT range
		{"100.128.0.0", false},    // Just above CGNAT range
		{"192.168.1.1", true},     // Regular private
		{"8.8.8.8", false},        // Public
		{"::1", true},             // IPv6 loopback
		{"fe80::1", true},         // IPv6 link-local

		// RFC 5737 documentation ranges
		{"192.0.2.1", true},
		{"198.51.100.1", true},
		{"203.0.113.1", true},
		{"203.0.113.50", true},
		{"192.0.2.255", true},

		// RFC 2544 benchmarking
		{"198.18.0.1", true},
		{"198.19.255.255", true},
		{"198.17.255.255", false}, // Just below
		{"198.20.0.0", false},     // Just above
	}

	for _, tt := range tests {
		got := isPrivateIP(net.ParseIP(tt.ip))
		if got != tt.private {
			t.Errorf("isPrivateIP(%q) = %v, want %v", tt.ip, got, tt.private)
		}
	}
}

func TestIsPrivateTargetCGNAT(t *testing.T) {
	// CGNAT targets should be treated as private
	if !isPrivateTarget("100.64.1.1") {
		t.Error("isPrivateTarget(100.64.1.1) should return true (CGNAT)")
	}
	if !isPrivateTarget("100.100.100.100") {
		t.Error("isPrivateTarget(100.100.100.100) should return true (CGNAT)")
	}
}
