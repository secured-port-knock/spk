// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package client

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"net"
	"testing"
)

// --- Fuzz tests ---

// FuzzParseSTUNResponse feeds arbitrary bytes into the STUN response parser
// to verify it never panics on malformed input.
func FuzzParseSTUNResponse(f *testing.F) {
	var txID [12]byte

	// Valid binding success response with XOR-MAPPED-ADDRESS
	validResp := buildSTUNResponse(txID, 0x0020, net.IPv4(1, 2, 3, 4).To4())
	f.Add(validResp)

	// Minimal header only
	f.Add(make([]byte, 20))

	// Too short
	f.Add(make([]byte, 5))
	f.Add([]byte{})

	// Random garbage
	garbage := make([]byte, 100)
	rand.Read(garbage)
	f.Add(garbage)

	// Large random
	large := make([]byte, 1000)
	rand.Read(large)
	f.Add(large)

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must not panic on any input
		_, _ = parseSTUNResponse(data, txID)
	})
}

// --- Property tests ---

// TestParseSTUNResponse_XORMappedRoundtrip verifies XOR-MAPPED-ADDRESS
// correctly XORs with magic cookie for IPv4.
func TestParseSTUNResponse_XORMappedRoundtrip(t *testing.T) {
	ips := []net.IP{
		net.IPv4(1, 2, 3, 4).To4(),
		net.IPv4(0, 0, 0, 0).To4(),
		net.IPv4(255, 255, 255, 255).To4(),
		net.IPv4(192, 168, 1, 1).To4(),
		net.IPv4(10, 0, 0, 1).To4(),
	}

	for _, ip := range ips {
		var txID [12]byte
		rand.Read(txID[:])

		resp := buildSTUNResponse(txID, 0x0020, ip)
		result, err := parseSTUNResponse(resp, txID)
		if err != nil {
			t.Fatalf("valid XOR-MAPPED response for %s failed: %v", ip, err)
		}

		parsed := net.ParseIP(result).To4()
		if !parsed.Equal(ip) {
			t.Errorf("XOR roundtrip: got %s, want %s", result, ip)
		}
	}
}

// TestParseSTUNResponse_MappedAddressRoundtrip verifies MAPPED-ADDRESS
// (non-XOR) for IPv4.
func TestParseSTUNResponse_MappedAddressRoundtrip(t *testing.T) {
	ips := []net.IP{
		net.IPv4(8, 8, 8, 8).To4(),
		net.IPv4(172, 16, 0, 1).To4(),
	}

	for _, ip := range ips {
		var txID [12]byte
		rand.Read(txID[:])

		resp := buildSTUNResponse(txID, 0x0001, ip)
		result, err := parseSTUNResponse(resp, txID)
		if err != nil {
			t.Fatalf("valid MAPPED response for %s failed: %v", ip, err)
		}

		parsed := net.ParseIP(result).To4()
		if !parsed.Equal(ip) {
			t.Errorf("MAPPED roundtrip: got %s, want %s", result, ip)
		}
	}
}

// TestParseSTUNResponse_IPv6XORRoundtrip verifies XOR-MAPPED-ADDRESS for IPv6.
func TestParseSTUNResponse_IPv6XORRoundtrip(t *testing.T) {
	ipv6 := net.ParseIP("2001:db8::1")

	var txID [12]byte
	rand.Read(txID[:])

	resp := buildSTUNResponseIPv6(txID, 0x0020, ipv6)
	result, err := parseSTUNResponse(resp, txID)
	if err != nil {
		t.Fatalf("IPv6 XOR-MAPPED failed: %v", err)
	}

	parsed := net.ParseIP(result)
	if !parsed.Equal(ipv6) {
		t.Errorf("IPv6 XOR roundtrip: got %s, want %s", result, ipv6)
	}
}

// TestParseSTUNResponse_TxIDMismatchRejected verifies wrong transaction ID is rejected.
func TestParseSTUNResponse_TxIDMismatchRejected(t *testing.T) {
	var txID1, txID2 [12]byte
	rand.Read(txID1[:])
	rand.Read(txID2[:])

	resp := buildSTUNResponse(txID1, 0x0020, net.IPv4(1, 2, 3, 4).To4())
	_, err := parseSTUNResponse(resp, txID2)
	if err == nil {
		t.Error("mismatched transaction ID should be rejected")
	}
}

// TestParseSTUNResponse_TruncatedAttributes verifies truncated attribute data is handled.
func TestParseSTUNResponse_TruncatedAttributes(t *testing.T) {
	var txID [12]byte

	resp := buildSTUNResponse(txID, 0x0020, net.IPv4(1, 2, 3, 4).To4())

	// Truncate at various points within the attribute
	for cut := 21; cut < len(resp); cut++ {
		truncated := make([]byte, cut)
		copy(truncated, resp)
		// Fix the message length header to match
		msgLen := cut - 20
		if msgLen < 0 {
			msgLen = 0
		}
		binary.BigEndian.PutUint16(truncated[2:4], uint16(msgLen))

		// Must not panic
		_, _ = parseSTUNResponse(truncated, txID)
	}
}

// TestParseSTUNResponse_WrongResponseType verifies non-success responses are rejected.
func TestParseSTUNResponse_WrongResponseType(t *testing.T) {
	var txID [12]byte

	wrongTypes := [][2]byte{
		{0x00, 0x01}, // Binding Request (not response)
		{0x01, 0x11}, // Binding Error Response
		{0x00, 0x00}, // Invalid
		{0xFF, 0xFF}, // Invalid
	}

	for _, rt := range wrongTypes {
		resp := buildSTUNResponse(txID, 0x0020, net.IPv4(1, 2, 3, 4).To4())
		resp[0] = rt[0]
		resp[1] = rt[1]

		_, err := parseSTUNResponse(resp, txID)
		if err == nil {
			t.Errorf("response type 0x%02x%02x should be rejected", rt[0], rt[1])
		}
	}
}

// TestParseSTUNResponse_UnknownAttributeSkipped verifies unknown attributes
// are skipped without error when a valid mapped address follows.
func TestParseSTUNResponse_UnknownAttributeSkipped(t *testing.T) {
	var txID [12]byte
	rand.Read(txID[:])

	// Build response with an unknown attribute before the mapped address
	var buf bytes.Buffer

	// Header
	buf.Write([]byte{0x01, 0x01}) // Binding Success Response
	buf.Write([]byte{0x00, 0x00}) // Length placeholder
	buf.Write(stunMagicCookie)
	buf.Write(txID[:])

	// Unknown attribute (type 0x8000, 4 bytes of data)
	buf.Write([]byte{0x80, 0x00})             // Unknown type
	buf.Write([]byte{0x00, 0x04})             // Length = 4
	buf.Write([]byte{0xDE, 0xAD, 0xBE, 0xEF}) // Data

	// XOR-MAPPED-ADDRESS for 1.2.3.4
	ip := net.IPv4(1, 2, 3, 4).To4()
	xoredIP := make([]byte, 4)
	xoredIP[0] = ip[0] ^ 0x21
	xoredIP[1] = ip[1] ^ 0x12
	xoredIP[2] = ip[2] ^ 0xA4
	xoredIP[3] = ip[3] ^ 0x42

	buf.Write([]byte{0x00, 0x20}) // XOR-MAPPED-ADDRESS
	buf.Write([]byte{0x00, 0x08}) // Length = 8
	buf.Write([]byte{0x00, 0x01}) // Reserved + Family (IPv4)
	buf.Write([]byte{0x00, 0x00}) // Port (don't care)
	buf.Write(xoredIP)

	resp := buf.Bytes()
	// Fix message length
	binary.BigEndian.PutUint16(resp[2:4], uint16(len(resp)-20))

	result, err := parseSTUNResponse(resp, txID)
	if err != nil {
		t.Fatalf("should parse past unknown attribute: %v", err)
	}
	if result != "1.2.3.4" {
		t.Errorf("got %s, want 1.2.3.4", result)
	}
}

// TestIsPrivateTarget_EdgeCases tests boundary IPs for private range detection.
func TestIsPrivateTarget_EdgeCases(t *testing.T) {
	tests := []struct {
		host    string
		private bool
	}{
		// RFC 6598 CGNAT boundaries
		{"100.64.0.0", true},
		{"100.127.255.255", true},
		{"100.63.255.255", false},
		{"100.128.0.0", false},

		// 10.x.x.x boundaries
		{"10.0.0.0", true},
		{"10.255.255.255", true},
		{"9.255.255.255", false},
		{"11.0.0.0", false},

		// Loopback
		{"127.0.0.1", true},
		{"127.255.255.255", true},

		// Link-local
		{"169.254.0.1", true},

		// Hostnames
		{"localhost", true},
	}

	for _, tt := range tests {
		got := isPrivateTarget(tt.host)
		if got != tt.private {
			t.Errorf("isPrivateTarget(%q) = %v, want %v", tt.host, got, tt.private)
		}
	}
}

// --- Helpers ---

// buildSTUNResponse creates a valid STUN Binding Success Response with
// an IPv4 mapped address attribute.
func buildSTUNResponse(txID [12]byte, attrType uint16, ipv4 net.IP) []byte {
	var buf bytes.Buffer

	// STUN Header
	buf.Write([]byte{0x01, 0x01}) // Binding Success Response
	buf.Write([]byte{0x00, 0x00}) // Length placeholder
	buf.Write(stunMagicCookie)
	buf.Write(txID[:])

	// Attribute
	ip := make([]byte, 4)
	copy(ip, ipv4.To4())

	if attrType == 0x0020 {
		// XOR with magic cookie for XOR-MAPPED-ADDRESS
		ip[0] ^= 0x21
		ip[1] ^= 0x12
		ip[2] ^= 0xA4
		ip[3] ^= 0x42
	}

	binary.BigEndian.PutUint16(buf.Bytes()[2:4], 0) // will fix below
	attrHeader := make([]byte, 4)
	binary.BigEndian.PutUint16(attrHeader[0:2], attrType)
	binary.BigEndian.PutUint16(attrHeader[2:4], 8) // attr length
	buf.Write(attrHeader)
	buf.Write([]byte{0x00, 0x01}) // Reserved + Family (IPv4)
	buf.Write([]byte{0x00, 0x00}) // Port
	buf.Write(ip)

	resp := buf.Bytes()
	// Fix message length field
	binary.BigEndian.PutUint16(resp[2:4], uint16(len(resp)-20))

	return resp
}

// buildSTUNResponseIPv6 creates a STUN response with an IPv6 mapped address.
func buildSTUNResponseIPv6(txID [12]byte, attrType uint16, ipv6 net.IP) []byte {
	var buf bytes.Buffer

	buf.Write([]byte{0x01, 0x01}) // Binding Success Response
	buf.Write([]byte{0x00, 0x00}) // Length placeholder
	buf.Write(stunMagicCookie)
	buf.Write(txID[:])

	ip := make([]byte, 16)
	copy(ip, ipv6.To16())

	if attrType == 0x0020 {
		xor := make([]byte, 16)
		copy(xor[0:4], stunMagicCookie)
		copy(xor[4:16], txID[:])
		for i := 0; i < 16; i++ {
			ip[i] ^= xor[i]
		}
	}

	attrHeader := make([]byte, 4)
	binary.BigEndian.PutUint16(attrHeader[0:2], attrType)
	binary.BigEndian.PutUint16(attrHeader[2:4], 20) // 1+1+2+16
	buf.Write(attrHeader)
	buf.Write([]byte{0x00, 0x02}) // Reserved + Family (IPv6)
	buf.Write([]byte{0x00, 0x00}) // Port
	buf.Write(ip)

	resp := buf.Bytes()
	binary.BigEndian.PutUint16(resp[2:4], uint16(len(resp)-20))

	return resp
}
