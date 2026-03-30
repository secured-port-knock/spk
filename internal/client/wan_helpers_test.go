// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package client

import (
	"net"
	"testing"
)

// =============================================================================
// parseSTUNAttrIPv4
// =============================================================================

func TestParseSTUNAttrIPv4_MappedAddress(t *testing.T) {
	// MAPPED-ADDRESS (attrType 0x0001): raw IP, no XOR
	// attrData: reserved(1) + family(1=IPv4) + port(2) + ip(4)
	data := []byte{0x00, 0x01, 0x00, 0x00, 192, 168, 1, 5}
	ip, ok := parseSTUNAttrIPv4(0x0001, data)
	if !ok {
		t.Fatal("expected ok=true for valid MAPPED-ADDRESS IPv4")
	}
	if ip != "192.168.1.5" {
		t.Errorf("parseSTUNAttrIPv4 = %q, want 192.168.1.5", ip)
	}
}

func TestParseSTUNAttrIPv4_XORMappedAddress(t *testing.T) {
	// XOR-MAPPED-ADDRESS (attrType 0x0020): IP XOR'd with magic cookie
	// magic cookie: 0x21 0x12 0xA4 0x42
	// To get 192.168.1.5 after XOR: XOR each byte with magic cookie
	rawIP := [4]byte{
		192 ^ 0x21,
		168 ^ 0x12,
		1 ^ 0xA4,
		5 ^ 0x42,
	}
	data := []byte{0x00, 0x01, 0x00, 0x00, rawIP[0], rawIP[1], rawIP[2], rawIP[3]}
	ip, ok := parseSTUNAttrIPv4(0x0020, data)
	if !ok {
		t.Fatal("expected ok=true for valid XOR-MAPPED-ADDRESS IPv4")
	}
	if ip != "192.168.1.5" {
		t.Errorf("parseSTUNAttrIPv4 XOR = %q, want 192.168.1.5", ip)
	}
}

func TestParseSTUNAttrIPv4_TooShort(t *testing.T) {
	data := []byte{0x00, 0x01, 0x00} // only 3 bytes
	_, ok := parseSTUNAttrIPv4(0x0001, data)
	if ok {
		t.Error("expected ok=false for too-short attrData")
	}
}

func TestParseSTUNAttrIPv4_WrongFamily(t *testing.T) {
	// family byte is 0x02 (IPv6), not 0x01 (IPv4)
	data := []byte{0x00, 0x02, 0x00, 0x00, 192, 168, 1, 5}
	_, ok := parseSTUNAttrIPv4(0x0001, data)
	if ok {
		t.Error("expected ok=false when address family is not IPv4 (0x01)")
	}
}

// =============================================================================
// parseSTUNAttrIPv6
// =============================================================================

func TestParseSTUNAttrIPv6_MappedAddress(t *testing.T) {
	// MAPPED-ADDRESS IPv6: attrData[1] = 0x02, raw 16-byte IPv6
	// Use ::1 (loopback) as a predictable IP
	loopback := net.ParseIP("::1").To16()
	data := make([]byte, 20)
	data[1] = 0x02 // IPv6 family
	copy(data[4:20], loopback)

	var txID [12]byte // zero transaction ID
	ip, ok := parseSTUNAttrIPv6(0x0001, data, txID)
	if !ok {
		t.Fatal("expected ok=true for valid MAPPED-ADDRESS IPv6")
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		t.Fatalf("parseSTUNAttrIPv6 returned invalid IP: %q", ip)
	}
	if !parsed.Equal(loopback) {
		t.Errorf("parseSTUNAttrIPv6 = %q, want ::1", ip)
	}
}

func TestParseSTUNAttrIPv6_XORMappedAddress(t *testing.T) {
	// XOR-MAPPED-ADDRESS IPv6: IP XOR'd with magic cookie + txID
	magicCookie := []byte{0x21, 0x12, 0xA4, 0x42}
	var txID [12]byte
	for i := range txID {
		txID[i] = byte(i + 1)
	}

	// Choose a target IP to reconstruct after XOR
	target := net.ParseIP("2001:db8::1").To16()

	// Build xor mask
	xor := make([]byte, 16)
	copy(xor[0:4], magicCookie)
	copy(xor[4:16], txID[:])

	// XOR target to get the stored bytes
	stored := make([]byte, 16)
	for i := range stored {
		stored[i] = target[i] ^ xor[i]
	}

	data := make([]byte, 20)
	data[1] = 0x02 // IPv6 family
	copy(data[4:20], stored)

	ip, ok := parseSTUNAttrIPv6(0x0020, data, txID)
	if !ok {
		t.Fatal("expected ok=true for XOR-MAPPED-ADDRESS IPv6")
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		t.Fatalf("parseSTUNAttrIPv6 XOR returned invalid IP: %q", ip)
	}
	if !parsed.Equal(target) {
		t.Errorf("parseSTUNAttrIPv6 XOR = %q, want 2001:db8::1", ip)
	}
}

func TestParseSTUNAttrIPv6_TooShort(t *testing.T) {
	data := make([]byte, 10) // less than 20 bytes
	data[1] = 0x02
	var txID [12]byte
	_, ok := parseSTUNAttrIPv6(0x0020, data, txID)
	if ok {
		t.Error("expected ok=false for too-short IPv6 attrData")
	}
}

func TestParseSTUNAttrIPv6_WrongFamily(t *testing.T) {
	// family byte 0x01 (IPv4), not 0x02 (IPv6)
	data := make([]byte, 20)
	data[1] = 0x01
	var txID [12]byte
	_, ok := parseSTUNAttrIPv6(0x0020, data, txID)
	if ok {
		t.Error("expected ok=false when address family is not IPv6 (0x02)")
	}
}
