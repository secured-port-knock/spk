// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package sniffer

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestLinkHeaderLen(t *testing.T) {
	tests := []struct {
		linkType int
		want     int
	}{
		{1, 14},   // DLT_EN10MB (Ethernet)
		{0, 4},    // DLT_NULL (BSD loopback)
		{113, 16}, // DLT_LINUX_SLL
		{12, 0},   // DLT_RAW
		{101, 0},  // DLT_RAW (other)
		{999, -1}, // Unsupported
	}

	for _, tt := range tests {
		got := linkHeaderLen(tt.linkType)
		if got != tt.want {
			t.Errorf("linkHeaderLen(%d) = %d, want %d", tt.linkType, got, tt.want)
		}
	}
}

func TestParseIPv4UDP(t *testing.T) {
	// Build a minimal IPv4+UDP packet
	// IPv4 header: 20 bytes (IHL=5, protocol=17)
	// UDP header: 8 bytes
	// Payload: "HELLO"
	payload := []byte("HELLO")
	udpLen := 8 + len(payload)
	totalLen := 20 + udpLen

	pkt := make([]byte, totalLen)
	// IPv4 header
	pkt[0] = 0x45 // Version=4, IHL=5
	pkt[9] = 17   // Protocol=UDP

	// Source IP: 10.20.30.40
	pkt[12], pkt[13], pkt[14], pkt[15] = 10, 20, 30, 40
	// Dest IP: 192.168.1.1
	pkt[16], pkt[17], pkt[18], pkt[19] = 192, 168, 1, 1

	// UDP header
	binary.BigEndian.PutUint16(pkt[20:22], 12345) // src port
	binary.BigEndian.PutUint16(pkt[22:24], 54321) // dst port
	binary.BigEndian.PutUint16(pkt[24:26], uint16(udpLen))
	// checksum = 0 (skip)

	// UDP payload
	copy(pkt[28:], payload)

	srcIP, data := parseIPv4UDP(pkt)
	if srcIP != "10.20.30.40" {
		t.Errorf("srcIP = %q, want 10.20.30.40", srcIP)
	}
	if string(data) != "HELLO" {
		t.Errorf("payload = %q, want HELLO", string(data))
	}
}

func TestParseIPv4UDPTooShort(t *testing.T) {
	_, data := parseIPv4UDP([]byte{0x45, 0, 0, 0})
	if data != nil {
		t.Error("expected nil payload for too-short packet")
	}
}

func TestParseIPv4UDPNotUDP(t *testing.T) {
	pkt := make([]byte, 40)
	pkt[0] = 0x45 // Version=4, IHL=5
	pkt[9] = 6    // Protocol=TCP (not UDP)
	_, data := parseIPv4UDP(pkt)
	if data != nil {
		t.Error("expected nil payload for non-UDP packet")
	}
}

func TestParseIPv6UDP(t *testing.T) {
	// Build a minimal IPv6+UDP packet
	// IPv6 header: 40 bytes
	// UDP header: 8 bytes
	// Payload: "TEST6"
	payload := []byte("TEST6")
	udpLen := 8 + len(payload)

	pkt := make([]byte, 40+udpLen)
	// IPv6 header
	pkt[0] = 0x60                                        // Version=6
	pkt[6] = 17                                          // Next Header = UDP
	binary.BigEndian.PutUint16(pkt[4:6], uint16(udpLen)) // Payload length

	// Source IP: 2001:db8::1
	srcIPBytes := net.ParseIP("2001:db8::1").To16()
	copy(pkt[8:24], srcIPBytes)

	// Dest IP: 2001:db8::2
	dstIPBytes := net.ParseIP("2001:db8::2").To16()
	copy(pkt[24:40], dstIPBytes)

	// UDP header
	binary.BigEndian.PutUint16(pkt[40:42], 12345) // src port
	binary.BigEndian.PutUint16(pkt[42:44], 54321) // dst port
	binary.BigEndian.PutUint16(pkt[44:46], uint16(udpLen))
	// checksum = 0

	// Payload
	copy(pkt[48:], payload)

	srcIP, data := parseIPv6UDP(pkt)
	if srcIP != "2001:db8::1" {
		t.Errorf("srcIP = %q, want 2001:db8::1", srcIP)
	}
	if string(data) != "TEST6" {
		t.Errorf("payload = %q, want TEST6", string(data))
	}
}

func TestParseIPv6UDPTooShort(t *testing.T) {
	_, data := parseIPv6UDP([]byte{0x60, 0, 0, 0})
	if data != nil {
		t.Error("expected nil payload for too-short IPv6 packet")
	}
}

func TestParsePcapPacketEthernetIPv4(t *testing.T) {
	// Build: Ethernet header (14) + IPv4 (20) + UDP (8) + payload
	payload := []byte("PKT4")
	udpLen := 8 + len(payload)

	raw := make([]byte, 14+20+udpLen)
	// Ethernet header: dst(6) + src(6) + type(2)
	binary.BigEndian.PutUint16(raw[12:14], 0x0800) // IPv4

	// IPv4
	ip := raw[14:]
	ip[0] = 0x45                                   // v4, IHL=5
	ip[9] = 17                                     // UDP
	ip[12], ip[13], ip[14], ip[15] = 172, 16, 0, 1 // src

	// UDP
	udp := raw[34:]
	binary.BigEndian.PutUint16(udp[0:2], 5000)
	binary.BigEndian.PutUint16(udp[2:4], 6000)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen))
	copy(udp[8:], payload)

	srcIP, data := parsePcapPacket(raw, 1, 14)
	if srcIP != "172.16.0.1" {
		t.Errorf("srcIP = %q, want 172.16.0.1", srcIP)
	}
	if string(data) != "PKT4" {
		t.Errorf("payload = %q, want PKT4", string(data))
	}
}

func TestParsePcapPacketEthernetIPv6(t *testing.T) {
	// Build: Ethernet header (14) + IPv6 (40) + UDP (8) + payload
	payload := []byte("PKT6")
	udpLen := 8 + len(payload)

	raw := make([]byte, 14+40+udpLen)
	// Ethernet header
	binary.BigEndian.PutUint16(raw[12:14], 0x86DD) // IPv6

	// IPv6
	ip := raw[14:]
	ip[0] = 0x60 // Version 6
	ip[6] = 17   // Next Header = UDP
	binary.BigEndian.PutUint16(ip[4:6], uint16(udpLen))

	srcIPBytes := net.ParseIP("fe80::1").To16()
	copy(ip[8:24], srcIPBytes)

	// UDP
	udp := raw[54:]
	binary.BigEndian.PutUint16(udp[0:2], 5000)
	binary.BigEndian.PutUint16(udp[2:4], 6000)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen))
	copy(udp[8:], payload)

	srcIP, data := parsePcapPacket(raw, 1, 14)
	if srcIP != "fe80::1" {
		t.Errorf("srcIP = %q, want fe80::1", srcIP)
	}
	if string(data) != "PKT6" {
		t.Errorf("payload = %q, want PKT6", string(data))
	}
}

func TestParsePcapPacketRawIP(t *testing.T) {
	// DLT_RAW: no link-layer header, starts with IP
	payload := []byte("RAW")
	udpLen := 8 + len(payload)

	raw := make([]byte, 20+udpLen)
	raw[0] = 0x45 // IPv4
	raw[9] = 17   // UDP
	raw[12], raw[13], raw[14], raw[15] = 1, 2, 3, 4

	udp := raw[20:]
	binary.BigEndian.PutUint16(udp[0:2], 1111)
	binary.BigEndian.PutUint16(udp[2:4], 2222)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen))
	copy(udp[8:], payload)

	srcIP, data := parsePcapPacket(raw, 12, 0)
	if srcIP != "1.2.3.4" {
		t.Errorf("srcIP = %q, want 1.2.3.4", srcIP)
	}
	if string(data) != "RAW" {
		t.Errorf("payload = %q, want RAW", string(data))
	}
}

func TestParsePcapPacketVLAN(t *testing.T) {
	// 802.1Q VLAN tagged: Ethernet type 0x8100, then VLAN tag, then real type
	payload := []byte("VLAN")
	udpLen := 8 + len(payload)

	raw := make([]byte, 18+20+udpLen) // 14 Eth + 4 VLAN + 20 IPv4 + udp
	// Ethernet
	binary.BigEndian.PutUint16(raw[12:14], 0x8100) // VLAN
	binary.BigEndian.PutUint16(raw[14:16], 100)    // VLAN ID
	binary.BigEndian.PutUint16(raw[16:18], 0x0800) // IPv4

	// IPv4 starts at offset 18
	ip := raw[18:]
	ip[0] = 0x45
	ip[9] = 17
	ip[12], ip[13], ip[14], ip[15] = 10, 0, 0, 1

	udp := raw[38:]
	binary.BigEndian.PutUint16(udp[0:2], 3000)
	binary.BigEndian.PutUint16(udp[2:4], 4000)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen))
	copy(udp[8:], payload)

	srcIP, data := parsePcapPacket(raw, 1, 14)
	if srcIP != "10.0.0.1" {
		t.Errorf("srcIP = %q, want 10.0.0.1", srcIP)
	}
	if string(data) != "VLAN" {
		t.Errorf("payload = %q, want VLAN", string(data))
	}
}

func TestParsePcapPacketTooShort(t *testing.T) {
	// Packet shorter than link header
	_, data := parsePcapPacket([]byte{0, 1, 2}, 1, 14)
	if data != nil {
		t.Error("expected nil for too-short Ethernet frame")
	}
}

func TestParsePcapPacketNonIP(t *testing.T) {
	// Ethernet with ARP (0x0806)
	raw := make([]byte, 60)
	binary.BigEndian.PutUint16(raw[12:14], 0x0806) // ARP
	_, data := parsePcapPacket(raw, 1, 14)
	if data != nil {
		t.Error("expected nil for non-IP packet (ARP)")
	}
}

func TestParseIPv4UDPWithOptions(t *testing.T) {
	// IPv4 with IHL=6 (24-byte header with 4 bytes of options)
	payload := []byte("OPTS")
	udpLen := 8 + len(payload)
	totalLen := 24 + udpLen

	pkt := make([]byte, totalLen)
	pkt[0] = 0x46 // Version=4, IHL=6
	pkt[9] = 17   // UDP
	pkt[12], pkt[13], pkt[14], pkt[15] = 1, 2, 3, 4

	// UDP header starts at offset 24 (IHL=6 * 4)
	binary.BigEndian.PutUint16(pkt[24:26], 5000)
	binary.BigEndian.PutUint16(pkt[26:28], 6000)
	binary.BigEndian.PutUint16(pkt[28:30], uint16(udpLen))
	copy(pkt[32:], payload)

	srcIP, data := parseIPv4UDP(pkt)
	if srcIP != "1.2.3.4" {
		t.Errorf("srcIP = %q, want 1.2.3.4", srcIP)
	}
	if string(data) != "OPTS" {
		t.Errorf("payload = %q, want OPTS", string(data))
	}
}

func TestParseIPv4UDPInvalidIHL(t *testing.T) {
	// IHL=1 (4 bytes, less than minimum 20)
	pkt := make([]byte, 40)
	pkt[0] = 0x41 // Version=4, IHL=1
	pkt[9] = 17
	_, data := parseIPv4UDP(pkt)
	if data != nil {
		t.Error("expected nil for invalid IHL < 5")
	}
}

func TestParseIPv6UDPNotUDP(t *testing.T) {
	// IPv6 with Next Header = TCP (6)
	pkt := make([]byte, 60)
	pkt[0] = 0x60 // Version=6
	pkt[6] = 6    // TCP, not UDP
	binary.BigEndian.PutUint16(pkt[4:6], 20)
	_, data := parseIPv6UDP(pkt)
	if data != nil {
		t.Error("expected nil for non-UDP IPv6 packet")
	}
}

func TestParseIPv6UDPWithExtensionHeader(t *testing.T) {
	// IPv6 with Hop-by-Hop extension header, then UDP
	payload := []byte("EXT6")
	udpLen := 8 + len(payload)

	// IPv6 header (40) + Hop-by-Hop ext (8) + UDP (8) + payload
	pkt := make([]byte, 40+8+udpLen)
	pkt[0] = 0x60 // Version=6
	pkt[6] = 0    // Next Header = Hop-by-Hop Options

	// Hop-by-Hop extension header (8 bytes)
	pkt[40] = 17 // Next Header = UDP
	pkt[41] = 0  // Hdr Ext Len = 0 (8 bytes total)

	// Source IP: 2001:db8::99
	srcIPBytes := net.ParseIP("2001:db8::99").To16()
	copy(pkt[8:24], srcIPBytes)

	// UDP at offset 48
	binary.BigEndian.PutUint16(pkt[48:50], 7777)
	binary.BigEndian.PutUint16(pkt[50:52], 8888)
	binary.BigEndian.PutUint16(pkt[52:54], uint16(udpLen))
	copy(pkt[56:], payload)

	srcIP, data := parseIPv6UDP(pkt)
	if srcIP != "2001:db8::99" {
		t.Errorf("srcIP = %q, want 2001:db8::99", srcIP)
	}
	if string(data) != "EXT6" {
		t.Errorf("payload = %q, want EXT6", string(data))
	}
}

func TestParseIPv6UDPNoNextHeader(t *testing.T) {
	// IPv6 with Next Header = 59 (No Next Header)
	pkt := make([]byte, 48)
	pkt[0] = 0x60
	pkt[6] = 59 // No Next Header
	_, data := parseIPv6UDP(pkt)
	if data != nil {
		t.Error("expected nil for No Next Header")
	}
}

func TestParsePcapPacketBSDLoopback(t *testing.T) {
	// BSD loopback (DLT_NULL): 4-byte header + IPv4
	payload := []byte("BSD")
	udpLen := 8 + len(payload)

	raw := make([]byte, 4+20+udpLen)
	// AF_INET = 2 (little-endian)
	binary.LittleEndian.PutUint32(raw[0:4], 2)

	// IPv4
	ip := raw[4:]
	ip[0] = 0x45
	ip[9] = 17
	ip[12], ip[13], ip[14], ip[15] = 5, 6, 7, 8

	// UDP
	udp := raw[24:]
	binary.BigEndian.PutUint16(udp[0:2], 1234)
	binary.BigEndian.PutUint16(udp[2:4], 5678)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen))
	copy(udp[8:], payload)

	srcIP, data := parsePcapPacket(raw, 0, 4)
	if srcIP != "5.6.7.8" {
		t.Errorf("srcIP = %q, want 5.6.7.8", srcIP)
	}
	if string(data) != "BSD" {
		t.Errorf("payload = %q, want BSD", string(data))
	}
}

func TestParsePcapPacketBSDLoopbackInvalidAF(t *testing.T) {
	// BSD loopback with unsupported address family
	raw := make([]byte, 60)
	binary.LittleEndian.PutUint32(raw[0:4], 99) // Unknown AF
	_, data := parsePcapPacket(raw, 0, 4)
	if data != nil {
		t.Error("expected nil for BSD loopback with unknown AF")
	}
}

func TestParsePcapPacketLinuxSLL(t *testing.T) {
	// Linux cooked capture (DLT_LINUX_SLL): 16-byte header + IPv4
	payload := []byte("SLL")
	udpLen := 8 + len(payload)

	raw := make([]byte, 16+20+udpLen)
	// Protocol at bytes 14-15 = 0x0800 (IPv4)
	binary.BigEndian.PutUint16(raw[14:16], 0x0800)

	// IPv4
	ip := raw[16:]
	ip[0] = 0x45
	ip[9] = 17
	ip[12], ip[13], ip[14], ip[15] = 9, 10, 11, 12

	// UDP
	udp := raw[36:]
	binary.BigEndian.PutUint16(udp[0:2], 2000)
	binary.BigEndian.PutUint16(udp[2:4], 3000)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen))
	copy(udp[8:], payload)

	srcIP, data := parsePcapPacket(raw, 113, 16)
	if srcIP != "9.10.11.12" {
		t.Errorf("srcIP = %q, want 9.10.11.12", srcIP)
	}
	if string(data) != "SLL" {
		t.Errorf("payload = %q, want SLL", string(data))
	}
}

func TestParsePcapPacketLinuxSLLNonIP(t *testing.T) {
	// Linux SLL with non-IP protocol
	raw := make([]byte, 60)
	binary.BigEndian.PutUint16(raw[14:16], 0x0806) // ARP
	_, data := parsePcapPacket(raw, 113, 16)
	if data != nil {
		t.Error("expected nil for Linux SLL with ARP")
	}
}

func TestParsePcapPacketDoubleVLAN(t *testing.T) {
	// VLAN with IPv6 inner protocol
	payload := []byte("V6VL")
	udpLen := 8 + len(payload)

	// Ethernet(14) + VLAN(4) = 18, then IPv6(40) + UDP
	raw := make([]byte, 18+40+udpLen)
	binary.BigEndian.PutUint16(raw[12:14], 0x8100) // VLAN
	binary.BigEndian.PutUint16(raw[14:16], 200)    // VLAN ID
	binary.BigEndian.PutUint16(raw[16:18], 0x86DD) // IPv6

	// IPv6 at offset 18
	ip := raw[18:]
	ip[0] = 0x60
	ip[6] = 17 // UDP
	binary.BigEndian.PutUint16(ip[4:6], uint16(udpLen))

	srcIPBytes := net.ParseIP("fd00::42").To16()
	copy(ip[8:24], srcIPBytes)

	// UDP at offset 58
	udp := raw[58:]
	binary.BigEndian.PutUint16(udp[0:2], 9000)
	binary.BigEndian.PutUint16(udp[2:4], 9001)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen))
	copy(udp[8:], payload)

	srcIP, data := parsePcapPacket(raw, 1, 14)
	if srcIP != "fd00::42" {
		t.Errorf("srcIP = %q, want fd00::42", srcIP)
	}
	if string(data) != "V6VL" {
		t.Errorf("payload = %q, want V6VL", string(data))
	}
}

func TestParsePcapPacketEmptyPayload(t *testing.T) {
	// Valid structure but empty payload
	raw := make([]byte, 14+20+8) // Ethernet + IPv4 + UDP header only
	binary.BigEndian.PutUint16(raw[12:14], 0x0800)

	ip := raw[14:]
	ip[0] = 0x45
	ip[9] = 17
	ip[12], ip[13], ip[14], ip[15] = 1, 1, 1, 1

	udp := raw[34:]
	binary.BigEndian.PutUint16(udp[0:2], 100)
	binary.BigEndian.PutUint16(udp[2:4], 200)
	binary.BigEndian.PutUint16(udp[4:6], 8) // only header, no payload

	srcIP, data := parsePcapPacket(raw, 1, 14)
	if srcIP != "1.1.1.1" {
		t.Errorf("srcIP = %q, want 1.1.1.1", srcIP)
	}
	// Empty payload is valid (zero length)
	if len(data) != 0 {
		t.Errorf("expected empty payload, got %d bytes", len(data))
	}
}

func TestLinkHeaderLenAllTypes(t *testing.T) {
	// Ensure we have complete coverage of all DLT types
	tests := []struct {
		name     string
		linkType int
		want     int
	}{
		{"Ethernet", dltEN10MB, 14},
		{"BSD loopback", dltNull, 4},
		{"Linux SLL", dltLinuxSLL, 16},
		{"Raw IP (12)", dltRaw12, 0},
		{"Raw IP (101)", dltRaw101, 0},
		{"Unsupported 50", 50, -1},
		{"Unsupported 200", 200, -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := linkHeaderLen(tt.linkType)
			if got != tt.want {
				t.Errorf("linkHeaderLen(%d) = %d, want %d", tt.linkType, got, tt.want)
			}
		})
	}
}

func TestParseIPv6UDPFragmentExtension(t *testing.T) {
	// IPv6 with Fragment extension header, then UDP
	payload := []byte("FRAG")
	udpLen := 8 + len(payload)

	// IPv6 header (40) + Fragment ext (8) + UDP + payload
	pkt := make([]byte, 40+8+udpLen)
	pkt[0] = 0x60
	pkt[6] = 44 // Next Header = Fragment

	srcIPBytes := net.ParseIP("2001:db8::ff").To16()
	copy(pkt[8:24], srcIPBytes)

	// Fragment extension header (8 bytes fixed)
	pkt[40] = 17 // Next Header = UDP
	// Fragment offset etc (we don't check it, just need to parse through)
	pkt[41] = 0

	// UDP at offset 48
	binary.BigEndian.PutUint16(pkt[48:50], 1111)
	binary.BigEndian.PutUint16(pkt[50:52], 2222)
	binary.BigEndian.PutUint16(pkt[52:54], uint16(udpLen))
	copy(pkt[56:], payload)

	srcIP, data := parseIPv6UDP(pkt)
	if srcIP != "2001:db8::ff" {
		t.Errorf("srcIP = %q, want 2001:db8::ff", srcIP)
	}
	if string(data) != "FRAG" {
		t.Errorf("payload = %q, want FRAG", string(data))
	}
}

func TestParsePcapPacketRawIPv6(t *testing.T) {
	// DLT_RAW with IPv6 packet
	payload := []byte("R6")
	udpLen := 8 + len(payload)

	raw := make([]byte, 40+udpLen) // No link header for DLT_RAW
	raw[0] = 0x60                  // IPv6
	raw[6] = 17                    // UDP
	binary.BigEndian.PutUint16(raw[4:6], uint16(udpLen))

	srcIPBytes := net.ParseIP("::1").To16()
	copy(raw[8:24], srcIPBytes)

	// UDP at offset 40
	binary.BigEndian.PutUint16(raw[40:42], 3333)
	binary.BigEndian.PutUint16(raw[42:44], 4444)
	binary.BigEndian.PutUint16(raw[44:46], uint16(udpLen))
	copy(raw[48:], payload)

	srcIP, data := parsePcapPacket(raw, 12, 0)
	if srcIP != "::1" {
		t.Errorf("srcIP = %q, want ::1", srcIP)
	}
	if string(data) != "R6" {
		t.Errorf("payload = %q, want R6", string(data))
	}
}

func TestParseIPv6UDPExcessiveExtensionHeaders(t *testing.T) {
	// Craft a packet with more extension headers than maxIPv6ExtHeaders.
	// The parser should give up and return nil rather than looping indefinitely.
	numHeaders := maxIPv6ExtHeaders + 5
	extSize := 8 // each hop-by-hop ext header is 8 bytes (len field = 0)

	pktSize := 40 + numHeaders*extSize + 8 + 5 // IPv6 + exts + UDP + payload
	pkt := make([]byte, pktSize)
	pkt[0] = 0x60 // Version=6
	pkt[6] = 0    // Next Header = Hop-by-Hop Options

	srcIPBytes := net.ParseIP("2001:db8::dead").To16()
	copy(pkt[8:24], srcIPBytes)

	// Chain extension headers: each points to Hop-by-Hop (type 0) except the last
	offset := 40
	for i := 0; i < numHeaders-1; i++ {
		pkt[offset] = 0   // Next Header = Hop-by-Hop (creates a chain)
		pkt[offset+1] = 0 // Hdr Ext Len = 0 (8 bytes)
		offset += extSize
	}
	// Last extension header points to UDP
	pkt[offset] = 17  // Next Header = UDP
	pkt[offset+1] = 0 // Hdr Ext Len = 0
	offset += extSize

	// UDP header
	binary.BigEndian.PutUint16(pkt[offset:offset+2], 1234)
	binary.BigEndian.PutUint16(pkt[offset+2:offset+4], 5678)
	binary.BigEndian.PutUint16(pkt[offset+4:offset+6], 13) // 8 + 5
	copy(pkt[offset+8:], []byte("FLOOD"))

	_, data := parseIPv6UDP(pkt)
	if data != nil {
		t.Error("expected nil for packet with excessive extension headers")
	}
}

func TestParseIPv6UDPMaxExtensionHeadersBoundary(t *testing.T) {
	// Exactly maxIPv6ExtHeaders extension headers should still work
	numHeaders := maxIPv6ExtHeaders
	extSize := 8

	payload := []byte("MAXOK")
	udpLen := 8 + len(payload)
	pktSize := 40 + numHeaders*extSize + udpLen
	pkt := make([]byte, pktSize)
	pkt[0] = 0x60
	pkt[6] = 0 // First ext: Hop-by-Hop

	srcIPBytes := net.ParseIP("2001:db8::cafe").To16()
	copy(pkt[8:24], srcIPBytes)

	offset := 40
	for i := 0; i < numHeaders-1; i++ {
		pkt[offset] = 0
		pkt[offset+1] = 0
		offset += extSize
	}
	// Last ext -> UDP
	pkt[offset] = 17
	pkt[offset+1] = 0
	offset += extSize

	binary.BigEndian.PutUint16(pkt[offset:offset+2], 1111)
	binary.BigEndian.PutUint16(pkt[offset+2:offset+4], 2222)
	binary.BigEndian.PutUint16(pkt[offset+4:offset+6], uint16(udpLen))
	copy(pkt[offset+8:], payload)

	srcIP, data := parseIPv6UDP(pkt)
	if srcIP != "2001:db8::cafe" {
		t.Errorf("srcIP = %q, want 2001:db8::cafe", srcIP)
	}
	if string(data) != "MAXOK" {
		t.Errorf("payload = %q, want MAXOK", string(data))
	}
}
