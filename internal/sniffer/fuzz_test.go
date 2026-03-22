// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package sniffer

import (
	"encoding/binary"
	"net"
	"testing"
)

// --- Fuzz tests for packet parsing ---

// FuzzParsePcapPacket feeds arbitrary raw bytes into the packet parser.
// Must never panic regardless of input. Covers link-layer, IP, and UDP parsing.
func FuzzParsePcapPacket(f *testing.F) {
	// Empty and tiny packets
	f.Add([]byte{}, 1, 14)
	f.Add([]byte{0}, 1, 14)
	f.Add(make([]byte, 14), 1, 14)

	// Valid-looking Ethernet + IPv4 + UDP
	ethIPv4UDP := buildTestEthernetIPv4UDP("10.20.30.40", 12345, 54321, []byte("payload"))
	f.Add(ethIPv4UDP, 1, 14)

	// BSD loopback
	loopback := buildTestLoopbackIPv4UDP("10.0.0.1", 1234, 5678, []byte("data"))
	f.Add(loopback, 0, 4)

	// Raw IP
	rawIP := buildTestIPv4UDP("172.16.0.1", 9999, 8888, []byte("raw"))
	f.Add(rawIP, 101, 0)

	// Linux cooked capture
	cooked := buildTestLinuxCookedIPv4UDP("192.168.0.1", 4444, 5555, []byte("cooked"))
	f.Add(cooked, 113, 16)

	// IPv6
	ethIPv6 := buildTestEthernetIPv6UDP("2001:db8::1", 1111, 2222, []byte("v6data"))
	f.Add(ethIPv6, 1, 14)

	// Various garbage
	f.Add(make([]byte, 100), 1, 14)
	f.Add(make([]byte, 100), 0, 4)
	f.Add(make([]byte, 100), 101, 0)
	f.Add(make([]byte, 100), 113, 16)
	f.Add(make([]byte, 1500), 1, 14)

	f.Fuzz(func(t *testing.T, data []byte, linkType, linkHdrLen int) {
		// Constrain linkType to valid values to test deeper paths
		switch linkType {
		case dltNull, dltEN10MB, dltRaw12, dltRaw101, dltLinuxSLL:
			// valid
		default:
			return // skip unsupported link types to focus on real paths
		}
		hdrLen := linkHeaderLen(linkType)
		if hdrLen < 0 {
			return
		}
		// Must not panic
		_, _ = parsePcapPacket(data, linkType, hdrLen)
	})
}

// FuzzParseIPv4UDP feeds arbitrary bytes into IPv4+UDP parser.
func FuzzParseIPv4UDP(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 20)) // minimum IPv4 header
	f.Add(make([]byte, 28)) // IPv4 + UDP header
	f.Add(make([]byte, 40)) // IPv4 + UDP + some payload

	validPkt := buildTestIPv4UDP("10.0.0.1", 1234, 5678, []byte("HELLO"))
	f.Add(validPkt)

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must not panic
		_, _ = parseIPv4UDP(data)
	})
}

// FuzzParseIPv6UDP feeds arbitrary bytes into IPv6+UDP parser.
func FuzzParseIPv6UDP(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 40)) // minimum IPv6 header
	f.Add(make([]byte, 48)) // IPv6 + UDP header
	f.Add(make([]byte, 60)) // with some payload

	validPkt := buildTestIPv6UDPRaw("2001:db8::1", 1234, 5678, []byte("DATA"))
	f.Add(validPkt)

	// IPv6 with extension headers
	withExtHeaders := buildTestIPv6WithExtHeaders("2001:db8::1", []byte("EXTDATA"))
	f.Add(withExtHeaders)

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must not panic
		_, _ = parseIPv6UDP(data)
	})
}

// --- Property-based tests ---

// TestParsePcapPacket_AllLinkTypes tests all supported link layer types.
func TestParsePcapPacket_AllLinkTypes(t *testing.T) {
	payload := []byte("test-payload-data-for-parsing")

	tests := []struct {
		name     string
		linkType int
		builder  func() []byte
	}{
		{"Ethernet_IPv4", dltEN10MB, func() []byte {
			return buildTestEthernetIPv4UDP("10.20.30.40", 12345, 54321, payload)
		}},
		{"BSDLoopback_IPv4", dltNull, func() []byte {
			return buildTestLoopbackIPv4UDP("10.0.0.1", 1234, 5678, payload)
		}},
		{"RawIP_IPv4", dltRaw101, func() []byte {
			return buildTestIPv4UDP("172.16.0.1", 9999, 8888, payload)
		}},
		{"RawIP12_IPv4", dltRaw12, func() []byte {
			return buildTestIPv4UDP("172.16.0.1", 9999, 8888, payload)
		}},
		{"LinuxCooked_IPv4", dltLinuxSLL, func() []byte {
			return buildTestLinuxCookedIPv4UDP("192.168.0.1", 4444, 5555, payload)
		}},
		{"Ethernet_IPv6", dltEN10MB, func() []byte {
			return buildTestEthernetIPv6UDP("2001:db8::1", 1111, 2222, payload)
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := tt.builder()
			hdrLen := linkHeaderLen(tt.linkType)
			srcIP, data := parsePcapPacket(raw, tt.linkType, hdrLen)
			if srcIP == "" {
				t.Error("expected source IP, got empty")
			}
			if data == nil {
				t.Error("expected payload, got nil")
			}
			if len(data) < len(payload) {
				t.Errorf("payload too short: got %d, want >= %d", len(data), len(payload))
			}
		})
	}
}

// TestParsePcapPacket_MalformedEthernet tests malformed Ethernet frames.
func TestParsePcapPacket_MalformedEthernet(t *testing.T) {
	tests := []struct {
		name string
		raw  []byte
	}{
		{"empty", []byte{}},
		{"too_short_for_ethernet", make([]byte, 13)},
		{"invalid_ethertype", func() []byte {
			pkt := make([]byte, 60)
			binary.BigEndian.PutUint16(pkt[12:14], 0x1234) // unknown EtherType
			return pkt
		}()},
		{"vlan_but_too_short", func() []byte {
			pkt := make([]byte, 16)
			binary.BigEndian.PutUint16(pkt[12:14], 0x8100) // VLAN
			return pkt
		}()},
		{"vlan_non_ip", func() []byte {
			pkt := make([]byte, 60)
			binary.BigEndian.PutUint16(pkt[12:14], 0x8100) // VLAN tag
			binary.BigEndian.PutUint16(pkt[16:18], 0x1234) // non-IP EtherType after VLAN
			return pkt
		}()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srcIP, data := parsePcapPacket(tt.raw, dltEN10MB, 14)
			if srcIP != "" || data != nil {
				t.Errorf("expected empty result for malformed packet, got srcIP=%q, data=%v", srcIP, data)
			}
		})
	}
}

// TestParsePcapPacket_InvalidBSDLoopback tests invalid BSD loopback address families.
func TestParsePcapPacket_InvalidBSDLoopback(t *testing.T) {
	// Build a packet with an unknown address family
	for _, af := range []uint32{0, 1, 3, 99, 0xFFFFFFFF} {
		pkt := make([]byte, 100)
		binary.LittleEndian.PutUint32(pkt[:4], af)
		// Add minimal IP-like header after
		pkt[4] = 0x45 // looks like IPv4
		pkt[13] = 17  // UDP

		srcIP, data := parsePcapPacket(pkt, dltNull, 4)
		if srcIP != "" || data != nil {
			t.Errorf("AF %d: expected rejection, got srcIP=%q", af, srcIP)
		}
	}
}

// TestParseIPv6_ExtensionHeaderDoS tests that excessive extension headers are bounded.
func TestParseIPv6_ExtensionHeaderDoS(t *testing.T) {
	// Build an IPv6 packet with maxIPv6ExtHeaders+5 hop-by-hop extension headers
	numExtHdrs := maxIPv6ExtHeaders + 5
	ipv6Hdr := make([]byte, 40)
	ipv6Hdr[0] = 0x60 // Version=6
	ipv6Hdr[6] = 0    // Next Header = Hop-by-Hop
	copy(ipv6Hdr[8:24], net.ParseIP("2001:db8::1").To16())
	copy(ipv6Hdr[24:40], net.ParseIP("2001:db8::2").To16())

	data := make([]byte, 0, 40+numExtHdrs*8+8+5)
	data = append(data, ipv6Hdr...)

	// Chain extension headers (hop-by-hop, each 8 bytes)
	for i := 0; i < numExtHdrs; i++ {
		nextHdr := byte(0) // Hop-by-Hop (chains to next)
		if i == numExtHdrs-1 {
			nextHdr = 17 // Last one points to UDP
		}
		extHdr := make([]byte, 8)
		extHdr[0] = nextHdr
		extHdr[1] = 0 // Length = 0 (8 bytes total: 1 unit * 8)
		data = append(data, extHdr...)
	}

	// Add UDP header + payload
	udpHdr := make([]byte, 8)
	binary.BigEndian.PutUint16(udpHdr[0:2], 1234)
	binary.BigEndian.PutUint16(udpHdr[2:4], 5678)
	binary.BigEndian.PutUint16(udpHdr[4:6], 13)
	data = append(data, udpHdr...)
	data = append(data, []byte("HELLO")...)

	srcIP, payload := parseIPv6UDP(data)
	// Should be empty because we exceeded maxIPv6ExtHeaders
	if srcIP != "" || payload != nil {
		t.Error("expected rejection of excessive extension headers")
	}
}

// TestParseIPv6_FragmentHeader tests IPv6 fragment extension header handling.
func TestParseIPv6_FragmentHeader(t *testing.T) {
	// IPv6 header with Fragment extension header (44) before UDP
	ipv6Hdr := make([]byte, 40)
	ipv6Hdr[0] = 0x60
	ipv6Hdr[6] = 44 // Next Header = Fragment
	copy(ipv6Hdr[8:24], net.ParseIP("2001:db8::1").To16())
	copy(ipv6Hdr[24:40], net.ParseIP("2001:db8::2").To16())

	// Fragment header (8 bytes)
	fragHdr := make([]byte, 8)
	fragHdr[0] = 17 // Next Header = UDP

	// UDP header + payload
	payload := []byte("TEST")
	udpHdr := make([]byte, 8)
	binary.BigEndian.PutUint16(udpHdr[0:2], 1234)
	binary.BigEndian.PutUint16(udpHdr[2:4], 5678)
	binary.BigEndian.PutUint16(udpHdr[4:6], uint16(8+len(payload)))

	var pkt []byte
	pkt = append(pkt, ipv6Hdr...)
	pkt = append(pkt, fragHdr...)
	pkt = append(pkt, udpHdr...)
	pkt = append(pkt, payload...)

	srcIP, data := parseIPv6UDP(pkt)
	if srcIP == "" {
		t.Error("expected valid source IP")
	}
	if data == nil || len(data) < len(payload) {
		t.Error("expected valid payload")
	}
}

// TestParseIPv4_VariableIHL tests IPv4 packets with different IHL values.
func TestParseIPv4_VariableIHL(t *testing.T) {
	tests := []struct {
		name   string
		ihl    int
		wantOK bool
	}{
		{"IHL=5 (20 bytes)", 5, true},
		{"IHL=6 (24 bytes, options)", 6, true},
		{"IHL=15 (60 bytes, max)", 15, true},
		{"IHL=4 (16 bytes, invalid)", 4, false},
		{"IHL=0 (invalid)", 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ihlBytes := tt.ihl * 4
			if ihlBytes < 20 && tt.wantOK {
				return // skip impossible cases
			}
			totalLen := ihlBytes + 8 + 5 // IPv4 + UDP + "HELLO"
			pkt := make([]byte, totalLen)
			pkt[0] = byte(0x40 | (tt.ihl & 0x0F)) // Version=4, IHL=tt.ihl
			pkt[9] = 17                           // UDP

			if ihlBytes >= 20 {
				copy(pkt[12:16], net.ParseIP("10.0.0.1").To4())

				// UDP header at offset ihlBytes
				udpOff := ihlBytes
				if udpOff+8 <= len(pkt) {
					binary.BigEndian.PutUint16(pkt[udpOff:udpOff+2], 1234)
					binary.BigEndian.PutUint16(pkt[udpOff+2:udpOff+4], 5678)
					binary.BigEndian.PutUint16(pkt[udpOff+4:udpOff+6], uint16(8+5))
				}

				if udpOff+8+5 <= len(pkt) {
					copy(pkt[udpOff+8:], []byte("HELLO"))
				}
			}

			srcIP, data := parseIPv4UDP(pkt)
			if tt.wantOK && srcIP == "" {
				t.Error("expected valid parse")
			}
			if !tt.wantOK && (srcIP != "" || data != nil) {
				t.Error("expected rejection")
			}
		})
	}
}

// TestParsePcapPacket_LinuxCookedNonIP tests Linux cooked capture with non-IP protocols.
func TestParsePcapPacket_LinuxCookedNonIP(t *testing.T) {
	for _, proto := range []uint16{0x0806, 0x8035, 0x0000, 0xFFFF} {
		pkt := make([]byte, 60)
		binary.BigEndian.PutUint16(pkt[14:16], proto) // non-IP protocol
		pkt[16] = 0x45                                // looks like IPv4 after header
		pkt[25] = 17                                  // UDP

		srcIP, data := parsePcapPacket(pkt, dltLinuxSLL, 16)
		if srcIP != "" || data != nil {
			t.Errorf("proto 0x%04x: expected rejection for non-IP protocol", proto)
		}
	}
}

// TestPacketSizeBounds verifies MinPacketSize and MaxPacketSize constants.
func TestPacketSizeBounds(t *testing.T) {
	if MinPacketSize != 1118 {
		t.Errorf("MinPacketSize = %d, want 1118", MinPacketSize)
	}
	if MaxPacketSize != 8192 {
		t.Errorf("MaxPacketSize = %d, want 8192", MaxPacketSize)
	}
	if MinPacketSize >= MaxPacketSize {
		t.Error("MinPacketSize must be less than MaxPacketSize")
	}
}

// --- Helper functions for building test packets ---

func buildTestIPv4UDP(srcIP string, srcPort, dstPort uint16, payload []byte) []byte {
	udpLen := 8 + len(payload)
	totalLen := 20 + udpLen
	pkt := make([]byte, totalLen)
	pkt[0] = 0x45 // Version=4, IHL=5
	pkt[9] = 17   // UDP
	copy(pkt[12:16], net.ParseIP(srcIP).To4())
	copy(pkt[16:20], net.ParseIP("192.168.1.1").To4())
	binary.BigEndian.PutUint16(pkt[20:22], srcPort)
	binary.BigEndian.PutUint16(pkt[22:24], dstPort)
	binary.BigEndian.PutUint16(pkt[24:26], uint16(udpLen))
	copy(pkt[28:], payload)
	return pkt
}

func buildTestEthernetIPv4UDP(srcIP string, srcPort, dstPort uint16, payload []byte) []byte {
	ipPkt := buildTestIPv4UDP(srcIP, srcPort, dstPort, payload)
	ethHdr := make([]byte, 14)
	binary.BigEndian.PutUint16(ethHdr[12:14], 0x0800) // IPv4
	return append(ethHdr, ipPkt...)
}

func buildTestLoopbackIPv4UDP(srcIP string, srcPort, dstPort uint16, payload []byte) []byte {
	ipPkt := buildTestIPv4UDP(srcIP, srcPort, dstPort, payload)
	loHdr := make([]byte, 4)
	binary.LittleEndian.PutUint32(loHdr, 2) // AF_INET
	return append(loHdr, ipPkt...)
}

func buildTestLinuxCookedIPv4UDP(srcIP string, srcPort, dstPort uint16, payload []byte) []byte {
	ipPkt := buildTestIPv4UDP(srcIP, srcPort, dstPort, payload)
	sllHdr := make([]byte, 16)
	binary.BigEndian.PutUint16(sllHdr[14:16], 0x0800) // IPv4
	return append(sllHdr, ipPkt...)
}

func buildTestIPv6UDPRaw(srcIP string, srcPort, dstPort uint16, payload []byte) []byte {
	udpLen := 8 + len(payload)
	pktLen := 40 + udpLen
	pkt := make([]byte, pktLen)
	pkt[0] = 0x60 // Version=6
	pkt[6] = 17   // Next Header = UDP
	binary.BigEndian.PutUint16(pkt[4:6], uint16(udpLen))
	copy(pkt[8:24], net.ParseIP(srcIP).To16())
	copy(pkt[24:40], net.ParseIP("2001:db8::2").To16())
	// UDP header
	binary.BigEndian.PutUint16(pkt[40:42], srcPort)
	binary.BigEndian.PutUint16(pkt[42:44], dstPort)
	binary.BigEndian.PutUint16(pkt[44:46], uint16(udpLen))
	copy(pkt[48:], payload)
	return pkt
}

func buildTestEthernetIPv6UDP(srcIP string, srcPort, dstPort uint16, payload []byte) []byte {
	ipPkt := buildTestIPv6UDPRaw(srcIP, srcPort, dstPort, payload)
	ethHdr := make([]byte, 14)
	binary.BigEndian.PutUint16(ethHdr[12:14], 0x86DD) // IPv6
	return append(ethHdr, ipPkt...)
}

func buildTestIPv6WithExtHeaders(srcIP string, payload []byte) []byte {
	udpLen := 8 + len(payload)
	// IPv6 header + 2 extension headers + UDP
	pkt := make([]byte, 40+8+8+udpLen)
	pkt[0] = 0x60
	pkt[6] = 0 // Next Header = Hop-by-Hop
	copy(pkt[8:24], net.ParseIP(srcIP).To16())
	copy(pkt[24:40], net.ParseIP("2001:db8::2").To16())

	// Hop-by-Hop ext header (8 bytes)
	pkt[40] = 43 // Next = Routing
	pkt[41] = 0  // Length = 0 (total 8 bytes)

	// Routing ext header (8 bytes)
	pkt[48] = 17 // Next = UDP
	pkt[49] = 0  // Length = 0

	// UDP header
	off := 56
	binary.BigEndian.PutUint16(pkt[off:off+2], 1234)
	binary.BigEndian.PutUint16(pkt[off+2:off+4], 5678)
	binary.BigEndian.PutUint16(pkt[off+4:off+6], uint16(udpLen))
	copy(pkt[off+8:], payload)
	return pkt
}

// --- Mutation-resilient tests ---

// TestParsePcapPacket_ProtocolNotUDP verifies non-UDP IPv4 packets are rejected.
func TestParsePcapPacket_ProtocolNotUDP(t *testing.T) {
	for _, proto := range []byte{0, 1, 6, 47, 50, 51, 58, 89, 132} {
		pkt := make([]byte, 60)
		pkt[0] = 0x45 // IPv4
		pkt[9] = proto
		copy(pkt[12:16], net.ParseIP("10.0.0.1").To4())

		srcIP, data := parseIPv4UDP(pkt)
		if srcIP != "" || data != nil {
			t.Errorf("protocol %d: expected rejection for non-UDP", proto)
		}
	}
}

// TestParseIPv4UDP_UDPHeaderTooShort verifies packets with truncated UDP headers.
func TestParseIPv4UDP_UDPHeaderTooShort(t *testing.T) {
	// IPv4 header (20 bytes) + 7 bytes UDP (too short, need 8)
	pkt := make([]byte, 27)
	pkt[0] = 0x45
	pkt[9] = 17
	copy(pkt[12:16], net.ParseIP("10.0.0.1").To4())

	srcIP, data := parseIPv4UDP(pkt)
	if srcIP != "" || data != nil {
		t.Error("expected rejection for truncated UDP header")
	}
}

// TestParseIPv6UDP_NoNextHeader tests IPv6 No Next Header (59).
func TestParseIPv6UDP_NoNextHeader(t *testing.T) {
	pkt := make([]byte, 40)
	pkt[0] = 0x60
	pkt[6] = 59 // No Next Header
	copy(pkt[8:24], net.ParseIP("2001:db8::1").To16())
	copy(pkt[24:40], net.ParseIP("2001:db8::2").To16())

	srcIP, data := parseIPv6UDP(pkt)
	if srcIP != "" || data != nil {
		t.Error("expected rejection for No Next Header")
	}
}

// TestParseIPv6UDP_UnknownExtHeader tests IPv6 with unrecognized extension header.
func TestParseIPv6UDP_UnknownExtHeader(t *testing.T) {
	pkt := make([]byte, 60)
	pkt[0] = 0x60
	pkt[6] = 200 // Unknown extension header type
	copy(pkt[8:24], net.ParseIP("2001:db8::1").To16())
	copy(pkt[24:40], net.ParseIP("2001:db8::2").To16())

	srcIP, data := parseIPv6UDP(pkt)
	if srcIP != "" || data != nil {
		t.Error("expected rejection for unknown extension header")
	}
}

// TestParsePcapPacket_EthernetVLAN tests VLAN-tagged Ethernet frames.
func TestParsePcapPacket_EthernetVLAN(t *testing.T) {
	// Build a VLAN-tagged IPv4 UDP packet
	ipPkt := buildTestIPv4UDP("10.0.0.1", 1234, 5678, []byte("VLAN"))

	// Ethernet header with VLAN tag
	ethHdr := make([]byte, 18)                        // 14 + 4 VLAN
	binary.BigEndian.PutUint16(ethHdr[12:14], 0x8100) // VLAN EtherType
	binary.BigEndian.PutUint16(ethHdr[14:16], 100)    // VLAN ID
	binary.BigEndian.PutUint16(ethHdr[16:18], 0x0800) // Inner EtherType: IPv4

	pkt := append(ethHdr, ipPkt...)

	srcIP, data := parsePcapPacket(pkt, dltEN10MB, 14)
	if srcIP == "" {
		t.Error("expected valid source IP for VLAN-tagged packet")
	}
	if data == nil {
		t.Error("expected valid payload for VLAN-tagged packet")
	}
}

// TestParseIPv4_NonIPVersion tests rejection of non-IPv4/IPv6 version fields.
func TestParseIPv4_NonIPVersion(t *testing.T) {
	for _, ver := range []byte{0, 1, 2, 3, 5, 7, 8, 15} {
		pkt := make([]byte, 60)
		pkt[0] = (ver << 4) | 5 // Version=ver, IHL=5

		// parsePcapPacket routes by version nibble
		srcIP, data := parsePcapPacket(pkt, dltRaw101, 0)
		if srcIP != "" || data != nil {
			t.Errorf("version %d: expected rejection", ver)
		}
	}
}
