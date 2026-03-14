//go:build windows

// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package sniffer

import (
	"encoding/binary"
	"net"
	"testing"
)

// ----------------------------------------------------------------------
//  processIPv4 tests
// ----------------------------------------------------------------------

// buildIPv4UDP constructs a raw IPv4+UDP packet (no Ethernet header).
func buildIPv4UDP(srcIP net.IP, dstPort uint16, payload []byte) []byte {
	// IPv4 header (20 bytes, IHL=5)
	iph := make([]byte, 20)
	iph[0] = 0x45 // Version=4, IHL=5
	totalLen := 20 + 8 + len(payload)
	binary.BigEndian.PutUint16(iph[2:4], uint16(totalLen))
	iph[9] = 17 // Protocol = UDP
	copy(iph[12:16], srcIP.To4())
	copy(iph[16:20], net.IPv4(10, 0, 0, 1).To4()) // dst IP

	// UDP header (8 bytes)
	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:2], 54321) // src port
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(8+len(payload)))

	pkt := iph
	pkt = append(pkt, udp...)
	pkt = append(pkt, payload...)
	return pkt
}

// buildIPv6UDP constructs a raw IPv6+UDP packet (no Ethernet header).
func buildIPv6UDP(srcIP net.IP, dstPort uint16, payload []byte) []byte {
	// IPv6 header (40 bytes)
	iph := make([]byte, 40)
	iph[0] = 0x60 // Version=6
	payLen := 8 + len(payload)
	binary.BigEndian.PutUint16(iph[4:6], uint16(payLen))
	iph[6] = 17 // Next Header = UDP
	iph[7] = 64 // Hop Limit
	copy(iph[8:24], srcIP.To16())
	copy(iph[24:40], net.ParseIP("::1").To16())

	// UDP header (8 bytes)
	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:2], 54321)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(8+len(payload)))

	pkt := iph
	pkt = append(pkt, udp...)
	pkt = append(pkt, payload...)
	return pkt
}

func TestProcessIPv4Valid(t *testing.T) {
	payload := make([]byte, MinPacketSize)
	for i := range payload {
		payload[i] = byte(i % 256)
	}
	srcIP := net.IPv4(192, 168, 1, 50)
	pkt := buildIPv4UDP(srcIP, 9999, payload)

	s := &WinDivertSniffer{port: 9999}
	var gotData []byte
	var gotIP string
	s.processIPv4(pkt, func(data []byte, ip string) {
		gotData = data
		gotIP = ip
	})

	if gotData == nil {
		t.Fatal("handler not called for valid IPv4 UDP packet")
	}
	if len(gotData) != MinPacketSize {
		t.Errorf("payload len = %d, want %d", len(gotData), MinPacketSize)
	}
	if gotIP != "192.168.1.50" {
		t.Errorf("source IP = %q, want 192.168.1.50", gotIP)
	}
}

func TestProcessIPv4WrongPort(t *testing.T) {
	payload := make([]byte, MinPacketSize)
	pkt := buildIPv4UDP(net.IPv4(10, 0, 0, 1), 8888, payload)

	s := &WinDivertSniffer{port: 9999}
	called := false
	s.processIPv4(pkt, func(data []byte, ip string) {
		called = true
	})
	if called {
		t.Error("handler should not be called for wrong port")
	}
}

func TestProcessIPv4NotUDP(t *testing.T) {
	pkt := buildIPv4UDP(net.IPv4(10, 0, 0, 1), 9999, make([]byte, MinPacketSize))
	pkt[9] = 6 // TCP

	s := &WinDivertSniffer{port: 9999}
	called := false
	s.processIPv4(pkt, func(data []byte, ip string) {
		called = true
	})
	if called {
		t.Error("handler should not be called for non-UDP packet")
	}
}

func TestProcessIPv4TooShort(t *testing.T) {
	s := &WinDivertSniffer{port: 9999}
	called := false
	s.processIPv4([]byte{1, 2, 3}, func(data []byte, ip string) {
		called = true
	})
	if called {
		t.Error("handler should not be called for truncated packet")
	}
}

func TestProcessIPv4ShortHeader(t *testing.T) {
	// 19-byte "packet" - less than minimum 20
	s := &WinDivertSniffer{port: 9999}
	called := false
	s.processIPv4(make([]byte, 19), func(data []byte, ip string) {
		called = true
	})
	if called {
		t.Error("handler should not be called for < 20 bytes")
	}
}

func TestProcessIPv4IHLTooSmall(t *testing.T) {
	pkt := buildIPv4UDP(net.IPv4(10, 0, 0, 1), 9999, make([]byte, MinPacketSize))
	pkt[0] = 0x43 // IHL=3

	s := &WinDivertSniffer{port: 9999}
	called := false
	s.processIPv4(pkt, func(data []byte, ip string) {
		called = true
	})
	if called {
		t.Error("handler should not be called for IHL < 5")
	}
}

func TestProcessIPv4IHLBeyondPacket(t *testing.T) {
	pkt := make([]byte, 28) // 20 header + 8 UDP, no payload
	pkt[0] = 0x4F           // IHL=15 (60 bytes)
	pkt[9] = 17

	s := &WinDivertSniffer{port: 9999}
	called := false
	s.processIPv4(pkt, func(data []byte, ip string) {
		called = true
	})
	if called {
		t.Error("handler should not be called when IHL exceeds packet")
	}
}

func TestProcessIPv4VariableIHL(t *testing.T) {
	// IHL=8 (32 bytes header with options)
	payload := make([]byte, MinPacketSize)
	srcIP := net.IPv4(172, 16, 0, 5)
	pkt := buildIPv4UDP(srcIP, 9999, payload)

	// Expand: insert 12 bytes of IP options between header[20:] and UDP
	pkt[0] = 0x48 // IHL=8
	expanded := make([]byte, 0, len(pkt)+12)
	expanded = append(expanded, pkt[:20]...)
	expanded = append(expanded, make([]byte, 12)...) // IP options
	expanded = append(expanded, pkt[20:]...)         // UDP + payload

	s := &WinDivertSniffer{port: 9999}
	var gotIP string
	s.processIPv4(expanded, func(data []byte, ip string) {
		gotIP = ip
	})
	if gotIP != "172.16.0.5" {
		t.Errorf("source IP = %q, want 172.16.0.5", gotIP)
	}
}

func TestProcessIPv4PayloadTooSmall(t *testing.T) {
	payload := make([]byte, MinPacketSize-1)
	pkt := buildIPv4UDP(net.IPv4(10, 0, 0, 1), 9999, payload)

	s := &WinDivertSniffer{port: 9999}
	called := false
	s.processIPv4(pkt, func(data []byte, ip string) {
		called = true
	})
	if called {
		t.Error("handler should not be called for undersized payload")
	}
}

func TestProcessIPv4PayloadTooLarge(t *testing.T) {
	payload := make([]byte, MaxPacketSize+1)
	pkt := buildIPv4UDP(net.IPv4(10, 0, 0, 1), 9999, payload)

	s := &WinDivertSniffer{port: 9999}
	called := false
	s.processIPv4(pkt, func(data []byte, ip string) {
		called = true
	})
	if called {
		t.Error("handler should not be called for oversized payload")
	}
}

func TestProcessIPv4MaxPayload(t *testing.T) {
	payload := make([]byte, MaxPacketSize)
	pkt := buildIPv4UDP(net.IPv4(1, 2, 3, 4), 9999, payload)

	s := &WinDivertSniffer{port: 9999}
	var gotLen int
	s.processIPv4(pkt, func(data []byte, ip string) {
		gotLen = len(data)
	})
	if gotLen != MaxPacketSize {
		t.Errorf("payload len = %d, want %d", gotLen, MaxPacketSize)
	}
}

func TestProcessIPv4DataCopied(t *testing.T) {
	payload := make([]byte, MinPacketSize)
	for i := range payload {
		payload[i] = 0xBB
	}
	pkt := buildIPv4UDP(net.IPv4(1, 1, 1, 1), 9999, payload)

	s := &WinDivertSniffer{port: 9999}
	var gotData []byte
	s.processIPv4(pkt, func(data []byte, ip string) {
		gotData = data
	})
	if gotData == nil {
		t.Fatal("handler not called")
	}
	// Modify original
	for i := 28; i < len(pkt); i++ {
		pkt[i] = 0
	}
	for _, b := range gotData {
		if b != 0xBB {
			t.Error("data not properly copied")
			break
		}
	}
}

// ----------------------------------------------------------------------
//  processIPv6 tests
// ----------------------------------------------------------------------

func TestProcessIPv6Valid(t *testing.T) {
	payload := make([]byte, MinPacketSize)
	srcIP := net.ParseIP("2001:db8::42")
	pkt := buildIPv6UDP(srcIP, 9999, payload)

	s := &WinDivertSniffer{port: 9999}
	var gotData []byte
	var gotIP string
	s.processIPv6(pkt, func(data []byte, ip string) {
		gotData = data
		gotIP = ip
	})

	if gotData == nil {
		t.Fatal("handler not called for valid IPv6 UDP packet")
	}
	if len(gotData) != MinPacketSize {
		t.Errorf("payload len = %d, want %d", len(gotData), MinPacketSize)
	}
	if gotIP != "2001:db8::42" {
		t.Errorf("source IP = %q, want 2001:db8::42", gotIP)
	}
}

func TestProcessIPv6WrongPort(t *testing.T) {
	payload := make([]byte, MinPacketSize)
	pkt := buildIPv6UDP(net.ParseIP("::1"), 7777, payload)

	s := &WinDivertSniffer{port: 9999}
	called := false
	s.processIPv6(pkt, func(data []byte, ip string) {
		called = true
	})
	if called {
		t.Error("handler should not be called for wrong port")
	}
}

func TestProcessIPv6NotUDP(t *testing.T) {
	pkt := buildIPv6UDP(net.ParseIP("::1"), 9999, make([]byte, MinPacketSize))
	pkt[6] = 6 // TCP instead of UDP

	s := &WinDivertSniffer{port: 9999}
	called := false
	s.processIPv6(pkt, func(data []byte, ip string) {
		called = true
	})
	if called {
		t.Error("handler should not be called for non-UDP IPv6 packet")
	}
}

func TestProcessIPv6TooShort(t *testing.T) {
	s := &WinDivertSniffer{port: 9999}
	called := false
	s.processIPv6(make([]byte, 39), func(data []byte, ip string) {
		called = true
	})
	if called {
		t.Error("handler should not be called for < 40 byte IPv6 header")
	}
}

func TestProcessIPv6ShortUDPHeader(t *testing.T) {
	// 40-byte IPv6 header + 7 bytes (1 byte short of UDP header)
	pkt := make([]byte, 47)
	pkt[0] = 0x60
	pkt[6] = 17

	s := &WinDivertSniffer{port: 9999}
	called := false
	s.processIPv6(pkt, func(data []byte, ip string) {
		called = true
	})
	if called {
		t.Error("handler should not be called for truncated UDP header after IPv6")
	}
}

func TestProcessIPv6PayloadTooSmall(t *testing.T) {
	payload := make([]byte, MinPacketSize-1)
	pkt := buildIPv6UDP(net.ParseIP("::1"), 9999, payload)

	s := &WinDivertSniffer{port: 9999}
	called := false
	s.processIPv6(pkt, func(data []byte, ip string) {
		called = true
	})
	if called {
		t.Error("handler should not be called for undersized payload")
	}
}

func TestProcessIPv6PayloadTooLarge(t *testing.T) {
	payload := make([]byte, MaxPacketSize+1)
	pkt := buildIPv6UDP(net.ParseIP("::1"), 9999, payload)

	s := &WinDivertSniffer{port: 9999}
	called := false
	s.processIPv6(pkt, func(data []byte, ip string) {
		called = true
	})
	if called {
		t.Error("handler should not be called for oversized payload")
	}
}

func TestProcessIPv6NoNextHeader(t *testing.T) {
	pkt := make([]byte, 60)
	pkt[0] = 0x60
	pkt[6] = 59 // No Next Header

	s := &WinDivertSniffer{port: 9999}
	called := false
	s.processIPv6(pkt, func(data []byte, ip string) {
		called = true
	})
	if called {
		t.Error("handler should not be called for No Next Header")
	}
}

func TestProcessIPv6WithHopByHopExtHeader(t *testing.T) {
	// IPv6 header with Hop-by-Hop extension header -> UDP
	payload := make([]byte, MinPacketSize)
	srcIP := net.ParseIP("fe80::1")

	// Build manually: IPv6 header -> Hop-by-Hop(8 bytes) -> UDP
	iph := make([]byte, 40)
	iph[0] = 0x60
	payLen := 8 + 8 + len(payload) // ext header (8) + UDP header (8) + payload
	binary.BigEndian.PutUint16(iph[4:6], uint16(payLen))
	iph[6] = 0 // Next Header = Hop-by-Hop Options
	iph[7] = 64
	copy(iph[8:24], srcIP.To16())
	copy(iph[24:40], net.ParseIP("::1").To16())

	// Hop-by-Hop extension header (8 bytes minimum)
	ext := make([]byte, 8)
	ext[0] = 17 // Next header = UDP
	ext[1] = 0  // Hdr Ext Len = 0 (8 bytes total)

	// UDP header
	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:2], 54321)
	binary.BigEndian.PutUint16(udp[2:4], 9999)
	binary.BigEndian.PutUint16(udp[4:6], uint16(8+len(payload)))

	pkt := iph
	pkt = append(pkt, ext...)
	pkt = append(pkt, udp...)
	pkt = append(pkt, payload...)

	s := &WinDivertSniffer{port: 9999}
	var gotIP string
	s.processIPv6(pkt, func(data []byte, ip string) {
		gotIP = ip
	})
	if gotIP != "fe80::1" {
		t.Errorf("source IP = %q, want fe80::1", gotIP)
	}
}

func TestProcessIPv6WithRoutingExtHeader(t *testing.T) {
	// IPv6 -> Routing -> UDP
	payload := make([]byte, MinPacketSize)
	srcIP := net.ParseIP("2001:db8::99")

	iph := make([]byte, 40)
	iph[0] = 0x60
	payLen := 8 + 8 + len(payload)
	binary.BigEndian.PutUint16(iph[4:6], uint16(payLen))
	iph[6] = 43 // Next Header = Routing
	iph[7] = 64
	copy(iph[8:24], srcIP.To16())
	copy(iph[24:40], net.ParseIP("::1").To16())

	ext := make([]byte, 8)
	ext[0] = 17 // Next = UDP
	ext[1] = 0  // Hdr Ext Len = 0

	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:2], 54321)
	binary.BigEndian.PutUint16(udp[2:4], 9999)
	binary.BigEndian.PutUint16(udp[4:6], uint16(8+len(payload)))

	pkt := iph
	pkt = append(pkt, ext...)
	pkt = append(pkt, udp...)
	pkt = append(pkt, payload...)

	s := &WinDivertSniffer{port: 9999}
	var gotIP string
	s.processIPv6(pkt, func(data []byte, ip string) {
		gotIP = ip
	})
	if gotIP != "2001:db8::99" {
		t.Errorf("source IP = %q, want 2001:db8::99", gotIP)
	}
}

func TestProcessIPv6WithFragmentHeader(t *testing.T) {
	// IPv6 -> Fragment (8 bytes) -> UDP
	payload := make([]byte, MinPacketSize)
	srcIP := net.ParseIP("fd00::1")

	iph := make([]byte, 40)
	iph[0] = 0x60
	payLen := 8 + 8 + len(payload) // fragment header (8) + UDP (8) + payload
	binary.BigEndian.PutUint16(iph[4:6], uint16(payLen))
	iph[6] = 44 // Next Header = Fragment
	iph[7] = 64
	copy(iph[8:24], srcIP.To16())
	copy(iph[24:40], net.ParseIP("::1").To16())

	// Fragment extension header (8 bytes fixed)
	frag := make([]byte, 8)
	frag[0] = 17 // Next Header = UDP
	// Rest is fragment offset etc. (zeros = first fragment)

	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:2], 54321)
	binary.BigEndian.PutUint16(udp[2:4], 9999)
	binary.BigEndian.PutUint16(udp[4:6], uint16(8+len(payload)))

	pkt := iph
	pkt = append(pkt, frag...)
	pkt = append(pkt, udp...)
	pkt = append(pkt, payload...)

	s := &WinDivertSniffer{port: 9999}
	var gotLen int
	s.processIPv6(pkt, func(data []byte, ip string) {
		gotLen = len(data)
	})
	if gotLen != MinPacketSize {
		t.Errorf("payload len = %d, want %d", gotLen, MinPacketSize)
	}
}

func TestProcessIPv6WithDestinationOptionsExtHeader(t *testing.T) {
	// IPv6 -> Destination Options (60) -> UDP
	payload := make([]byte, MinPacketSize)
	srcIP := net.ParseIP("2001:db8:1::1")

	iph := make([]byte, 40)
	iph[0] = 0x60
	payLen := 8 + 8 + len(payload)
	binary.BigEndian.PutUint16(iph[4:6], uint16(payLen))
	iph[6] = 60 // Destination Options
	iph[7] = 64
	copy(iph[8:24], srcIP.To16())
	copy(iph[24:40], net.ParseIP("::1").To16())

	ext := make([]byte, 8)
	ext[0] = 17 // Next = UDP
	ext[1] = 0  // 8 bytes total

	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:2], 54321)
	binary.BigEndian.PutUint16(udp[2:4], 9999)
	binary.BigEndian.PutUint16(udp[4:6], uint16(8+len(payload)))

	pkt := iph
	pkt = append(pkt, ext...)
	pkt = append(pkt, udp...)
	pkt = append(pkt, payload...)

	s := &WinDivertSniffer{port: 9999}
	var gotIP string
	s.processIPv6(pkt, func(data []byte, ip string) {
		gotIP = ip
	})
	if gotIP != "2001:db8:1::1" {
		t.Errorf("source IP = %q, want 2001:db8:1::1", gotIP)
	}
}

func TestProcessIPv6MultipleExtHeaders(t *testing.T) {
	// IPv6 -> Hop-by-Hop -> Routing -> UDP
	payload := make([]byte, MinPacketSize)
	srcIP := net.ParseIP("2001:db8::ff")

	iph := make([]byte, 40)
	iph[0] = 0x60
	payLen := 8 + 8 + 8 + len(payload) // 2 ext headers + UDP + payload
	binary.BigEndian.PutUint16(iph[4:6], uint16(payLen))
	iph[6] = 0 // Hop-by-Hop Options
	iph[7] = 64
	copy(iph[8:24], srcIP.To16())
	copy(iph[24:40], net.ParseIP("::1").To16())

	// Hop-by-Hop -> Routing
	hopByHop := make([]byte, 8)
	hopByHop[0] = 43 // Next = Routing
	hopByHop[1] = 0  // 8 bytes

	// Routing -> UDP
	routing := make([]byte, 8)
	routing[0] = 17 // Next = UDP
	routing[1] = 0  // 8 bytes

	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:2], 54321)
	binary.BigEndian.PutUint16(udp[2:4], 9999)
	binary.BigEndian.PutUint16(udp[4:6], uint16(8+len(payload)))

	pkt := iph
	pkt = append(pkt, hopByHop...)
	pkt = append(pkt, routing...)
	pkt = append(pkt, udp...)
	pkt = append(pkt, payload...)

	s := &WinDivertSniffer{port: 9999}
	var gotIP string
	s.processIPv6(pkt, func(data []byte, ip string) {
		gotIP = ip
	})
	if gotIP != "2001:db8::ff" {
		t.Errorf("source IP = %q, want 2001:db8::ff", gotIP)
	}
}

func TestProcessIPv6TruncatedExtHeader(t *testing.T) {
	// IPv6 header with Hop-by-Hop but ext header is truncated
	pkt := make([]byte, 41) // 40 + 1 byte (need 2 for ext header)
	pkt[0] = 0x60
	pkt[6] = 0 // Hop-by-Hop

	s := &WinDivertSniffer{port: 9999}
	called := false
	s.processIPv6(pkt, func(data []byte, ip string) {
		called = true
	})
	if called {
		t.Error("handler should not be called for truncated extension header")
	}
}

func TestProcessIPv6UnknownNextHeader(t *testing.T) {
	// Next header 99 (unknown protocol, not UDP)
	pkt := make([]byte, 60)
	pkt[0] = 0x60
	pkt[6] = 99

	s := &WinDivertSniffer{port: 9999}
	called := false
	s.processIPv6(pkt, func(data []byte, ip string) {
		called = true
	})
	if called {
		t.Error("handler should not be called for unknown next header")
	}
}

func TestProcessIPv6DataCopied(t *testing.T) {
	payload := make([]byte, MinPacketSize)
	for i := range payload {
		payload[i] = 0xCC
	}
	pkt := buildIPv6UDP(net.ParseIP("::1"), 9999, payload)

	s := &WinDivertSniffer{port: 9999}
	var gotData []byte
	s.processIPv6(pkt, func(data []byte, ip string) {
		gotData = data
	})
	if gotData == nil {
		t.Fatal("handler not called")
	}
	// Modify original
	for i := 48; i < len(pkt); i++ {
		pkt[i] = 0
	}
	for _, b := range gotData {
		if b != 0xCC {
			t.Error("data not properly copied")
			break
		}
	}
}

// ----------------------------------------------------------------------
//  WinDivertSniffer lifecycle
// ----------------------------------------------------------------------

func TestNewWinDivertSnifferFields(t *testing.T) {
	s := NewWinDivertSniffer("10.0.0.1", 8443)
	if s.address != "10.0.0.1" {
		t.Errorf("address = %q, want 10.0.0.1", s.address)
	}
	if s.port != 8443 {
		t.Errorf("port = %d, want 8443", s.port)
	}
	if s.handle != 0 {
		t.Errorf("handle = %d, want 0", s.handle)
	}
}

func TestWinDivertStopBeforeStart(t *testing.T) {
	s := NewWinDivertSniffer("0.0.0.0", 9999)
	if err := s.Stop(); err != nil {
		t.Errorf("Stop before Start should not error: %v", err)
	}
}

func TestWinDivertDoubleStop(t *testing.T) {
	s := NewWinDivertSniffer("0.0.0.0", 9999)
	s.Stop()
	if err := s.Stop(); err != nil {
		t.Errorf("double Stop should not error: %v", err)
	}
}

func TestWinDivertConstants(t *testing.T) {
	if _WINDIVERT_LAYER_NETWORK != 0 {
		t.Errorf("WINDIVERT_LAYER_NETWORK = %d, want 0", _WINDIVERT_LAYER_NETWORK)
	}
	if _WINDIVERT_FLAG_SNIFF != 1 {
		t.Errorf("WINDIVERT_FLAG_SNIFF = %d, want 1", _WINDIVERT_FLAG_SNIFF)
	}
	if windivertAddressSize != 80 {
		t.Errorf("windivertAddressSize = %d, want 80", windivertAddressSize)
	}
}
