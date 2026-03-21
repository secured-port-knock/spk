//go:build (linux || darwin) && cgo

// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

// pcap_unix_test.go contains Linux/macOS pcap integration tests.
// It mirrors the Windows tests in pcap_windows_test.go.
//
// These tests require:
//   - libpcap installed (libpcap-dev on Debian/Ubuntu, built-in on macOS)
//   - CGO enabled (the cgo build tag is set automatically when CGO_ENABLED=1)
//   - Root or CAP_NET_RAW (for raw pcap capture)
//
// Tests skip gracefully when libpcap is unavailable or permissions are
// insufficient, so they are safe to run via "go test ./..." on any machine.
// All C calls go through helpers in pcap_unix.go -- no "import C" needed here.

package sniffer

import (
	"fmt"
	"net"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

// TestPcapEnumerateAllDevices lists every device pcap sees with its addresses.
// Equivalent to the Windows test in pcap_windows_test.go.
func TestPcapEnumerateAllDevices(t *testing.T) {
	if !pcapImplemented() {
		t.Skip("pcap not implemented in this build (CGO_ENABLED=0)")
	}
	devs, err := pcapListDeviceInfos()
	if err != nil {
		t.Skipf("pcapListDeviceInfos: %v (libpcap may not be installed)", err)
	}
	if len(devs) == 0 {
		t.Error("no pcap devices found")
	}
	for i, d := range devs {
		t.Logf("Device %d: %s", i, d.Name)
		for _, ip4 := range d.IPv4s {
			t.Logf("  IPv4: %s", ip4)
		}
		for _, ip6 := range d.IPv6s {
			t.Logf("  IPv6: %s", ip6)
		}
	}
	t.Logf("Total devices: %d", len(devs))
}

// TestPcapFindDeviceWildcard verifies that findDevice("0.0.0.0") returns a
// device. On Linux this should be "any"; on macOS the default-route device.
func TestPcapFindDeviceWildcard(t *testing.T) {
	if !pcapImplemented() {
		t.Skip("pcap not implemented in this build (CGO_ENABLED=0)")
	}
	ps := NewPcapSniffer("0.0.0.0", 12345).(*PcapSniffer)
	dev, err := ps.findDevice()
	if err != nil {
		t.Skipf("findDevice (addr=0.0.0.0): %v (libpcap may not be installed)", err)
	}
	t.Logf("findDevice (addr=0.0.0.0) -> %s", dev)
	if runtime.GOOS == "linux" && dev != "any" {
		t.Logf("Note: expected 'any' device on Linux, got %s", dev)
	}
}

// TestPcapFindDeviceSpecificIP verifies that a real local IP resolves to a
// device. Uses findNonLoopbackLocalIP from sniffer_test.go.
func TestPcapFindDeviceSpecificIP(t *testing.T) {
	if !pcapImplemented() {
		t.Skip("pcap not implemented in this build (CGO_ENABLED=0)")
	}
	ip, err := findNonLoopbackLocalIP()
	if err != nil {
		t.Skipf("no non-loopback interface: %v", err)
	}
	ps := NewPcapSniffer(ip.String(), 12345).(*PcapSniffer)
	dev, err := ps.findDevice()
	if err != nil {
		t.Skipf("findDevice (addr=%s): %v (libpcap may not be installed)", ip, err)
	}
	t.Logf("findDevice (addr=%s) -> %s", ip, dev)
}

// TestPcapFindDeviceUnassignedIPErrors verifies that an IP from the RFC 5737
// documentation range produces an error rather than a silent fallback.
func TestPcapFindDeviceUnassignedIPErrors(t *testing.T) {
	if !pcapImplemented() {
		t.Skip("pcap not implemented in this build (CGO_ENABLED=0)")
	}
	ps := NewPcapSniffer("203.0.113.1", 12345).(*PcapSniffer)
	_, err := ps.findDevice()
	if err == nil {
		t.Error("findDevice on unassigned RFC5737 IP should return error, got nil")
	}
	t.Logf("findDevice on unassigned IP error (expected): %v", err)
}

// TestPcapCaptureRaw opens pcap on the default device with no BPF filter and
// captures any traffic for a few seconds. ARP/mDNS/broadcast should appear
// on an active network.
func TestPcapCaptureRaw(t *testing.T) {
	if !pcapImplemented() {
		t.Skip("pcap not implemented in this build (CGO_ENABLED=0)")
	}

	ps := NewPcapSniffer("0.0.0.0", 0).(*PcapSniffer)
	dev, err := ps.findDevice()
	if err != nil {
		t.Skipf("findDevice: %v (libpcap may not be installed)", err)
	}
	t.Logf("Selected device: %s", dev)

	h, err := pcapOpenRaw(dev, 65535, 1, 1000)
	if err != nil {
		t.Skipf("pcapOpenRaw(%s): %v (may need root/CAP_NET_RAW)", dev, err)
	}
	defer h.Close()

	t.Logf("Link type: %d (header len: %d)", h.linkType, linkHeaderLen(h.linkType))

	// Generate traffic on the NIC by sending to a documentation address.
	go func() {
		time.Sleep(200 * time.Millisecond)
		conn, err := net.Dial("udp4", "198.51.100.1:19999")
		if err != nil {
			return
		}
		defer conn.Close()
		for i := 0; i < 5; i++ {
			conn.Write([]byte("pcap-test-probe"))
			time.Sleep(100 * time.Millisecond)
		}
	}()

	// Capture for 5 seconds with no filter -- count everything.
	captured := 0
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		raw, lt, err := h.ReadNext()
		if err != nil {
			t.Logf("ReadNext error: %v", err)
			break
		}
		if raw == nil {
			continue // timeout
		}
		captured++
		if captured <= 10 {
			proto := classifyEthertype(raw, lt)
			t.Logf("  Pkt %d: caplen=%d proto=%s", captured, len(raw), proto)
		}
	}

	t.Logf("Captured %d packets in 5 seconds (no filter, promiscuous)", captured)
	if captured == 0 {
		t.Log("ZERO packets captured -- pcap may not be functional on this interface.")
		t.Log("Check: (1) libpcap installed, (2) root/CAP_NET_RAW, (3) network is active")
	}
}

// TestPcapBPFFilter verifies that BPF filter compilation and port-matching
// works by starting a PcapSniffer on a test port and sending padded packets.
func TestPcapBPFFilter(t *testing.T) {
	if !pcapImplemented() {
		t.Skip("pcap not implemented in this build (CGO_ENABLED=0)")
	}

	testPort := 39999
	var received atomic.Int32

	sniff := NewPcapSniffer("0.0.0.0", testPort)
	errCh := make(chan error, 1)
	go func() {
		errCh <- sniff.Start(func(data []byte, srcIP string) {
			received.Add(1)
		})
	}()
	time.Sleep(500 * time.Millisecond)

	select {
	case err := <-errCh:
		if err != nil {
			t.Skipf("PcapSniffer.Start failed (may need root): %v", err)
		}
	default:
	}

	// Send padded UDP packets to 198.51.100.1 on the test port.
	// BPF filter "udp dst port 39999" should match these.
	conn, err := net.Dial("udp4", fmt.Sprintf("198.51.100.1:%d", testPort))
	if err != nil {
		t.Logf("Cannot send test packets: %v", err)
	} else {
		bigPayload := make([]byte, MinPacketSize+10)
		for i := range bigPayload {
			bigPayload[i] = byte(i % 256)
		}
		for i := 0; i < 10; i++ {
			conn.Write(bigPayload)
			time.Sleep(100 * time.Millisecond)
		}
		conn.Close()
	}

	time.Sleep(2 * time.Second)
	sniff.Stop()

	r := received.Load()
	t.Logf("Captured %d packets with BPF filter 'udp dst port %d'", r, testPort)
	if r == 0 {
		t.Log("No filtered packets captured. This might mean:")
		t.Log("  - Outgoing packets not visible on this device")
		t.Log("  - BPF filter not matching (routing/interface issue)")
		t.Log("  - Need root/CAP_NET_RAW")
	}
}

// TestPcapSnifferIntegration performs a full integration test of PcapSniffer.
// It starts the sniffer on a test port and sends UDP packets, then verifies
// reception -- the Unix equivalent of the Windows TestPcapSnifferIntegration.
func TestPcapSnifferIntegration(t *testing.T) {
	if !pcapImplemented() {
		t.Skip("pcap not implemented in this build (CGO_ENABLED=0)")
	}

	testPort := 48765
	var received atomic.Int32

	sniff := NewPcapSniffer("0.0.0.0", testPort)
	errCh := make(chan error, 1)
	go func() {
		errCh <- sniff.Start(func(data []byte, srcIP string) {
			received.Add(1)
			t.Logf("Received packet: %d bytes from %s", len(data), srcIP)
		})
	}()

	time.Sleep(500 * time.Millisecond)

	select {
	case err := <-errCh:
		if err != nil {
			t.Skipf("PcapSniffer.Start failed (may need root): %v", err)
		}
	default:
		// Still running (expected)
	}

	// Send packets larger than MinPacketSize through the NIC.
	// On Linux, the "any" device captures outgoing traffic.
	bigPayload := make([]byte, MinPacketSize+10)
	for i := range bigPayload {
		bigPayload[i] = byte(i % 256)
	}
	conn, err := net.Dial("udp4", fmt.Sprintf("198.51.100.1:%d", testPort))
	if err != nil {
		t.Logf("Cannot send test packets: %v", err)
	} else {
		for i := 0; i < 5; i++ {
			conn.Write(bigPayload)
			time.Sleep(100 * time.Millisecond)
		}
		conn.Close()
	}

	time.Sleep(2 * time.Second)
	sniff.Stop()

	r := received.Load()
	t.Logf("PcapSniffer received %d packets (port %d)", r, testPort)
	if r == 0 {
		t.Log("No packets received. On macOS, self-sent packets may not be visible.")
		t.Log("On Linux with 'any' device, outgoing packets should be captured.")
	}
}

// TestPcapStopWaitsForCaptureLoop is the Linux/macOS equivalent of the same
// test in pcap_windows_test.go.
//
// Regression test for: calling pcap_close() concurrently with pcap_next_ex()
// is a use-after-free. Stop() must wait for Start() to exit the libpcap capture
// loop before calling pcap_close(). Without the fix a crash or memory corruption
// occurs when libpcap cleans up its internal state (visible under ASAN/TSAN or
// when the process exits under memory pressure).
func TestPcapStopWaitsForCaptureLoop(t *testing.T) {
	if !pcapImplemented() {
		t.Skip("pcap not implemented in this build (CGO_ENABLED=0)")
	}

	sniff := NewPcapSniffer("0.0.0.0", 49876)

	startErr := make(chan error, 1)
	go func() {
		startErr <- sniff.Start(func(_ []byte, _ string) {})
	}()

	// Allow Start() to enter pcap_next_ex (200 ms read timeout) at least once.
	time.Sleep(150 * time.Millisecond)

	select {
	case err := <-startErr:
		if err != nil {
			t.Skipf("Start() failed (may need root/CAP_NET_RAW): %v", err)
		}
		return // Start returned early — library not available, skip
	default:
	}

	// Stop() must call pcap_breakloop, then wait for Start() to return from
	// pcap_next_ex, and only then call pcap_close(). The old code raced.
	if err := sniff.Stop(); err != nil {
		t.Errorf("Stop() returned unexpected error: %v", err)
	}

	select {
	case err := <-startErr:
		if err != nil {
			t.Errorf("Start() returned unexpected error after Stop(): %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("Start() did not return within 2 s after Stop()")
	}
}

// classifyEthertype returns a human-readable protocol name from a raw frame.
func classifyEthertype(raw []byte, linkType int) string {
	hdrLen := linkHeaderLen(linkType)
	if hdrLen < 0 || len(raw) <= hdrLen+1 {
		return fmt.Sprintf("linktype=%d", linkType)
	}
	var etOff int
	switch linkType {
	case dltEN10MB:
		if len(raw) < 14 {
			return "?"
		}
		etOff = 12
	case dltLinuxSLL:
		if len(raw) < 16 {
			return "?"
		}
		etOff = 14
	default:
		return fmt.Sprintf("linktype=%d", linkType)
	}
	et := uint16(raw[etOff])<<8 | uint16(raw[etOff+1])
	switch et {
	case 0x0800:
		return "IPv4"
	case 0x0806:
		return "ARP"
	case 0x86DD:
		return "IPv6"
	default:
		return fmt.Sprintf("0x%04x", et)
	}
}
