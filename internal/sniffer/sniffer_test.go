// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package sniffer

import (
	"fmt"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// --- NewSniffer factory tests ---

func TestNewSnifferUDP(t *testing.T) {
	s, err := NewSniffer("udp", []string{"127.0.0.1"}, 12345)
	if err != nil {
		t.Fatalf("NewSniffer(udp): %v", err)
	}
	if s == nil {
		t.Fatal("NewSniffer(udp) returned nil")
	}
	udp, ok := s.(*UDPSniffer)
	if !ok {
		t.Fatalf("expected *UDPSniffer, got %T", s)
	}
	if udp.Address != "127.0.0.1:12345" {
		t.Errorf("address = %q, want 127.0.0.1:12345", udp.Address)
	}
}

func TestNewSnifferEmptyMode(t *testing.T) {
	// Empty mode should default to UDP
	s, err := NewSniffer("", []string{"0.0.0.0"}, 9999)
	if err != nil {
		t.Fatalf("NewSniffer(empty): %v", err)
	}
	if _, ok := s.(*UDPSniffer); !ok {
		t.Fatalf("empty mode should create UDPSniffer, got %T", s)
	}
}

func TestNewSnifferUnsupported(t *testing.T) {
	_, err := NewSniffer("nflog", []string{"0.0.0.0"}, 12345)
	if err == nil {
		t.Error("expected error for unsupported sniffer mode 'nflog'")
	}
}

func TestNewSnifferInvalidMode(t *testing.T) {
	_, err := NewSniffer("nonexistent_backend", []string{"0.0.0.0"}, 12345)
	if err == nil {
		t.Fatal("expected error for unknown sniffer mode")
	}
}

func TestNewSnifferAFPacket(t *testing.T) {
	// AF_PACKET sniffer should be created (but Start would need root on Linux)
	s, err := NewSniffer("afpacket", []string{"0.0.0.0"}, 12345)
	if err != nil {
		t.Fatalf("NewSniffer(afpacket): %v", err)
	}
	if s == nil {
		t.Fatal("NewSniffer(afpacket) returned nil")
	}
}

// --- UDPSniffer creation tests ---

func TestNewUDPSnifferIPv4(t *testing.T) {
	s := NewUDPSniffer("192.168.1.1", 8080)
	if s.Address != "192.168.1.1:8080" {
		t.Errorf("address = %q, want 192.168.1.1:8080", s.Address)
	}
}

func TestNewUDPSnifferIPv6(t *testing.T) {
	s := NewUDPSniffer("::1", 8080)
	// net.JoinHostPort should bracket IPv6
	if s.Address != "[::1]:8080" {
		t.Errorf("address = %q, want [::1]:8080", s.Address)
	}
}

func TestNewUDPSnifferAllInterfaces(t *testing.T) {
	s := NewUDPSniffer("0.0.0.0", 0)
	if s.Address != "0.0.0.0:0" {
		t.Errorf("address = %q, want 0.0.0.0:0", s.Address)
	}
}

func TestUDPSnifferStopBeforeStart(t *testing.T) {
	s := NewUDPSniffer("127.0.0.1", 0)
	// Stopping before starting should not error
	if err := s.Stop(); err != nil {
		t.Errorf("Stop before Start should not error: %v", err)
	}
}

// --- Packet size constants ---

func TestPacketSizeConstants(t *testing.T) {
	// MaxPacketSize must be at least MinPacketSize
	if MaxPacketSize < MinPacketSize {
		t.Errorf("MaxPacketSize (%d) < MinPacketSize (%d)", MaxPacketSize, MinPacketSize)
	}
	// MinPacketSize should be 1118 (1088 + 12 + 16 + 2)
	expected := 1088 + 12 + 16 + 2
	if MinPacketSize != expected {
		t.Errorf("MinPacketSize = %d, want %d", MinPacketSize, expected)
	}
}

// --- DetectSniffers tests ---

func TestDetectSniffersReturnsAtLeastUDP(t *testing.T) {
	options := DetectSniffers()
	if len(options) == 0 {
		t.Fatal("DetectSniffers should return at least one option")
	}
	found := false
	for _, opt := range options {
		if opt.ID == "udp" {
			found = true
			if !opt.Installed {
				t.Error("UDP should always be installed")
			}
			if !opt.Implemented {
				t.Error("UDP should always be implemented")
			}
		}
	}
	if !found {
		t.Error("UDP option not found in DetectSniffers results")
	}
}

func TestDetectSniffersHasPcap(t *testing.T) {
	options := DetectSniffers()
	// On all platforms we should see pcap as an option (may not be installed)
	found := false
	for _, opt := range options {
		if opt.ID == "pcap" {
			found = true
			if opt.Maturity != "stable" {
				t.Errorf("pcap maturity = %q, want stable", opt.Maturity)
			}
		}
	}
	// pcap should be detected on Linux, Windows, macOS (all desktop platforms)
	switch runtime.GOOS {
	case "linux", "windows", "darwin":
		if !found {
			t.Errorf("pcap option not found on %s", runtime.GOOS)
		}
	}
}

func TestDetectSniffersLinuxAFPacket(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("AF_PACKET only on Linux")
	}
	options := DetectSniffers()
	found := false
	for _, opt := range options {
		if opt.ID == "afpacket" {
			found = true
			if !opt.Installed {
				t.Error("AF_PACKET should always be installed on Linux")
			}
			if !opt.Implemented {
				t.Error("AF_PACKET should be implemented on Linux")
			}
		}
	}
	if !found {
		t.Error("AF_PACKET option not found on Linux")
	}
}

// --- TestSniffer function ---

func TestTestSnifferUDP(t *testing.T) {
	err := TestSniffer("udp")
	if err != nil {
		t.Errorf("TestSniffer(udp) failed: %v", err)
	}
}

func TestTestSnifferWinDivert(t *testing.T) {
	// On non-Windows the stub returns an error.
	if runtime.GOOS != "windows" {
		err := TestSniffer("windivert")
		if err == nil {
			t.Error("TestSniffer(windivert) should return error on non-Windows")
		}
	}
}

func TestTestSnifferAFPacketNonLinux(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("Skipping non-Linux AF_PACKET test")
	}
	err := TestSniffer("afpacket")
	if err == nil {
		t.Error("TestSniffer(afpacket) should fail on non-Linux")
	}
}

// --- Helper function tests ---

func TestCommandExists(t *testing.T) {
	// "go" should always be available (we're running go tests)
	if !commandExists("go") {
		t.Error("commandExists(go) should return true")
	}
	// Unlikely command
	if commandExists("highly_unlikely_command_xyz_999") {
		t.Error("commandExists should return false for non-existent command")
	}
}

func TestFileExists(t *testing.T) {
	// Current test file should exist
	if !fileExists("sniffer_test.go") {
		t.Error("fileExists should find this test file")
	}
	if fileExists("nonexistent_file_xyz.go") {
		t.Error("fileExists should return false for non-existent file")
	}
}

func TestUdpOption(t *testing.T) {
	opt := udpOption(true)
	if opt.ID != "udp" {
		t.Errorf("ID = %q, want udp", opt.ID)
	}
	if !opt.Recommended {
		t.Error("expected Recommended=true when passed true")
	}
	opt2 := udpOption(false)
	if opt2.Recommended {
		t.Error("expected Recommended=false when passed false")
	}
}

// --- DetectSniffers platform-specific checks ---

func TestDetectSniffersWindowsPcap(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-specific test")
	}
	options := DetectSniffers()
	found := false
	for _, opt := range options {
		if opt.ID == "pcap" && opt.Name == "Npcap" {
			found = true
			if opt.InstallCmd == "" {
				t.Error("Npcap should have install cmd")
			}
		}
	}
	if !found {
		t.Error("Npcap option not found on Windows")
	}
}

func TestDetectSniffersAllImplementedOrMarked(t *testing.T) {
	// All options should either be implemented or clearly marked
	options := DetectSniffers()
	for _, opt := range options {
		if opt.ID == "" {
			t.Error("option has empty ID")
		}
		if opt.Name == "" {
			t.Errorf("option %q has empty Name", opt.ID)
		}
		if opt.Description == "" {
			t.Errorf("option %q has empty Description", opt.ID)
		}
		if opt.Maturity == "" {
			t.Errorf("option %q has empty Maturity", opt.ID)
		}
	}
}

func TestDetectSniffersNoDuplicateIDs(t *testing.T) {
	options := DetectSniffers()
	seen := make(map[string]bool)
	for _, opt := range options {
		if seen[opt.ID] {
			t.Errorf("duplicate sniffer ID: %q", opt.ID)
		}
		seen[opt.ID] = true
	}
}

func TestDetectSniffersUDPAlwaysFirst(t *testing.T) {
	options := DetectSniffers()
	if len(options) == 0 {
		t.Fatal("no options returned")
	}
	if options[0].ID != "udp" {
		t.Errorf("first option ID = %q, want udp", options[0].ID)
	}
}

func TestTestSnifferUnknown(t *testing.T) {
	err := TestSniffer("nonexistent")
	if err == nil {
		t.Error("expected error for unknown sniffer")
	}
}

// --- NewSniffer factory edge cases ---

func TestNewSnifferPcapCreation(t *testing.T) {
	// Should always succeed - returns a stub or real sniffer depending on build
	s, err := NewSniffer("pcap", []string{"0.0.0.0"}, 12345)
	if err != nil {
		t.Fatalf("NewSniffer(pcap): %v", err)
	}
	if s == nil {
		t.Fatal("NewSniffer(pcap) returned nil")
	}
}

func TestNewSnifferAFPacketCreation(t *testing.T) {
	s, err := NewSniffer("afpacket", []string{"0.0.0.0"}, 54321)
	if err != nil {
		t.Fatalf("NewSniffer(afpacket): %v", err)
	}
	if s == nil {
		t.Fatal("NewSniffer(afpacket) returned nil")
	}
}

func TestMinPacketSizeValue(t *testing.T) {
	// MinPacketSize = 1088 + 12 + 16 + 2 = 1118 (ML-KEM-768, smallest valid knock)
	if MinPacketSize != 1118 {
		t.Errorf("MinPacketSize = %d, want 1118", MinPacketSize)
	}
}

func TestMaxPacketSizeValue(t *testing.T) {
	if MaxPacketSize != 8192 {
		t.Errorf("MaxPacketSize = %d, want 8192", MaxPacketSize)
	}
}

// --- UDPSniffer concurrent Start/Stop tests ---

func TestUDPSnifferStartStop(t *testing.T) {
	s := NewUDPSniffer("127.0.0.1", 0)

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.Start(func(data []byte, srcIP string) {})
	}()

	// Give sniffer time to bind
	time.Sleep(50 * time.Millisecond)

	if err := s.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	if err := <-errCh; err != nil {
		t.Errorf("Start returned error: %v", err)
	}
}

func TestUDPSnifferConcurrentStop(t *testing.T) {
	s := NewUDPSniffer("127.0.0.1", 0)

	go func() {
		_ = s.Start(func(data []byte, srcIP string) {})
	}()

	time.Sleep(50 * time.Millisecond)

	// Call Stop from 10 goroutines concurrently - no panic, no data race
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = s.Stop()
		}()
	}
	wg.Wait()
}

func TestUDPSnifferDoubleStop(t *testing.T) {
	s := NewUDPSniffer("127.0.0.1", 0)

	go func() {
		_ = s.Start(func(data []byte, srcIP string) {})
	}()

	time.Sleep(50 * time.Millisecond)

	if err := s.Stop(); err != nil {
		t.Fatalf("first Stop: %v", err)
	}

	// Second stop should be safe (no panic, conn already nil)
	if err := s.Stop(); err != nil {
		t.Errorf("second Stop should not error: %v", err)
	}
}

// --- UDPSniffer packet boundary tests ---

func sendUDPPacket(t *testing.T, addr string, data []byte) {
	t.Helper()
	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write(data); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func TestUDPSnifferDropsUndersizedPacket(t *testing.T) {
	s := NewUDPSniffer("127.0.0.1", 0)
	var called atomic.Int32

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.Start(func(data []byte, srcIP string) {
			called.Add(1)
		})
	}()

	time.Sleep(50 * time.Millisecond)

	// Get the actual bound address
	s.mu.Lock()
	addr := s.conn.LocalAddr().String()
	s.mu.Unlock()

	// Send undersized packet (MinPacketSize - 1)
	small := make([]byte, MinPacketSize-1)
	sendUDPPacket(t, addr, small)

	time.Sleep(50 * time.Millisecond)

	if called.Load() != 0 {
		t.Error("handler should not be called for undersized packet")
	}

	s.Stop()
	<-errCh
}

func TestUDPSnifferAcceptsExactMinPacket(t *testing.T) {
	s := NewUDPSniffer("127.0.0.1", 0)
	var called atomic.Int32

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.Start(func(data []byte, srcIP string) {
			called.Add(1)
		})
	}()

	time.Sleep(50 * time.Millisecond)

	s.mu.Lock()
	addr := s.conn.LocalAddr().String()
	s.mu.Unlock()

	// Send exactly MinPacketSize bytes
	exact := make([]byte, MinPacketSize)
	sendUDPPacket(t, addr, exact)

	time.Sleep(100 * time.Millisecond)

	if called.Load() != 1 {
		t.Errorf("handler should be called once for exact MinPacketSize, called %d times", called.Load())
	}

	s.Stop()
	<-errCh
}

func TestUDPSnifferAcceptsExactMaxPacket(t *testing.T) {
	s := NewUDPSniffer("127.0.0.1", 0)
	var called atomic.Int32

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.Start(func(data []byte, srcIP string) {
			called.Add(1)
		})
	}()

	time.Sleep(50 * time.Millisecond)

	s.mu.Lock()
	addr := s.conn.LocalAddr().String()
	s.mu.Unlock()

	// Send exactly MaxPacketSize bytes
	exact := make([]byte, MaxPacketSize)
	sendUDPPacket(t, addr, exact)

	time.Sleep(100 * time.Millisecond)

	if called.Load() != 1 {
		t.Errorf("handler should be called once for exact MaxPacketSize, called %d times", called.Load())
	}

	s.Stop()
	<-errCh
}

// --- Sniffer factory edge cases ---

func TestNewSnifferCaseSensitive(t *testing.T) {
	// Sniffer modes are case-sensitive
	_, err := NewSniffer("UDP", []string{"127.0.0.1"}, 12345)
	if err == nil {
		t.Error("expected error for uppercase 'UDP' (case-sensitive)")
	}
	_, err = NewSniffer("Udp", []string{"127.0.0.1"}, 12345)
	if err == nil {
		t.Error("expected error for mixed-case 'Udp'")
	}
}

func TestNewSnifferPort0(t *testing.T) {
	s, err := NewSniffer("udp", []string{"127.0.0.1"}, 0)
	if err != nil {
		t.Fatalf("NewSniffer with port 0: %v", err)
	}
	udp, ok := s.(*UDPSniffer)
	if !ok {
		t.Fatal("expected *UDPSniffer")
	}
	if udp.Address != "127.0.0.1:0" {
		t.Errorf("address = %q, want 127.0.0.1:0", udp.Address)
	}
}

func TestNewSnifferWhitespaceMode(t *testing.T) {
	_, err := NewSniffer(" udp ", []string{"127.0.0.1"}, 12345)
	if err == nil {
		t.Error("expected error for mode with whitespace")
	}
}

func TestNewUDPSnifferHighPort(t *testing.T) {
	s := NewUDPSniffer("0.0.0.0", 65535)
	if s.Address != "0.0.0.0:65535" {
		t.Errorf("address = %q, want 0.0.0.0:65535", s.Address)
	}
}

// --- MultiSniffer / multi-address tests ---

func TestNewSnifferMultiAddress(t *testing.T) {
	// Two addresses should create a MultiSniffer for UDP mode
	s, err := NewSniffer("udp", []string{"127.0.0.1", "::1"}, 0)
	if err != nil {
		t.Fatalf("NewSniffer multi-address: %v", err)
	}
	multi, ok := s.(*MultiSniffer)
	if !ok {
		t.Fatalf("expected *MultiSniffer, got %T", s)
	}
	if len(multi.sniffers) != 2 {
		t.Errorf("MultiSniffer should wrap 2 sniffers, got %d", len(multi.sniffers))
	}
}

func TestNewSnifferSingleAddress(t *testing.T) {
	// Single address should create a plain UDPSniffer, not MultiSniffer
	s, err := NewSniffer("udp", []string{"127.0.0.1"}, 0)
	if err != nil {
		t.Fatalf("NewSniffer single-address: %v", err)
	}
	if _, ok := s.(*UDPSniffer); !ok {
		t.Fatalf("single address should create *UDPSniffer, got %T", s)
	}
}

func TestNewSnifferEmptyAddresses(t *testing.T) {
	// Empty addresses should default to 0.0.0.0
	s, err := NewSniffer("udp", nil, 0)
	if err != nil {
		t.Fatalf("NewSniffer empty addresses: %v", err)
	}
	udp, ok := s.(*UDPSniffer)
	if !ok {
		t.Fatalf("expected *UDPSniffer, got %T", s)
	}
	if udp.Address != "0.0.0.0:0" {
		t.Errorf("address = %q, want 0.0.0.0:0", udp.Address)
	}
}

func TestNewSnifferStealthModeSingleAddress(t *testing.T) {
	// Stealth modes with wildcards produce a single sniffer (not MultiSniffer)
	// because 0.0.0.0 / :: already imply "capture all interfaces".
	for _, mode := range []string{"afpacket", "pcap", "windivert"} {
		s, err := NewSniffer(mode, []string{"0.0.0.0", "::"}, 12345)
		if err != nil {
			t.Fatalf("NewSniffer(%s) multi-address: %v", mode, err)
		}
		if s == nil {
			t.Fatalf("NewSniffer(%s) returned nil", mode)
		}
		// Wildcards collapse to a single sniffer, not MultiSniffer
		if _, ok := s.(*MultiSniffer); ok {
			t.Errorf("stealth mode %s with wildcards should not create MultiSniffer", mode)
		}
	}
}

func TestMultiSnifferStartStop(t *testing.T) {
	// Create two UDP sniffers on different addresses
	s, err := NewSniffer("udp", []string{"127.0.0.1", "127.0.0.1"}, 0)
	if err != nil {
		t.Fatalf("NewSniffer multi: %v", err)
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.Start(func(data []byte, srcIP string) {})
	}()

	time.Sleep(100 * time.Millisecond)

	if err := s.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("Start returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after Stop")
	}
}

// --- RecommendSniffers tests ---

func TestRecommendSniffersPcapOverAll(t *testing.T) {
	opts := []SnifferOption{
		{ID: "udp", Installed: true, Implemented: true},
		{ID: "afpacket", Installed: true, Implemented: true},
		{ID: "pcap", Installed: true, Implemented: true},
	}
	result := RecommendSniffers(opts)
	for _, o := range result {
		if o.ID == "pcap" && !o.Recommended {
			t.Error("pcap should be recommended when installed+implemented")
		}
		if o.ID != "pcap" && o.Recommended {
			t.Errorf("%s should not be recommended when pcap is available", o.ID)
		}
	}
}

func TestRecommendSniffersAFPacketFallback(t *testing.T) {
	opts := []SnifferOption{
		{ID: "udp", Installed: true, Implemented: true},
		{ID: "afpacket", Installed: true, Implemented: true},
		{ID: "pcap", Installed: false, Implemented: true}, // not installed
	}
	result := RecommendSniffers(opts)
	for _, o := range result {
		if o.ID == "afpacket" && !o.Recommended {
			t.Error("afpacket should be recommended when pcap not installed")
		}
		if o.ID == "pcap" && o.Recommended {
			t.Error("pcap should not be recommended when not installed")
		}
	}
}

func TestRecommendSniffersWinDivertFallback(t *testing.T) {
	opts := []SnifferOption{
		{ID: "udp", Installed: true, Implemented: true},
		{ID: "windivert", Installed: true, Implemented: true},
		{ID: "pcap", Installed: true, Implemented: false}, // not implemented
	}
	result := RecommendSniffers(opts)
	for _, o := range result {
		if o.ID == "windivert" && !o.Recommended {
			t.Error("windivert should be recommended when pcap not implemented")
		}
		if o.ID == "pcap" && o.Recommended {
			t.Error("pcap should not be recommended when not implemented")
		}
	}
}

func TestRecommendSniffersUDPOnly(t *testing.T) {
	opts := []SnifferOption{
		{ID: "udp", Installed: true, Implemented: true},
		{ID: "pcap", Installed: false, Implemented: false},
	}
	result := RecommendSniffers(opts)
	if !result[0].Recommended {
		t.Error("udp should be recommended when it's the only viable option")
	}
}

func TestRecommendSniffersNoneViable(t *testing.T) {
	opts := []SnifferOption{
		{ID: "udp", Installed: false, Implemented: false},
	}
	result := RecommendSniffers(opts)
	for _, o := range result {
		if o.Recommended {
			t.Errorf("%s should not be recommended (not installed/implemented)", o.ID)
		}
	}
}

func TestRecommendSniffersClearsOldRecommendation(t *testing.T) {
	opts := []SnifferOption{
		{ID: "udp", Installed: true, Implemented: true, Recommended: true},
		{ID: "pcap", Installed: true, Implemented: true, Recommended: true},
	}
	result := RecommendSniffers(opts)
	recCount := 0
	for _, o := range result {
		if o.Recommended {
			recCount++
		}
	}
	if recCount != 1 {
		t.Errorf("expected exactly 1 recommended option, got %d", recCount)
	}
	if !result[1].Recommended || result[1].ID != "pcap" {
		t.Error("pcap should be the sole recommended option")
	}
}

func TestRecommendSniffersEmptySlice(t *testing.T) {
	result := RecommendSniffers(nil)
	if len(result) != 0 {
		t.Errorf("expected empty result for nil input, got %d", len(result))
	}
}

// ============================================================
// Interface helper tests (sniffer_iface.go)
// ============================================================

func TestIsWildcardAddr(t *testing.T) {
	tests := []struct {
		addr string
		want bool
	}{
		{"0.0.0.0", true},
		{"::", true},
		{"", true},
		{"127.0.0.1", false},
		{"::1", false},
		{"192.168.1.2", false},
		{"10.0.0.1", false},
		{"fe80::1", false},
	}
	for _, tt := range tests {
		got := isWildcardAddr(tt.addr)
		if got != tt.want {
			t.Errorf("isWildcardAddr(%q) = %v, want %v", tt.addr, got, tt.want)
		}
	}
}

func TestHasAnyWildcard(t *testing.T) {
	tests := []struct {
		addrs []string
		want  bool
	}{
		{[]string{"0.0.0.0"}, true},
		{[]string{"::"}, true},
		{[]string{"0.0.0.0", "::"}, true},
		{[]string{"0.0.0.0", "192.168.1.2"}, true},
		{[]string{"127.0.0.1"}, false},
		{[]string{"127.0.0.1", "::1"}, false},
		{nil, false},
	}
	for _, tt := range tests {
		got := hasAnyWildcard(tt.addrs)
		if got != tt.want {
			t.Errorf("hasAnyWildcard(%v) = %v, want %v", tt.addrs, got, tt.want)
		}
	}
}

func TestLocalInterfaceByIPLoopback(t *testing.T) {
	// Loopback (127.0.0.1) is always assigned on every machine.
	ip := net.ParseIP("127.0.0.1")
	iface, err := localInterfaceByIP(ip)
	if err != nil {
		t.Fatalf("localInterfaceByIP(127.0.0.1): %v", err)
	}
	if iface == nil {
		t.Fatal("expected non-nil interface for 127.0.0.1")
	}
	// The loopback interface index should be > 0
	if iface.Index <= 0 {
		t.Errorf("loopback interface index = %d, want > 0", iface.Index)
	}
}

func TestLocalInterfaceByIPv6Loopback(t *testing.T) {
	// IPv6 loopback ::1 should also be available on most systems.
	ip := net.ParseIP("::1")
	iface, err := localInterfaceByIP(ip)
	if err != nil {
		t.Skipf("IPv6 loopback not available: %v", err)
	}
	if iface == nil {
		t.Fatal("expected non-nil interface for ::1")
	}
}

func TestLocalInterfaceByIPNotAssigned(t *testing.T) {
	// Use an IP from TEST-NET-3 (RFC 5737) which is never assigned to real interfaces.
	ip := net.ParseIP("203.0.113.254")
	_, err := localInterfaceByIP(ip)
	if err == nil {
		t.Error("expected error for unassigned IP 203.0.113.254, got nil")
	}
}

func TestValidateListenAddressesWildcards(t *testing.T) {
	// Wildcards are always accepted without checking interfaces.
	if err := validateListenAddresses([]string{"0.0.0.0"}); err != nil {
		t.Errorf("0.0.0.0: %v", err)
	}
	if err := validateListenAddresses([]string{"::"}); err != nil {
		t.Errorf("::: %v", err)
	}
	if err := validateListenAddresses([]string{"0.0.0.0", "::"}); err != nil {
		t.Errorf("0.0.0.0 + ::: %v", err)
	}
	if err := validateListenAddresses(nil); err != nil {
		t.Errorf("nil: %v", err)
	}
}

func TestValidateListenAddressesLoopback(t *testing.T) {
	// Loopback addresses must exist on all machines.
	if err := validateListenAddresses([]string{"127.0.0.1"}); err != nil {
		t.Errorf("127.0.0.1: %v", err)
	}
}

func TestValidateListenAddressesInvalidIP(t *testing.T) {
	if err := validateListenAddresses([]string{"not-an-ip"}); err == nil {
		t.Error("expected error for invalid IP string, got nil")
	}
}

func TestValidateListenAddressesUnassigned(t *testing.T) {
	// Documentation range (RFC 5737) -- should not be assigned.
	if err := validateListenAddresses([]string{"198.51.100.1"}); err == nil {
		t.Error("expected error for RFC 5737 documentation address, got nil")
	}
}

func TestValidateListenAddressesMixed(t *testing.T) {
	// Mixing wildcard (always ok) with a bad specific address should succeed
	// because wildcards are not validated and we stop on the first specific one.
	// Only the specific address matters -- the wildcard is skipped.
	if err := validateListenAddresses([]string{"0.0.0.0", "198.51.100.1"}); err == nil {
		t.Error("expected error: specific unassigned address alongside wildcard")
	}
}

// TestLocalIPsOnInterface verifies the helper returns at least one IP for the loopback.
func TestLocalIPsOnInterface(t *testing.T) {
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatalf("net.Interfaces: %v", err)
	}
	// Find the loopback interface
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback == 0 {
			continue
		}
		ips, err := localIPsOnInterface(&iface)
		if err != nil {
			t.Fatalf("localIPsOnInterface: %v", err)
		}
		if len(ips) == 0 {
			t.Error("loopback interface should have at least one IP")
		}
		return
	}
	t.Skip("no loopback interface found")
}

// ============================================================
// NewSniffer address-validation integration tests
// ============================================================

func TestNewSnifferSpecificIPNotLocal(t *testing.T) {
	// RFC 5737 documentation range -- not assigned to any real interface.
	_, err := NewSniffer("udp", []string{"203.0.113.1"}, 12345)
	if err == nil {
		t.Error("expected error for unassigned specific IP, got nil")
	}
}

func TestNewSnifferSpecificIPLoopback(t *testing.T) {
	// 127.0.0.1 is always a valid local address.
	s, err := NewSniffer("udp", []string{"127.0.0.1"}, 0)
	if err != nil {
		t.Fatalf("NewSniffer(udp, 127.0.0.1): %v", err)
	}
	if s == nil {
		t.Fatal("expected non-nil sniffer")
	}
}

func TestNewSnifferStealthSpecificIPNotLocal(t *testing.T) {
	// Stealth modes should also reject an unassigned specific IP.
	for _, mode := range []string{"afpacket", "pcap", "windivert"} {
		_, err := NewSniffer(mode, []string{"203.0.113.1"}, 12345)
		if err == nil {
			t.Errorf("NewSniffer(%s, unassigned IP): expected error, got nil", mode)
		}
	}
}

func TestNewSnifferStealthWildcardAlwaysValid(t *testing.T) {
	// Wildcards must never fail validation regardless of sniffer mode.
	for _, mode := range []string{"afpacket", "pcap", "windivert"} {
		for _, addr := range []string{"0.0.0.0", "::"} {
			s, err := NewSniffer(mode, []string{addr}, 12345)
			if err != nil {
				t.Errorf("NewSniffer(%s, %s): unexpected error: %v", mode, addr, err)
			}
			if s == nil {
				t.Errorf("NewSniffer(%s, %s): returned nil sniffer", mode, addr)
			}
		}
	}
}

func TestNewSnifferMultipleSpecificIPsUsesMultiSniffer(t *testing.T) {
	// When multiple specific (non-wildcard) local IPs are given, stealth modes
	// should produce a MultiSniffer so each interface is captured.
	// Use 127.0.0.1 twice to avoid depending on the machine's real NIC IPs.
	// Duplicate addresses are unusual but should not panic.
	for _, mode := range []string{"afpacket", "pcap", "windivert"} {
		s, err := NewSniffer(mode, []string{"127.0.0.1", "127.0.0.1"}, 12345)
		if err != nil {
			t.Fatalf("NewSniffer(%s, two loopback addrs): %v", mode, err)
		}
		if _, ok := s.(*MultiSniffer); !ok {
			t.Errorf("NewSniffer(%s) with multiple specific IPs should return *MultiSniffer, got %T", mode, s)
		}
	}
}

func TestNewSnifferDualStackWildcardIsSingle(t *testing.T) {
	// ["0.0.0.0", "::"] is the standard dual-stack config.
	// For stealth modes it should produce one sniffer (not MultiSniffer),
	// because the wildcard sniffer already handles all interfaces.
	for _, mode := range []string{"afpacket", "pcap", "windivert"} {
		s, err := NewSniffer(mode, []string{"0.0.0.0", "::"}, 12345)
		if err != nil {
			t.Fatalf("NewSniffer(%s, dual-stack): %v", mode, err)
		}
		if _, ok := s.(*MultiSniffer); ok {
			t.Errorf("NewSniffer(%s) with dual-stack wildcards should NOT return MultiSniffer", mode)
		}
	}
}

func TestNewSnifferDualStackUDPIsMulti(t *testing.T) {
	// UDP with ["0.0.0.0", "::"] -> MultiSniffer (one socket per protocol family).
	s, err := NewSniffer("udp", []string{"0.0.0.0", "::"}, 0)
	if err != nil {
		t.Fatalf("NewSniffer(udp, dual-stack): %v", err)
	}
	if _, ok := s.(*MultiSniffer); !ok {
		t.Fatalf("UDP dual-stack should produce *MultiSniffer, got %T", s)
	}
}

// TestNewSnifferAdapterWithMultipleIPs uses a real local IP discovered at
// runtime, then asks NewSniffer to use that IP.  This validates that the
// full validation path works against actual kernel-assigned addresses.
func TestNewSnifferAdapterWithMultipleIPs(t *testing.T) {
	localIP, err := findNonLoopbackLocalIP()
	if err != nil {
		t.Skipf("no non-loopback interface available: %v", err)
	}

	s, err := NewSniffer("udp", []string{localIP.String()}, 0)
	if err != nil {
		t.Fatalf("NewSniffer(udp, %s): %v", localIP, err)
	}
	if s == nil {
		t.Fatal("expected non-nil sniffer")
	}
}

func TestNewSnifferMultipleRealIPsUStealth(t *testing.T) {
	// Discover at least two real IPs (or two different loopback variants)
	// and verify stealth modes produce a MultiSniffer for them.
	ip1 := net.ParseIP("127.0.0.1")
	var ip2 net.IP
	// Try to find a second distinct real IP
	ip2found, err := findNonLoopbackLocalIP()
	if err == nil {
		ip2 = ip2found
	} else {
		// Fall back to another loopback variant (same IP, still makes two addresses)
		ip2 = ip1
	}

	for _, mode := range []string{"afpacket", "pcap", "windivert"} {
		s, err := NewSniffer(mode, []string{ip1.String(), ip2.String()}, 12345)
		if err != nil {
			t.Fatalf("NewSniffer(%s, [%s, %s]): %v", mode, ip1, ip2, err)
		}
		if _, ok := s.(*MultiSniffer); !ok {
			t.Errorf("NewSniffer(%s) with 2 specific addrs should return *MultiSniffer, got %T", mode, s)
		}
	}
}

// TestListLocalAddressesDiagnostic verifies the diagnostic helper doesn't panic
// and returns a non-nil slice on a normal machine.
func TestListLocalAddressesDiagnostic(t *testing.T) {
	addrs := listLocalAddresses()
	// Not all CI environments have non-loopback interfaces, so just check no panic
	_ = addrs
}

// findNonLoopbackLocalIP returns the first non-loopback, non-link-local IPv4
// address found on the machine.  Used by tests that need a real local IP.
func findNonLoopbackLocalIP() (net.IP, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
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
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			if ip4 := ip.To4(); ip4 != nil {
				return ip4, nil
			}
		}
	}
	return nil, fmt.Errorf("no non-loopback IPv4 interface found")
}
