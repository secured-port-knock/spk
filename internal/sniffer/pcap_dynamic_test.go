// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package sniffer

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// =====================================================================
// Dynamic pcap/sniffer backend loading tests
// These tests verify runtime library loading for all sniffer backends.
// Tests that require specific libraries (Npcap, WinDivert, libpcap)
// are skipped if the library is not present on the system.
// =====================================================================

// ---------- pcap dynamic loading tests ----------

func TestPcapImplementedFlag(t *testing.T) {
	got := pcapImplemented()
	// On Windows, pcap is always implemented (pure Go dynamic loading).
	// On Linux/macOS with CGO, pcap is implemented (dlfcn dynamic loading).
	// On Linux/macOS without CGO, pcap is NOT implemented (stub).
	if runtime.GOOS == "windows" {
		if !got {
			t.Error("pcapImplemented() should return true on Windows (pure Go)")
		}
	}
	t.Logf("pcapImplemented() = %v on %s", got, runtime.GOOS)
}

func TestPcapSnifferCreation(t *testing.T) {
	s := NewPcapSniffer("0.0.0.0", 9999)
	if s == nil {
		t.Fatal("NewPcapSniffer returned nil")
	}
}

func TestPcapSnifferImplementsInterface(t *testing.T) {
	var _ Sniffer = NewPcapSniffer("0.0.0.0", 9999)
}

func TestPcapSnifferStopBeforeStart(t *testing.T) {
	s := NewPcapSniffer("0.0.0.0", 9999)
	if err := s.Stop(); err != nil {
		t.Errorf("Stop before Start should not error: %v", err)
	}
}

func TestPcapSnifferDoubleStop(t *testing.T) {
	s := NewPcapSniffer("0.0.0.0", 9999)
	_ = s.Stop()
	if err := s.Stop(); err != nil {
		t.Errorf("second Stop should not error: %v", err)
	}
}

func TestTestPcapAvailability(t *testing.T) {
	if !pcapImplemented() {
		t.Skip("pcap not implemented in this build")
	}

	err := testPcap()
	if err != nil {
		t.Logf("testPcap() returned: %v (library may not be installed)", err)
	} else {
		t.Log("testPcap() succeeded -- pcap library is available")
	}
}

// TestPcapLoadOnWindows verifies the critical DLL loading path on Windows.
// This test exercises the SetDllDirectoryW fix for the "specified procedure
// could not be found" error that occurs when wpcap.dll's dependency
// (Packet.dll) cannot be located.
func TestPcapLoadOnWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only test")
	}

	sysRoot := os.Getenv("SystemRoot")
	if sysRoot == "" {
		sysRoot = `C:\Windows`
	}
	npcapDir := filepath.Join(sysRoot, "System32", "Npcap")
	wpcapPath := filepath.Join(npcapDir, "wpcap.dll")
	if _, err := os.Stat(wpcapPath); err != nil {
		t.Skipf("Npcap not installed (wpcap.dll not found at %s)", wpcapPath)
	}

	// Verify Packet.dll exists (the dependency that caused the original error)
	packetPath := filepath.Join(npcapDir, "Packet.dll")
	if _, err := os.Stat(packetPath); err != nil {
		t.Logf("Warning: Packet.dll not found at %s", packetPath)
	}

	err := testPcap()
	if err != nil {
		t.Fatalf("testPcap() failed with Npcap installed: %v\n"+
			"This may indicate the SetDllDirectoryW fix is not working.", err)
	}
	t.Log("Npcap loaded successfully via dynamic loading")
}

// ---------- WinDivert loading test ----------

func TestWinDivertLoadAvailability(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("WinDivert is Windows-only")
	}

	err := testWinDivert()
	if err != nil {
		t.Logf("WinDivert not available: %v (driver may not be installed)", err)
	} else {
		t.Log("WinDivert loaded successfully")
	}
}

// ---------- AF_PACKET loading test ----------

func TestAFPacketAvailability(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("AF_PACKET is Linux-only")
	}

	err := testAFPacket()
	if err != nil {
		t.Logf("AF_PACKET test: %v (may need root/CAP_NET_RAW)", err)
	} else {
		t.Log("AF_PACKET is available")
	}
}

func TestAFPacketStubOnNonLinux(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("Not a stub test on Linux")
	}
	s := NewAFPacketSniffer("0.0.0.0", 9999)
	if s == nil {
		t.Fatal("NewAFPacketSniffer returned nil")
	}
	err := s.Start(func(data []byte, srcIP string) {})
	if err == nil {
		t.Error("AF_PACKET Start should fail on non-Linux")
	}
}

// ---------- UDP backend (always available) ----------

func TestUDPBackendAlwaysAvailable(t *testing.T) {
	err := TestSniffer("udp")
	if err != nil {
		t.Fatalf("UDP sniffer should always work: %v", err)
	}
}

// ---------- DetectSniffers with dynamic loading ----------

func TestDetectSniffersPcapDynamicImpl(t *testing.T) {
	options := DetectSniffers()
	for _, opt := range options {
		if opt.ID == "pcap" {
			if runtime.GOOS == "windows" && !opt.Implemented {
				t.Error("pcap should always be implemented on Windows (pure Go)")
			}
			if opt.Description == "" {
				t.Error("pcap description should not be empty")
			}
			t.Logf("pcap: Installed=%v, Implemented=%v, Name=%s",
				opt.Installed, opt.Implemented, opt.Name)
			return
		}
	}
	switch runtime.GOOS {
	case "windows", "linux", "darwin":
		t.Error("pcap option not found in DetectSniffers results")
	}
}

// ---------- pcap stub tests ----------

func TestPcapStubBehavior(t *testing.T) {
	if pcapImplemented() {
		t.Skip("pcap is implemented in this build -- stub tests not applicable")
	}

	s := NewPcapSniffer("0.0.0.0", 9999)
	err := s.Start(func(data []byte, srcIP string) {})
	if err == nil {
		t.Error("pcap stub Start should return error")
	}
	t.Logf("pcap stub error: %v", err)
}
