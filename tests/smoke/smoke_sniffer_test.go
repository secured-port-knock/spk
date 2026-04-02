// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

//go:build testsmoke

package smoke_test

import (
	"runtime"
	"testing"
	"time"
)

// TestSmokePcapSniffer runs a basic knock through the pcap sniffer backend,
// if pcap is installed and the process has sufficient privileges.
// On Linux, pcap requires root or CAP_NET_RAW. On macOS, root is required.
// On Windows, Npcap must be installed and the process must be Administrator.
func TestSmokePcapSniffer(t *testing.T) {
	if !snifferAvailable("pcap") {
		t.Skip("pcap not installed or not implemented on this platform")
	}
	if !isRoot() {
		t.Skip("pcap sniffer requires root / Administrator privileges")
	}

	setup := defaultSetup()
	setup.snifferMode = "pcap"

	srv := setupTestServer(t, setup)

	marker := markerPath(srv.markerDir, "open_tcp", "127.0.0.1", "22")
	if !sendKnockUntilMarker(t, srv, "127.0.0.1", "open-t22", 0, marker, 10*time.Second) {
		t.Errorf("pcap knock: open command marker missing after 10s: %s", marker)
	}
}

// TestSmokeAfPacketSniffer runs a basic knock through the AF_PACKET sniffer
// backend (Linux only). Requires root or CAP_NET_RAW.
func TestSmokeAfPacketSniffer(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("afpacket sniffer is Linux-only")
	}
	if !snifferAvailable("afpacket") {
		t.Skip("afpacket not available on this platform")
	}
	if !isRoot() {
		t.Skip("afpacket sniffer requires root or CAP_NET_RAW")
	}

	setup := defaultSetup()
	setup.snifferMode = "afpacket"

	srv := setupTestServer(t, setup)

	marker := markerPath(srv.markerDir, "open_tcp", "127.0.0.1", "22")
	if !sendKnockUntilMarker(t, srv, "127.0.0.1", "open-t22", 0, marker, 10*time.Second) {
		t.Errorf("afpacket knock: open command marker missing after 10s: %s", marker)
	}
}

// TestSmokeWinDivertSniffer runs a basic knock through the WinDivert sniffer
// backend (Windows only). Requires WinDivert to be installed and the process
// to have Administrator privileges.
func TestSmokeWinDivertSniffer(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("windivert sniffer is Windows-only")
	}
	if !snifferAvailable("windivert") {
		t.Skip("WinDivert not installed on this machine")
	}
	if !isRoot() {
		t.Skip("WinDivert sniffer requires Administrator privileges")
	}

	setup := defaultSetup()
	setup.snifferMode = "windivert"

	srv := setupTestServer(t, setup)

	marker := markerPath(srv.markerDir, "open_tcp", "127.0.0.1", "22")
	if !sendKnockUntilMarker(t, srv, "127.0.0.1", "open-t22", 0, marker, 10*time.Second) {
		t.Errorf("windivert knock: open command marker missing after 10s: %s", marker)
	}
}
