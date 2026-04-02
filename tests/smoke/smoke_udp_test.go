// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

//go:build testsmoke

package smoke_test

import (
	"encoding/hex"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/secured-port-knock/spk/internal/crypto"
	"github.com/secured-port-knock/spk/internal/protocol"
)

// TestSmokeUDPBasicKnock verifies that a single open-t22 knock causes the
// server to execute the configured open_tcp_command.
func TestSmokeUDPBasicKnock(t *testing.T) {
	srv := setupTestServer(t, defaultSetup())
	sendKnock(t, "127.0.0.1", srv.port, srv.ek, "127.0.0.1", "open-t22", 0)

	marker := markerPath(srv.markerDir, "open_tcp", "127.0.0.1", "22")
	if !waitForFile(marker, 15*time.Second) {
		t.Errorf("open_tcp command marker not created within 15s: %s", marker)
	}
}

// TestSmokeUDPCloseOnShutdown verifies that when the server shuts down
// gracefully it executes the close command for any still-open ports.
// This test is skipped on Windows because os.Process.Signal(os.Interrupt)
// cannot deliver CTRL_C_EVENT to child processes with piped stdio.
func TestSmokeUDPCloseOnShutdown(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("graceful shutdown via os.Interrupt not supported for child processes on Windows")
	}
	setup := defaultSetup()
	setup.defaultOpenDuration = 120 // long-lived so expiry does not race the test

	srv := setupTestServer(t, setup)
	sendKnock(t, "127.0.0.1", srv.port, srv.ek, "127.0.0.1", "open-t22", 0)

	openMarker := markerPath(srv.markerDir, "open_tcp", "127.0.0.1", "22")
	if !waitForFile(openMarker, 15*time.Second) {
		t.Fatalf("open command marker missing after 15s: %s", openMarker)
	}

	// Graceful shutdown triggers tracker.CloseAll().
	srv.stop()

	closeMarker := markerPath(srv.markerDir, "close_tcp", "127.0.0.1", "22")
	if !waitForFile(closeMarker, 10*time.Second) {
		t.Errorf("close command marker missing after shutdown: %s", closeMarker)
	}
}

// TestSmokeUDPCloseOnExpiry verifies that the server executes the close
// command when the port open duration expires (expiry-watcher path).
// The watcher sleeps adaptively to the next entry expiry, so the close
// command should run within a few seconds of the TTL elapsing.
func TestSmokeUDPCloseOnExpiry(t *testing.T) {
	setup := defaultSetup()
	setup.defaultOpenDuration = 3 // 3-second TTL

	srv := setupTestServer(t, setup)
	sendKnock(t, "127.0.0.1", srv.port, srv.ek, "127.0.0.1", "open-t22", 0)

	openMarker := markerPath(srv.markerDir, "open_tcp", "127.0.0.1", "22")
	if !waitForFile(openMarker, 20*time.Second) {
		t.Fatalf("open command marker missing after 20s: %s", openMarker)
	}

	// Expiry watcher uses adaptive sleep (wakes at entry expiry), so close
	// should happen approximately 3s after open plus a few hundred ms.
	// Allow 25s to accommodate slow CI environments where cmd execution
	// may be delayed by prior test cleanup.
	closeMarker := markerPath(srv.markerDir, "close_tcp", "127.0.0.1", "22")
	if !waitForFile(closeMarker, 25*time.Second) {
		t.Errorf("close command marker missing after 25s (3s TTL): %s", closeMarker)
	}
}

// TestSmokeUDPTOTP verifies that a knock with a valid TOTP code is accepted,
// and a knock without a required TOTP code is rejected.
func TestSmokeUDPTOTP(t *testing.T) {
	secret, err := crypto.GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}

	// Valid TOTP: open command must execute.
	setup := defaultSetup()
	setup.totpEnabled = true
	setup.totpSecret = secret

	srv := setupTestServer(t, setup)

	totpCode, err := crypto.GenerateTOTP(secret, time.Now())
	if err != nil {
		t.Fatalf("GenerateTOTP: %v", err)
	}

	sendKnock(t, "127.0.0.1", srv.port, srv.ek, "127.0.0.1", "open-t22", 0,
		protocol.KnockOptions{TOTP: totpCode})

	openMarker := markerPath(srv.markerDir, "open_tcp", "127.0.0.1", "22")
	if !waitForFile(openMarker, 15*time.Second) {
		t.Errorf("TOTP-valid knock: open command marker missing: %s", openMarker)
	}

	// Missing TOTP: open command must NOT execute.
	setup2 := defaultSetup()
	setup2.totpEnabled = true
	setup2.totpSecret = secret
	setup2.allowCustomPort = true

	srv2 := setupTestServer(t, setup2)
	sendKnock(t, "127.0.0.1", srv2.port, srv2.ek, "127.0.0.1", "open-t80", 0)
	// No TOTP code supplied; give the server time to reject the packet.
	time.Sleep(2 * time.Second)
	badMarker := markerPath(srv2.markerDir, "open_tcp", "127.0.0.1", "80")
	if _, statErr := os.Stat(badMarker); statErr == nil {
		t.Errorf("TOTP-missing knock: open command was executed but should have been rejected")
	}
}

// TestSmokeUDPDynamicPort verifies that client and server independently
// compute the same dynamic port from a shared seed, and that a knock sent to
// that port is received and processed correctly.
func TestSmokeUDPDynamicPort(t *testing.T) {
	seed := randomPortSeed(t)
	window := 60 // minimum allowed window (60 s)

	setup := serverSetup{
		snifferMode:         "udp",
		allowedPorts:        []string{"t22"},
		defaultOpenDuration: 60,
		matchIncomingIP:     true,
		dynamicPort:         true,
		portSeed:            seed,
		dynPortWindow:       window,
	}

	srv := setupTestServer(t, setup)

	// Verify client port computation agrees with the server.
	seedBytes, err := hex.DecodeString(seed)
	if err != nil {
		t.Fatalf("decode seed: %v", err)
	}
	clientPort := crypto.ComputeDynamicPortWithWindow(seedBytes, window)
	if clientPort != srv.port {
		t.Fatalf("dynamic port mismatch: client computed %d, server using %d", clientPort, srv.port)
	}

	sendKnock(t, "127.0.0.1", srv.port, srv.ek, "127.0.0.1", "open-t22", 0)

	openMarker := markerPath(srv.markerDir, "open_tcp", "127.0.0.1", "22")
	if !waitForFile(openMarker, 15*time.Second) {
		t.Errorf("dynamic port knock: open command marker missing: %s", openMarker)
	}
}

// TestSmokeUDPAllowedPorts verifies that the server denies requests for ports
// not in the allowed_ports list when allow_custom_port is false.
func TestSmokeUDPAllowedPorts(t *testing.T) {
	setup := defaultSetup()
	setup.allowedPorts = []string{"t22"}
	setup.allowCustomPort = false

	srv := setupTestServer(t, setup)

	// t22 is allowed: open marker must appear.
	sendKnock(t, "127.0.0.1", srv.port, srv.ek, "127.0.0.1", "open-t22", 0)
	allowedMarker := markerPath(srv.markerDir, "open_tcp", "127.0.0.1", "22")
	if !waitForFile(allowedMarker, 15*time.Second) {
		t.Errorf("allowed port t22: open command marker missing")
	}

	// t443 is not in allowed_ports: open marker must NOT appear.
	sendKnock(t, "127.0.0.1", srv.port, srv.ek, "127.0.0.1", "open-t443", 0)
	deniedMarker := markerPath(srv.markerDir, "open_tcp", "127.0.0.1", "443")
	time.Sleep(2 * time.Second)
	if _, err := os.Stat(deniedMarker); err == nil {
		t.Errorf("denied port t443: open command was executed but should have been denied")
	}
}

// TestSmokeUDPAllowOpenAll verifies that open-all triggers the
// open_all_command when allow_open_all is enabled in the server config.
func TestSmokeUDPAllowOpenAll(t *testing.T) {
	setup := defaultSetup()
	setup.allowOpenAll = true

	srv := setupTestServer(t, setup)

	sendKnock(t, "127.0.0.1", srv.port, srv.ek, "127.0.0.1", "open-all", 0)

	// open_all_command uses BuildCommand(template, ip, "", "") so {{PORT}} is
	// substituted with an empty string in the marker filename.
	openAllMarker := markerPath(srv.markerDir, "open_all", "127.0.0.1", "")
	if !waitForFile(openAllMarker, 15*time.Second) {
		t.Errorf("open-all: open_all command marker missing: %s", openAllMarker)
	}
}

// TestSmokeUDPAllowOpenAllDenied verifies that open-all is rejected when
// allow_open_all is false.
func TestSmokeUDPAllowOpenAllDenied(t *testing.T) {
	setup := defaultSetup()
	setup.allowOpenAll = false

	srv := setupTestServer(t, setup)

	sendKnock(t, "127.0.0.1", srv.port, srv.ek, "127.0.0.1", "open-all", 0)

	openAllMarker := markerPath(srv.markerDir, "open_all", "127.0.0.1", "")
	time.Sleep(2 * time.Second)
	if _, err := os.Stat(openAllMarker); err == nil {
		t.Errorf("open-all with allow_open_all=false: command was executed but should be denied")
	}
}

// TestSmokeUDPMatchIncomingIP verifies that the server rejects packets where
// the payload client IP does not match the UDP source address when
// match_incoming_ip is true.
func TestSmokeUDPMatchIncomingIP(t *testing.T) {
	setup := defaultSetup()
	setup.matchIncomingIP = true
	setup.allowCustomPort = true

	srv := setupTestServer(t, setup)

	// Send with a spoofed client IP: should be rejected.
	sendKnock(t, "127.0.0.1", srv.port, srv.ek, "192.168.1.100", "open-t80", 0)
	spoofedMarker := markerPath(srv.markerDir, "open_tcp", "192.168.1.100", "80")
	time.Sleep(2 * time.Second)
	if _, err := os.Stat(spoofedMarker); err == nil {
		t.Errorf("IP-mismatch knock: open command was executed but should have been rejected")
	}

	// Send with the correct source IP (127.0.0.1): should succeed.
	sendKnock(t, "127.0.0.1", srv.port, srv.ek, "127.0.0.1", "open-t22", 0)
	goodMarker := markerPath(srv.markerDir, "open_tcp", "127.0.0.1", "22")
	if !waitForFile(goodMarker, 15*time.Second) {
		t.Errorf("IP-match knock: open command marker missing: %s", goodMarker)
	}
}
