// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package server

import (
	"bytes"
	"fmt"
	"log"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"spk/internal/config"
	"spk/internal/crypto"
	"spk/internal/protocol"
)

// testLogger captures log output for verification.
type testLogger struct {
	buf bytes.Buffer
}

func (l *testLogger) Printf(format string, v ...interface{}) {
	fmt.Fprintf(&l.buf, format+"\n", v...)
}

// --- handleCloseAll tests ---

func TestHandleCloseAllNoPorts(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	stdLogger := log.New(&bytes.Buffer{}, "", 0)
	tracker := NewTracker(statePath, stdLogger, true)

	logger := &testLogger{}
	cfg := &config.Config{CommandTimeout: 0.5}

	handleCloseAll(logger, cfg, tracker, "10.0.0.1")

	if out := logger.buf.String(); out == "" {
		t.Error("expected log output for no open ports")
	}
}

func TestHandleCloseAllMultiplePorts(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	stdLogger := log.New(&bytes.Buffer{}, "", 0)
	tracker := NewTracker(statePath, stdLogger, true)

	expires := time.Now().Add(1 * time.Hour)
	tracker.Add(&PortEntry{
		IP: "10.0.0.1", Port: "t22", Proto: "tcp", PortNum: "22",
		ExpiresAt: expires, CloseCmd: "echo close22",
	})
	tracker.Add(&PortEntry{
		IP: "10.0.0.1", Port: "t443", Proto: "tcp", PortNum: "443",
		ExpiresAt: expires, CloseCmd: "echo close443",
	})
	// Different IP - should not be closed
	tracker.Add(&PortEntry{
		IP: "10.0.0.2", Port: "t80", Proto: "tcp", PortNum: "80",
		ExpiresAt: expires, CloseCmd: "echo close80",
	})

	logger := &testLogger{}
	cfg := &config.Config{CommandTimeout: 1}

	handleCloseAll(logger, cfg, tracker, "10.0.0.1")

	// Only 10.0.0.1 entries should be removed
	remaining := tracker.GetAll()
	if len(remaining) != 1 {
		t.Errorf("expected 1 remaining entry (10.0.0.2), got %d", len(remaining))
	}
	if len(remaining) > 0 && remaining[0].IP != "10.0.0.2" {
		t.Errorf("remaining entry IP = %q, want 10.0.0.2", remaining[0].IP)
	}
}

func TestHandleCloseAllLogsCommandOutput(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	stdLogger := log.New(&bytes.Buffer{}, "", 0)
	tracker := NewTracker(statePath, stdLogger, true)

	tracker.Add(&PortEntry{
		IP: "10.0.0.1", Port: "t22", Proto: "tcp", PortNum: "22",
		ExpiresAt: time.Now().Add(1 * time.Hour), CloseCmd: "echo closed_port_22",
	})

	logger := &testLogger{}
	cfg := &config.Config{
		CommandTimeout:   1,
		LogCommandOutput: true,
	}

	handleCloseAll(logger, cfg, tracker, "10.0.0.1")

	out := logger.buf.String()
	if out == "" {
		t.Error("expected log output")
	}
}

// --- handleCustomCommand tests ---

func TestHandleCustomCommandKnown(t *testing.T) {
	logger := &testLogger{}
	cfg := &config.Config{
		CustomCommands: map[string]string{
			"ping": "echo pong",
		},
		CommandTimeout: 1,
	}

	handleCustomCommand(logger, cfg, "10.0.0.1", "ping")

	out := logger.buf.String()
	if out == "" {
		t.Error("expected log output for known command")
	}
}

func TestHandleCustomCommandUnknown(t *testing.T) {
	logger := &testLogger{}
	cfg := &config.Config{
		CustomCommands: map[string]string{
			"ping": "echo pong",
		},
		CommandTimeout: 1,
	}

	handleCustomCommand(logger, cfg, "10.0.0.1", "nonexistent")

	out := logger.buf.String()
	if out == "" {
		t.Fatal("expected IGNORE log")
	}
}

func TestHandleCustomCommandEmptyCommands(t *testing.T) {
	logger := &testLogger{}
	cfg := &config.Config{
		CustomCommands: map[string]string{},
		CommandTimeout: 1,
	}

	handleCustomCommand(logger, cfg, "10.0.0.1", "anything")
	// Should not panic, should log IGNORE
}

func TestHandleCustomCommandNilCommands(t *testing.T) {
	logger := &testLogger{}
	cfg := &config.Config{
		CustomCommands: nil,
		CommandTimeout: 1,
	}

	handleCustomCommand(logger, cfg, "10.0.0.1", "anything")
	// Should not panic
}

func TestHandleCustomCommandWithIPSubstitution(t *testing.T) {
	logger := &testLogger{}
	cfg := &config.Config{
		CustomCommands: map[string]string{
			"check": "echo checking {{IP}}",
		},
		CommandTimeout:   1,
		LogCommandOutput: true,
	}

	handleCustomCommand(logger, cfg, "10.0.0.1", "check")

	out := logger.buf.String()
	if out == "" {
		t.Error("expected log output")
	}
}

// --- commandTimeout tests ---

func TestCommandTimeoutCustom(t *testing.T) {
	cfg := &config.Config{CommandTimeout: 2.5}
	got := commandTimeout(cfg)
	want := time.Duration(2.5 * float64(time.Second))
	if got != want {
		t.Errorf("commandTimeout = %v, want %v", got, want)
	}
}

// TestCommandTimeoutDefault is intentionally omitted: the zero-value case is
// already exercised by TestCommandTimeoutHelper in dedup_test.go.

// =============================================================================
// Server Policy Enforcement Tests
//
// These tests verify that the server correctly enforces its access-control
// policies -- even when an attacker sends a fully valid, authenticated knock.
// Authentication alone does not grant access; the server's configured policies
// act as the second gate.
// =============================================================================

// TestHandleOpenDeniedPortNotAllowed verifies that handleOpen rejects a port
// that is not in the allowed_ports list when allow_custom_port is false.
// Attack scenario: a legitimate client (or an attacker who obtained the
// activation bundle) sends a knock for an unlisted port hoping to open it.
func TestHandleOpenDeniedPortNotAllowed(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	stdLogger := log.New(&bytes.Buffer{}, "", 0)
	tracker := NewTracker(statePath, stdLogger, true)

	cfg := &config.Config{
		AllowCustomPort: false, // strict allowlist enforcement
		OpenTCPCommand:  "echo open {{PORT}} {{IP}}",
		CloseTCPCommand: "echo close {{PORT}} {{IP}}",
		CommandTimeout:  0.5,
	}
	// Only t22 is allowed; attacker tries t443
	allowedPorts := map[string]bool{"t22": true}
	logger := &testLogger{}

	handleOpen(logger, cfg, tracker, allowedPorts, "10.0.0.1", "t443", 3600)

	if !strings.Contains(logger.buf.String(), "[DENY]") {
		t.Errorf("expected [DENY] log for non-allowed port, got: %s", logger.buf.String())
	}
	if len(tracker.GetAll()) != 0 {
		t.Error("tracker must remain empty after DENY -- no port was opened")
	}
}

// TestHandleOpenAllDeniedWhenDisabled verifies that handleOpenAll rejects the
// open-all command when allow_open_all=false.
// Attack scenario: an attacker knows the activation bundle and tries to open
// all allowed ports at once -- which should be blocked by server policy.
func TestHandleOpenAllDeniedWhenDisabled(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	stdLogger := log.New(&bytes.Buffer{}, "", 0)
	tracker := NewTracker(statePath, stdLogger, true)

	cfg := &config.Config{
		AllowOpenAll:   false,
		CommandTimeout: 0.5,
	}
	allowedPorts := map[string]bool{"t22": true, "t443": true}
	logger := &testLogger{}

	handleOpenAll(logger, cfg, tracker, allowedPorts, "10.0.0.1", 3600)

	if !strings.Contains(logger.buf.String(), "[DENY]") {
		t.Errorf("expected [DENY] log when open-all is disabled, got: %s", logger.buf.String())
	}
	if len(tracker.GetAll()) != 0 {
		t.Error("tracker must remain empty -- open-all was denied")
	}
}

// TestHandleKnockTOTPRequiredButMissing verifies that handleKnock rejects a
// fully-valid knock when TOTP is enabled server-side but no TOTP code is
// included in the packet.
// Attack scenario: an attacker has obtained the server public key (e.g., from
// a stolen activation bundle) but does not have the TOTP secret.  They can
// construct a cryptographically-valid knock, but the missing TOTP code must
// cause rejection before any firewall rule is applied.
func TestHandleKnockTOTPRequiredButMissing(t *testing.T) {
	dk, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	totpSecret, err := crypto.GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}

	cfg := &config.Config{
		TOTPEnabled:     true,
		TOTPSecret:      totpSecret,
		MatchIncomingIP: true,
		AllowCustomPort: true,
		CommandTimeout:  0.5,
	}

	statePath := filepath.Join(t.TempDir(), "state.json")
	stdLogger := log.New(&bytes.Buffer{}, "", 0)
	tracker := NewTracker(statePath, stdLogger, false)
	nonceTracker := protocol.NewNonceTrackerWithLimit(2*time.Minute, 10000)
	allowedPorts := map[string]bool{"t22": true}
	logger := &testLogger{}

	// Build a valid knock WITHOUT a TOTP code
	packet, err := protocol.BuildKnockPacket(dk.EncapsulationKey(), "127.0.0.1", "open-t22", 0)
	if err != nil {
		t.Fatalf("BuildKnockPacket: %v", err)
	}

	handleKnock(logger, dk, cfg, nonceTracker, tracker, allowedPorts, 30, packet, "127.0.0.1")

	out := logger.buf.String()
	if !strings.Contains(out, "[REJECT]") {
		t.Errorf("expected [REJECT] when TOTP required but not provided, got: %s", out)
	}
	if len(tracker.GetAll()) != 0 {
		t.Error("no port should be opened when TOTP code is missing")
	}
}

// TestHandleKnockTOTPWrongCode verifies that handleKnock rejects a knock with
// a TOTP code derived from a different (attacker-controlled) secret.
// Attack scenario: an attacker knows the server public key and has a TOTP
// authenticator, but is using the wrong secret -- the knock must be rejected.
func TestHandleKnockTOTPWrongCode(t *testing.T) {
	dk, _ := crypto.GenerateKeyPair()

	serverSecret, _ := crypto.GenerateTOTPSecret()
	attackerSecret, _ := crypto.GenerateTOTPSecret() // different secret

	cfg := &config.Config{
		TOTPEnabled:     true,
		TOTPSecret:      serverSecret,
		MatchIncomingIP: true,
		AllowCustomPort: true,
		CommandTimeout:  0.5,
	}

	statePath := filepath.Join(t.TempDir(), "state.json")
	stdLogger := log.New(&bytes.Buffer{}, "", 0)
	tracker := NewTracker(statePath, stdLogger, false)
	nonceTracker := protocol.NewNonceTrackerWithLimit(2*time.Minute, 10000)
	allowedPorts := map[string]bool{"t22": true}
	logger := &testLogger{}

	// Generate a TOTP code using the attacker's (wrong) secret
	attackerCode, err := crypto.GenerateTOTP(attackerSecret, time.Now())
	if err != nil {
		t.Fatalf("GenerateTOTP: %v", err)
	}

	opts := protocol.KnockOptions{TOTP: attackerCode}
	packet, err := protocol.BuildKnockPacket(dk.EncapsulationKey(), "127.0.0.1", "open-t22", 0, opts)
	if err != nil {
		t.Fatalf("BuildKnockPacket: %v", err)
	}

	handleKnock(logger, dk, cfg, nonceTracker, tracker, allowedPorts, 30, packet, "127.0.0.1")

	out := logger.buf.String()
	if !strings.Contains(out, "[REJECT]") {
		t.Errorf("expected [REJECT] for wrong TOTP secret, got: %s", out)
	}
	if len(tracker.GetAll()) != 0 {
		t.Error("no port should be opened with a wrong TOTP code")
	}
}

// TestHandleKnockRelayAttackRejected verifies source-IP mismatch is rejected
// when match_incoming_ip is enabled, before nonce/state mutation.
// Unlike TestHandleKnockReplayRejected, the key assertion here is that the
// nonce is NOT consumed: a relay attempt must not burn the legitimate client's
// nonce slot, which would let an attacker DoS the client via nonce exhaustion.
func TestHandleKnockRelayAttackRejected(t *testing.T) {
	dk, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	cfg := &config.Config{
		MatchIncomingIP: true,
		AllowCustomPort: true,
		CommandTimeout:  0.5,
	}

	statePath := filepath.Join(t.TempDir(), "state.json")
	stdLogger := log.New(&bytes.Buffer{}, "", 0)
	tracker := NewTracker(statePath, stdLogger, false)
	nonceTracker := protocol.NewNonceTrackerWithLimit(2*time.Minute, 10000)
	allowedPorts := map[string]bool{"t22": true}
	logger := &testLogger{}

	// Packet claims 10.0.0.1 in encrypted payload, but arrives from another source.
	packet, err := protocol.BuildKnockPacket(dk.EncapsulationKey(), "10.0.0.1", "open-t22", 0)
	if err != nil {
		t.Fatalf("BuildKnockPacket: %v", err)
	}

	handleKnock(logger, dk, cfg, nonceTracker, tracker, allowedPorts, 30, packet, "203.0.113.55")

	if !strings.Contains(logger.buf.String(), "[REJECT]") {
		t.Errorf("expected [REJECT] for relayed packet, got: %s", logger.buf.String())
	}
	if len(tracker.GetAll()) != 0 {
		t.Errorf("relay attempt should not open any port, got %d entries", len(tracker.GetAll()))
	}
	if nonceTracker.Size() != 0 {
		t.Errorf("relay attempt should not reserve nonce, nonce cache size=%d", nonceTracker.Size())
	}
}

// TestHandleKnockReplayRejected verifies that replaying an identical packet is
// rejected at the server handler layer and does not execute a second open.
func TestHandleKnockReplayRejected(t *testing.T) {
	dk, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	cfg := &config.Config{
		MatchIncomingIP:     true,
		AllowCustomPort:     true,
		DefaultOpenDuration: 3600,
		OpenTCPCommand:      "echo open {{PORT}} {{IP}}",
		CloseTCPCommand:     "echo close {{PORT}} {{IP}}",
		CommandTimeout:      0.5,
	}

	statePath := filepath.Join(t.TempDir(), "state.json")
	stdLogger := log.New(&bytes.Buffer{}, "", 0)
	tracker := NewTracker(statePath, stdLogger, false)
	nonceTracker := protocol.NewNonceTrackerWithLimit(2*time.Minute, 10000)
	allowedPorts := map[string]bool{"t22": true}
	logger := &testLogger{}

	packet, err := protocol.BuildKnockPacket(dk.EncapsulationKey(), "127.0.0.1", "open-t22", 0)
	if err != nil {
		t.Fatalf("BuildKnockPacket: %v", err)
	}

	// First packet should be accepted and open one tracked port.
	handleKnock(logger, dk, cfg, nonceTracker, tracker, allowedPorts, 30, packet, "127.0.0.1")
	if len(tracker.GetAll()) != 1 {
		t.Fatalf("expected 1 tracked entry after first knock, got %d", len(tracker.GetAll()))
	}

	// Replay the same packet: should be rejected by duplicate nonce check.
	handleKnock(logger, dk, cfg, nonceTracker, tracker, allowedPorts, 30, packet, "127.0.0.1")

	if !strings.Contains(logger.buf.String(), "possible replay attack") {
		t.Errorf("expected replay rejection log, got: %s", logger.buf.String())
	}
	if len(tracker.GetAll()) != 1 {
		t.Errorf("replay should not create extra tracker entries, got %d", len(tracker.GetAll()))
	}
}

// (TestHandleKnockRelayAttackRejected has been moved above TestHandleKnockReplayRejected
// to match the execution order in handleKnock: IP verification runs first.)

// =============================================================================
// handleKnock happy-path and edge-case tests
// =============================================================================

// TestHandleKnockSuccessOpensPort verifies the normal operation: a valid,
// authenticated knock causes exactly one tracker entry to be created.
// This is the critical baseline test -- if this breaks, nothing works at all.
func TestHandleKnockSuccessOpensPort(t *testing.T) {
	dk, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	cfg := &config.Config{
		MatchIncomingIP:     true,
		AllowCustomPort:     true,
		DefaultOpenDuration: 30,
		OpenTCPCommand:      "echo open {{PORT}} {{IP}}",
		CloseTCPCommand:     "echo close {{PORT}} {{IP}}",
		CommandTimeout:      0.5,
	}

	statePath := filepath.Join(t.TempDir(), "state.json")
	stdLogger := log.New(&bytes.Buffer{}, "", 0)
	tracker := NewTracker(statePath, stdLogger, false)
	nonceTracker := protocol.NewNonceTrackerWithLimit(2*time.Minute, 10000)
	allowedPorts := map[string]bool{"t22": true}
	logger := &testLogger{}

	packet, err := protocol.BuildKnockPacket(dk.EncapsulationKey(), "127.0.0.1", "open-t22", 0)
	if err != nil {
		t.Fatalf("BuildKnockPacket: %v", err)
	}

	handleKnock(logger, dk, cfg, nonceTracker, tracker, allowedPorts, 30, packet, "127.0.0.1")

	entries := tracker.GetAll()
	if len(entries) != 1 {
		t.Fatalf("expected 1 tracked entry after valid knock, got %d (log: %s)", len(entries), logger.buf.String())
	}
	if entries[0].IP != "127.0.0.1" {
		t.Errorf("tracker entry IP = %q, want 127.0.0.1", entries[0].IP)
	}
	if entries[0].PortNum != "22" {
		t.Errorf("tracker entry port = %q, want 22", entries[0].PortNum)
	}
	if nonceTracker.Size() != 1 {
		t.Errorf("expected nonce to be recorded, got size=%d", nonceTracker.Size())
	}
}

// TestHandleKnockTOTPSuccess verifies that a knock accompanied by a valid TOTP
// code is accepted and opens the requested port.
func TestHandleKnockTOTPSuccess(t *testing.T) {
	dk, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	secret, err := crypto.GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	code, err := crypto.GenerateTOTP(secret, time.Now())
	if err != nil {
		t.Fatalf("GenerateTOTP: %v", err)
	}

	cfg := &config.Config{
		TOTPEnabled:         true,
		TOTPSecret:          secret,
		MatchIncomingIP:     true,
		AllowCustomPort:     true,
		DefaultOpenDuration: 30,
		OpenTCPCommand:      "echo open {{PORT}} {{IP}}",
		CloseTCPCommand:     "echo close {{PORT}} {{IP}}",
		CommandTimeout:      0.5,
	}

	statePath := filepath.Join(t.TempDir(), "state.json")
	stdLogger := log.New(&bytes.Buffer{}, "", 0)
	tracker := NewTracker(statePath, stdLogger, false)
	nonceTracker := protocol.NewNonceTrackerWithLimit(2*time.Minute, 10000)
	allowedPorts := map[string]bool{"t22": true}
	logger := &testLogger{}

	opts := protocol.KnockOptions{TOTP: code}
	packet, err := protocol.BuildKnockPacket(dk.EncapsulationKey(), "127.0.0.1", "open-t22", 0, opts)
	if err != nil {
		t.Fatalf("BuildKnockPacket: %v", err)
	}

	handleKnock(logger, dk, cfg, nonceTracker, tracker, allowedPorts, 30, packet, "127.0.0.1")

	if len(tracker.GetAll()) != 1 {
		t.Fatalf("TOTP-authenticated knock should open a port, got %d entries (log: %s)",
			len(tracker.GetAll()), logger.buf.String())
	}
}

// TestHandleKnockMatchIncomingIPFalse verifies the NAT/proxy use case: when
// match_incoming_ip is disabled, the server uses the IP claimed in the
// encrypted payload (not the UDP source address) for the firewall rule.
// This is important because clients behind NAT never know their external IP.
func TestHandleKnockMatchIncomingIPFalse(t *testing.T) {
	dk, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	cfg := &config.Config{
		MatchIncomingIP:     false, // NAT mode: trust payload IP
		AllowCustomPort:     true,
		DefaultOpenDuration: 30,
		OpenTCPCommand:      "echo open {{PORT}} {{IP}}",
		CloseTCPCommand:     "echo close {{PORT}} {{IP}}",
		CommandTimeout:      0.5,
	}

	statePath := filepath.Join(t.TempDir(), "state.json")
	stdLogger := log.New(&bytes.Buffer{}, "", 0)
	tracker := NewTracker(statePath, stdLogger, false)
	nonceTracker := protocol.NewNonceTrackerWithLimit(2*time.Minute, 10000)
	allowedPorts := map[string]bool{"t22": true}
	logger := &testLogger{}

	// Client claims its LAN IP 10.0.0.5; the packet arrives from NAT gateway 203.0.113.1.
	packet, err := protocol.BuildKnockPacket(dk.EncapsulationKey(), "10.0.0.5", "open-t22", 0)
	if err != nil {
		t.Fatalf("BuildKnockPacket: %v", err)
	}

	handleKnock(logger, dk, cfg, nonceTracker, tracker, allowedPorts, 30, packet, "203.0.113.1")

	entries := tracker.GetAll()
	if len(entries) != 1 {
		t.Fatalf("NAT knock should open port, got %d entries (log: %s)", len(entries), logger.buf.String())
	}
	// The firewall rule must target the payload IP (the client's real address behind NAT).
	if entries[0].IP != "10.0.0.5" {
		t.Errorf("firewall rule IP = %q, want 10.0.0.5 (payload IP, not source IP)", entries[0].IP)
	}
}

// TestHandleKnockMalformedPacketNoPanic verifies that malformed and garbage
// input never causes a panic and is silently rejected.
// This exercises the panic-recovery defer in handleKnock.
func TestHandleKnockMalformedPacketNoPanic(t *testing.T) {
	dk, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	cfg := &config.Config{MatchIncomingIP: true, AllowCustomPort: true, CommandTimeout: 0.5}

	statePath := filepath.Join(t.TempDir(), "state.json")
	stdLogger := log.New(&bytes.Buffer{}, "", 0)
	tracker := NewTracker(statePath, stdLogger, false)
	nonceTracker := protocol.NewNonceTrackerWithLimit(2*time.Minute, 10000)
	allowedPorts := map[string]bool{"t22": true}
	logger := &testLogger{}

	malformed := [][]byte{
		{},
		{0x00},
		[]byte("not a valid encrypted packet at all"),
		bytes.Repeat([]byte{0xFF}, 512),
		bytes.Repeat([]byte{0xAB, 0xCD}, 256),
		[]byte("A"),
	}

	for _, pkt := range malformed {
		// Must not panic.
		handleKnock(logger, dk, cfg, nonceTracker, tracker, allowedPorts, 30, pkt, "10.0.0.1")
	}

	if len(tracker.GetAll()) != 0 {
		t.Error("malformed packets must never open a port")
	}
}

// TestHandleKnockMaxOpenDurationEnforced verifies that when max_open_duration
// is set, a client-supplied open duration exceeding that cap is silently
// clamped to the server maximum.
func TestHandleKnockMaxOpenDurationEnforced(t *testing.T) {
	dk, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	cfg := &config.Config{
		MatchIncomingIP:         true,
		AllowCustomPort:         true,
		AllowCustomOpenDuration: true,
		DefaultOpenDuration:     30,
		MaxOpenDuration:         60, // server cap
		OpenTCPCommand:          "echo open {{PORT}} {{IP}}",
		CloseTCPCommand:         "echo close {{PORT}} {{IP}}",
		CommandTimeout:          0.5,
	}

	statePath := filepath.Join(t.TempDir(), "state.json")
	stdLogger := log.New(&bytes.Buffer{}, "", 0)
	tracker := NewTracker(statePath, stdLogger, false)
	nonceTracker := protocol.NewNonceTrackerWithLimit(2*time.Minute, 10000)
	allowedPorts := map[string]bool{"t22": true}
	logger := &testLogger{}

	// Client requests 3600 seconds; server should cap it to 60.
	packet, err := protocol.BuildKnockPacket(dk.EncapsulationKey(), "127.0.0.1", "open-t22", 3600)
	if err != nil {
		t.Fatalf("BuildKnockPacket: %v", err)
	}

	handleKnock(logger, dk, cfg, nonceTracker, tracker, allowedPorts, 30, packet, "127.0.0.1")

	entries := tracker.GetAll()
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d (log: %s)", len(entries), logger.buf.String())
	}
	// Expiry should be at most MaxOpenDuration (60s) in the future, not 3600s.
	maxExpiry := time.Now().Add(65 * time.Second) // 60s cap + 5s tolerance
	if entries[0].ExpiresAt.After(maxExpiry) {
		t.Errorf("expiry %v exceeds max_open_duration cap (60s)", entries[0].ExpiresAt)
	}
}

// TestHandleKnockCustomOpenDurationIgnoredWhenDisabled verifies that when
// allow_custom_open_duration is false, the server uses default_open_duration
// regardless of what the client requests.
func TestHandleKnockCustomOpenDurationIgnoredWhenDisabled(t *testing.T) {
	dk, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	cfg := &config.Config{
		MatchIncomingIP:         true,
		AllowCustomPort:         true,
		AllowCustomOpenDuration: false, // client cannot override
		DefaultOpenDuration:     30,
		OpenTCPCommand:          "echo open {{PORT}} {{IP}}",
		CloseTCPCommand:         "echo close {{PORT}} {{IP}}",
		CommandTimeout:          0.5,
	}

	statePath := filepath.Join(t.TempDir(), "state.json")
	stdLogger := log.New(&bytes.Buffer{}, "", 0)
	tracker := NewTracker(statePath, stdLogger, false)
	nonceTracker := protocol.NewNonceTrackerWithLimit(2*time.Minute, 10000)
	allowedPorts := map[string]bool{"t22": true}
	logger := &testLogger{}

	// Client requests 7200 seconds, but custom duration is disabled.
	packet, err := protocol.BuildKnockPacket(dk.EncapsulationKey(), "127.0.0.1", "open-t22", 7200)
	if err != nil {
		t.Fatalf("BuildKnockPacket: %v", err)
	}

	handleKnock(logger, dk, cfg, nonceTracker, tracker, allowedPorts, 30, packet, "127.0.0.1")

	entries := tracker.GetAll()
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d (log: %s)", len(entries), logger.buf.String())
	}
	// Expiry should be ~30s (default), not ~7200s.
	maxExpiry := time.Now().Add(40 * time.Second) // 30s default + 10s tolerance
	if entries[0].ExpiresAt.After(maxExpiry) {
		t.Errorf("expiry %v exceeds default_open_duration (30s); custom duration was incorrectly honoured", entries[0].ExpiresAt)
	}
}

// TestHandleKnockBatchPortSpecs verifies that a single knock with a
// comma-separated port list (e.g. "open-t22,t443") opens each port exactly once.
func TestHandleKnockBatchPortSpecs(t *testing.T) {
	dk, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	cfg := &config.Config{
		MatchIncomingIP:     true,
		AllowCustomPort:     true,
		DefaultOpenDuration: 30,
		OpenTCPCommand:      "echo open {{PORT}} {{IP}}",
		CloseTCPCommand:     "echo close {{PORT}} {{IP}}",
		CommandTimeout:      0.5,
	}

	statePath := filepath.Join(t.TempDir(), "state.json")
	stdLogger := log.New(&bytes.Buffer{}, "", 0)
	tracker := NewTracker(statePath, stdLogger, false)
	nonceTracker := protocol.NewNonceTrackerWithLimit(2*time.Minute, 10000)
	allowedPorts := map[string]bool{"t22": true, "t443": true}
	logger := &testLogger{}

	packet, err := protocol.BuildKnockPacket(dk.EncapsulationKey(), "127.0.0.1", "open-t22,t443", 0)
	if err != nil {
		t.Fatalf("BuildKnockPacket: %v", err)
	}

	handleKnock(logger, dk, cfg, nonceTracker, tracker, allowedPorts, 30, packet, "127.0.0.1")

	entries := tracker.GetAll()
	if len(entries) != 2 {
		t.Fatalf("batch knock should open 2 ports, got %d (log: %s)", len(entries), logger.buf.String())
	}
	ports := map[string]bool{}
	for _, e := range entries {
		ports[e.PortNum] = true
	}
	if !ports["22"] {
		t.Error("port 22 should be open after batch knock")
	}
	if !ports["443"] {
		t.Error("port 443 should be open after batch knock")
	}
}

// =============================================================================
// handleClose tests
// =============================================================================

// TestHandleCloseSinglePort verifies that handleClose runs the close command
// and removes the tracker entry for the specified port.
func TestHandleCloseSinglePort(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	stdLogger := log.New(&bytes.Buffer{}, "", 0)
	tracker := NewTracker(statePath, stdLogger, true)

	tracker.Add(&PortEntry{
		IP: "10.0.0.1", Port: "t22", Proto: "tcp", PortNum: "22",
		ExpiresAt: time.Now().Add(1 * time.Hour),
		CloseCmd:  "echo close 22 10.0.0.1",
	})

	cfg := &config.Config{
		AllowCustomPort: true,
		CloseTCPCommand: "echo close {{PORT}} {{IP}}",
		CommandTimeout:  0.5,
	}
	allowedPorts := map[string]bool{"t22": true}
	logger := &testLogger{}

	handleClose(logger, cfg, tracker, allowedPorts, "10.0.0.1", "t22")

	if len(tracker.GetAll()) != 0 {
		t.Errorf("tracker should be empty after handleClose, got %d entries", len(tracker.GetAll()))
	}
	if !strings.Contains(logger.buf.String(), "[CLOSE]") {
		t.Errorf("expected [CLOSE] log, got: %s", logger.buf.String())
	}
}

// TestHandleClosePortNotAllowed verifies that handleClose logs [DENY] and does
// not remove a tracker entry when allow_custom_port=false and the port is not
// in the allowed list.
func TestHandleClosePortNotAllowed(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	stdLogger := log.New(&bytes.Buffer{}, "", 0)
	tracker := NewTracker(statePath, stdLogger, true)

	tracker.Add(&PortEntry{
		IP: "10.0.0.1", Port: "t443", Proto: "tcp", PortNum: "443",
		ExpiresAt: time.Now().Add(1 * time.Hour),
		CloseCmd:  "echo close 443",
	})

	cfg := &config.Config{
		AllowCustomPort: false, // strict allowlist
		CloseTCPCommand: "echo close {{PORT}} {{IP}}",
		CommandTimeout:  0.5,
	}
	allowedPorts := map[string]bool{"t22": true} // t443 not allowed
	logger := &testLogger{}

	handleClose(logger, cfg, tracker, allowedPorts, "10.0.0.1", "t443")

	if !strings.Contains(logger.buf.String(), "[DENY]") {
		t.Errorf("expected [DENY] for unlisted port, got: %s", logger.buf.String())
	}
	// The tracker entry must remain intact -- the port was not closed.
	if len(tracker.GetAll()) != 1 {
		t.Errorf("tracker entry should be preserved after DENY, got %d entries", len(tracker.GetAll()))
	}
}

// TestHandleCloseUnknownPort verifies that handleClose does nothing (no crash,
// no log noise) when asked to close a port not currently in the tracker.
func TestHandleCloseUnknownPort(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	stdLogger := log.New(&bytes.Buffer{}, "", 0)
	tracker := NewTracker(statePath, stdLogger, true)

	cfg := &config.Config{
		AllowCustomPort: true,
		CloseTCPCommand: "echo close {{PORT}} {{IP}}",
		CommandTimeout:  0.5,
	}
	allowedPorts := map[string]bool{"t22": true}
	logger := &testLogger{}

	// No entry in tracker, but handleClose should not panic.
	handleClose(logger, cfg, tracker, allowedPorts, "10.0.0.1", "t22")

	if len(tracker.GetAll()) != 0 {
		t.Error("tracker should remain empty")
	}
}

// =============================================================================
// handleOpen edge-case tests
// =============================================================================

// TestHandleOpenRefreshesExpiryOnDuplicate verifies that requesting the same
// port twice does not create a second tracker entry but instead extends the
// expiry of the existing one (the "refresh" dedup path).
func TestHandleOpenRefreshesExpiryOnDuplicate(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	stdLogger := log.New(&bytes.Buffer{}, "", 0)
	tracker := NewTracker(statePath, stdLogger, true)

	cfg := &config.Config{
		AllowCustomPort: true,
		OpenTCPCommand:  "echo open {{PORT}} {{IP}}",
		CloseTCPCommand: "echo close {{PORT}} {{IP}}",
		CommandTimeout:  0.5,
	}
	allowedPorts := map[string]bool{"t22": true}
	logger := &testLogger{}

	// First open -- reserves entry with 30s duration.
	handleOpen(logger, cfg, tracker, allowedPorts, "10.0.0.1", "t22", 30)
	if len(tracker.GetAll()) != 1 {
		t.Fatalf("expected 1 entry after first open, got %d", len(tracker.GetAll()))
	}
	firstExpiry := tracker.GetAll()[0].ExpiresAt
	time.Sleep(10 * time.Millisecond) // ensure clock advances

	// Second open for the same port -- must refresh expiry, not add a second entry.
	handleOpen(logger, cfg, tracker, allowedPorts, "10.0.0.1", "t22", 30)
	entries := tracker.GetAll()
	if len(entries) != 1 {
		t.Fatalf("duplicate open must not create a second entry, got %d", len(entries))
	}
	if !entries[0].ExpiresAt.After(firstExpiry) {
		t.Errorf("expiry should be refreshed: first=%v, refreshed=%v", firstExpiry, entries[0].ExpiresAt)
	}
	if !strings.Contains(logger.buf.String(), "[REFRESH]") {
		t.Errorf("expected [REFRESH] log for duplicate open, got: %s", logger.buf.String())
	}
}
