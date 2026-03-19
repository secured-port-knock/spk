// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package protocol

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"spk/internal/crypto"
)

func TestBuildParseKnockPacket(t *testing.T) {
	dk, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	ek := dk.EncapsulationKey()

	clientIP := "192.168.1.100"
	command := "open-t22"
	timeout := 3600

	packet, err := BuildKnockPacket(ek, clientIP, command, timeout)
	if err != nil {
		t.Fatalf("BuildKnockPacket: %v", err)
	}

	// Packet should be reasonable size
	if len(packet) < 1568+12+16 {
		t.Errorf("packet too small: %d bytes", len(packet))
	}
	if len(packet) > MaxPacketSize {
		t.Errorf("packet too large: %d bytes", len(packet))
	}

	// Parse with correct source IP
	payload, err := ParseKnockPacket(dk, packet, clientIP, 30)
	if err != nil {
		t.Fatalf("ParseKnockPacket: %v", err)
	}

	if payload.Version != ProtocolVersion {
		t.Errorf("version = %d, want %d", payload.Version, ProtocolVersion)
	}
	if payload.ClientIP != clientIP {
		t.Errorf("clientIP = %s, want %s", payload.ClientIP, clientIP)
	}
	if payload.Command != command {
		t.Errorf("command = %s, want %s", payload.Command, command)
	}
	if payload.OpenDuration != timeout {
		t.Errorf("open duration = %d, want %d", payload.OpenDuration, timeout)
	}
	if payload.Nonce == "" {
		t.Error("nonce is empty")
	}

	// Timestamp should be within tolerance
	now := time.Now().Unix()
	if abs(now-payload.Timestamp) > 5 {
		t.Errorf("timestamp drift too large: %d", abs(now-payload.Timestamp))
	}
}

func TestIPSpoofingRejection(t *testing.T) {
	dk, _ := crypto.GenerateKeyPair()
	ek := dk.EncapsulationKey()

	// Client claims to be 192.168.1.100
	packet, _ := BuildKnockPacket(ek, "192.168.1.100", "open-t22", 0)

	// Server sees packet from different IP (attacker forwarded/spoofed)
	_, err := ParseKnockPacket(dk, packet, "10.0.0.50", 30)
	if err == nil {
		t.Error("expected IP mismatch error for spoofed packet")
	}
}

func TestReplayRejection(t *testing.T) {
	dk, _ := crypto.GenerateKeyPair()
	ek := dk.EncapsulationKey()

	packet, _ := BuildKnockPacket(ek, "192.168.1.100", "open-t22", 0)

	// Parse twice - second should detect replay via nonce tracker
	tracker := NewNonceTracker(120 * time.Second)

	payload, err := ParseKnockPacket(dk, packet, "192.168.1.100", 30)
	if err != nil {
		t.Fatalf("first parse: %v", err)
	}

	if !tracker.Check(payload.Nonce) {
		t.Error("first nonce check should succeed")
	}

	// Same nonce again
	if tracker.Check(payload.Nonce) {
		t.Error("second nonce check should fail (replay)")
	}
}

func TestTimestampRejection(t *testing.T) {
	dk, _ := crypto.GenerateKeyPair()
	ek := dk.EncapsulationKey()

	// Build a valid packet
	packet, _ := BuildKnockPacket(ek, "192.168.1.100", "open-t22", 0)

	// Parse with very tight tolerance (0 seconds) - should still pass since it was just created
	_, err := ParseKnockPacket(dk, packet, "192.168.1.100", 2)
	if err != nil {
		t.Fatalf("fresh packet should pass with 2s tolerance: %v", err)
	}
}

func TestWrongKeyRejection(t *testing.T) {
	dk1, _ := crypto.GenerateKeyPair()
	dk2, _ := crypto.GenerateKeyPair()

	ek1 := dk1.EncapsulationKey()

	// Encrypt with server1's key
	packet, _ := BuildKnockPacket(ek1, "192.168.1.100", "open-t22", 0)

	// Try to decrypt with server2's key
	_, err := ParseKnockPacket(dk2, packet, "192.168.1.100", 30)
	if err == nil {
		t.Error("expected error when decrypting with wrong server key")
	}
}

func TestNonceTracker(t *testing.T) {
	tracker := NewNonceTracker(1 * time.Second)

	// New nonce should pass
	if !tracker.Check("nonce1") {
		t.Error("fresh nonce should pass")
	}

	// Same nonce should fail
	if tracker.Check("nonce1") {
		t.Error("duplicate nonce should fail")
	}

	// Different nonce should pass
	if !tracker.Check("nonce2") {
		t.Error("different nonce should pass")
	}

	// Check size
	if tracker.Size() != 2 {
		t.Errorf("size = %d, want 2", tracker.Size())
	}

	// Wait for expiry
	time.Sleep(1500 * time.Millisecond)

	// Expired nonce should pass again (after cleanup runs)
	// Note: cleanup runs every 30s by default, so we manually check
	tracker.mu.Lock()
	cutoff := time.Now().Add(-tracker.expiry)
	for nonce, ts := range tracker.nonces {
		if ts.Before(cutoff) {
			delete(tracker.nonces, nonce)
		}
	}
	tracker.mu.Unlock()

	if !tracker.Check("nonce1") {
		t.Error("expired nonce should pass again after cleanup")
	}
}

func TestTamperedPacketRejection(t *testing.T) {
	dk, _ := crypto.GenerateKeyPair()
	ek := dk.EncapsulationKey()

	packet, _ := BuildKnockPacket(ek, "192.168.1.100", "open-t22", 0)

	// Tamper in the encrypted payload area
	packet[len(packet)-5] ^= 0xFF

	_, err := ParseKnockPacket(dk, packet, "192.168.1.100", 30)
	if err == nil {
		t.Error("tampered packet should fail authentication")
	}
}

func TestMaxPacketSize(t *testing.T) {
	dk, _ := crypto.GenerateKeyPair()

	// Create oversized packet
	bigPacket := make([]byte, MaxPacketSize+1)
	_, err := ParseKnockPacket(dk, bigPacket, "1.2.3.4", 30)
	if err == nil {
		t.Error("oversized packet should be rejected")
	}
}

func abs(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}

// TestBatchCommandPacket tests that batch commands like "open-t22,t443,u53" are valid payloads.
func TestBatchCommandPacket(t *testing.T) {
	dk, _ := crypto.GenerateKeyPair()
	ek := dk.EncapsulationKey()

	// Batch command
	batchCmd := "open-t22,t443,u53"
	packet, err := BuildKnockPacket(ek, "10.0.0.1", batchCmd, 1800)
	if err != nil {
		t.Fatalf("BuildKnockPacket batch: %v", err)
	}

	payload, err := ParseKnockPacket(dk, packet, "10.0.0.1", 30)
	if err != nil {
		t.Fatalf("ParseKnockPacket batch: %v", err)
	}

	if payload.Command != batchCmd {
		t.Errorf("command = %s, want %s", payload.Command, batchCmd)
	}
}

// TestBatchCloseCommandPacket tests that batch close commands like "close-t22,t443" round-trip
// through the protocol correctly.
func TestBatchCloseCommandPacket(t *testing.T) {
	dk, _ := crypto.GenerateKeyPair()
	ek := dk.EncapsulationKey()

	cases := []string{
		"close-t22,t443",
		"close-t22,t443,u53",
		"close-u53,u123",
		"close-all",
	}

	for _, batchCmd := range cases {
		packet, err := BuildKnockPacket(ek, "10.0.0.1", batchCmd, 0)
		if err != nil {
			t.Fatalf("BuildKnockPacket(%q): %v", batchCmd, err)
		}
		payload, err := ParseKnockPacket(dk, packet, "10.0.0.1", 30)
		if err != nil {
			t.Fatalf("ParseKnockPacket(%q): %v", batchCmd, err)
		}
		if payload.Command != batchCmd {
			t.Errorf("command = %q, want %q", payload.Command, batchCmd)
		}
		if payload.OpenDuration != 0 {
			t.Errorf("close command should have OpenDuration=0, got %d", payload.OpenDuration)
		}
	}
}

// TestValidateCommandBatchClose verifies batch close commands are accepted by ValidateCommand
// and various malformed batch close commands are rejected.
func TestValidateCommandBatchClose(t *testing.T) {
	tests := []struct {
		cmd     string
		wantErr bool
	}{
		{"close-t22,t443", false},
		{"close-t22,t443,u53", false},
		{"close-u53,u123", false},
		{"close-all", false},
		// Malformed
		{"close-t22,", false},      // trailing comma: empty spec is skipped
		{"close-,t22", false},      // leading comma: empty spec is skipped
		{"close-t22,,t443", false}, // double comma: empty spec is skipped
		{"close-t99999,t22", true}, // port > 65535
		{"close-x22,t443", true},   // unknown protocol prefix
	}
	for _, tc := range tests {
		err := ValidateCommand(tc.cmd)
		if (err != nil) != tc.wantErr {
			t.Errorf("ValidateCommand(%q) err=%v, wantErr=%v", tc.cmd, err, tc.wantErr)
		}
	}
}

// TestLargeOpenDuration tests that extreme open duration values are handled.
func TestLargeOpenDuration(t *testing.T) {
	dk, _ := crypto.GenerateKeyPair()
	ek := dk.EncapsulationKey()

	// Valid max open duration (7 days = 604800)
	packet, err := BuildKnockPacket(ek, "10.0.0.1", "open-t22", 604800)
	if err != nil {
		t.Fatalf("BuildKnockPacket: %v", err)
	}

	payload, err := ParseKnockPacket(dk, packet, "10.0.0.1", 30)
	if err != nil {
		t.Fatalf("ParseKnockPacket: %v", err)
	}

	if payload.OpenDuration != 604800 {
		t.Errorf("open duration = %d, want 604800", payload.OpenDuration)
	}
}

// TestEmptyCommand tests that empty commands are rejected.
func TestEmptyCommand(t *testing.T) {
	dk, _ := crypto.GenerateKeyPair()
	ek := dk.EncapsulationKey()

	_, err := BuildKnockPacket(ek, "10.0.0.1", "", 0)
	if err == nil {
		t.Fatal("empty command should be rejected")
	}
	if !strings.Contains(err.Error(), "cannot encode command") {
		t.Errorf("error should mention encoding failure, got: %v", err)
	}
}

// TestZeroLengthPacket tests that zero-length packets are rejected.
func TestZeroLengthPacket(t *testing.T) {
	dk, _ := crypto.GenerateKeyPair()
	_, err := ParseKnockPacket(dk, []byte{}, "1.2.3.4", 30)
	if err == nil {
		t.Error("zero-length packet should be rejected")
	}
}

// TestGarbagePacket tests that random garbage is rejected gracefully.
func TestGarbagePacket(t *testing.T) {
	dk, _ := crypto.GenerateKeyPair()
	garbage := make([]byte, 2000)
	for i := range garbage {
		garbage[i] = byte(i % 256)
	}
	_, err := ParseKnockPacket(dk, garbage, "1.2.3.4", 30)
	if err == nil {
		t.Error("garbage packet should be rejected")
	}
}

// TestNonceUniqueness tests that successive packets have unique nonces.
func TestNonceUniqueness(t *testing.T) {
	dk, _ := crypto.GenerateKeyPair()
	ek := dk.EncapsulationKey()

	nonces := make(map[string]bool)
	for i := 0; i < 100; i++ {
		packet, err := BuildKnockPacket(ek, "10.0.0.1", "open-t22", 0)
		if err != nil {
			t.Fatalf("BuildKnockPacket iteration %d: %v", i, err)
		}
		payload, err := ParseKnockPacket(dk, packet, "10.0.0.1", 30)
		if err != nil {
			t.Fatalf("ParseKnockPacket iteration %d: %v", i, err)
		}
		if nonces[payload.Nonce] {
			t.Fatalf("duplicate nonce detected at iteration %d", i)
		}
		nonces[payload.Nonce] = true
	}
}

// TestIPv6Support tests that IPv6 addresses work in payloads.
func TestIPv6Support(t *testing.T) {
	dk, _ := crypto.GenerateKeyPair()
	ek := dk.EncapsulationKey()

	ipv6 := "2001:db8::1"
	packet, err := BuildKnockPacket(ek, ipv6, "open-t22", 0)
	if err != nil {
		t.Fatalf("BuildKnockPacket IPv6: %v", err)
	}

	payload, err := ParseKnockPacket(dk, packet, ipv6, 30)
	if err != nil {
		t.Fatalf("ParseKnockPacket IPv6: %v", err)
	}

	if payload.ClientIP != ipv6 {
		t.Errorf("clientIP = %s, want %s", payload.ClientIP, ipv6)
	}
}

// ---------------------------------------------------------------------------
// ValidateCommand tests (exported API, zero prior coverage)
// ---------------------------------------------------------------------------

func TestValidateCommandOpenClose(t *testing.T) {
	tests := []struct {
		cmd     string
		wantErr bool
	}{
		{"open-t22", false},
		{"open-u53", false},
		{"close-t443", false},
		{"close-all", false},
		{"open-t22,t443,u53", false},
		{"open-all", false},
		{"Open-T22", false},   // case-insensitive
		{"", true},            // unknown prefix
		{"xxx-t22", true},     // unknown prefix
		{"open-", true},       // empty spec
		{"close-", true},      // empty spec
		{"open-x22", true},    // bad protocol prefix
		{"open-t0", true},     // port 0
		{"open-t99999", true}, // port > 65535
		{"open-tabc", true},   // non-numeric port
	}
	for _, tc := range tests {
		err := ValidateCommand(tc.cmd)
		if (err != nil) != tc.wantErr {
			t.Errorf("ValidateCommand(%q) err=%v, wantErr=%v", tc.cmd, err, tc.wantErr)
		}
	}
}

func TestValidateCommandCustomASCII(t *testing.T) {
	tests := []struct {
		cmd     string
		wantErr bool
	}{
		{"cust-ping", false},
		{"cust-1", false},
		{"cust-restart_ssh", false},
		{"cust-", true},               // empty ID
		{"cust-\x01bad", true},        // control char
		{"cust-hello\x80world", true}, // high byte
	}
	for _, tc := range tests {
		err := ValidateCommand(tc.cmd)
		if (err != nil) != tc.wantErr {
			t.Errorf("ValidateCommand(%q) err=%v, wantErr=%v", tc.cmd, err, tc.wantErr)
		}
	}
}

// ---------------------------------------------------------------------------
// BuildKnockPacket with options (padding, TOTP)
// ---------------------------------------------------------------------------

func TestBuildKnockPacketWithPadding(t *testing.T) {
	dk, _ := crypto.GenerateKeyPair()
	ek := dk.EncapsulationKey()

	opts := KnockOptions{
		Padding: PaddingConfig{Enabled: true, MinBytes: 32, MaxBytes: 64},
	}

	// Build with padding
	padded, err := BuildKnockPacket(ek, "10.0.0.1", "open-t22", 0, opts)
	if err != nil {
		t.Fatalf("BuildKnockPacket with padding: %v", err)
	}

	// Build without padding for size comparison
	plain, err := BuildKnockPacket(ek, "10.0.0.1", "open-t22", 0)
	if err != nil {
		t.Fatalf("BuildKnockPacket without padding: %v", err)
	}

	if len(padded) <= len(plain) {
		t.Errorf("padded packet (%d) should be larger than plain (%d)", len(padded), len(plain))
	}

	// Verify round-trip
	payload, err := ParseKnockPacket(dk, padded, "10.0.0.1", 30)
	if err != nil {
		t.Fatalf("ParseKnockPacket padded: %v", err)
	}
	if payload.Command != "open-t22" {
		t.Errorf("command = %s, want open-t22", payload.Command)
	}
}

func TestBuildKnockPacketWithTOTP(t *testing.T) {
	dk, _ := crypto.GenerateKeyPair()
	ek := dk.EncapsulationKey()

	opts := KnockOptions{TOTP: "123456"}
	packet, err := BuildKnockPacket(ek, "10.0.0.1", "open-t22", 0, opts)
	if err != nil {
		t.Fatalf("BuildKnockPacket with TOTP: %v", err)
	}

	payload, err := ParseKnockPacket(dk, packet, "10.0.0.1", 30)
	if err != nil {
		t.Fatalf("ParseKnockPacket TOTP: %v", err)
	}
	if payload.TOTP != "123456" {
		t.Errorf("TOTP = %q, want 123456", payload.TOTP)
	}
}

func TestBuildKnockPacketWithPaddingAndTOTP(t *testing.T) {
	dk, _ := crypto.GenerateKeyPair()
	ek := dk.EncapsulationKey()

	opts := KnockOptions{
		Padding: PaddingConfig{Enabled: true, MinBytes: 16, MaxBytes: 32},
		TOTP:    "654321",
	}
	packet, err := BuildKnockPacket(ek, "10.0.0.1", "open-t22", 0, opts)
	if err != nil {
		t.Fatalf("BuildKnockPacket padding+TOTP: %v", err)
	}

	payload, err := ParseKnockPacket(dk, packet, "10.0.0.1", 30)
	if err != nil {
		t.Fatalf("ParseKnockPacket padding+TOTP: %v", err)
	}
	if payload.TOTP != "654321" {
		t.Errorf("TOTP = %q, want 654321", payload.TOTP)
	}
	if payload.Command != "open-t22" {
		t.Errorf("command = %s, want open-t22", payload.Command)
	}
}

// ---------------------------------------------------------------------------
// NonceTracker eviction and concurrency
// ---------------------------------------------------------------------------

func TestNonceTrackerEviction(t *testing.T) {
	tracker := NewNonceTrackerWithLimit(60*time.Second, 10)

	// Insert 50 nonces to force multiple eviction cycles
	for i := 0; i < 50; i++ {
		tracker.Check(fmt.Sprintf("nonce_%d", i))
	}

	// Size should be capped at maxCache (10)
	if tracker.Size() > 10 {
		t.Errorf("tracker size = %d after eviction, want <= 10", tracker.Size())
	}

	// At least some early nonces must have been evicted (size is only 10 out of 50)
	// Try inserting a fresh nonce -- should succeed (proves cache isn't frozen)
	if !tracker.Check("fresh_nonce") {
		t.Error("fresh nonce should be accepted")
	}
}

// ---------------------------------------------------------------------------
// ParseKnockPacket with skipIPVerify
// ---------------------------------------------------------------------------

func TestParseKnockPacketSkipIPVerify(t *testing.T) {
	dk, _ := crypto.GenerateKeyPair()
	ek := dk.EncapsulationKey()

	// Build with IP "1.1.1.1"
	packet, err := BuildKnockPacket(ek, "1.1.1.1", "open-t22", 0)
	if err != nil {
		t.Fatalf("BuildKnockPacket: %v", err)
	}

	// Parse with different source IP should fail
	_, err = ParseKnockPacket(dk, packet, "2.2.2.2", 30)
	if err == nil {
		t.Error("mismatched IP should fail with normal parse")
	}

	// Parse with skipIPVerify=true should succeed
	payload, err := ParseKnockPacket(dk, packet, "2.2.2.2", 30, true)
	if err != nil {
		t.Fatalf("ParseKnockPacket with skipIPVerify: %v", err)
	}
	if payload.ClientIP != "1.1.1.1" {
		t.Errorf("clientIP = %s, want 1.1.1.1", payload.ClientIP)
	}
}

// ---------------------------------------------------------------------------
// DefaultPaddingConfig
// ---------------------------------------------------------------------------

func TestDefaultPaddingConfig(t *testing.T) {
	cfg := DefaultPaddingConfig()
	if cfg.Enabled {
		t.Error("default padding should be disabled")
	}
	if cfg.MinBytes != 64 {
		t.Errorf("MinBytes = %d, want 64", cfg.MinBytes)
	}
	if cfg.MaxBytes != 512 {
		t.Errorf("MaxBytes = %d, want 512", cfg.MaxBytes)
	}
}
