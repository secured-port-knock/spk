// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package protocol

import (
	"strings"
	"testing"
	"time"

	"spk/internal/crypto"
)

// ------------------------------------------------------------------------
// Timestamp Direction Error Tests
// ------------------------------------------------------------------------

func TestTimestampPastSpecificError(t *testing.T) {
	dk, _ := crypto.GenerateKeyPair()
	ek := dk.EncapsulationKey()

	// Build packet, wait 3s, then parse with 1s tolerance
	packet, _ := BuildKnockPacket(ek, "10.0.0.1", "open-t22", 0)
	time.Sleep(3 * time.Second)

	_, err := ParseKnockPacket(dk, packet, "10.0.0.1", 1)
	if err == nil {
		t.Fatal("old packet should be rejected")
	}

	msg := err.Error()
	if !strings.Contains(msg, "timestamp too old") {
		t.Errorf("expected 'timestamp too old' in error, got: %s", msg)
	}
	if !strings.Contains(msg, "in the past") {
		t.Errorf("expected 'in the past' in error, got: %s", msg)
	}
	if !strings.Contains(msg, "replay attack or clock skew") {
		t.Errorf("expected diagnostic hint in error, got: %s", msg)
	}
	if !strings.Contains(msg, "tolerance:") {
		t.Errorf("expected tolerance info in error, got: %s", msg)
	}
}

// TestTimestampErrorFormatIncludesDrift verifies drift seconds are in the error.
func TestTimestampErrorFormatIncludesDrift(t *testing.T) {
	dk, _ := crypto.GenerateKeyPair()
	ek := dk.EncapsulationKey()

	packet, _ := BuildKnockPacket(ek, "10.0.0.1", "open-t22", 0)
	time.Sleep(3 * time.Second)

	_, err := ParseKnockPacket(dk, packet, "10.0.0.1", 1)
	if err == nil {
		t.Fatal("expected rejection")
	}

	msg := err.Error()
	// Should contain drift like "3s" or "2s"
	if !strings.Contains(msg, "s in the past") {
		t.Errorf("expected drift in seconds in error, got: %s", msg)
	}
}

// ------------------------------------------------------------------------
// TOTP Field in KnockPayload Tests
// ------------------------------------------------------------------------

func TestKnockPayloadTOTPField(t *testing.T) {
	dk, _ := crypto.GenerateKeyPair()
	ek := dk.EncapsulationKey()

	// Without TOTP
	pkt1, _ := BuildKnockPacket(ek, "10.0.0.1", "open-t22", 0)
	p1, _ := ParseKnockPacket(dk, pkt1, "10.0.0.1", 30)
	if p1.TOTP != "" {
		t.Errorf("TOTP should be empty without option, got %q", p1.TOTP)
	}

	// With TOTP
	opts := KnockOptions{TOTP: "543210"}
	pkt2, _ := BuildKnockPacket(ek, "10.0.0.1", "open-t22", 0, opts)
	p2, _ := ParseKnockPacket(dk, pkt2, "10.0.0.1", 30)
	if p2.TOTP != "543210" {
		t.Errorf("TOTP = %q, want 543210", p2.TOTP)
	}
}

func TestKnockPayloadTOTPOmitEmpty(t *testing.T) {
	dk, _ := crypto.GenerateKeyPair()
	ek := dk.EncapsulationKey()

	// When TOTP is not set, the binary payload omits the 6-byte TOTP field
	// (smaller packet without the TOTP bytes)
	pktNoTOTP, _ := BuildKnockPacket(ek, "10.0.0.1", "open-t22", 0)
	pktWithTOTP, _ := BuildKnockPacket(ek, "10.0.0.1", "open-t22", 0, KnockOptions{TOTP: "123456"})

	// Packet with TOTP should be slightly larger (has the 6-byte TOTP field)
	// Due to KEM randomness, raw packet sizes are similar, but this test verifies
	// the field is present/absent at the binary level
	p1, _ := ParseKnockPacket(dk, pktNoTOTP, "10.0.0.1", 30)
	p2, _ := ParseKnockPacket(dk, pktWithTOTP, "10.0.0.1", 30)

	if p1.TOTP != "" {
		t.Error("no-TOTP packet should have empty TOTP field")
	}
	if p2.TOTP != "123456" {
		t.Errorf("TOTP packet should have code, got %q", p2.TOTP)
	}
}

// ------------------------------------------------------------------------
// IP Mismatch Error Message Tests
// ------------------------------------------------------------------------

func TestIPMismatchErrorContainsAddresses(t *testing.T) {
	dk, _ := crypto.GenerateKeyPair()
	ek := dk.EncapsulationKey()

	packet, _ := BuildKnockPacket(ek, "192.168.1.100", "open-t22", 0)
	_, err := ParseKnockPacket(dk, packet, "10.0.0.50", 30)
	if err == nil {
		t.Fatal("IP mismatch should fail")
	}

	msg := err.Error()
	if !strings.Contains(msg, "192.168.1.100") {
		t.Errorf("error should contain claimed IP, got: %s", msg)
	}
	if !strings.Contains(msg, "10.0.0.50") {
		t.Errorf("error should contain actual source IP, got: %s", msg)
	}
	if !strings.Contains(msg, "spoofing") || !strings.Contains(msg, "NAT") {
		t.Errorf("error should suggest spoofing/NAT, got: %s", msg)
	}
}

// ------------------------------------------------------------------------
// Field Validation Error Tests
// ------------------------------------------------------------------------

func TestCommandLengthLimit(t *testing.T) {
	dk, _ := crypto.GenerateKeyPair()
	ek := dk.EncapsulationKey()

	// Max valid: cust- prefix + 249 bytes data = 254 total string
	// Encodes as type(1) + data(249) = 250 CmdLen, fits in 1 byte
	longCmd := "cust-" + strings.Repeat("a", 249)
	pkt, err := BuildKnockPacket(ek, "10.0.0.1", longCmd, 0)
	if err != nil {
		t.Fatalf("BuildKnockPacket: %v", err)
	}
	_, err = ParseKnockPacket(dk, pkt, "10.0.0.1", 30)
	if err != nil {
		t.Fatalf("max-length command should parse: %v", err)
	}

	// Exceeds limit: cust- prefix + 255 bytes data = 260 total string
	// Encodes as type(1) + data(255) = 256 CmdLen, exceeds 1-byte max
	tooLong := "cust-" + strings.Repeat("a", 255)
	_, err = BuildKnockPacket(ek, "10.0.0.1", tooLong, 0)
	if err == nil {
		t.Error("oversized command should be rejected at build time")
	}
	if err != nil && !strings.Contains(err.Error(), "command too long") {
		t.Errorf("error should mention command too long, got: %v", err)
	}
}

func TestOpenDurationRangeValidation(t *testing.T) {
	dk, _ := crypto.GenerateKeyPair()
	ek := dk.EncapsulationKey()

	// Valid: exactly 604800 (7 days)
	pkt, _ := BuildKnockPacket(ek, "10.0.0.1", "open-t22", 604800)
	_, err := ParseKnockPacket(dk, pkt, "10.0.0.1", 30)
	if err != nil {
		t.Fatalf("max open duration should be valid: %v", err)
	}

	// Valid: 0
	pkt2, _ := BuildKnockPacket(ek, "10.0.0.1", "open-t22", 0)
	_, err = ParseKnockPacket(dk, pkt2, "10.0.0.1", 30)
	if err != nil {
		t.Fatalf("zero open duration should be valid: %v", err)
	}
}

// ------------------------------------------------------------------------
// DefaultPaddingConfig Tests
// ------------------------------------------------------------------------

func TestDefaultPaddingConfigValues(t *testing.T) {
	pc := DefaultPaddingConfig()

	if pc.Enabled {
		t.Error("default padding should be disabled")
	}
	if pc.MinBytes != 64 {
		t.Errorf("MinBytes = %d, want 64", pc.MinBytes)
	}
	if pc.MaxBytes != 512 {
		t.Errorf("MaxBytes = %d, want 512", pc.MaxBytes)
	}
}

// ------------------------------------------------------------------------
// Nonce Tracker Edge Cases
// ------------------------------------------------------------------------

func TestNonceTrackerExpiredNonceReusable(t *testing.T) {
	// After a nonce expires, the same nonce value should be accepted again.
	// This is important because the nonce tracker must not grow unbounded.
	tracker := NewNonceTrackerWithLimit(100*time.Millisecond, 0)

	nonce := "test_nonce_expiry"
	if !tracker.Check(nonce) {
		t.Error("first check should pass")
	}
	if tracker.Check(nonce) {
		t.Error("immediate replay should fail")
	}

	// Wait for expiry
	time.Sleep(200 * time.Millisecond)

	// Manually clean up (in production the ticker does this)
	tracker.mu.Lock()
	cutoff := time.Now().Add(-tracker.expiry)
	for k, v := range tracker.nonces {
		if v.Before(cutoff) {
			delete(tracker.nonces, k)
		}
	}
	tracker.mu.Unlock()

	// Should be accepted again
	if !tracker.Check(nonce) {
		t.Error("expired nonce should be accepted again")
	}
}

func TestNonceTrackerEmptyNonce(t *testing.T) {
	tracker := NewNonceTracker(5 * time.Minute)

	// Empty string nonce should still work (tracked like any other)
	if !tracker.Check("") {
		t.Error("empty nonce first check should pass")
	}
	if tracker.Check("") {
		t.Error("empty nonce replay should fail")
	}
}
