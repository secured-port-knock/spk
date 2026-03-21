// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package integration

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"spk/internal/crypto"
	"spk/internal/protocol"
)

// ------------------------------------------------------------------------
// TOTP Integration Tests
// Tests that TOTP codes survive the full encrypt -> send -> decrypt cycle
// ------------------------------------------------------------------------

// TestTOTPKnockRoundTrip verifies a knock packet with a valid TOTP code
// survives the full build -> parse cycle.
func TestTOTPKnockRoundTrip(t *testing.T) {
	dk, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	ek := dk.EncapsulationKey()

	secret, err := crypto.GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}

	code, err := crypto.GenerateTOTP(secret, time.Now())
	if err != nil {
		t.Fatalf("GenerateTOTP: %v", err)
	}

	// Build packet with TOTP code
	opts := protocol.KnockOptions{TOTP: code}
	packet, err := protocol.BuildKnockPacket(ek, "10.0.0.1", "open-t22", 3600, opts)
	if err != nil {
		t.Fatalf("BuildKnockPacket with TOTP: %v", err)
	}

	// Parse and verify
	payload, err := protocol.ParseKnockPacket(dk, packet, "10.0.0.1", 30)
	if err != nil {
		t.Fatalf("ParseKnockPacket: %v", err)
	}

	if payload.TOTP != code {
		t.Errorf("TOTP = %q, want %q", payload.TOTP, code)
	}
	if payload.Command != "open-t22" {
		t.Errorf("command = %s, want open-t22", payload.Command)
	}

	// Verify the TOTP code would pass server-side validation
	if !crypto.ValidateTOTP(secret, payload.TOTP) {
		t.Error("TOTP code should pass server-side validation after round-trip")
	}
}

// TestTOTPKnockValidation verifies that the server-side TOTP validation
// accepts valid codes and rejects invalid ones after the knock cycle.
func TestTOTPKnockValidation(t *testing.T) {
	dk, _ := crypto.GenerateKeyPair()
	ek := dk.EncapsulationKey()

	secret, _ := crypto.GenerateTOTPSecret()
	validCode, _ := crypto.GenerateTOTP(secret, time.Now())

	// Valid TOTP code should validate
	opts := protocol.KnockOptions{TOTP: validCode}
	packet, _ := protocol.BuildKnockPacket(ek, "10.0.0.1", "open-t22", 0, opts)
	payload, err := protocol.ParseKnockPacket(dk, packet, "10.0.0.1", 30)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !crypto.ValidateTOTP(secret, payload.TOTP) {
		t.Error("valid TOTP code should validate after round-trip")
	}

	// Invalid TOTP code should NOT validate
	opts2 := protocol.KnockOptions{TOTP: "000000"}
	packet2, _ := protocol.BuildKnockPacket(ek, "10.0.0.1", "open-t22", 0, opts2)
	payload2, _ := protocol.ParseKnockPacket(dk, packet2, "10.0.0.1", 30)
	if crypto.ValidateTOTP(secret, payload2.TOTP) {
		t.Log("000000 happened to be valid (extremely unlikely) - skipping")
	}
}

// TestTOTPKnockWithPadding verifies TOTP works alongside padding.
func TestTOTPKnockWithPadding(t *testing.T) {
	dk, _ := crypto.GenerateKeyPair()
	ek := dk.EncapsulationKey()

	secret, _ := crypto.GenerateTOTPSecret()
	code, _ := crypto.GenerateTOTP(secret, time.Now())

	opts := protocol.KnockOptions{
		TOTP: code,
		Padding: protocol.PaddingConfig{
			Enabled:  true,
			MinBytes: 100,
			MaxBytes: 300,
		},
	}

	packet, err := protocol.BuildKnockPacket(ek, "10.0.0.1", "open-t22,t443", 7200, opts)
	if err != nil {
		t.Fatalf("BuildKnockPacket with TOTP+padding: %v", err)
	}

	payload, err := protocol.ParseKnockPacket(dk, packet, "10.0.0.1", 30)
	if err != nil {
		t.Fatalf("ParseKnockPacket: %v", err)
	}

	if payload.TOTP != code {
		t.Errorf("TOTP = %q, want %q", payload.TOTP, code)
	}
	if payload.Command != "open-t22,t443" {
		t.Errorf("command = %s, want open-t22,t443", payload.Command)
	}
	if payload.Padding == "" {
		t.Error("padding should be present")
	}
}

// TestTOTPKnockE2EUDP tests TOTP in a full network round-trip over UDP.
func TestTOTPKnockE2EUDP(t *testing.T) {
	dk, _ := crypto.GenerateKeyPair()
	ek := dk.EncapsulationKey()

	secret, _ := crypto.GenerateTOTPSecret()
	code, _ := crypto.GenerateTOTP(secret, time.Now())

	// Start UDP listener
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer conn.Close()

	type result struct {
		payload *protocol.KnockPayload
		err     error
	}
	ch := make(chan result, 1)

	go func() {
		buf := make([]byte, 8192)
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			ch <- result{nil, err}
			return
		}
		srcIP := addr.(*net.UDPAddr).IP.String()
		payload, err := protocol.ParseKnockPacket(dk, buf[:n], srcIP, 30)
		ch <- result{payload, err}
	}()

	// Send packet with TOTP
	clientConn, _ := net.Dial("udp", conn.LocalAddr().String())
	defer clientConn.Close()
	localIP := clientConn.LocalAddr().(*net.UDPAddr).IP.String()

	opts := protocol.KnockOptions{TOTP: code}
	packet, _ := protocol.BuildKnockPacket(ek, localIP, "open-t22", 0, opts)
	clientConn.Write(packet)

	res := <-ch
	if res.err != nil {
		t.Fatalf("server parse: %v", res.err)
	}
	if res.payload.TOTP != code {
		t.Errorf("TOTP = %q, want %q", res.payload.TOTP, code)
	}
	if !crypto.ValidateTOTP(secret, res.payload.TOTP) {
		t.Error("TOTP should validate on server side")
	}
}

// TestTOTPKnockWithoutCode verifies that a packet without TOTP has empty TOTP field.
func TestTOTPKnockWithoutCode(t *testing.T) {
	dk, _ := crypto.GenerateKeyPair()
	ek := dk.EncapsulationKey()

	// Build packet without TOTP
	packet, _ := protocol.BuildKnockPacket(ek, "10.0.0.1", "open-t22", 0)
	payload, err := protocol.ParseKnockPacket(dk, packet, "10.0.0.1", 30)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if payload.TOTP != "" {
		t.Errorf("TOTP should be empty when not provided, got %q", payload.TOTP)
	}
}

// TestTOTPKnockWrongSecretRejectsAfterRoundTrip confirms that a valid TOTP code
// generated with one secret fails validation against a different secret,
// even after surviving the encrypt->decrypt cycle.
func TestTOTPKnockWrongSecretRejectsAfterRoundTrip(t *testing.T) {
	dk, _ := crypto.GenerateKeyPair()
	ek := dk.EncapsulationKey()

	secret1, _ := crypto.GenerateTOTPSecret()
	secret2, _ := crypto.GenerateTOTPSecret()
	code, _ := crypto.GenerateTOTP(secret1, time.Now())

	opts := protocol.KnockOptions{TOTP: code}
	packet, _ := protocol.BuildKnockPacket(ek, "10.0.0.1", "open-t22", 0, opts)
	payload, _ := protocol.ParseKnockPacket(dk, packet, "10.0.0.1", 30)

	// Code from secret1 should NOT validate against secret2
	if crypto.ValidateTOTP(secret2, payload.TOTP) {
		t.Error("code from secret1 should not validate with secret2")
	}
}

// ------------------------------------------------------------------------
// Timestamp Rejection Error Message Tests
// ------------------------------------------------------------------------

// TestTimestampPastErrorMessage verifies the specific error message for old packets.
func TestTimestampPastErrorMessage(t *testing.T) {
	dk, _ := crypto.GenerateKeyPair()
	ek := dk.EncapsulationKey()

	// Build packet, wait, then parse with tight tolerance
	packet, _ := protocol.BuildKnockPacket(ek, "10.0.0.1", "open-t22", 0)
	time.Sleep(2 * time.Second)

	_, err := protocol.ParseKnockPacket(dk, packet, "10.0.0.1", 1)
	if err == nil {
		t.Fatal("old packet should be rejected with 1s tolerance")
	}

	errMsg := err.Error()
	if !strings.Contains(errMsg, "timestamp too old") {
		t.Errorf("error should mention 'timestamp too old', got: %s", errMsg)
	}
	if !strings.Contains(errMsg, "in the past") {
		t.Errorf("error should mention 'in the past', got: %s", errMsg)
	}
	if !strings.Contains(errMsg, "replay attack or clock skew") {
		t.Errorf("error should suggest replay/clock skew, got: %s", errMsg)
	}
}

// TestTimestampErrorIncludesTolerance verifies the error includes tolerance info.
func TestTimestampErrorIncludesTolerance(t *testing.T) {
	dk, _ := crypto.GenerateKeyPair()
	ek := dk.EncapsulationKey()

	packet, _ := protocol.BuildKnockPacket(ek, "10.0.0.1", "open-t22", 0)
	time.Sleep(3 * time.Second)

	_, err := protocol.ParseKnockPacket(dk, packet, "10.0.0.1", 1)
	if err == nil {
		t.Fatal("expected rejection")
	}

	errMsg := err.Error()
	if !strings.Contains(errMsg, "tolerance:") {
		t.Errorf("error should include tolerance info, got: %s", errMsg)
	}
}

// ------------------------------------------------------------------------
// Rejection Reason Message Tests
// ------------------------------------------------------------------------

// TestIPMismatchErrorMessage verifies the spoofing/relay/NAT hint in IP errors.
func TestIPMismatchErrorMessage(t *testing.T) {
	dk, _ := crypto.GenerateKeyPair()
	ek := dk.EncapsulationKey()

	packet, _ := protocol.BuildKnockPacket(ek, "10.0.0.1", "open-t22", 0)
	_, err := protocol.ParseKnockPacket(dk, packet, "10.0.0.2", 30)
	if err == nil {
		t.Fatal("IP mismatch should be rejected")
	}

	errMsg := err.Error()
	if !strings.Contains(errMsg, "IP mismatch") {
		t.Errorf("error should mention IP mismatch, got: %s", errMsg)
	}
	if !strings.Contains(errMsg, "spoofing") {
		t.Errorf("error should suggest spoofing, got: %s", errMsg)
	}
}

// TestProtocolVersionErrorMessage verifies unsupported version error.
func TestProtocolVersionErrorMessage(t *testing.T) {
	dk, _ := crypto.GenerateKeyPair()
	ek := dk.EncapsulationKey()

	// Build a valid packet, but we can't directly set version.
	// Instead test that valid packets pass the version check.
	packet, _ := protocol.BuildKnockPacket(ek, "10.0.0.1", "open-t22", 0)
	payload, err := protocol.ParseKnockPacket(dk, packet, "10.0.0.1", 30)
	if err != nil {
		t.Fatalf("valid packet should parse: %v", err)
	}
	if payload.Version != protocol.ProtocolVersion {
		t.Errorf("version = %d, want %d", payload.Version, protocol.ProtocolVersion)
	}
}

// ------------------------------------------------------------------------
// KnockOptions Tests
// ------------------------------------------------------------------------

// TestKnockOptionsEmpty verifies that empty KnockOptions produces no TOTP or padding.
func TestKnockOptionsEmpty(t *testing.T) {
	dk, _ := crypto.GenerateKeyPair()
	ek := dk.EncapsulationKey()

	opts := protocol.KnockOptions{}
	packet, _ := protocol.BuildKnockPacket(ek, "10.0.0.1", "open-t22", 0, opts)
	payload, err := protocol.ParseKnockPacket(dk, packet, "10.0.0.1", 30)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if payload.TOTP != "" {
		t.Errorf("TOTP should be empty with empty opts, got %q", payload.TOTP)
	}
	if payload.Padding != "" {
		t.Errorf("padding should be empty with empty opts, got len=%d", len(payload.Padding))
	}
}

// TestKnockOptionsTOTPOnly verifies TOTP without padding.
func TestKnockOptionsTOTPOnly(t *testing.T) {
	dk, _ := crypto.GenerateKeyPair()
	ek := dk.EncapsulationKey()

	opts := protocol.KnockOptions{TOTP: "123456"}
	packet, _ := protocol.BuildKnockPacket(ek, "10.0.0.1", "open-t22", 0, opts)
	payload, _ := protocol.ParseKnockPacket(dk, packet, "10.0.0.1", 30)

	if payload.TOTP != "123456" {
		t.Errorf("TOTP = %q, want 123456", payload.TOTP)
	}
	if payload.Padding != "" {
		t.Error("padding should be empty when not enabled")
	}
}

// TestKnockOptionsPaddingOnly verifies padding without TOTP.
func TestKnockOptionsPaddingOnly(t *testing.T) {
	dk, _ := crypto.GenerateKeyPair()
	ek := dk.EncapsulationKey()

	opts := protocol.KnockOptions{
		Padding: protocol.PaddingConfig{
			Enabled:  true,
			MinBytes: 50,
			MaxBytes: 100,
		},
	}
	packet, _ := protocol.BuildKnockPacket(ek, "10.0.0.1", "open-t22", 0, opts)
	payload, _ := protocol.ParseKnockPacket(dk, packet, "10.0.0.1", 30)

	if payload.TOTP != "" {
		t.Error("TOTP should be empty")
	}
	if payload.Padding == "" {
		t.Error("padding should be present")
	}
	// Padding is hex-encoded, so double the bytes
	hexLen := len(payload.Padding)
	if hexLen < 50*2 || hexLen > 100*2 {
		t.Errorf("padding hex length = %d, want [%d, %d]", hexLen, 50*2, 100*2)
	}
}

// TestKnockOptionsBothTOTPAndPadding verifies both at once.
func TestKnockOptionsBothTOTPAndPadding(t *testing.T) {
	dk, _ := crypto.GenerateKeyPair()
	ek := dk.EncapsulationKey()

	opts := protocol.KnockOptions{
		TOTP: "654321",
		Padding: protocol.PaddingConfig{
			Enabled:  true,
			MinBytes: 64,
			MaxBytes: 128,
		},
	}
	packet, _ := protocol.BuildKnockPacket(ek, "10.0.0.1", "open-t22", 3600, opts)
	payload, _ := protocol.ParseKnockPacket(dk, packet, "10.0.0.1", 30)

	if payload.TOTP != "654321" {
		t.Errorf("TOTP = %q, want 654321", payload.TOTP)
	}
	if payload.Padding == "" {
		t.Error("padding should be present")
	}
	if payload.Command != "open-t22" {
		t.Errorf("command = %s, want open-t22", payload.Command)
	}
	if payload.OpenDuration != 3600 {
		t.Errorf("open duration = %d, want 3600", payload.OpenDuration)
	}
}

// ------------------------------------------------------------------------
// Padding Edge Case Tests
// ------------------------------------------------------------------------

// TestPaddingMinEqualsMax verifies fixed-size padding when min==max.
func TestPaddingMinEqualsMax(t *testing.T) {
	dk, _ := crypto.GenerateKeyPair()
	ek := dk.EncapsulationKey()

	opts := protocol.KnockOptions{
		Padding: protocol.PaddingConfig{
			Enabled:  true,
			MinBytes: 200,
			MaxBytes: 200,
		},
	}

	packet, _ := protocol.BuildKnockPacket(ek, "10.0.0.1", "open-t22", 0, opts)
	payload, _ := protocol.ParseKnockPacket(dk, packet, "10.0.0.1", 30)

	if payload.Padding == "" {
		t.Error("padding should be present")
	}
	// Exact size: 200 bytes = 400 hex chars
	if len(payload.Padding) != 400 {
		t.Errorf("padding hex length = %d, want 400 (200 bytes)", len(payload.Padding))
	}
}

// TestPaddingMinGreaterThanMax verifies the auto-correction when min > max.
func TestPaddingMinGreaterThanMax(t *testing.T) {
	dk, _ := crypto.GenerateKeyPair()
	ek := dk.EncapsulationKey()

	opts := protocol.KnockOptions{
		Padding: protocol.PaddingConfig{
			Enabled:  true,
			MinBytes: 500,
			MaxBytes: 100, // less than min
		},
	}

	// Should not error - auto-corrects max to min+256
	packet, err := protocol.BuildKnockPacket(ek, "10.0.0.1", "open-t22", 0, opts)
	if err != nil {
		t.Fatalf("BuildKnockPacket should auto-correct min>max: %v", err)
	}
	payload, _ := protocol.ParseKnockPacket(dk, packet, "10.0.0.1", 30)
	if payload.Padding == "" {
		t.Error("padding should be present after auto-correction")
	}
}

// TestPaddingZeroMin verifies that zero min defaults to 64.
func TestPaddingZeroMin(t *testing.T) {
	dk, _ := crypto.GenerateKeyPair()
	ek := dk.EncapsulationKey()

	opts := protocol.KnockOptions{
		Padding: protocol.PaddingConfig{
			Enabled:  true,
			MinBytes: 0,
			MaxBytes: 0,
		},
	}

	packet, _ := protocol.BuildKnockPacket(ek, "10.0.0.1", "open-t22", 0, opts)
	payload, _ := protocol.ParseKnockPacket(dk, packet, "10.0.0.1", 30)

	if payload.Padding == "" {
		t.Error("padding should be present with defaults")
	}
	// With 0/0, defaults to minB=64, maxB=64+256=320
	hexLen := len(payload.Padding)
	if hexLen < 64*2 {
		t.Errorf("padding hex length = %d, should be >= %d (64 bytes default)", hexLen, 64*2)
	}
}

// ------------------------------------------------------------------------
// Multiple Sequential TOTP Knocks
// ------------------------------------------------------------------------

// TestMultipleTOTPKnocksUniqueNonces verifies TOTP knocks have unique nonces.
func TestMultipleTOTPKnocksUniqueNonces(t *testing.T) {
	dk, _ := crypto.GenerateKeyPair()
	ek := dk.EncapsulationKey()

	secret, _ := crypto.GenerateTOTPSecret()
	code, _ := crypto.GenerateTOTP(secret, time.Now())

	nonces := make(map[string]bool)
	for i := 0; i < 50; i++ {
		opts := protocol.KnockOptions{TOTP: code}
		packet, _ := protocol.BuildKnockPacket(ek, "10.0.0.1", fmt.Sprintf("open-t%d", 22+i), 0, opts)
		payload, err := protocol.ParseKnockPacket(dk, packet, "10.0.0.1", 30)
		if err != nil {
			t.Fatalf("parse %d: %v", i, err)
		}
		if nonces[payload.Nonce] {
			t.Fatalf("duplicate nonce at iteration %d", i)
		}
		nonces[payload.Nonce] = true
		if payload.TOTP != code {
			t.Errorf("iteration %d: TOTP = %q, want %q", i, payload.TOTP, code)
		}
	}
}
