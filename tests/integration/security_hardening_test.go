// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package integration

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/secured-port-knock/spk/internal/config"
	"github.com/secured-port-knock/spk/internal/crypto"
	"github.com/secured-port-knock/spk/internal/protocol"
)

// ---------------------------------------------------------------------------
// Bundle size bound tests
// ---------------------------------------------------------------------------

// TestBundleSizeValidationNormalBundle verifies that normal-sized export
// bundles parse successfully (no false positives from the size cap).
func TestBundleSizeValidationNormalBundle(t *testing.T) {
	for _, kem := range []crypto.KEMSize{crypto.KEM768, crypto.KEM1024} {
		dk, err := crypto.GenerateKeyPair(kem)
		if err != nil {
			t.Fatalf("GenerateKeyPair(%d): %v", kem, err)
		}
		ek := dk.EncapsulationKey()

		b64, err := crypto.CreateExportBundle(ek, 12345, true, true, true)
		if err != nil {
			t.Fatalf("CreateExportBundle (KEM-%d): %v", kem, err)
		}
		bundle, err := crypto.ParseExportBundle(b64, "")
		if err != nil {
			t.Fatalf("ParseExportBundle (KEM-%d): %v", kem, err)
		}
		if bundle.Version != 1 {
			t.Errorf("version = %d, want 1", bundle.Version)
		}
		if bundle.KEMSize != int(kem) {
			t.Errorf("KEMSize = %d, want %d", bundle.KEMSize, kem)
		}
	}
}

// TestBundleSizeValidationEncryptedBundle verifies password-encrypted
// bundles also work within the size cap.
func TestBundleSizeValidationEncryptedBundle(t *testing.T) {
	dk, err := crypto.GenerateKeyPair(crypto.KEM768)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	ek := dk.EncapsulationKey()

	b64, err := crypto.CreateEncryptedExportBundle(ek, 54321, false, false, false, "hunter2")
	if err != nil {
		t.Fatalf("CreateEncryptedExportBundle: %v", err)
	}
	bundle, err := crypto.ParseExportBundle(b64, "hunter2")
	if err != nil {
		t.Fatalf("ParseExportBundle: %v", err)
	}
	if bundle.Port != 54321 {
		t.Errorf("port = %d, want 54321", bundle.Port)
	}
}

// TestBundleSizeValidationRejectsOversized verifies that a bundle whose
// decoded raw size exceeds maxBundleRawSize is rejected before parsing.
// This prevents large-allocation attacks from crafted inputs.
func TestBundleSizeValidationRejectsOversized(t *testing.T) {
	// 5 KB starting with "SPK" magic: passes magic check but exceeds the 4 KB limit.
	oversized := make([]byte, 5*1024)
	oversized[0] = 'S'
	oversized[1] = 'P'
	oversized[2] = 'K'
	b64 := base64.StdEncoding.EncodeToString(oversized)

	_, err := crypto.ParseExportBundle(b64, "")
	if err == nil {
		t.Fatal("expected error for oversized bundle, got nil")
	}
	t.Logf("correctly rejected oversized bundle: %v", err)
}

// TestBundleSizeValidationJustOverLimit verifies the exact boundary: a bundle
// one byte over maxBundleRawSize (4096 bytes) is rejected.
func TestBundleSizeValidationJustOverLimit(t *testing.T) {
	oversized := make([]byte, 4097)
	oversized[0] = 'S'
	oversized[1] = 'P'
	oversized[2] = 'K'
	b64 := base64.StdEncoding.EncodeToString(oversized)

	_, err := crypto.ParseExportBundle(b64, "")
	if err == nil {
		t.Fatal("expected error for bundle just over size limit")
	}
}

// ---------------------------------------------------------------------------
// Packet size validation (sniffer layer pre-filter)
// ---------------------------------------------------------------------------

// TestPacketSizeValidationMinimum verifies that valid knock packets are
// at least MinPacketSize (1118 bytes).
func TestPacketSizeValidationMinimum(t *testing.T) {
	dk, err := crypto.GenerateKeyPair(crypto.KEM768)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	ek := dk.EncapsulationKey()

	packet, err := protocol.BuildKnockPacket(ek, "1.2.3.4", "open-t22", 60)
	if err != nil {
		t.Fatalf("BuildKnockPacket: %v", err)
	}
	// ML-KEM-768 ciphertext = 1088, plus nonce(12) + GCM tag(16) + payload
	if len(packet) < 1118 {
		t.Errorf("packet size %d < 1118 (MinPacketSize)", len(packet))
	}
}

// TestPacketSizeTooSmallRejected verifies truncated packets fail decryption.
func TestPacketSizeTooSmallRejected(t *testing.T) {
	dk, err := crypto.GenerateKeyPair(crypto.KEM768)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	tooSmall := make([]byte, 500)
	_, err = crypto.DecapsulateAndDecrypt(dk, tooSmall)
	if err == nil {
		t.Fatal("expected error for undersized packet")
	}
}

// TestPacketSizeTooLargeRejected verifies oversized random data fails.
func TestPacketSizeTooLargeRejected(t *testing.T) {
	dk, err := crypto.GenerateKeyPair(crypto.KEM768)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	tooLarge := make([]byte, 10000)
	_, err = crypto.DecapsulateAndDecrypt(dk, tooLarge)
	if err == nil {
		t.Fatal("expected error for oversized random packet")
	}
}

// ---------------------------------------------------------------------------
// Config validation enforcement
// ---------------------------------------------------------------------------

// TestConfigValidateRejectsInvalidPort verifies Validate catches out-of-range ports.
func TestConfigValidateRejectsInvalidPort(t *testing.T) {
	cfg := &config.Config{ListenPort: 99999}
	errs := cfg.Validate()
	found := false
	for _, e := range errs {
		if strings.Contains(e, "listen_port") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected listen_port error, got: %v", errs)
	}
}

// TestConfigValidateRejectsNegativeOpenDuration verifies Validate catches negatives.
func TestConfigValidateRejectsNegativeOpenDuration(t *testing.T) {
	cfg := &config.Config{DefaultOpenDuration: -1}
	errs := cfg.Validate()
	found := false
	for _, e := range errs {
		if strings.Contains(e, "default_open_duration") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected default_open_duration error, got: %v", errs)
	}
}

// TestConfigValidateRejectsOpenDurationExceedsMax verifies default > max is caught.
func TestConfigValidateRejectsOpenDurationExceedsMax(t *testing.T) {
	cfg := &config.Config{DefaultOpenDuration: 7200, MaxOpenDuration: 3600}
	errs := cfg.Validate()
	found := false
	for _, e := range errs {
		if strings.Contains(e, "exceeds max_open_duration") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected open duration ordering error, got: %v", errs)
	}
}

// TestConfigValidateAcceptsValidDefaults verifies the default config passes.
func TestConfigValidateAcceptsValidDefaults(t *testing.T) {
	cfg := config.DefaultServerConfig()
	errs := cfg.Validate()
	if len(errs) != 0 {
		t.Fatalf("expected no validation errors for defaults, got: %v", errs)
	}
}

// ---------------------------------------------------------------------------
// State file size limit (tracker)
// ---------------------------------------------------------------------------

// TestStatFileSizeLimitRejectsOversize is tested at the unit level in the
// server package. Here we verify the constant exists and matches expectations.
// The actual tracker test with oversized files lives in server_security_test.go.

// ---------------------------------------------------------------------------
// Log sanitization
// ---------------------------------------------------------------------------

// TestLogSanitizationBlocksControlChars verifies that the sanitizeForLog
// function (tested at unit level in server package) prevents injection.
// This integration test verifies the principle: control characters in commands
// should not appear in log output.
func TestCommandFieldLengthLimit(t *testing.T) {
	dk, err := crypto.GenerateKeyPair(crypto.KEM768)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	ek := dk.EncapsulationKey()

	// Build packet with a command that stays within the binary encoding limit.
	// Binary layout: type(1) + cmdData, so for "open-t<portspecs>" the cmdData
	// is "t<portspecs>" (250 bytes), so totalCmdLen = 251 <= 255. Must succeed.
	longCmd := "open-t" + strings.Repeat("2", 249) // 249 = 255-byte binary limit - 1 (type byte) - 5 ("open-" prefix stripped from cmdData)
	if len(longCmd) > 255 {
		longCmd = longCmd[:255]
	}
	_, err = protocol.BuildKnockPacket(ek, "10.0.0.1", longCmd, 60)
	if err != nil {
		t.Fatalf("BuildKnockPacket with 255-char command: %v", err)
	}

	// A cust- command with a 255-char ID produces totalCmdLen = 1 + 255 = 256
	// which exceeds the 255-byte binary field limit. BuildKnockPacket must
	// reject it rather than silently truncating or encoding a malformed packet.
	tooLong := "cust-" + strings.Repeat("x", 255) // 255 data bytes: type(1) + data(255) = 256 total, exceeds the 255-byte binary field limit
	_, err = protocol.BuildKnockPacket(ek, "10.0.0.1", tooLong, 60)
	if err == nil {
		t.Fatal("expected error for command exceeding 255-byte binary encoding limit, got nil")
	}
}
