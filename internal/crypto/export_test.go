// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package crypto

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestCreateParseExportBundle(t *testing.T) {
	dk, err := GenerateKeyPair(KEM768)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	ek := dk.EncapsulationKey()

	b64, err := CreateExportBundle(ek, 12345, true, false, true)
	if err != nil {
		t.Fatalf("CreateExportBundle: %v", err)
	}

	if b64 == "" {
		t.Fatal("empty bundle")
	}

	// Parse it back
	bundle, err := ParseExportBundle(b64, "")
	if err != nil {
		t.Fatalf("ParseExportBundle: %v", err)
	}

	if bundle.Version != 1 {
		t.Errorf("version = %d, want 1", bundle.Version)
	}
	if bundle.KEMSize != 768 {
		t.Errorf("KEMSize = %d, want 768", bundle.KEMSize)
	}
	if bundle.Port != 12345 {
		t.Errorf("port = %d, want 12345", bundle.Port)
	}
	if !bundle.AllowCustomOpenDuration {
		t.Error("AllowCustomOpenDuration = false, want true")
	}
	if bundle.AllowCustomPort {
		t.Error("AllowCustomPort = true, want false")
	}
	if !bundle.AllowOpenAll {
		t.Error("AllowOpenAll = false, want true")
	}

	// Verify the key can be parsed
	rekonstruct, err := GetEncapsulationKeyFromBundle(bundle)
	if err != nil {
		t.Fatalf("GetEncapsulationKeyFromBundle: %v", err)
	}

	// Key should work for encryption
	plaintext := []byte("test payload")
	packet, err := EncapsulateAndEncrypt(rekonstruct, plaintext)
	if err != nil {
		t.Fatalf("EncapsulateAndEncrypt with reconstructed key: %v", err)
	}

	result, err := DecapsulateAndDecrypt(dk, packet)
	if err != nil {
		t.Fatalf("DecapsulateAndDecrypt: %v", err)
	}

	if string(result) != string(plaintext) {
		t.Errorf("round-trip failed: got %s, want %s", result, plaintext)
	}
}

func TestEncryptedExportBundle(t *testing.T) {
	dk, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	ek := dk.EncapsulationKey()

	password := "test-password-123"

	b64, err := CreateEncryptedExportBundle(ek, 54321, false, true, false, password)
	if err != nil {
		t.Fatalf("CreateEncryptedExportBundle: %v", err)
	}

	// Should fail without password
	_, err = ParseExportBundle(b64, "")
	if err == nil {
		t.Error("expected error when parsing encrypted bundle without password")
	}

	// Should fail with wrong password
	_, err = ParseExportBundle(b64, "wrong-password")
	if err == nil {
		t.Error("expected error with wrong password")
	}

	// Should succeed with correct password
	bundle, err := ParseExportBundle(b64, password)
	if err != nil {
		t.Fatalf("ParseExportBundle with correct password: %v", err)
	}

	if bundle.Port != 54321 {
		t.Errorf("port = %d, want 54321", bundle.Port)
	}
	if !bundle.AllowCustomPort {
		t.Error("AllowCustomPort = false, want true")
	}
}

func TestExportBundleFileRoundTrip(t *testing.T) {
	dk, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	ek := dk.EncapsulationKey()

	b64, err := CreateExportBundle(ek, 11111, false, false, false)
	if err != nil {
		t.Fatalf("CreateExportBundle: %v", err)
	}

	path := t.TempDir() + "/test.b64"
	if err := ExportToFile(path, b64); err != nil {
		t.Fatalf("ExportToFile: %v", err)
	}

	loaded, err := ImportFromFile(path)
	if err != nil {
		t.Fatalf("ImportFromFile: %v", err)
	}

	if loaded != b64 {
		t.Error("file round-trip changed the data")
	}
}

// =============================================================================
// Wire-format regression tests
//
// These tests assert the exact byte-level prefix of every bundle variant to
// prevent the "double-SPK" bug from ever recurring. The rule is simple:
//
//   - Unencrypted base64 bundle: decoded bytes start with "SPK" + version(0x01)
//   - Unencrypted raw bundle (QR code): bytes start with "SPK" + version(0x01)
//   - Encrypted base64 bundle: decoded bytes start with "SPKE"
//
// If encodeV1Binary or the callers ever double-write "SPK" again, these tests
// will catch it immediately because byte [3] would be 'S' (0x53) instead of
// the version byte 0x01.
// =============================================================================

// TestBase64BundleMagicNotDoubled verifies that the base64-decoded wire format
// starts with exactly "SPK" + version(1), not "SPKSPK" + version(1).
func TestBase64BundleMagicNotDoubled(t *testing.T) {
	dk, err := GenerateKeyPair(KEM768)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	ek := dk.EncapsulationKey()

	b64, err := CreateExportBundle(ek, 12345, true, false, true)
	if err != nil {
		t.Fatalf("CreateExportBundle: %v", err)
	}

	decoded, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}

	if len(decoded) < 4 {
		t.Fatalf("decoded too short: %d bytes", len(decoded))
	}

	// Bytes 0-2 must be "SPK", byte 3 must be version 0x01.
	if string(decoded[:3]) != "SPK" {
		t.Errorf("magic = %q, want \"SPK\"", string(decoded[:3]))
	}
	if decoded[3] != 0x01 {
		t.Errorf("byte[3] = 0x%02X, want 0x01 (version); double-magic bug if 0x53 ('S')", decoded[3])
	}

	// Explicit check: the decoded data must NOT start with "SPKSPK".
	if len(decoded) >= 6 && string(decoded[:6]) == "SPKSPK" {
		t.Fatal("REGRESSION: bundle starts with \"SPKSPK\" -- encodeV1Binary output was double-prefixed")
	}

	// Verify round-trip still works.
	bundle, err := ParseExportBundle(b64, "")
	if err != nil {
		t.Fatalf("ParseExportBundle: %v", err)
	}
	if bundle.Port != 12345 || bundle.Version != 1 {
		t.Errorf("unexpected bundle values: port=%d version=%d", bundle.Port, bundle.Version)
	}
}

// TestRawBundleMagicNotDoubled verifies that the raw binary bundle (used for
// QR codes) starts with exactly "SPK" + version(1), not "SPKSPK" + version(1).
func TestRawBundleMagicNotDoubled(t *testing.T) {
	dk, err := GenerateKeyPair(KEM768)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	ek := dk.EncapsulationKey()

	raw, err := CreateExportBundleRawWithWindow(ek, 9999, false, true, false, nil, false, 60, 0)
	if err != nil {
		t.Fatalf("CreateExportBundleRawWithWindow: %v", err)
	}

	if len(raw) < 4 {
		t.Fatalf("raw too short: %d bytes", len(raw))
	}

	if string(raw[:3]) != "SPK" {
		t.Errorf("magic = %q, want \"SPK\"", string(raw[:3]))
	}
	if raw[3] != 0x01 {
		t.Errorf("byte[3] = 0x%02X, want 0x01 (version); double-magic bug if 0x53 ('S')", raw[3])
	}
	if len(raw) >= 6 && string(raw[:6]) == "SPKSPK" {
		t.Fatal("REGRESSION: raw bundle starts with \"SPKSPK\" -- double-prefixed")
	}

	// Verify round-trip via ParseExportBundleRaw.
	bundle, err := ParseExportBundleRaw(raw, "")
	if err != nil {
		t.Fatalf("ParseExportBundleRaw: %v", err)
	}
	if bundle.Port != 9999 {
		t.Errorf("port = %d, want 9999", bundle.Port)
	}
}

// TestEncryptedBundleMagicPrefix verifies that encrypted bundles start with
// "SPKE" (4 bytes) and that the decrypted inner payload starts with "SPK" + version.
func TestEncryptedBundleMagicPrefix(t *testing.T) {
	dk, err := GenerateKeyPair(KEM768)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	ek := dk.EncapsulationKey()
	password := "regression-test-pw"

	b64, err := CreateEncryptedExportBundle(ek, 8080, true, true, false, password)
	if err != nil {
		t.Fatalf("CreateEncryptedExportBundle: %v", err)
	}

	decoded, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}

	// Outer framing must be "SPKE".
	if len(decoded) < 4 || string(decoded[:4]) != "SPKE" {
		t.Fatalf("encrypted bundle should start with \"SPKE\", got %q", string(decoded[:4]))
	}

	// Verify round-trip.
	bundle, err := ParseExportBundle(b64, password)
	if err != nil {
		t.Fatalf("ParseExportBundle: %v", err)
	}
	if bundle.Port != 8080 {
		t.Errorf("port = %d, want 8080", bundle.Port)
	}
}

// TestBase64AndRawBundlesProduceSamePayload verifies that the base64-encoded
// and raw binary creation paths produce identical binary content (base64
// encoding being the only difference).
func TestBase64AndRawBundlesProduceSamePayload(t *testing.T) {
	dk, err := GenerateKeyPair(KEM768)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	ek := dk.EncapsulationKey()

	b64, err := CreateExportBundleWithWindow(ek, 5555, true, false, true, nil, false, 120, 0)
	if err != nil {
		t.Fatalf("CreateExportBundleWithWindow: %v", err)
	}
	raw, err := CreateExportBundleRawWithWindow(ek, 5555, true, false, true, nil, false, 120, 0)
	if err != nil {
		t.Fatalf("CreateExportBundleRawWithWindow: %v", err)
	}

	decoded, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}

	if !bytes.Equal(decoded, raw) {
		t.Fatal("base64 bundle and raw bundle should encode identical binary content")
	}
}

// TestEncodeV1BinaryOutputStartsWithMagic verifies that encodeV1Binary itself
// includes the "SPK" magic prefix in its output.
func TestEncodeV1BinaryOutputStartsWithMagic(t *testing.T) {
	dk, err := GenerateKeyPair(KEM768)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	ek := dk.EncapsulationKey()

	raw, err := encodeV1Binary(ek, 22222, false, false, false, nil, false, 1800, 300)
	if err != nil {
		t.Fatalf("encodeV1Binary: %v", err)
	}

	if len(raw) < 4 {
		t.Fatalf("raw too short: %d bytes", len(raw))
	}
	if string(raw[:3]) != "SPK" {
		t.Errorf("encodeV1Binary output should start with \"SPK\", got %q", string(raw[:3]))
	}
	if raw[3] != 0x01 {
		t.Errorf("version byte = 0x%02X, want 0x01", raw[3])
	}
}

// TestBundleKEM1024MagicNotDoubled repeats the magic prefix check for KEM-1024.
func TestBundleKEM1024MagicNotDoubled(t *testing.T) {
	dk, err := GenerateKeyPair(KEM1024)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	ek := dk.EncapsulationKey()

	b64, err := CreateExportBundle(ek, 54321, false, true, false)
	if err != nil {
		t.Fatalf("CreateExportBundle (1024): %v", err)
	}

	decoded, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}

	if string(decoded[:3]) != "SPK" || decoded[3] != 0x01 {
		t.Errorf("KEM-1024 bundle header = [0x%02X 0x%02X 0x%02X 0x%02X], want [0x53 0x50 0x4B 0x01]",
			decoded[0], decoded[1], decoded[2], decoded[3])
	}
	if len(decoded) >= 6 && string(decoded[:6]) == "SPKSPK" {
		t.Fatal("REGRESSION: KEM-1024 bundle starts with \"SPKSPK\"")
	}
}

// =============================================================================
// Encrypted raw bundle tests (QR code encryption)
//
// These tests verify that the encrypted raw bundle path (used for QR codes)
// produces SPKE-prefixed data that can only be parsed with the correct password,
// ensuring QR codes are protected when password encryption is enabled.
// =============================================================================

// TestEncryptedRawBundleRoundTrip verifies that CreateEncryptedExportBundleRawWithWindow
// produces raw bytes starting with "SPKE" that ParseExportBundleRaw can decrypt.
func TestEncryptedRawBundleRoundTrip(t *testing.T) {
	dk, err := GenerateKeyPair(KEM768)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	ek := dk.EncapsulationKey()
	password := "test-qr-password"

	raw, err := CreateEncryptedExportBundleRawWithWindow(ek, 12345, true, false, true,
		password, nil, false, 3600, 0)
	if err != nil {
		t.Fatalf("CreateEncryptedExportBundleRawWithWindow: %v", err)
	}

	// Must start with "SPKE"
	if len(raw) < 4 || string(raw[:4]) != "SPKE" {
		t.Fatalf("encrypted raw bundle should start with \"SPKE\", got %q", string(raw[:4]))
	}

	// Must NOT start with plain "SPK" followed by version byte
	if len(raw) >= 4 && raw[3] == 0x01 {
		t.Fatal("encrypted raw bundle byte[3] is version 0x01 -- data is NOT encrypted")
	}

	// Should fail without password
	_, err = ParseExportBundleRaw(raw, "")
	if err == nil {
		t.Error("expected error parsing encrypted raw bundle without password")
	}

	// Should fail with wrong password
	_, err = ParseExportBundleRaw(raw, "wrong-password")
	if err == nil {
		t.Error("expected error parsing encrypted raw bundle with wrong password")
	}

	// Should succeed with correct password
	bundle, err := ParseExportBundleRaw(raw, password)
	if err != nil {
		t.Fatalf("ParseExportBundleRaw with correct password: %v", err)
	}

	if bundle.Port != 12345 {
		t.Errorf("port = %d, want 12345", bundle.Port)
	}
	if !bundle.AllowCustomOpenDuration {
		t.Error("AllowCustomOpenDuration should be true")
	}
	if !bundle.AllowOpenAll {
		t.Error("AllowOpenAll should be true")
	}
	if bundle.DefaultOpenDuration != 3600 {
		t.Errorf("DefaultOpenDuration = %d, want 3600", bundle.DefaultOpenDuration)
	}
}

// TestEncryptedRawBundleKeyRoundTrip verifies that the encapsulation key
// survives encrypted raw bundle round-trip and can be used for encryption.
func TestEncryptedRawBundleKeyRoundTrip(t *testing.T) {
	dk, err := GenerateKeyPair(KEM768)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	ek := dk.EncapsulationKey()
	password := "key-round-trip-pw"

	raw, err := CreateEncryptedExportBundleRawWithWindow(ek, 9999, false, true, false,
		password, nil, false, 60, 0)
	if err != nil {
		t.Fatalf("CreateEncryptedExportBundleRawWithWindow: %v", err)
	}

	bundle, err := ParseExportBundleRaw(raw, password)
	if err != nil {
		t.Fatalf("ParseExportBundleRaw: %v", err)
	}

	reconstructed, err := GetEncapsulationKeyFromBundle(bundle)
	if err != nil {
		t.Fatalf("GetEncapsulationKeyFromBundle: %v", err)
	}

	plaintext := []byte("encrypted QR test payload")
	packet, err := EncapsulateAndEncrypt(reconstructed, plaintext)
	if err != nil {
		t.Fatalf("EncapsulateAndEncrypt: %v", err)
	}
	result, err := DecapsulateAndDecrypt(dk, packet)
	if err != nil {
		t.Fatalf("DecapsulateAndDecrypt: %v", err)
	}
	if string(result) != string(plaintext) {
		t.Errorf("round-trip failed: got %q, want %q", result, plaintext)
	}
}

// TestEncryptedAndUnencryptedRawBundlesDiffer verifies that encrypted and
// unencrypted raw bundles for the same key material produce different bytes,
// confirming the QR code content is actually encrypted.
func TestEncryptedAndUnencryptedRawBundlesDiffer(t *testing.T) {
	dk, err := GenerateKeyPair(KEM768)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	ek := dk.EncapsulationKey()

	plain, err := CreateExportBundleRawWithWindow(ek, 5555, true, false, true, nil, false, 120, 0)
	if err != nil {
		t.Fatalf("CreateExportBundleRawWithWindow: %v", err)
	}

	enc, err := CreateEncryptedExportBundleRawWithWindow(ek, 5555, true, false, true,
		"some-password", nil, false, 120, 0)
	if err != nil {
		t.Fatalf("CreateEncryptedExportBundleRawWithWindow: %v", err)
	}

	// Encrypted bundle must be larger (salt + AES-GCM overhead)
	if len(enc) <= len(plain) {
		t.Errorf("encrypted raw (%d bytes) should be larger than plain raw (%d bytes)", len(enc), len(plain))
	}

	// Prefixes must differ: "SPK" vs "SPKE"
	if string(plain[:3]) != "SPK" {
		t.Errorf("plain prefix = %q, want \"SPK\"", string(plain[:3]))
	}
	if string(enc[:4]) != "SPKE" {
		t.Errorf("encrypted prefix = %q, want \"SPKE\"", string(enc[:4]))
	}

	// Content must differ
	if bytes.Equal(plain, enc) {
		t.Fatal("encrypted and unencrypted raw bundles should not be identical")
	}
}

// TestEncryptedRawAndBase64BundlesParseToSameValues verifies that the encrypted
// raw bundle (for QR) and encrypted base64 bundle (for text) both decrypt to
// the same logical content.
func TestEncryptedRawAndBase64BundlesParseToSameValues(t *testing.T) {
	dk, err := GenerateKeyPair(KEM768)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	ek := dk.EncapsulationKey()
	password := "consistency-test-pw"

	b64, err := CreateEncryptedExportBundleWithWindow(ek, 7777, true, true, false,
		password, nil, false, 300, 0)
	if err != nil {
		t.Fatalf("CreateEncryptedExportBundleWithWindow: %v", err)
	}

	raw, err := CreateEncryptedExportBundleRawWithWindow(ek, 7777, true, true, false,
		password, nil, false, 300, 0)
	if err != nil {
		t.Fatalf("CreateEncryptedExportBundleRawWithWindow: %v", err)
	}

	bundleB64, err := ParseExportBundle(b64, password)
	if err != nil {
		t.Fatalf("ParseExportBundle: %v", err)
	}

	bundleRaw, err := ParseExportBundleRaw(raw, password)
	if err != nil {
		t.Fatalf("ParseExportBundleRaw: %v", err)
	}

	// Same logical values
	if bundleB64.Port != bundleRaw.Port {
		t.Errorf("port mismatch: b64=%d, raw=%d", bundleB64.Port, bundleRaw.Port)
	}
	if bundleB64.AllowCustomOpenDuration != bundleRaw.AllowCustomOpenDuration {
		t.Error("AllowCustomOpenDuration mismatch")
	}
	if bundleB64.AllowCustomPort != bundleRaw.AllowCustomPort {
		t.Error("AllowCustomPort mismatch")
	}
	if bundleB64.AllowOpenAll != bundleRaw.AllowOpenAll {
		t.Error("AllowOpenAll mismatch")
	}
	if bundleB64.KEMSize != bundleRaw.KEMSize {
		t.Errorf("KEMSize mismatch: b64=%d, raw=%d", bundleB64.KEMSize, bundleRaw.KEMSize)
	}
	if bundleB64.EncapsulationKey != bundleRaw.EncapsulationKey {
		t.Error("EncapsulationKey mismatch between base64 and raw encrypted bundles")
	}
}
