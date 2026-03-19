// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package crypto

import (
	"encoding/base64"
	"encoding/binary"
	"testing"
)

// =============================================================================
// Export Bundle v1 Multi-KEM Tests
// =============================================================================

func TestExportBundleV1WithKEM768(t *testing.T) {
	dk, _ := GenerateKeyPair(KEM768)
	ek := dk.EncapsulationKey()

	b64, err := CreateExportBundle(ek, 12345, true, false, true)
	if err != nil {
		t.Fatalf("CreateExportBundle: %v", err)
	}

	bundle, err := ParseExportBundle(b64, "")
	if err != nil {
		t.Fatalf("ParseExportBundle: %v", err)
	}

	if bundle.Version != 1 {
		t.Errorf("Version = %d, want 1", bundle.Version)
	}
	if bundle.KEMSize != 768 {
		t.Errorf("KEMSize = %d, want 768", bundle.KEMSize)
	}
	if bundle.Port != 12345 {
		t.Errorf("Port = %d, want 12345", bundle.Port)
	}
	if !bundle.AllowCustomOpenDuration {
		t.Error("AllowCustomOpenDuration should be true")
	}
	if bundle.AllowCustomPort {
		t.Error("AllowCustomPort should be false")
	}
	if !bundle.AllowOpenAll {
		t.Error("AllowOpenAll should be true")
	}

	// Verify reconstructed key works
	reconstructed, err := GetEncapsulationKeyFromBundle(bundle)
	if err != nil {
		t.Fatalf("GetEncapsulationKeyFromBundle: %v", err)
	}
	if reconstructed.KEMSize() != KEM768 {
		t.Errorf("reconstructed key KEMSize = %d, want 768", reconstructed.KEMSize())
	}

	// Full encrypt/decrypt round trip
	plaintext := []byte("v1 bundle test 768")
	packet, err := EncapsulateAndEncrypt(reconstructed, plaintext)
	if err != nil {
		t.Fatalf("EncapsulateAndEncrypt: %v", err)
	}
	result, err := DecapsulateAndDecrypt(dk, packet)
	if err != nil {
		t.Fatalf("DecapsulateAndDecrypt: %v", err)
	}
	if string(result) != string(plaintext) {
		t.Errorf("round-trip failed: %q != %q", result, plaintext)
	}
}

func TestExportBundleV1WithKEM1024(t *testing.T) {
	dk, _ := GenerateKeyPair(KEM1024)
	ek := dk.EncapsulationKey()

	b64, err := CreateExportBundle(ek, 54321, false, true, false)
	if err != nil {
		t.Fatalf("CreateExportBundle: %v", err)
	}

	bundle, err := ParseExportBundle(b64, "")
	if err != nil {
		t.Fatalf("ParseExportBundle: %v", err)
	}

	if bundle.Version != 1 {
		t.Errorf("Version = %d, want 1", bundle.Version)
	}
	if bundle.KEMSize != 1024 {
		t.Errorf("KEMSize = %d, want 1024", bundle.KEMSize)
	}
	if bundle.Port != 54321 {
		t.Errorf("Port = %d, want 54321", bundle.Port)
	}
	if bundle.AllowCustomOpenDuration {
		t.Error("AllowCustomOpenDuration should be false")
	}
	if !bundle.AllowCustomPort {
		t.Error("AllowCustomPort should be true")
	}

	// Verify reconstructed key works
	reconstructed, err := GetEncapsulationKeyFromBundle(bundle)
	if err != nil {
		t.Fatalf("GetEncapsulationKeyFromBundle: %v", err)
	}
	if reconstructed.KEMSize() != KEM1024 {
		t.Errorf("reconstructed key KEMSize = %d, want 1024", reconstructed.KEMSize())
	}

	// Full encrypt/decrypt round trip
	plaintext := []byte("v1 bundle test 1024")
	packet, _ := EncapsulateAndEncrypt(reconstructed, plaintext)
	result, err := DecapsulateAndDecrypt(dk, packet)
	if err != nil {
		t.Fatalf("DecapsulateAndDecrypt: %v", err)
	}
	if string(result) != string(plaintext) {
		t.Errorf("round-trip failed: %q != %q", result, plaintext)
	}
}

func TestExportBundleVersionRejected(t *testing.T) {
	// Decoder should reject any version other than 1.
	dk, _ := GenerateKeyPair(KEM1024)
	ek := dk.EncapsulationKey()

	// Build a binary bundle with unsupported version 2:
	// "SK" + ver(2) + flags(0) + port(2) + open_duration(4) + window(4) + ek(1568)
	var raw []byte
	raw = append(raw, 'S', 'K') // magic
	raw = append(raw, 2)        // version 2 (unsupported)
	raw = append(raw, 0x01)     // flags: allowCustomOpenDuration

	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, 11111)
	raw = append(raw, portBytes...)

	openDurationBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(openDurationBytes, 3600)
	raw = append(raw, openDurationBytes...)

	windowBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(windowBytes, 600)
	raw = append(raw, windowBytes...)

	raw = append(raw, ek.Bytes()...)

	// Parser should reject unsupported version
	_, err := decodeBinary(raw)
	if err == nil {
		t.Fatal("expected error parsing unsupported bundle version, got nil")
	}
}

func TestExportBundleV1RawBinaryFormat(t *testing.T) {
	// Verify the v1 binary format explicitly has the kem_size field
	dk, _ := GenerateKeyPair(KEM768)
	ek := dk.EncapsulationKey()

	raw, err := encodeV1Binary(ek, 22222, false, false, false, nil, false, 1800, 300)
	if err != nil {
		t.Fatalf("encodeV1Binary: %v", err)
	}

	// Check magic
	if raw[0] != 'S' || raw[1] != 'K' {
		t.Errorf("magic = %q, want 'SK'", string(raw[:2]))
	}
	// Check version
	if raw[2] != 1 {
		t.Errorf("version = %d, want 1", raw[2])
	}
	// Check flags (all false = 0)
	if raw[3] != 0 {
		t.Errorf("flags = 0x%02x, want 0x00", raw[3])
	}
	// port(2) at offset 4
	port := binary.BigEndian.Uint16(raw[4:6])
	if port != 22222 {
		t.Errorf("port = %d, want 22222", port)
	}
	// open_duration(4) at offset 6
	openDuration := binary.BigEndian.Uint32(raw[6:10])
	if openDuration != 1800 {
		t.Errorf("open_duration = %d, want 1800", openDuration)
	}
	// window(4) at offset 10
	window := binary.BigEndian.Uint32(raw[10:14])
	if window != 300 {
		t.Errorf("window = %d, want 300", window)
	}
	// kem_size(2) at offset 14
	kemSize := binary.BigEndian.Uint16(raw[14:16])
	if kemSize != 768 {
		t.Errorf("kem_size = %d, want 768", kemSize)
	}
	// ek starts at offset 16
	ekBytes := raw[16:]
	if len(ekBytes) != EncapsulationKeySize768 {
		t.Errorf("ek length = %d, want %d", len(ekBytes), EncapsulationKeySize768)
	}
}

func TestExportBundleEncryptedWithKEM768(t *testing.T) {
	dk, _ := GenerateKeyPair(KEM768)
	ek := dk.EncapsulationKey()
	password := "test-password-768"

	b64, err := CreateEncryptedExportBundle(ek, 33333, true, true, true, password)
	if err != nil {
		t.Fatalf("CreateEncryptedExportBundle: %v", err)
	}

	// Should fail without password
	_, err = ParseExportBundle(b64, "")
	if err == nil {
		t.Error("expected error parsing encrypted bundle without password")
	}

	// Should fail with wrong password
	_, err = ParseExportBundle(b64, "wrong-password")
	if err == nil {
		t.Error("expected error with wrong password")
	}

	// Should succeed with correct password
	bundle, err := ParseExportBundle(b64, password)
	if err != nil {
		t.Fatalf("ParseExportBundle with password: %v", err)
	}

	if bundle.KEMSize != 768 {
		t.Errorf("KEMSize = %d, want 768", bundle.KEMSize)
	}
	if bundle.Port != 33333 {
		t.Errorf("Port = %d, want 33333", bundle.Port)
	}
}

func TestExportBundleDynamicPortWithKEM768(t *testing.T) {
	dk, _ := GenerateKeyPair(KEM768)
	ek := dk.EncapsulationKey()

	seed := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	raw, err := encodeV1Binary(ek, 0, false, false, false, seed, true, 3600, 600)
	if err != nil {
		t.Fatalf("encodeV1Binary with dynamic port: %v", err)
	}

	bundle, err := decodeBinary(raw)
	if err != nil {
		t.Fatalf("decodeBinary: %v", err)
	}

	if !bundle.DynamicPort {
		t.Error("DynamicPort should be true")
	}
	if len(bundle.PortSeed) != 8 {
		t.Errorf("PortSeed length = %d, want 8", len(bundle.PortSeed))
	}
	if bundle.KEMSize != 768 {
		t.Errorf("KEMSize = %d, want 768", bundle.KEMSize)
	}
	if bundle.DynPortWindow != 600 {
		t.Errorf("DynPortWindow = %d, want 600", bundle.DynPortWindow)
	}
}

func TestExportBundleBase64RoundTrip768(t *testing.T) {
	dk, _ := GenerateKeyPair(KEM768)
	ek := dk.EncapsulationKey()

	b64, err := CreateExportBundle(ek, 44444, true, true, true)
	if err != nil {
		t.Fatalf("CreateExportBundle: %v", err)
	}

	// Verify it's valid base64
	_, err = base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("invalid base64: %v", err)
	}

	// Parse and verify
	bundle, err := ParseExportBundle(b64, "")
	if err != nil {
		t.Fatalf("ParseExportBundle: %v", err)
	}

	// File round trip
	path := t.TempDir() + "/test768.b64"
	if err := ExportToFile(path, b64); err != nil {
		t.Fatalf("ExportToFile: %v", err)
	}
	loaded, err := ImportFromFile(path)
	if err != nil {
		t.Fatalf("ImportFromFile: %v", err)
	}
	if loaded != b64 {
		t.Error("file round-trip changed data")
	}

	// Parse from file and verify KEMSize preserved
	bundle2, err := ParseExportBundle(loaded, "")
	if err != nil {
		t.Fatalf("ParseExportBundle from file: %v", err)
	}
	if bundle2.KEMSize != bundle.KEMSize {
		t.Errorf("KEMSize mismatch after file round-trip: %d != %d", bundle2.KEMSize, bundle.KEMSize)
	}
}
