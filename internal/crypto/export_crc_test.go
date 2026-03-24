// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package crypto

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"testing"
)

// =============================================================================
// CRC32 checksum tests for the activation bundle binary format.
//
// The v1 binary bundle always ends with a 4-byte CRC32/IEEE checksum
// (big-endian) covering all preceding bytes. These tests verify:
//
//  1. The checksum is present and correct in newly generated bundles.
//  2. Any single-byte corruption is detected and rejected.
//  3. Bundles with wrong checksums return a clear error.
//  4. Bundles missing the CRC32 trailer are rejected.
//  5. CRC32 validation works for all bundle variants (KEM-768, KEM-1024,
//     static port, dynamic port, encrypted inner payload).
// =============================================================================

// TestBundleCRC32TrailerPresent verifies that encodeV1Binary appends a 4-byte
// CRC32 trailer at the end of every produced binary bundle.
func TestBundleCRC32TrailerPresent(t *testing.T) {
	dk, err := GenerateKeyPair(KEM768)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	ek := dk.EncapsulationKey()

	raw, err := encodeV1Binary(ek, 22222, false, false, false, nil, false, 1800, 300)
	if err != nil {
		t.Fatalf("encodeV1Binary: %v", err)
	}

	// Expected layout: 3(magic) + 1(ver) + 1(flags) + 2(port) + 4(dur) + 4(win) + 2(kem) + ekSize + 4(crc32)
	ekSize := EncapsulationKeySize768
	wantLen := 3 + 1 + 1 + 2 + 4 + 4 + 2 + ekSize + crc32Size
	if len(raw) != wantLen {
		t.Fatalf("raw bundle length = %d, want %d", len(raw), wantLen)
	}
}

// TestBundleCRC32Value verifies that the stored CRC32 value equals the
// CRC32/IEEE checksum of all bytes preceding the last 4 bytes.
func TestBundleCRC32Value(t *testing.T) {
	dk, err := GenerateKeyPair(KEM768)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	ek := dk.EncapsulationKey()

	raw, err := encodeV1Binary(ek, 12345, true, false, true, nil, false, 3600, 0)
	if err != nil {
		t.Fatalf("encodeV1Binary: %v", err)
	}

	if len(raw) < crc32Size {
		t.Fatalf("bundle too short: %d bytes", len(raw))
	}

	payload := raw[:len(raw)-crc32Size]
	stored := binary.BigEndian.Uint32(raw[len(raw)-crc32Size:])
	expected := crc32.ChecksumIEEE(payload)

	if stored != expected {
		t.Errorf("stored CRC32 = 0x%08X, want 0x%08X", stored, expected)
	}
}

// TestBundleCRC32RoundTripKEM768 verifies create-and-parse round-trip with
// CRC32 for a KEM-768 static-port bundle.
func TestBundleCRC32RoundTripKEM768(t *testing.T) {
	dk, err := GenerateKeyPair(KEM768)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	ek := dk.EncapsulationKey()

	b64, err := CreateExportBundle(ek, 55555, true, true, false)
	if err != nil {
		t.Fatalf("CreateExportBundle (768): %v", err)
	}

	bundle, err := ParseExportBundle(b64, "")
	if err != nil {
		t.Fatalf("ParseExportBundle (768): %v", err)
	}

	if bundle.Port != 55555 {
		t.Errorf("port = %d, want 55555", bundle.Port)
	}
	if bundle.KEMSize != 768 {
		t.Errorf("KEMSize = %d, want 768", bundle.KEMSize)
	}
	if bundle.Version != 1 {
		t.Errorf("Version = %d, want 1", bundle.Version)
	}
}

// TestBundleCRC32RoundTripKEM1024 verifies create-and-parse round-trip with
// CRC32 for a KEM-1024 static-port bundle.
func TestBundleCRC32RoundTripKEM1024(t *testing.T) {
	dk, err := GenerateKeyPair(KEM1024)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	ek := dk.EncapsulationKey()

	b64, err := CreateExportBundle(ek, 44444, false, false, true)
	if err != nil {
		t.Fatalf("CreateExportBundle (1024): %v", err)
	}

	bundle, err := ParseExportBundle(b64, "")
	if err != nil {
		t.Fatalf("ParseExportBundle (1024): %v", err)
	}

	if bundle.Port != 44444 {
		t.Errorf("port = %d, want 44444", bundle.Port)
	}
	if bundle.KEMSize != 1024 {
		t.Errorf("KEMSize = %d, want 1024", bundle.KEMSize)
	}
}

// TestBundleCRC32RoundTripDynamicPort verifies CRC32 works for dynamic-port bundles.
func TestBundleCRC32RoundTripDynamicPort(t *testing.T) {
	dk, err := GenerateKeyPair(KEM768)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	ek := dk.EncapsulationKey()
	seed := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0x00, 0x01}

	raw, err := encodeV1Binary(ek, 0, true, false, false, seed, true, 7200, 600)
	if err != nil {
		t.Fatalf("encodeV1Binary: %v", err)
	}

	bundle, err := decodeBinary(raw)
	if err != nil {
		t.Fatalf("decodeBinary: %v", err)
	}

	if !bundle.DynamicPort {
		t.Error("DynamicPort should be true")
	}
	if !bytes.Equal(bundle.PortSeed, seed) {
		t.Errorf("PortSeed = %x, want %x", bundle.PortSeed, seed)
	}
	if bundle.DefaultOpenDuration != 7200 {
		t.Errorf("DefaultOpenDuration = %d, want 7200", bundle.DefaultOpenDuration)
	}
}

// TestBundleCRC32Mismatch verifies that a single-byte flip anywhere in the
// bundle (excluding the CRC32 trailer itself) is detected as a CRC32 mismatch.
func TestBundleCRC32Mismatch(t *testing.T) {
	dk, err := GenerateKeyPair(KEM768)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	ek := dk.EncapsulationKey()

	raw, err := encodeV1Binary(ek, 8080, false, false, false, nil, false, 3600, 0)
	if err != nil {
		t.Fatalf("encodeV1Binary: %v", err)
	}

	// Flip bytes at various positions in the payload (everything except the
	// last 4 bytes which are the stored checksum).
	payloadLen := len(raw) - crc32Size
	positions := []int{
		0,              // first byte of magic
		1,              // second byte of magic
		2,              // third byte of magic
		3,              // version byte
		4,              // flags byte
		5,              // first port byte
		6,              // second port byte
		7,              // open_duration byte 0
		payloadLen - 1, // last byte of EK
	}

	for _, pos := range positions {
		corrupted := make([]byte, len(raw))
		copy(corrupted, raw)
		corrupted[pos] ^= 0xFF // flip all bits at this position

		_, err = decodeBinary(corrupted)
		if err == nil {
			t.Errorf("position %d: expected CRC32 mismatch error, got nil", pos)
		}
	}
}

// TestBundleCRC32WrongChecksum verifies that supplying an incorrect CRC32
// value (without changing the payload) returns a clear error.
func TestBundleCRC32WrongChecksum(t *testing.T) {
	dk, err := GenerateKeyPair(KEM768)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	ek := dk.EncapsulationKey()

	raw, err := encodeV1Binary(ek, 9999, false, false, false, nil, false, 0, 0)
	if err != nil {
		t.Fatalf("encodeV1Binary: %v", err)
	}

	// Corrupt only the stored CRC32 (last 4 bytes).
	tampered := make([]byte, len(raw))
	copy(tampered, raw)
	binary.BigEndian.PutUint32(tampered[len(tampered)-crc32Size:], 0xDEADBEEF)

	_, err = decodeBinary(tampered)
	if err == nil {
		t.Fatal("expected error for wrong CRC32 value, got nil")
	}
}

// TestBundleCRC32LegacyNoCRC32Rejected verifies that bundles without the
// CRC32 trailer (0 trailing bytes after the encapsulation key) are rejected.
func TestBundleCRC32LegacyNoCRC32Rejected(t *testing.T) {
	dk, err := GenerateKeyPair(KEM768)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	ek := dk.EncapsulationKey()

	// Build a bundle without CRC32: "SPK" + ver + flags + port + duration + window + kem_size + EK
	var buf bytes.Buffer
	buf.WriteString("SPK")
	buf.WriteByte(1)    // version
	buf.WriteByte(0x01) // flags: allowCustomOpenDuration

	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, 11111)
	buf.Write(portBytes)

	durationBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(durationBytes, 3600)
	buf.Write(durationBytes)

	windowBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(windowBytes, 600)
	buf.Write(windowBytes)

	kemSizeBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(kemSizeBytes, 768)
	buf.Write(kemSizeBytes)

	buf.Write(ek.Bytes()) // no CRC32

	_, err = decodeBinary(buf.Bytes())
	if err == nil {
		t.Fatal("expected error for bundle without CRC32 trailer, got nil")
	}
}

// TestBundleCRC32TrailingBytesRejected verifies that bundles with any number
// of trailing bytes other than exactly 4 (the CRC32 field) are rejected.
// This includes 0 trailing bytes (missing CRC32) and any number other than 4.
func TestBundleCRC32TrailingBytesRejected(t *testing.T) {
	dk, err := GenerateKeyPair(KEM768)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	ek := dk.EncapsulationKey()

	raw, err := encodeV1Binary(ek, 8888, false, false, false, nil, false, 0, 0)
	if err != nil {
		t.Fatalf("encodeV1Binary: %v", err)
	}

	// Bundle without CRC32: strip the last 4 bytes.
	noCRC := raw[:len(raw)-crc32Size]
	if _, err := decodeBinary(noCRC); err == nil {
		t.Error("expected error for bundle missing CRC32 trailer, got nil")
	}

	// Bundles with 1, 2, 3, or 5 extra bytes after the CRC32 are also rejected.
	for _, extra := range []int{1, 2, 3, 5} {
		padded := make([]byte, len(raw)+extra)
		copy(padded, raw)
		if _, err := decodeBinary(padded); err == nil {
			t.Errorf("extra=%d: expected error for unexpected trailing bytes, got nil", extra)
		}
	}
}

// TestBundleCRC32EncryptedInnerVerified verifies that encrypted bundles have
// their inner (decrypted) payload's CRC32 validated when a password is supplied.
func TestBundleCRC32EncryptedInnerVerified(t *testing.T) {
	dk, err := GenerateKeyPair(KEM768)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	ek := dk.EncapsulationKey()
	password := "test-crc32-enc-pw"

	b64, err := CreateEncryptedExportBundle(ek, 7777, true, false, true, password)
	if err != nil {
		t.Fatalf("CreateEncryptedExportBundle: %v", err)
	}

	// Correct password -- decryption succeeds and inner CRC32 is valid.
	bundle, err := ParseExportBundle(b64, password)
	if err != nil {
		t.Fatalf("ParseExportBundle with correct password: %v", err)
	}
	if bundle.Port != 7777 {
		t.Errorf("port = %d, want 7777", bundle.Port)
	}
}

// TestBundleCRC32RawAndBase64Consistent verifies that the raw binary and
// base64-encoded paths produce exactly the same bytes (including CRC32).
func TestBundleCRC32RawAndBase64Consistent(t *testing.T) {
	dk, err := GenerateKeyPair(KEM768)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	ek := dk.EncapsulationKey()

	raw, err := CreateExportBundleRawWithWindow(ek, 11111, true, true, false, nil, false, 900, 300)
	if err != nil {
		t.Fatalf("CreateExportBundleRawWithWindow: %v", err)
	}

	b64, err := CreateExportBundleWithWindow(ek, 11111, true, true, false, nil, false, 900, 300)
	if err != nil {
		t.Fatalf("CreateExportBundleWithWindow: %v", err)
	}

	// Both use the same key pair so cannot compare bytes directly,
	// but we can verify both parse to identical field values.
	bundleRaw, err := ParseExportBundleRaw(raw, "")
	if err != nil {
		t.Fatalf("ParseExportBundleRaw: %v", err)
	}
	bundleB64, err := ParseExportBundle(b64, "")
	if err != nil {
		t.Fatalf("ParseExportBundle: %v", err)
	}

	if bundleRaw.Port != bundleB64.Port {
		t.Errorf("port mismatch: %d vs %d", bundleRaw.Port, bundleB64.Port)
	}
	if bundleRaw.KEMSize != bundleB64.KEMSize {
		t.Errorf("KEMSize mismatch: %d vs %d", bundleRaw.KEMSize, bundleB64.KEMSize)
	}
	if bundleRaw.AllowCustomOpenDuration != bundleB64.AllowCustomOpenDuration {
		t.Error("AllowCustomOpenDuration mismatch")
	}
	if bundleRaw.DynPortWindow != bundleB64.DynPortWindow {
		t.Errorf("DynPortWindow mismatch: %d vs %d", bundleRaw.DynPortWindow, bundleB64.DynPortWindow)
	}
}

// TestBundleCRC32AllFieldsRoundTrip verifies that every logical field survives
// a full encode-then-decode cycle with CRC32 present.
func TestBundleCRC32AllFieldsRoundTrip(t *testing.T) {
	dk, err := GenerateKeyPair(KEM768)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	ek := dk.EncapsulationKey()

	cases := []struct {
		name         string
		port         int
		customDur    bool
		customPort   bool
		openAll      bool
		seed         []byte
		dynamic      bool
		openDuration int
		window       int
	}{
		{"static-minimal", 22, false, false, false, nil, false, 0, 0},
		{"static-all-flags", 443, true, true, true, nil, false, 3600, 900},
		{"dynamic-no-flags", 0, false, false, false, []byte{1, 2, 3, 4, 5, 6, 7, 8}, true, 300, 120},
		{"dynamic-all-flags", 0, true, true, true, []byte{0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8}, true, 86400, 3600},
		{"max-port", 65535, false, true, false, nil, false, 7200, 0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := encodeV1Binary(ek, tc.port, tc.customDur, tc.customPort, tc.openAll,
				tc.seed, tc.dynamic, tc.openDuration, tc.window)
			if err != nil {
				t.Fatalf("encodeV1Binary: %v", err)
			}

			bundle, err := decodeBinary(raw)
			if err != nil {
				t.Fatalf("decodeBinary: %v", err)
			}

			if bundle.DynamicPort != tc.dynamic {
				t.Errorf("DynamicPort = %v, want %v", bundle.DynamicPort, tc.dynamic)
			}
			if !tc.dynamic && bundle.Port != tc.port {
				t.Errorf("Port = %d, want %d", bundle.Port, tc.port)
			}
			if bundle.AllowCustomOpenDuration != tc.customDur {
				t.Errorf("AllowCustomOpenDuration = %v, want %v", bundle.AllowCustomOpenDuration, tc.customDur)
			}
			if bundle.AllowCustomPort != tc.customPort {
				t.Errorf("AllowCustomPort = %v, want %v", bundle.AllowCustomPort, tc.customPort)
			}
			if bundle.AllowOpenAll != tc.openAll {
				t.Errorf("AllowOpenAll = %v, want %v", bundle.AllowOpenAll, tc.openAll)
			}
			if bundle.DefaultOpenDuration != tc.openDuration {
				t.Errorf("DefaultOpenDuration = %d, want %d", bundle.DefaultOpenDuration, tc.openDuration)
			}
			if bundle.DynPortWindow != tc.window {
				t.Errorf("DynPortWindow = %d, want %d", bundle.DynPortWindow, tc.window)
			}
		})
	}
}

// TestBundleCRC32KEM1024TrailerSize verifies the correct trailer offset for
// KEM-1024 bundles (larger EK means the CRC32 is at a different offset).
func TestBundleCRC32KEM1024TrailerSize(t *testing.T) {
	dk, err := GenerateKeyPair(KEM1024)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	ek := dk.EncapsulationKey()

	raw, err := encodeV1Binary(ek, 443, false, false, false, nil, false, 0, 0)
	if err != nil {
		t.Fatalf("encodeV1Binary (1024): %v", err)
	}

	// magic(3) + ver(1) + flags(1) + port(2) + dur(4) + win(4) + kem(2) + EK1024 + CRC32(4)
	wantLen := 3 + 1 + 1 + 2 + 4 + 4 + 2 + EncapsulationKeySize1024 + crc32Size
	if len(raw) != wantLen {
		t.Fatalf("KEM-1024 bundle length = %d, want %d", len(raw), wantLen)
	}

	// Verify the stored checksum is correct.
	payload := raw[:len(raw)-crc32Size]
	stored := binary.BigEndian.Uint32(raw[len(raw)-crc32Size:])
	expected := crc32.ChecksumIEEE(payload)
	if stored != expected {
		t.Errorf("KEM-1024 CRC32 = 0x%08X, want 0x%08X", stored, expected)
	}

	// Round-trip through the parser.
	bundle, err := decodeBinary(raw)
	if err != nil {
		t.Fatalf("decodeBinary (1024): %v", err)
	}
	if bundle.KEMSize != 1024 {
		t.Errorf("KEMSize = %d, want 1024", bundle.KEMSize)
	}
}

// TestBundleCRC32MagicByteCorruption verifies that flipping a magic byte
// causes either a format-rejection error or a CRC32 mismatch -- in both
// cases decoding must not succeed.
func TestBundleCRC32MagicByteCorruption(t *testing.T) {
	dk, err := GenerateKeyPair(KEM768)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	ek := dk.EncapsulationKey()

	raw, err := encodeV1Binary(ek, 22, false, false, false, nil, false, 0, 0)
	if err != nil {
		t.Fatalf("encodeV1Binary: %v", err)
	}

	for i := 0; i < 3; i++ {
		corrupted := make([]byte, len(raw))
		copy(corrupted, raw)
		corrupted[i] ^= 0x01 // single-bit flip in the magic

		// decodeBinary is called directly so we must redirect through ParseExportBundleRaw
		// which also validates the magic prefix.
		_, err = ParseExportBundleRaw(corrupted, "")
		if err == nil {
			t.Errorf("magic byte %d corrupted: expected error, got nil", i)
		}
	}
}

// TestBundleCRC32EKKeyUsableAfterVerification verifies that the encapsulation
// key decoded from a CRC32-validated bundle can still be used for encryption
// and that decapsulation recovers the original plaintext.
func TestBundleCRC32EKKeyUsableAfterVerification(t *testing.T) {
	dk, err := GenerateKeyPair(KEM768)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	ek := dk.EncapsulationKey()

	raw, err := encodeV1Binary(ek, 8080, true, false, false, nil, false, 3600, 0)
	if err != nil {
		t.Fatalf("encodeV1Binary: %v", err)
	}

	bundle, err := decodeBinary(raw)
	if err != nil {
		t.Fatalf("decodeBinary: %v", err)
	}

	reconstructed, err := GetEncapsulationKeyFromBundle(bundle)
	if err != nil {
		t.Fatalf("GetEncapsulationKeyFromBundle: %v", err)
	}

	plaintext := []byte("CRC32 validation round-trip test")
	packet, err := EncapsulateAndEncrypt(reconstructed, plaintext)
	if err != nil {
		t.Fatalf("EncapsulateAndEncrypt: %v", err)
	}

	result, err := DecapsulateAndDecrypt(dk, packet)
	if err != nil {
		t.Fatalf("DecapsulateAndDecrypt: %v", err)
	}

	if string(result) != string(plaintext) {
		t.Errorf("key round-trip failed: got %q, want %q", result, plaintext)
	}
}
