// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package crypto

import (
	"crypto/rand"
	"testing"
)

func TestBundleWithWindowRoundTrip(t *testing.T) {
	dk, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	ek := dk.EncapsulationKey()

	seed := make([]byte, 8)
	rand.Read(seed)

	// Create bundle with custom window
	b64, err := CreateExportBundleWithWindow(ek, 0, true, false, false, seed, true, 7200, 300)
	if err != nil {
		t.Fatalf("CreateExportBundleWithWindow: %v", err)
	}

	bundle, err := ParseExportBundle(b64, "")
	if err != nil {
		t.Fatalf("ParseExportBundle: %v", err)
	}

	if bundle.DynPortWindow != 300 {
		t.Errorf("DynPortWindow = %d, want 300", bundle.DynPortWindow)
	}
	if bundle.DefaultOpenDuration != 7200 {
		t.Errorf("DefaultOpenDuration = %d, want 7200", bundle.DefaultOpenDuration)
	}
	if !bundle.DynamicPort {
		t.Error("DynamicPort = false, want true")
	}
	if !bundle.AllowCustomOpenDuration {
		t.Error("AllowCustomOpenDuration = false, want true")
	}

	// Verify key round-trip
	rekEK, err := GetEncapsulationKeyFromBundle(bundle)
	if err != nil {
		t.Fatalf("GetEncapsulationKeyFromBundle: %v", err)
	}

	plaintext := []byte("test round trip with window")
	packet, err := EncapsulateAndEncrypt(rekEK, plaintext)
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

func TestBundleDefaultWindowCompatibility(t *testing.T) {
	// Test that bundles created with the new format (window field) can be parsed
	// and that the window value is correctly read
	dk, _ := GenerateKeyPair()
	ek := dk.EncapsulationKey()
	seed := make([]byte, 8)
	rand.Read(seed)

	// Create with window=0 (default marker)
	raw, err := encodeV1Binary(ek, 0, false, false, false, seed, true, 3600, 0)
	if err != nil {
		t.Fatalf("encodeV1Binary: %v", err)
	}

	bundle, err := decodeBinary(raw)
	if err != nil {
		t.Fatalf("decodeBinary: %v", err)
	}

	// Window=0 means "use default" - the user-code should interpret 0 as 600
	if bundle.DynPortWindow != 0 {
		t.Errorf("DynPortWindow = %d, want 0 (caller decides default)", bundle.DynPortWindow)
	}
}

func TestBundleWindowVariousValues(t *testing.T) {
	dk, _ := GenerateKeyPair()
	ek := dk.EncapsulationKey()
	seed := make([]byte, 8)
	rand.Read(seed)

	for _, window := range []int{60, 120, 300, 600, 900, 3600, 86400} {
		raw, err := encodeV1Binary(ek, 0, true, false, true, seed, true, 3600, window)
		if err != nil {
			t.Fatalf("encodeV1Binary(window=%d): %v", window, err)
		}

		bundle, err := decodeBinary(raw)
		if err != nil {
			t.Fatalf("decodeBinary(window=%d): %v", window, err)
		}

		if bundle.DynPortWindow != window {
			t.Errorf("window=%d: got DynPortWindow=%d", window, bundle.DynPortWindow)
		}
	}
}

func TestBundleStaticPortWithWindow(t *testing.T) {
	dk, _ := GenerateKeyPair()
	ek := dk.EncapsulationKey()

	// Static port bundle with window field - window is meaningless but should survive
	raw, err := encodeV1Binary(ek, 12345, true, true, false, nil, false, 3600, 300)
	if err != nil {
		t.Fatalf("encodeV1Binary: %v", err)
	}

	bundle, err := decodeBinary(raw)
	if err != nil {
		t.Fatalf("decodeBinary: %v", err)
	}

	if bundle.Port != 12345 {
		t.Errorf("Port = %d, want 12345", bundle.Port)
	}
	if bundle.DynamicPort {
		t.Error("DynamicPort should be false")
	}
	if bundle.DynPortWindow != 300 {
		t.Errorf("DynPortWindow = %d, want 300", bundle.DynPortWindow)
	}
}

func TestBundleEncryptedWithWindow(t *testing.T) {
	dk, _ := GenerateKeyPair()
	ek := dk.EncapsulationKey()
	seed := make([]byte, 8)
	rand.Read(seed)

	password := "test-password-456"

	b64, err := CreateEncryptedExportBundleWithWindow(ek, 0, true, false, false, password, seed, true, 3600, 900)
	if err != nil {
		t.Fatalf("CreateEncryptedExportBundleWithWindow: %v", err)
	}

	// Wrong password should fail
	_, err = ParseExportBundle(b64, "wrong")
	if err == nil {
		t.Error("expected error with wrong password")
	}

	// Correct password
	bundle, err := ParseExportBundle(b64, password)
	if err != nil {
		t.Fatalf("ParseExportBundle: %v", err)
	}

	if bundle.DynPortWindow != 900 {
		t.Errorf("DynPortWindow = %d, want 900", bundle.DynPortWindow)
	}
	if !bundle.DynamicPort {
		t.Error("DynamicPort = false, want true")
	}
	if bundle.DefaultOpenDuration != 3600 {
		t.Errorf("DefaultOpenDuration = %d, want 3600", bundle.DefaultOpenDuration)
	}
}

func TestBundleRawWithWindow(t *testing.T) {
	dk, _ := GenerateKeyPair()
	ek := dk.EncapsulationKey()
	seed := make([]byte, 8)
	rand.Read(seed)

	raw, err := CreateExportBundleRawWithWindow(ek, 0, false, false, false, seed, true, 1800, 120)
	if err != nil {
		t.Fatalf("CreateExportBundleRawWithWindow: %v", err)
	}

	// Raw bundles have "SK" prefix + zlib compressed data - use ParseExportBundleRaw
	bundle, err := ParseExportBundleRaw(raw, "")
	if err != nil {
		t.Fatalf("ParseExportBundleRaw: %v", err)
	}

	if bundle.DynPortWindow != 120 {
		t.Errorf("DynPortWindow = %d, want 120", bundle.DynPortWindow)
	}
}

func TestBundleSeedPreserved(t *testing.T) {
	dk, _ := GenerateKeyPair()
	ek := dk.EncapsulationKey()

	seed := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE}

	raw, _ := encodeV1Binary(ek, 0, false, false, false, seed, true, 3600, 600)
	bundle, err := decodeBinary(raw)
	if err != nil {
		t.Fatalf("decodeBinary: %v", err)
	}

	if len(bundle.PortSeed) != 8 {
		t.Fatalf("PortSeed length = %d, want 8", len(bundle.PortSeed))
	}
	for i, b := range seed {
		if bundle.PortSeed[i] != b {
			t.Errorf("PortSeed[%d] = 0x%02X, want 0x%02X", i, bundle.PortSeed[i], b)
		}
	}
}
