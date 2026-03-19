// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package crypto

import (
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
	dk, _ := GenerateKeyPair()
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
	dk, _ := GenerateKeyPair()
	ek := dk.EncapsulationKey()

	b64, _ := CreateExportBundle(ek, 11111, false, false, false)

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
