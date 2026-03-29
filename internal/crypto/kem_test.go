// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package crypto

import (
	"os"
	"path/filepath"
	"testing"
)

// =============================================================================
// Multi-KEM Key Generation
// =============================================================================

func TestGenerateKeyPair768(t *testing.T) {
	dk, err := GenerateKeyPair(KEM768)
	if err != nil {
		t.Fatalf("GenerateKeyPair(KEM768): %v", err)
	}
	if dk.KEMSize() != KEM768 {
		t.Errorf("KEMSize() = %d, want %d", dk.KEMSize(), KEM768)
	}
	ek := dk.EncapsulationKey()
	if len(ek.Bytes()) != EncapsulationKeySize768 {
		t.Errorf("EK size = %d, want %d", len(ek.Bytes()), EncapsulationKeySize768)
	}
	if ek.KEMSize() != KEM768 {
		t.Errorf("EK KEMSize() = %d, want %d", ek.KEMSize(), KEM768)
	}
	if len(dk.Bytes()) != DecapsulationSeedSize {
		t.Errorf("DK seed size = %d, want %d", len(dk.Bytes()), DecapsulationSeedSize)
	}
}

func TestGenerateKeyPair1024(t *testing.T) {
	dk, err := GenerateKeyPair(KEM1024)
	if err != nil {
		t.Fatalf("GenerateKeyPair(KEM1024): %v", err)
	}
	if dk.KEMSize() != KEM1024 {
		t.Errorf("KEMSize() = %d, want %d", dk.KEMSize(), KEM1024)
	}
	ek := dk.EncapsulationKey()
	if len(ek.Bytes()) != EncapsulationKeySize1024 {
		t.Errorf("EK size = %d, want %d", len(ek.Bytes()), EncapsulationKeySize1024)
	}
	if ek.KEMSize() != KEM1024 {
		t.Errorf("EK KEMSize() = %d, want %d", ek.KEMSize(), KEM1024)
	}
}

func TestGenerateKeyPairDefaultIs1024(t *testing.T) {
	// No size argument = backward-compatible default = KEM1024
	dk, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair(): %v", err)
	}
	if dk.KEMSize() != KEM1024 {
		t.Errorf("default KEMSize() = %d, want %d (KEM1024)", dk.KEMSize(), KEM1024)
	}
}

func TestGenerateKeyPairUnsupportedSize(t *testing.T) {
	_, err := GenerateKeyPair(KEMSize(512))
	if err == nil {
		t.Error("expected error for unsupported KEM size 512")
	}
}

// =============================================================================
// Multi-KEM Encrypt/Decrypt Round Trip
// =============================================================================

func TestEncryptDecryptRoundTrip768(t *testing.T) {
	dk, err := GenerateKeyPair(KEM768)
	if err != nil {
		t.Fatalf("GenerateKeyPair(KEM768): %v", err)
	}
	ek := dk.EncapsulationKey()

	plaintext := []byte(`{"command":"open-t22","ip":"192.168.1.1","timeout":3600}`)
	packet, err := EncapsulateAndEncrypt(ek, plaintext)
	if err != nil {
		t.Fatalf("EncapsulateAndEncrypt: %v", err)
	}

	// Verify packet size (KEM-768 ciphertext + nonce + AES overhead + payload)
	minSize := CiphertextSize768 + 12 + 16 + len(plaintext)
	if len(packet) < minSize {
		t.Errorf("packet too small: %d < %d", len(packet), minSize)
	}

	result, err := DecapsulateAndDecrypt(dk, packet)
	if err != nil {
		t.Fatalf("DecapsulateAndDecrypt: %v", err)
	}

	if string(result) != string(plaintext) {
		t.Errorf("round-trip mismatch: got %q, want %q", result, plaintext)
	}
}

func TestEncryptDecryptRoundTrip1024(t *testing.T) {
	dk, err := GenerateKeyPair(KEM1024)
	if err != nil {
		t.Fatalf("GenerateKeyPair(KEM1024): %v", err)
	}
	ek := dk.EncapsulationKey()

	plaintext := []byte(`{"command":"open-t443","ip":"10.0.0.1"}`)
	packet, err := EncapsulateAndEncrypt(ek, plaintext)
	if err != nil {
		t.Fatalf("EncapsulateAndEncrypt: %v", err)
	}

	minSize := CiphertextSize1024 + 12 + 16 + len(plaintext)
	if len(packet) < minSize {
		t.Errorf("packet too small: %d < %d", len(packet), minSize)
	}

	result, err := DecapsulateAndDecrypt(dk, packet)
	if err != nil {
		t.Fatalf("DecapsulateAndDecrypt: %v", err)
	}

	if string(result) != string(plaintext) {
		t.Errorf("round-trip mismatch: got %q, want %q", result, plaintext)
	}
}

func TestCrossKEMDecryptFails(t *testing.T) {
	// A packet encrypted with KEM-768 key should NOT decrypt with a KEM-1024 key
	dk768, err := GenerateKeyPair(KEM768)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	dk1024, err := GenerateKeyPair(KEM1024)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	plaintext := []byte("test data")
	packet, err := EncapsulateAndEncrypt(dk768.EncapsulationKey(), plaintext)
	if err != nil {
		t.Fatalf("EncapsulateAndEncrypt: %v", err)
	}

	_, err = DecapsulateAndDecrypt(dk1024, packet)
	if err == nil {
		t.Error("expected error decrypting KEM-768 packet with KEM-1024 key")
	}
}

func TestCrossKEMDecryptFails1024To768(t *testing.T) {
	// A packet encrypted with KEM-1024 key should NOT decrypt with a KEM-768 key
	dk768, err := GenerateKeyPair(KEM768)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	dk1024, err := GenerateKeyPair(KEM1024)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	plaintext := []byte("test data")
	packet, err := EncapsulateAndEncrypt(dk1024.EncapsulationKey(), plaintext)
	if err != nil {
		t.Fatalf("EncapsulateAndEncrypt: %v", err)
	}

	_, err = DecapsulateAndDecrypt(dk768, packet)
	if err == nil {
		t.Error("expected error decrypting KEM-1024 packet with KEM-768 key")
	}
}

// =============================================================================
// Packet Size / MTU Verification
// =============================================================================

func TestKEM768PacketFitsMTU(t *testing.T) {
	dk, err := GenerateKeyPair(KEM768)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	ek := dk.EncapsulationKey()

	// Typical compact binary knock payload (version + flags + timestamp + nonce + ip + timeout + cmdlen + cmd)
	payload := make([]byte, 59) // 1+1+8+32+4+4+1+8 = 59 bytes for "open-t22" with IPv4
	payload[0] = 1              // version
	payload[1] = 0              // flags (IPv4, no TOTP, no padding)
	packet, err := EncapsulateAndEncrypt(ek, payload)
	if err != nil {
		t.Fatalf("EncapsulateAndEncrypt: %v", err)
	}

	// UDP payload must fit: IP header (20) + UDP header (8) + payload <=1500
	maxUDPPayload := 1500 - 20 - 8
	if len(packet) > maxUDPPayload {
		t.Errorf("KEM-768 packet exceeds MTU: %d bytes > %d max UDP payload", len(packet), maxUDPPayload)
	}

	t.Logf("KEM-768 packet size: %d bytes (max %d for 1500 MTU)", len(packet), maxUDPPayload)
}

func TestKEM1024PacketExceedsMTU(t *testing.T) {
	dk, err := GenerateKeyPair(KEM1024)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	ek := dk.EncapsulationKey()

	// Even an empty payload exceeds MTU with KEM-1024
	payload := []byte(`{"version":1,"client_ip":"192.168.1.100","command":"open-t22","timeout":3600,"timestamp":1700000000,"nonce":"abcdef1234567890"}`)
	packet, err := EncapsulateAndEncrypt(ek, payload)
	if err != nil {
		t.Fatalf("EncapsulateAndEncrypt: %v", err)
	}

	maxUDPPayload := 1500 - 20 - 8
	if len(packet) <= maxUDPPayload {
		t.Errorf("KEM-1024 packet unexpectedly fits in MTU: %d bytes <=%d", len(packet), maxUDPPayload)
	}

	t.Logf("KEM-1024 packet size: %d bytes (exceeds %d max UDP payload)", len(packet), maxUDPPayload)
}

// =============================================================================
// Save / Load Key PEM Detection
// =============================================================================

func TestSaveLoadPrivateKey768(t *testing.T) {
	dk, err := GenerateKeyPair(KEM768)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "private.pem")

	if err := SavePrivateKey(path, dk); err != nil {
		t.Fatalf("SavePrivateKey: %v", err)
	}

	// Verify PEM type
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !contains(string(data), "MLKEM768 PRIVATE KEY") {
		t.Error("PEM file should contain MLKEM768 PRIVATE KEY header")
	}

	loaded, err := LoadPrivateKey(path)
	if err != nil {
		t.Fatalf("LoadPrivateKey: %v", err)
	}
	if loaded.KEMSize() != KEM768 {
		t.Errorf("loaded key KEMSize = %d, want 768", loaded.KEMSize())
	}

	// Verify key material matches
	if string(loaded.Bytes()) != string(dk.Bytes()) {
		t.Error("loaded private key seed doesn't match original")
	}
}

func TestSaveLoadPrivateKey1024(t *testing.T) {
	dk, err := GenerateKeyPair(KEM1024)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "private.pem")

	if err := SavePrivateKey(path, dk); err != nil {
		t.Fatalf("SavePrivateKey: %v", err)
	}

	// Verify PEM type
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !contains(string(data), "MLKEM1024 PRIVATE KEY") {
		t.Error("PEM file should contain MLKEM1024 PRIVATE KEY header")
	}

	loaded, err := LoadPrivateKey(path)
	if err != nil {
		t.Fatalf("LoadPrivateKey: %v", err)
	}
	if loaded.KEMSize() != KEM1024 {
		t.Errorf("loaded key KEMSize = %d, want 1024", loaded.KEMSize())
	}
}

func TestSaveLoadPublicKey768(t *testing.T) {
	dk, err := GenerateKeyPair(KEM768)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "public.pem")

	if err := SavePublicKey(path, dk); err != nil {
		t.Fatalf("SavePublicKey: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !contains(string(data), "MLKEM768 PUBLIC KEY") {
		t.Error("PEM file should contain MLKEM768 PUBLIC KEY header")
	}

	loaded, err := LoadPublicKey(path)
	if err != nil {
		t.Fatalf("LoadPublicKey: %v", err)
	}
	if loaded.KEMSize() != KEM768 {
		t.Errorf("loaded key KEMSize = %d, want 768", loaded.KEMSize())
	}
}

func TestSaveLoadPublicKey1024(t *testing.T) {
	dk, err := GenerateKeyPair(KEM1024)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "public.pem")

	if err := SavePublicKey(path, dk); err != nil {
		t.Fatalf("SavePublicKey: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !contains(string(data), "MLKEM1024 PUBLIC KEY") {
		t.Error("PEM file should contain MLKEM1024 PUBLIC KEY header")
	}

	loaded, err := LoadPublicKey(path)
	if err != nil {
		t.Fatalf("LoadPublicKey: %v", err)
	}
	if loaded.KEMSize() != KEM1024 {
		t.Errorf("loaded key KEMSize = %d, want 1024", loaded.KEMSize())
	}
}

func TestSaveLoadRoundTrip768(t *testing.T) {
	// Generate, save, load, encrypt, decrypt - full round trip with KEM-768
	dk, err := GenerateKeyPair(KEM768)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	dir := t.TempDir()
	privPath := filepath.Join(dir, "priv.pem")
	pubPath := filepath.Join(dir, "pub.pem")

	SavePrivateKey(privPath, dk)
	SavePublicKey(pubPath, dk)

	loadedDK, err := LoadPrivateKey(privPath)
	if err != nil {
		t.Fatalf("LoadPrivateKey: %v", err)
	}
	loadedEK, err := LoadPublicKey(pubPath)
	if err != nil {
		t.Fatalf("LoadPublicKey: %v", err)
	}

	plaintext := []byte("test payload for KEM-768 save/load round trip")
	packet, err := EncapsulateAndEncrypt(loadedEK, plaintext)
	if err != nil {
		t.Fatalf("EncapsulateAndEncrypt: %v", err)
	}
	result, err := DecapsulateAndDecrypt(loadedDK, packet)
	if err != nil {
		t.Fatalf("DecapsulateAndDecrypt: %v", err)
	}
	if string(result) != string(plaintext) {
		t.Errorf("round-trip mismatch: got %q, want %q", result, plaintext)
	}
}

// =============================================================================
// LoadPublicKeyBytes Auto-Detection
// =============================================================================

func TestLoadPublicKeyBytesAutoDetect768(t *testing.T) {
	dk, err := GenerateKeyPair(KEM768)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	ekBytes := dk.EncapsulationKey().Bytes()

	// No explicit size - should auto-detect from length
	loaded, err := LoadPublicKeyBytes(ekBytes)
	if err != nil {
		t.Fatalf("LoadPublicKeyBytes: %v", err)
	}
	if loaded.KEMSize() != KEM768 {
		t.Errorf("auto-detected KEMSize = %d, want 768", loaded.KEMSize())
	}
}

func TestLoadPublicKeyBytesAutoDetect1024(t *testing.T) {
	dk, err := GenerateKeyPair(KEM1024)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	ekBytes := dk.EncapsulationKey().Bytes()

	loaded, err := LoadPublicKeyBytes(ekBytes)
	if err != nil {
		t.Fatalf("LoadPublicKeyBytes: %v", err)
	}
	if loaded.KEMSize() != KEM1024 {
		t.Errorf("auto-detected KEMSize = %d, want 1024", loaded.KEMSize())
	}
}

func TestLoadPublicKeyBytesExplicitSize(t *testing.T) {
	dk, err := GenerateKeyPair(KEM768)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	ekBytes := dk.EncapsulationKey().Bytes()

	// Explicit KEM768 size
	loaded, err := LoadPublicKeyBytes(ekBytes, KEM768)
	if err != nil {
		t.Fatalf("LoadPublicKeyBytes(KEM768): %v", err)
	}
	if loaded.KEMSize() != KEM768 {
		t.Errorf("KEMSize = %d, want 768", loaded.KEMSize())
	}
}

// =============================================================================
// Helper Functions
// =============================================================================

func TestKEMSizeFromEKLength(t *testing.T) {
	tests := []struct {
		length  int
		want    KEMSize
		wantErr bool
	}{
		{EncapsulationKeySize768, KEM768, false},
		{EncapsulationKeySize1024, KEM1024, false},
		{0, 0, true},
		{1000, 0, true},
		{2048, 0, true},
	}
	for _, tt := range tests {
		got, err := KEMSizeFromEKLength(tt.length)
		if (err != nil) != tt.wantErr {
			t.Errorf("KEMSizeFromEKLength(%d) error = %v, wantErr = %v", tt.length, err, tt.wantErr)
			continue
		}
		if got != tt.want {
			t.Errorf("KEMSizeFromEKLength(%d) = %d, want %d", tt.length, got, tt.want)
		}
	}
}

func TestEncapsulationKeySizeFor(t *testing.T) {
	if EncapsulationKeySizeFor(KEM768) != 1184 {
		t.Errorf("EncapsulationKeySizeFor(768) = %d, want 1184", EncapsulationKeySizeFor(KEM768))
	}
	if EncapsulationKeySizeFor(KEM1024) != 1568 {
		t.Errorf("EncapsulationKeySizeFor(1024) = %d, want 1568", EncapsulationKeySizeFor(KEM1024))
	}
}

func TestCiphertextSizeFor(t *testing.T) {
	if CiphertextSizeFor(KEM768) != 1088 {
		t.Errorf("CiphertextSizeFor(768) = %d, want 1088", CiphertextSizeFor(KEM768))
	}
	if CiphertextSizeFor(KEM1024) != 1568 {
		t.Errorf("CiphertextSizeFor(1024) = %d, want 1568", CiphertextSizeFor(KEM1024))
	}
}

// contains is a simple string search helper for tests.
func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
