// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package crypto

import (
	"bytes"
	"crypto/mlkem"
	"encoding/pem"
	"os"
	"strings"
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	dk, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	if dk == nil {
		t.Fatal("GenerateKeyPair returned nil")
	}

	// Verify seed size
	seed := dk.Bytes()
	if len(seed) != DecapsulationSeedSize {
		t.Errorf("seed length = %d, want %d", len(seed), DecapsulationSeedSize)
	}

	// Verify encapsulation key size
	ek := dk.EncapsulationKey()
	ekBytes := ek.Bytes()
	if len(ekBytes) != EncapsulationKeySize {
		t.Errorf("encapsulation key length = %d, want %d", len(ekBytes), EncapsulationKeySize)
	}
}

func TestSaveLoadPrivateKey(t *testing.T) {
	dk, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	path := t.TempDir() + "/test.key"
	if err := SavePrivateKey(path, dk); err != nil {
		t.Fatalf("SavePrivateKey: %v", err)
	}

	dk2, err := LoadPrivateKey(path)
	if err != nil {
		t.Fatalf("LoadPrivateKey: %v", err)
	}

	// Seeds should match
	if !bytes.Equal(dk.Bytes(), dk2.Bytes()) {
		t.Error("loaded private key seed does not match original")
	}
}

func TestSaveLoadPublicKey(t *testing.T) {
	dk, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	path := t.TempDir() + "/test.crt"
	if err := SavePublicKey(path, dk); err != nil {
		t.Fatalf("SavePublicKey: %v", err)
	}

	ek, err := LoadPublicKey(path)
	if err != nil {
		t.Fatalf("LoadPublicKey: %v", err)
	}

	// Encapsulation keys should match
	original := dk.EncapsulationKey().Bytes()
	loaded := ek.Bytes()
	if !bytes.Equal(original, loaded) {
		t.Error("loaded public key does not match original")
	}
}

func TestEncapsulateDecapsulate(t *testing.T) {
	dk, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	ek := dk.EncapsulationKey()

	plaintext := []byte(`{"test": "hello world", "data": 12345}`)

	// Encrypt
	packet, err := EncapsulateAndEncrypt(ek, plaintext)
	if err != nil {
		t.Fatalf("EncapsulateAndEncrypt: %v", err)
	}

	// Verify packet size
	// Should be: ciphertext(1568) + nonce(12) + encrypted payload + tag(16)
	minSize := CiphertextSize + 12 + len(plaintext) + 16
	if len(packet) < minSize {
		t.Errorf("packet size %d < expected minimum %d", len(packet), minSize)
	}

	// Decrypt
	result, err := DecapsulateAndDecrypt(dk, packet)
	if err != nil {
		t.Fatalf("DecapsulateAndDecrypt: %v", err)
	}

	if !bytes.Equal(plaintext, result) {
		t.Errorf("decrypted = %s, want %s", result, plaintext)
	}
}

func TestEncryptDecryptWrongKey(t *testing.T) {
	dk1, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	dk2, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	ek1 := dk1.EncapsulationKey()
	plaintext := []byte("secret data")

	// Encrypt with key 1
	packet, err := EncapsulateAndEncrypt(ek1, plaintext)
	if err != nil {
		t.Fatalf("EncapsulateAndEncrypt: %v", err)
	}

	// Try to decrypt with key 2 - should fail
	_, err = DecapsulateAndDecrypt(dk2, packet)
	if err == nil {
		t.Error("expected decryption to fail with wrong key")
	}
}

func TestEncryptDecryptTampered(t *testing.T) {
	dk, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	ek := dk.EncapsulationKey()

	packet, err := EncapsulateAndEncrypt(ek, []byte("important data"))
	if err != nil {
		t.Fatalf("EncapsulateAndEncrypt: %v", err)
	}

	// Tamper with the encrypted payload (last byte)
	packet[len(packet)-1] ^= 0xFF

	_, err = DecapsulateAndDecrypt(dk, packet)
	if err == nil {
		t.Error("expected decryption to fail with tampered packet")
	}
}

func TestSymmetricEncryptDecrypt(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	plaintext := []byte("symmetric test data")

	encrypted, err := SymmetricEncrypt(key, plaintext)
	if err != nil {
		t.Fatalf("SymmetricEncrypt: %v", err)
	}

	decrypted, err := SymmetricDecrypt(key, encrypted)
	if err != nil {
		t.Fatalf("SymmetricDecrypt: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("decrypted = %s, want %s", decrypted, plaintext)
	}
}

func TestSymmetricDecryptWrongKey(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	key2[0] = 1

	encrypted, err := SymmetricEncrypt(key1, []byte("data"))
	if err != nil {
		t.Fatalf("SymmetricEncrypt: %v", err)
	}

	_, err = SymmetricDecrypt(key2, encrypted)
	if err == nil {
		t.Error("expected decryption to fail with wrong key")
	}
}

func TestPacketTooSmall(t *testing.T) {
	dk, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	_, err = DecapsulateAndDecrypt(dk, []byte("too small"))
	if err == nil {
		t.Error("expected error for too-small packet")
	}
}

func TestKeyReconstructFromSeed(t *testing.T) {
	dk, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	seed := dk.Bytes()

	// Reconstruct from seed
	raw, err := mlkem.NewDecapsulationKey1024(seed)
	if err != nil {
		t.Fatalf("NewDecapsulationKey1024: %v", err)
	}
	dk2 := &dk1024{raw}

	// Both should produce same encapsulation key
	ek1 := dk.EncapsulationKey().Bytes()
	ek2 := dk2.EncapsulationKey().Bytes()
	if !bytes.Equal(ek1, ek2) {
		t.Error("reconstructed key does not match original")
	}
}

func TestMultipleEncapsulations(t *testing.T) {
	dk, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	ek := dk.EncapsulationKey()

	// Each encapsulation should produce different ciphertext
	// Encapsulate returns (ciphertext, sharedKey) -- sharedKey is intentionally discarded here.
	ct1, _ := ek.Encapsulate()
	ct2, _ := ek.Encapsulate()

	if bytes.Equal(ct1, ct2) {
		t.Error("two encapsulations produced identical ciphertext (should be randomized)")
	}
}

// ---------------------------------------------------------------------------
// PEM error paths
// ---------------------------------------------------------------------------

func TestLoadPrivateKeyInvalidPEM(t *testing.T) {
	path := t.TempDir() + "/garbage.key"
	os.WriteFile(path, []byte("this is not PEM"), 0600)

	_, err := LoadPrivateKey(path)
	if err == nil {
		t.Error("expected error for invalid PEM")
	}
	if !strings.Contains(err.Error(), "invalid PEM") {
		t.Errorf("error should mention invalid PEM, got: %v", err)
	}
}

func TestLoadPrivateKeyWrongPEMType(t *testing.T) {
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: make([]byte, 64)}
	path := t.TempDir() + "/wrong_type.key"
	os.WriteFile(path, pem.EncodeToMemory(block), 0600)

	_, err := LoadPrivateKey(path)
	if err == nil {
		t.Error("expected error for wrong PEM type")
	}
	if !strings.Contains(err.Error(), "unexpected PEM type") {
		t.Errorf("error should mention unexpected PEM type, got: %v", err)
	}
}

func TestLoadPublicKeyInvalidPEM(t *testing.T) {
	path := t.TempDir() + "/garbage.crt"
	os.WriteFile(path, []byte("not pem data"), 0644)

	_, err := LoadPublicKey(path)
	if err == nil {
		t.Error("expected error for invalid PEM")
	}
}

func TestLoadPublicKeyWrongPEMType(t *testing.T) {
	block := &pem.Block{Type: "RSA PUBLIC KEY", Bytes: make([]byte, 1184)}
	path := t.TempDir() + "/wrong_type.crt"
	os.WriteFile(path, pem.EncodeToMemory(block), 0644)

	_, err := LoadPublicKey(path)
	if err == nil {
		t.Error("expected error for wrong PEM type")
	}
}

func TestLoadPrivateKeyNonexistent(t *testing.T) {
	_, err := LoadPrivateKey("/nonexistent/path/key.pem")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

// ---------------------------------------------------------------------------
// Symmetric edge cases
// ---------------------------------------------------------------------------

func TestSymmetricDecryptTooShort(t *testing.T) {
	key := make([]byte, 32)
	_, err := SymmetricDecrypt(key, []byte{1, 2, 3})
	if err == nil {
		t.Error("expected error for too-short ciphertext")
	}
	if !strings.Contains(err.Error(), "too short") {
		t.Errorf("error should mention too short, got: %v", err)
	}
}
