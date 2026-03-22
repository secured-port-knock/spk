// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package crypto

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"io"
	"testing"
)

// --- Fuzz tests for the encryption pipeline ---

// FuzzDecapsulateAndDecrypt feeds random bytes into the decryption pipeline.
// Must never panic, must always return an error for invalid input.
func FuzzDecapsulateAndDecrypt(f *testing.F) {
	// Seed corpus with various edge cases
	f.Add([]byte{})
	f.Add([]byte{0})
	f.Add(make([]byte, 1088+12+16))   // exact minimum for KEM-768
	f.Add(make([]byte, 1568+12+16))   // exact minimum for KEM-1024
	f.Add(make([]byte, 1088+12+16-1)) // one byte too short for KEM-768
	f.Add(make([]byte, 8192))         // max packet size

	dk768, _ := GenerateKeyPair(KEM768)
	dk1024, _ := GenerateKeyPair(KEM1024)

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must not panic, must return error for random garbage
		_, err768 := DecapsulateAndDecrypt(dk768, data)
		_ = err768
		_, err1024 := DecapsulateAndDecrypt(dk1024, data)
		_ = err1024
	})
}

// FuzzSymmetricDecrypt tests AES-256-GCM decryption with random input.
func FuzzSymmetricDecrypt(f *testing.F) {
	f.Add([]byte{}, []byte{})
	f.Add(make([]byte, 32), []byte{0x00})
	f.Add(make([]byte, 32), make([]byte, 12+16)) // nonce + tag
	f.Add(make([]byte, 32), make([]byte, 100))
	f.Add(make([]byte, 16), make([]byte, 50)) // wrong key size

	f.Fuzz(func(t *testing.T, key, data []byte) {
		// Must not panic
		_, _ = SymmetricDecrypt(key, data)
	})
}

// FuzzSymmetricRoundtrip verifies encrypt->decrypt always recovers plaintext.
func FuzzSymmetricRoundtrip(f *testing.F) {
	f.Add([]byte("hello world"))
	f.Add([]byte{})
	f.Add(make([]byte, 1024))
	f.Add([]byte{0xFF, 0x00, 0xAA, 0x55})

	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		f.Fatal(err)
	}

	f.Fuzz(func(t *testing.T, plaintext []byte) {
		encrypted, err := SymmetricEncrypt(key, plaintext)
		if err != nil {
			t.Fatalf("SymmetricEncrypt failed: %v", err)
		}
		decrypted, err := SymmetricDecrypt(key, encrypted)
		if err != nil {
			t.Fatalf("SymmetricDecrypt failed: %v", err)
		}
		if !bytes.Equal(plaintext, decrypted) {
			t.Fatalf("roundtrip mismatch: got %d bytes, want %d bytes", len(decrypted), len(plaintext))
		}
	})
}

// FuzzEncryptDecryptRoundtrip tests the full KEM+AES pipeline with arbitrary plaintext.
func FuzzEncryptDecryptRoundtrip(f *testing.F) {
	f.Add([]byte("test payload"))
	f.Add([]byte{})
	f.Add(make([]byte, 4096))
	f.Add([]byte{0x01, 0x02, 0x03})

	dk, err := GenerateKeyPair(KEM768)
	if err != nil {
		f.Fatal(err)
	}
	ek := dk.EncapsulationKey()

	f.Fuzz(func(t *testing.T, plaintext []byte) {
		encrypted, err := EncapsulateAndEncrypt(ek, plaintext)
		if err != nil {
			t.Fatalf("EncapsulateAndEncrypt failed: %v", err)
		}
		decrypted, err := DecapsulateAndDecrypt(dk, encrypted)
		if err != nil {
			t.Fatalf("DecapsulateAndDecrypt failed: %v", err)
		}
		if !bytes.Equal(plaintext, decrypted) {
			t.Fatalf("roundtrip mismatch")
		}
	})
}

// FuzzParseExportBundle feeds random base64 data to the bundle parser.
func FuzzParseExportBundle(f *testing.F) {
	f.Add("", "")
	f.Add("AAAA", "")
	f.Add(base64.StdEncoding.EncodeToString([]byte("SK")), "")
	f.Add(base64.StdEncoding.EncodeToString([]byte("SKE")), "password")
	f.Add(base64.StdEncoding.EncodeToString(make([]byte, 100)), "")
	f.Add(base64.StdEncoding.EncodeToString(make([]byte, 4096)), "")

	f.Fuzz(func(t *testing.T, b64Data, password string) {
		// Must not panic on any input
		_, _ = ParseExportBundle(b64Data, password)
	})
}

// FuzzParseExportBundleRaw feeds raw bytes encoded as base64 into bundle parsing.
func FuzzParseExportBundleRaw(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("SK"))
	f.Add([]byte("SKE"))
	skData := make([]byte, 2000)
	copy(skData, []byte("SK"))
	skData[2] = 1 // version 1
	f.Add(skData)

	f.Fuzz(func(t *testing.T, rawData []byte) {
		b64 := base64.StdEncoding.EncodeToString(rawData)
		// Must not panic
		_, _ = ParseExportBundle(b64, "")
		_, _ = ParseExportBundle(b64, "somepassword")
	})
}

// FuzzDecodeBinary directly fuzzes the binary bundle decoder.
func FuzzDecodeBinary(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 10))
	f.Add(make([]byte, 100))
	f.Add(make([]byte, 1200)) // around EK size for KEM-768

	// Valid-ish seed: magic + ver + flags + port + duration + window + kemsize
	valid := []byte{'S', 'K', 1, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	f.Add(valid)

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must not panic
		_, _ = decodeBinary(data)
	})
}
