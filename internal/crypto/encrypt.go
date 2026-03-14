// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

// EncapsulateAndEncrypt encrypts plaintext using ML-KEM KEM + AES-256-GCM.
// Works with any supported KEM size (768 or 1024).
// Returns (kemCiphertext || aesNonce || aesEncryptedPayload).
func EncapsulateAndEncrypt(ek EncapsulationKey, plaintext []byte) ([]byte, error) {
	// Step 1: KEM encapsulate -> (sharedKey, ciphertext)
	sharedKey, ciphertext := ek.Encapsulate()

	// Step 2: AES-256-GCM encrypt with the shared key
	block, err := aes.NewCipher(sharedKey)
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	// Generate random nonce
	nonce := make([]byte, gcm.NonceSize()) // 12 bytes
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	// Encrypt (appends auth tag to ciphertext)
	encrypted := gcm.Seal(nil, nonce, plaintext, nil)

	// Step 3: Assemble packet: [KEM ciphertext] [AES nonce (12)] [AES ciphertext+tag]
	packet := make([]byte, 0, len(ciphertext)+len(nonce)+len(encrypted))
	packet = append(packet, ciphertext...)
	packet = append(packet, nonce...)
	packet = append(packet, encrypted...)

	return packet, nil
}

// DecapsulateAndDecrypt decrypts a packet using ML-KEM KEM + AES-256-GCM.
// Automatically uses the correct ciphertext size based on the key's KEM size.
// Expects input format: [KEM ciphertext] [AES nonce (12)] [AES ciphertext+tag].
func DecapsulateAndDecrypt(dk DecapsulationKey, packet []byte) ([]byte, error) {
	ctSize := CiphertextSizeFor(dk.KEMSize())

	// Minimum size: KEM ciphertext + AES nonce + at least AES tag
	minSize := ctSize + 12 + 16
	if len(packet) < minSize {
		return nil, fmt.Errorf("packet too small: %d bytes (minimum %d for ML-KEM-%d)", len(packet), minSize, dk.KEMSize())
	}

	// Step 1: Extract KEM ciphertext
	kemCiphertext := packet[:ctSize]
	remaining := packet[ctSize:]

	// Step 2: KEM decapsulate -> sharedKey
	sharedKey, err := dk.Decapsulate(kemCiphertext)
	if err != nil {
		return nil, fmt.Errorf("KEM decapsulate: %w", err)
	}

	// Step 3: AES-256-GCM decrypt
	block, err := aes.NewCipher(sharedKey)
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(remaining) < nonceSize+gcm.Overhead() {
		return nil, fmt.Errorf("invalid encrypted payload size")
	}

	aesNonce := remaining[:nonceSize]
	aesCiphertext := remaining[nonceSize:]

	plaintext, err := gcm.Open(nil, aesNonce, aesCiphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM decrypt (authentication failed - wrong key or tampered packet): %w", err)
	}

	return plaintext, nil
}

// SymmetricEncrypt encrypts plaintext with a 32-byte key using AES-256-GCM.
func SymmetricEncrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	// Return nonce + ciphertext+tag
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// SymmetricDecrypt decrypts data encrypted by SymmetricEncrypt.
func SymmetricDecrypt(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize+gcm.Overhead() {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce := data[:nonceSize]
	ciphertext := data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}
