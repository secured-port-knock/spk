// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
// Package crypto handles ML-KEM key generation, storage, and management.
// Supports ML-KEM-768 (default, fits within 1500 MTU) and ML-KEM-1024.
package crypto

import (
	"crypto/mlkem"
	"encoding/pem"
	"fmt"
	"os"
)

// KEMSize represents the ML-KEM key size.
type KEMSize int

const (
	// KEM768 selects ML-KEM-768 (default). Packets fit within standard 1500-byte MTU.
	KEM768 KEMSize = 768
	// KEM1024 selects ML-KEM-1024. Packets exceed 1500-byte MTU and require IP fragmentation.
	KEM1024 KEMSize = 1024
)

// PEM type constants for each KEM size.
const (
	PrivateKeyPEMType768  = "MLKEM768 PRIVATE KEY"
	PublicKeyPEMType768   = "MLKEM768 PUBLIC KEY"
	PrivateKeyPEMType1024 = "MLKEM1024 PRIVATE KEY"
	PublicKeyPEMType1024  = "MLKEM1024 PUBLIC KEY"
)

// Deprecated: PrivateKeyPEMType defaults to ML-KEM-1024. Use PrivateKeyPEMType768
// or PrivateKeyPEMType1024 directly to be explicit about the key size.
const PrivateKeyPEMType = PrivateKeyPEMType1024

// Deprecated: PublicKeyPEMType defaults to ML-KEM-1024. Use PublicKeyPEMType768
// or PublicKeyPEMType1024 directly to be explicit about the key size.
const PublicKeyPEMType = PublicKeyPEMType1024

// Per-size constants.
const (
	EncapsulationKeySize768  = 1184
	CiphertextSize768        = 1088
	EncapsulationKeySize1024 = 1568
	CiphertextSize1024       = 1568

	DecapsulationSeedSize = 64 // Same for both sizes
	SharedKeySize         = 32 // Same for both sizes
)

// Deprecated: EncapsulationKeySize defaults to ML-KEM-1024. Use
// EncapsulationKeySize768 or EncapsulationKeySize1024 directly.
const EncapsulationKeySize = EncapsulationKeySize1024

// Deprecated: CiphertextSize defaults to ML-KEM-1024. Use CiphertextSize768
// or CiphertextSize1024 directly.
const CiphertextSize = CiphertextSize1024

// EncapsulationKeySizeFor returns the encapsulation key byte size for a KEM size.
func EncapsulationKeySizeFor(size KEMSize) int {
	switch size {
	case KEM768:
		return EncapsulationKeySize768
	default:
		return EncapsulationKeySize1024
	}
}

// CiphertextSizeFor returns the KEM ciphertext byte size for a KEM size.
func CiphertextSizeFor(size KEMSize) int {
	switch size {
	case KEM768:
		return CiphertextSize768
	default:
		return CiphertextSize1024
	}
}

// KEMSizeFromEKLength detects KEMSize from encapsulation key byte length.
func KEMSizeFromEKLength(length int) (KEMSize, error) {
	switch length {
	case EncapsulationKeySize768:
		return KEM768, nil
	case EncapsulationKeySize1024:
		return KEM1024, nil
	default:
		return 0, fmt.Errorf("unknown encapsulation key length: %d", length)
	}
}

// EncapsulationKey is a generic ML-KEM encapsulation (public) key interface.
type EncapsulationKey interface {
	Bytes() []byte
	Encapsulate() (sharedKey, ciphertext []byte)
	KEMSize() KEMSize
}

// DecapsulationKey is a generic ML-KEM decapsulation (private) key interface.
type DecapsulationKey interface {
	Bytes() []byte
	Decapsulate(ciphertext []byte) (sharedKey []byte, err error)
	EncapsulationKey() EncapsulationKey
	KEMSize() KEMSize
}

// --- ML-KEM-768 wrappers ---

type ek768 struct{ key *mlkem.EncapsulationKey768 }

func (e *ek768) Bytes() []byte                 { return e.key.Bytes() }
func (e *ek768) Encapsulate() ([]byte, []byte) { return e.key.Encapsulate() }
func (e *ek768) KEMSize() KEMSize              { return KEM768 }

type dk768 struct{ key *mlkem.DecapsulationKey768 }

func (d *dk768) Bytes() []byte                         { return d.key.Bytes() }
func (d *dk768) Decapsulate(ct []byte) ([]byte, error) { return d.key.Decapsulate(ct) }
func (d *dk768) EncapsulationKey() EncapsulationKey    { return &ek768{d.key.EncapsulationKey()} }
func (d *dk768) KEMSize() KEMSize                      { return KEM768 }

// --- ML-KEM-1024 wrappers ---

type ek1024 struct{ key *mlkem.EncapsulationKey1024 }

func (e *ek1024) Bytes() []byte                 { return e.key.Bytes() }
func (e *ek1024) Encapsulate() ([]byte, []byte) { return e.key.Encapsulate() }
func (e *ek1024) KEMSize() KEMSize              { return KEM1024 }

type dk1024 struct{ key *mlkem.DecapsulationKey1024 }

func (d *dk1024) Bytes() []byte                         { return d.key.Bytes() }
func (d *dk1024) Decapsulate(ct []byte) ([]byte, error) { return d.key.Decapsulate(ct) }
func (d *dk1024) EncapsulationKey() EncapsulationKey    { return &ek1024{d.key.EncapsulationKey()} }
func (d *dk1024) KEMSize() KEMSize                      { return KEM1024 }

// GenerateKeyPair generates a new ML-KEM keypair. Defaults to ML-KEM-1024
// when no size is provided, for backward compatibility.
func GenerateKeyPair(sizes ...KEMSize) (DecapsulationKey, error) {
	size := KEM1024
	if len(sizes) > 0 {
		size = sizes[0]
	}
	switch size {
	case KEM768:
		raw, err := mlkem.GenerateKey768()
		if err != nil {
			return nil, fmt.Errorf("generate ML-KEM-768 key: %w", err)
		}
		return &dk768{raw}, nil
	case KEM1024:
		raw, err := mlkem.GenerateKey1024()
		if err != nil {
			return nil, fmt.Errorf("generate ML-KEM-1024 key: %w", err)
		}
		return &dk1024{raw}, nil
	default:
		return nil, fmt.Errorf("unsupported KEM size: %d (supported: 768, 1024)", size)
	}
}

// pemPrivateType returns the PEM block type string for a private key of the given KEM size.
func pemPrivateType(size KEMSize) string {
	if size == KEM768 {
		return PrivateKeyPEMType768
	}
	return PrivateKeyPEMType1024
}

func pemPublicType(size KEMSize) string {
	if size == KEM768 {
		return PublicKeyPEMType768
	}
	return PublicKeyPEMType1024
}

// SavePrivateKey saves a decapsulation key to a PEM file.
func SavePrivateKey(path string, dk DecapsulationKey) error {
	seed := dk.Bytes() // 64-byte seed
	block := &pem.Block{
		Type:  pemPrivateType(dk.KEMSize()),
		Bytes: seed,
	}
	data := pem.EncodeToMemory(block)
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("save private key: %w", err)
	}
	return nil
}

// SavePublicKey saves an encapsulation key to a PEM file.
func SavePublicKey(path string, dk DecapsulationKey) error {
	ek := dk.EncapsulationKey()
	block := &pem.Block{
		Type:  pemPublicType(dk.KEMSize()),
		Bytes: ek.Bytes(),
	}
	data := pem.EncodeToMemory(block)
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("save public key: %w", err)
	}
	return nil
}

// LoadPrivateKey loads a decapsulation key from a PEM file.
// Automatically detects KEM size from the PEM type header.
func LoadPrivateKey(path string) (DecapsulationKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("invalid PEM data in %s", path)
	}
	switch block.Type {
	case PrivateKeyPEMType768:
		raw, err := mlkem.NewDecapsulationKey768(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse ML-KEM-768 private key: %w", err)
		}
		return &dk768{raw}, nil
	case PrivateKeyPEMType1024:
		raw, err := mlkem.NewDecapsulationKey1024(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse ML-KEM-1024 private key: %w", err)
		}
		return &dk1024{raw}, nil
	default:
		return nil, fmt.Errorf("unexpected PEM type: %s (expected %s or %s)", block.Type, PrivateKeyPEMType768, PrivateKeyPEMType1024)
	}
}

// LoadPublicKey loads an encapsulation key from a PEM file.
// Automatically detects KEM size from the PEM type header.
func LoadPublicKey(path string) (EncapsulationKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read public key: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("invalid PEM data in %s", path)
	}
	switch block.Type {
	case PublicKeyPEMType768:
		raw, err := mlkem.NewEncapsulationKey768(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse ML-KEM-768 public key: %w", err)
		}
		return &ek768{raw}, nil
	case PublicKeyPEMType1024:
		raw, err := mlkem.NewEncapsulationKey1024(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse ML-KEM-1024 public key: %w", err)
		}
		return &ek1024{raw}, nil
	default:
		return nil, fmt.Errorf("unexpected PEM type: %s (expected %s or %s)", block.Type, PublicKeyPEMType768, PublicKeyPEMType1024)
	}
}

// LoadPublicKeyBytes parses an encapsulation key from raw bytes.
// Requires explicit KEM size since raw bytes have no header.
func LoadPublicKeyBytes(data []byte, sizes ...KEMSize) (EncapsulationKey, error) {
	// Auto-detect from data length if no size specified
	size := KEM1024
	if len(sizes) > 0 {
		size = sizes[0]
	} else {
		detected, err := KEMSizeFromEKLength(len(data))
		if err == nil {
			size = detected
		}
	}
	switch size {
	case KEM768:
		raw, err := mlkem.NewEncapsulationKey768(data)
		if err != nil {
			return nil, fmt.Errorf("parse ML-KEM-768 encapsulation key: %w", err)
		}
		return &ek768{raw}, nil
	default:
		raw, err := mlkem.NewEncapsulationKey1024(data)
		if err != nil {
			return nil, fmt.Errorf("parse ML-KEM-1024 encapsulation key: %w", err)
		}
		return &ek1024{raw}, nil
	}
}
