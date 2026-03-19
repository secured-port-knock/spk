// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package crypto

import (
	"bytes"
	"compress/zlib"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"os"

	qrcode "github.com/skip2/go-qrcode"
	"golang.org/x/crypto/argon2"
)

// ExportBundle contains server public key and metadata for client provisioning.
type ExportBundle struct {
	Version                 int    `json:"v"`
	EncapsulationKey        string `json:"ek"` // base64-encoded key (1184 or 1568 bytes)
	Port                    int    `json:"p"`  // Server knock port
	AllowCustomOpenDuration bool   `json:"ct"` // Can client set open duration?
	AllowCustomPort         bool   `json:"cp"` // Can client choose port?
	AllowOpenAll            bool   `json:"oa"` // Can client open all?
	PortSeed                []byte `json:"-"`  // 8-byte seed for dynamic port
	DynamicPort             bool   `json:"-"`  // Dynamic port enabled
	DefaultOpenDuration     int    `json:"-"`  // Default open duration seconds
	DynPortWindow           int    `json:"-"`  // Port rotation period in seconds (0 = default 600)
	KEMSize                 int    `json:"-"`  // ML-KEM key size (768 or 1024)
}

// bundleMagic identifies a compressed binary bundle.
var bundleMagic = []byte("SK")

// encMagic identifies an encrypted binary bundle.
var encMagic = []byte("SKE")

const (
	argon2Time    = 3
	argon2Memory  = 64 * 1024 // 64 MB
	argon2Threads = 4
	argon2KeyLen  = 32
	saltSize      = 32
)

// CreateExportBundle creates a base64-encoded compact bundle for client provisioning.
// Uses binary format with zlib compression for QR code compatibility.
func CreateExportBundle(ek EncapsulationKey, port int, customDuration, customPort, openAll bool) (string, error) {
	return CreateExportBundleWithWindow(ek, port, customDuration, customPort, openAll, nil, false, 0, 0)
}

// CreateExportBundleWithWindow creates a compact binary bundle with all metadata including custom rotation window.
func CreateExportBundleWithWindow(ek EncapsulationKey, port int, customDuration, customPort, openAll bool,
	portSeed []byte, dynamicPort bool, defaultOpenDuration int, dynPortWindow int) (string, error) {

	raw, err := encodeV1Binary(ek, port, customDuration, customPort, openAll, portSeed, dynamicPort, defaultOpenDuration, dynPortWindow)
	if err != nil {
		return "", err
	}

	compressed, err := zlibCompress(raw)
	if err != nil {
		return "", fmt.Errorf("compress bundle: %w", err)
	}

	// Prepend magic outside compression so ParseExportBundle can detect format
	output := make([]byte, len(bundleMagic)+len(compressed))
	copy(output, bundleMagic)
	copy(output[len(bundleMagic):], compressed)

	return base64.StdEncoding.EncodeToString(output), nil
}

// CreateExportBundleRawWithWindow returns the raw compressed binary with custom rotation window (for QR codes).
func CreateExportBundleRawWithWindow(ek EncapsulationKey, port int, customDuration, customPort, openAll bool,
	portSeed []byte, dynamicPort bool, defaultOpenDuration int, dynPortWindow int) ([]byte, error) {

	raw, err := encodeV1Binary(ek, port, customDuration, customPort, openAll, portSeed, dynamicPort, defaultOpenDuration, dynPortWindow)
	if err != nil {
		return nil, err
	}

	compressed, err := zlibCompress(raw)
	if err != nil {
		return nil, fmt.Errorf("compress bundle: %w", err)
	}

	// Prepend magic so ParseExportBundleRaw can detect format
	output := make([]byte, len(bundleMagic)+len(compressed))
	copy(output, bundleMagic)
	copy(output[len(bundleMagic):], compressed)

	return output, nil
}

// encodeV1Binary creates the raw v1 binary bundle.
// Format: "SK"(2) + ver(1=1) + flags(1) + [port(2)|seed(8)] + open_duration(4) + window(4) + kem_size(2) + ek(variable)
func encodeV1Binary(ek EncapsulationKey, port int, customDuration, customPort, openAll bool,
	portSeed []byte, dynamicPort bool, defaultOpenDuration int, dynPortWindow int) ([]byte, error) {

	var buf bytes.Buffer

	// Magic + version
	buf.Write(bundleMagic) // "SK"
	buf.WriteByte(1)       // version 1

	// Flags (1 byte)
	var flags byte
	if customDuration {
		flags |= 0x01
	}
	if customPort {
		flags |= 0x02
	}
	if openAll {
		flags |= 0x04
	}
	if dynamicPort {
		flags |= 0x08
	}
	buf.WriteByte(flags)

	// If dynamic port: write 8-byte seed (no static port needed)
	// If static port: write 2-byte port (no seed needed)
	if dynamicPort {
		seed := make([]byte, 8)
		if len(portSeed) >= 8 {
			copy(seed, portSeed[:8])
		} else if len(portSeed) > 0 {
			copy(seed, portSeed)
		}
		buf.Write(seed)
	} else {
		portBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(portBytes, uint16(port))
		buf.Write(portBytes)
	}

	// Default open duration (4 bytes big-endian)
	toBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(toBytes, uint32(defaultOpenDuration))
	buf.Write(toBytes)

	// Dynamic port window (4 bytes big-endian, 0 = default 600s)
	wBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(wBytes, uint32(dynPortWindow))
	buf.Write(wBytes)

	// KEM size (2 bytes big-endian)
	kemSize := int(ek.KEMSize())
	ksBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(ksBytes, uint16(kemSize))
	buf.Write(ksBytes)

	// Encapsulation key (variable size: 1184 for 768, 1568 for 1024)
	ekBytes := ek.Bytes()
	buf.Write(ekBytes)

	return buf.Bytes(), nil
}

// decodeBinary parses a v1 binary bundle (after decompression).
// Format: "SK"(2) + ver(1=1) + flags(1) + [port(2) | seed(8)] + open_duration(4) + window(4) + kem_size(2) + ek(variable)
func decodeBinary(data []byte) (*ExportBundle, error) {
	// Minimum size: magic(2) + ver(1) + flags(1) + port(2) + open_duration(4) = 10 + some EK
	if len(data) < 10 {
		return nil, fmt.Errorf("bundle too short: %d bytes", len(data))
	}

	r := bytes.NewReader(data)

	// Skip magic (already verified by caller)
	magic := make([]byte, 2)
	if _, err := io.ReadFull(r, magic); err != nil {
		return nil, fmt.Errorf("read magic: %w", err)
	}

	// Version
	ver, err := r.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("read version: %w", err)
	}
	if ver != 1 {
		return nil, fmt.Errorf("unsupported bundle version: %d (expected 1)", ver)
	}

	// Flags
	flags, err := r.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("read flags: %w", err)
	}
	customDuration := flags&0x01 != 0
	customPort := flags&0x02 != 0
	openAll := flags&0x04 != 0
	dynPort := flags&0x08 != 0

	var port int
	var seed []byte

	if dynPort {
		// Dynamic port: read 8-byte seed
		seed = make([]byte, 8)
		if _, err := io.ReadFull(r, seed); err != nil {
			return nil, fmt.Errorf("read seed: %w", err)
		}
	} else {
		// Static port: read 2-byte port
		portBytes := make([]byte, 2)
		if _, err := io.ReadFull(r, portBytes); err != nil {
			return nil, fmt.Errorf("read port: %w", err)
		}
		port = int(binary.BigEndian.Uint16(portBytes))
	}

	// Default open duration
	toBytes := make([]byte, 4)
	if _, err := io.ReadFull(r, toBytes); err != nil {
		return nil, fmt.Errorf("read open_duration: %w", err)
	}
	defOpenDuration := int(binary.BigEndian.Uint32(toBytes))

	var dynWindow int
	var kemSize int

	// v1: always has window + kem_size fields
	wBytes := make([]byte, 4)
	if _, err := io.ReadFull(r, wBytes); err != nil {
		return nil, fmt.Errorf("read window: %w", err)
	}
	dynWindow = int(binary.BigEndian.Uint32(wBytes))

	ksBytes := make([]byte, 2)
	if _, err := io.ReadFull(r, ksBytes); err != nil {
		return nil, fmt.Errorf("read kem_size: %w", err)
	}
	kemSize = int(binary.BigEndian.Uint16(ksBytes))

	// Determine expected EK size
	ekSize := EncapsulationKeySizeFor(KEMSize(kemSize))

	// Encapsulation key
	ekBytes := make([]byte, ekSize)
	n, err := io.ReadFull(r, ekBytes)
	if err != nil || n != ekSize {
		return nil, fmt.Errorf("read encapsulation key: got %d bytes, want %d", n, ekSize)
	}

	bundle := &ExportBundle{
		Version:                 int(ver),
		EncapsulationKey:        base64.StdEncoding.EncodeToString(ekBytes),
		Port:                    port,
		AllowCustomOpenDuration: customDuration,
		AllowCustomPort:         customPort,
		AllowOpenAll:            openAll,
		PortSeed:                seed,
		DynamicPort:             dynPort,
		DefaultOpenDuration:     defOpenDuration,
		DynPortWindow:           dynWindow,
		KEMSize:                 kemSize,
	}
	return bundle, nil
}

// zlibCompress compresses data using zlib.
func zlibCompress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, err := zlib.NewWriterLevel(&buf, zlib.BestCompression)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(data); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// maxDecompressedSize limits decompressed bundle size to prevent memory exhaustion.
// A v1 binary bundle with ML-KEM-1024 is ~1580 bytes uncompressed; 16 KB is generous.
const maxDecompressedSize = 16 * 1024

// zlibDecompress decompresses zlib data with a size limit.
// Rejects decompressed output exceeding maxDecompressedSize to prevent
// memory pressure from malicious compressed payloads (zip bomb defense).
func zlibDecompress(data []byte) ([]byte, error) {
	r, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	limited := io.LimitReader(r, maxDecompressedSize+1)
	result, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if len(result) > maxDecompressedSize {
		return nil, fmt.Errorf("decompressed bundle exceeds %d bytes (possible zip bomb)", maxDecompressedSize)
	}
	return result, nil
}

// CreateEncryptedExportBundle creates a password-encrypted base64-encoded bundle.
// Uses Argon2id for key derivation (PQC-safe symmetric algorithm) + AES-256-GCM.
func CreateEncryptedExportBundle(ek EncapsulationKey, port int, customDuration, customPort, openAll bool, password string) (string, error) {
	return CreateEncryptedExportBundleWithWindow(ek, port, customDuration, customPort, openAll, password, nil, false, 0, 0)
}

// CreateEncryptedExportBundleWithWindow creates a password-encrypted bundle with custom rotation window.
func CreateEncryptedExportBundleWithWindow(ek EncapsulationKey, port int, customDuration, customPort, openAll bool,
	password string, portSeed []byte, dynamicPort bool, defaultOpenDuration int, dynPortWindow int) (string, error) {

	// First create the raw v1 binary bundle
	raw, err := encodeV1Binary(ek, port, customDuration, customPort, openAll, portSeed, dynamicPort, defaultOpenDuration, dynPortWindow)
	if err != nil {
		return "", err
	}

	compressed, err := zlibCompress(raw)
	if err != nil {
		return "", fmt.Errorf("compress bundle: %w", err)
	}

	// Generate salt
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}

	// Derive key using Argon2id (quantum-resistant KDF)
	key := argon2.IDKey([]byte(password), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)

	// Encrypt with AES-256-GCM
	encrypted, err := SymmetricEncrypt(key, compressed)
	if err != nil {
		return "", fmt.Errorf("encrypt bundle: %w", err)
	}

	// Encrypted binary: "SKE" + salt(32) + encrypted(nonce+ciphertext+tag)
	var encBuf bytes.Buffer
	encBuf.Write(encMagic) // "SKE"
	encBuf.Write(salt)
	encBuf.Write(encrypted)

	return base64.StdEncoding.EncodeToString(encBuf.Bytes()), nil
}

// ParseExportBundle parses a base64-encoded export bundle.
// Supports compressed binary and encrypted formats.
// If encrypted, password is required.
func ParseExportBundle(b64Data string, password string) (*ExportBundle, error) {
	data, err := base64.StdEncoding.DecodeString(b64Data)
	if err != nil {
		return nil, fmt.Errorf("invalid base64: %w", err)
	}

	// Detect format from first bytes
	if len(data) >= 3 && string(data[:3]) == "SKE" {
		// Encrypted bundle
		return parseEncrypted(data, password)
	}
	if len(data) >= 2 && string(data[:2]) == "SK" {
		// Compressed binary (starts with "SK" but NOT "SKE")
		// Skip the 2-byte magic prefix before decompressing
		decompressed, err := zlibDecompress(data[2:])
		if err != nil {
			return nil, fmt.Errorf("decompress bundle: %w", err)
		}
		return decodeBinary(decompressed)
	}

	return nil, fmt.Errorf("unrecognized bundle format")
}

// parseEncrypted decrypts an encrypted bundle.
func parseEncrypted(data []byte, password string) (*ExportBundle, error) {
	if password == "" {
		return nil, fmt.Errorf("bundle is encrypted - password required")
	}

	// Format: "SKE"(3) + salt(32) + encrypted_data(variable)
	if len(data) < 3+saltSize+12+16 {
		return nil, fmt.Errorf("encrypted bundle too short")
	}

	salt := data[3 : 3+saltSize]
	encData := data[3+saltSize:]

	key := argon2.IDKey([]byte(password), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)

	compressed, err := SymmetricDecrypt(key, encData)
	if err != nil {
		return nil, fmt.Errorf("decrypt failed - wrong password or corrupted data: %w", err)
	}

	decompressed, err := zlibDecompress(compressed)
	if err != nil {
		return nil, fmt.Errorf("decompress decrypted bundle: %w", err)
	}

	return decodeBinary(decompressed)
}

// ExportToFile writes the bundle to a base64 file.
func ExportToFile(path string, b64Data string) error {
	return os.WriteFile(path, []byte(b64Data), 0600)
}

// ImportFromFile reads a base64 bundle from file.
func ImportFromFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// GenerateQRCode generates a QR code PNG from raw binary bundle data.
// Uses Medium error correction since raw binary is compact enough.
func GenerateQRCode(rawData []byte, outputPath string) error {
	qr, err := qrcode.New(string(rawData), qrcode.Medium)
	if err != nil {
		// Fall back to Low EC if Medium doesn't fit
		qr, err = qrcode.New(string(rawData), qrcode.Low)
		if err != nil {
			return fmt.Errorf("generate QR code: %w (data size: %d bytes)", err, len(rawData))
		}
	}
	if err := qr.WriteFile(512, outputPath); err != nil {
		return fmt.Errorf("write QR code: %w", err)
	}
	// Restrict permissions -- QR may contain the server public key.
	if err := os.Chmod(outputPath, 0600); err != nil {
		return fmt.Errorf("chmod QR file: %w", err)
	}
	return nil
}

// PrintQRCodeToConsole prints a QR code to stdout using Unicode block characters.
// Works in most modern terminals (xterm, PuTTY, Windows Terminal, pure TTY).
// Uses Medium error correction since raw binary is compact.
func PrintQRCodeToConsole(rawData []byte) error {
	qr, err := qrcode.New(string(rawData), qrcode.Medium)
	if err != nil {
		// Fall back to Low EC
		qr, err = qrcode.New(string(rawData), qrcode.Low)
		if err != nil {
			return fmt.Errorf("generate QR: %w", err)
		}
	}

	// Use ToSmallString which uses Unicode half-block characters
	art := qr.ToSmallString(false)
	if art != "" {
		fmt.Println("\n--- QR Code (scan with phone) ---")
		fmt.Print(art)
		fmt.Println("--- End QR ---")
		return nil
	}

	// Fallback: use the bitmap directly for pure ASCII terminals
	bitmap := qr.Bitmap()
	fmt.Println("\n--- QR Code (scan with phone) ---")
	for _, row := range bitmap {
		for _, cell := range row {
			if cell {
				fmt.Print("##")
			} else {
				fmt.Print("  ")
			}
		}
		fmt.Println()
	}
	fmt.Println("--- End QR ---")
	return nil
}

// ParseExportBundleRaw parses raw binary bundle data (e.g., from QR code scan).
func ParseExportBundleRaw(data []byte, password string) (*ExportBundle, error) {
	// Detect format from first bytes
	if len(data) >= 3 && string(data[:3]) == "SKE" {
		return parseEncrypted(data, password)
	}
	if len(data) >= 2 && string(data[:2]) == "SK" {
		decompressed, err := zlibDecompress(data[2:])
		if err != nil {
			return nil, fmt.Errorf("decompress bundle: %w", err)
		}
		return decodeBinary(decompressed)
	}
	return nil, fmt.Errorf("unrecognized binary bundle format")
}

// GetEncapsulationKeyFromBundle extracts and parses the ML-KEM encapsulation key.
// Automatically selects the correct KEM size based on the bundle's KEMSize field.
func GetEncapsulationKeyFromBundle(bundle *ExportBundle) (EncapsulationKey, error) {
	ekBytes, err := base64.StdEncoding.DecodeString(bundle.EncapsulationKey)
	if err != nil {
		return nil, fmt.Errorf("decode encapsulation key: %w", err)
	}
	kemSize := KEMSize(bundle.KEMSize)
	if kemSize == 0 {
		kemSize = KEM1024 // default fallback
	}
	return LoadPublicKeyBytes(ekBytes, kemSize)
}
