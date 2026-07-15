// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package crypto

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"math"
	"os"

	qrcode "github.com/skip2/go-qrcode"
	"golang.org/x/crypto/argon2"
)

// toUint16 narrows an int to uint16, returning an error if it does not fit.
// Used at the bundle wire-encoding boundaries so each narrowing conversion is
// explicitly range-checked rather than relying on upstream validation.
func toUint16(name string, v int) (uint16, error) {
	if v < 0 || v > math.MaxUint16 {
		return 0, fmt.Errorf("%s (%d) does not fit in a uint16", name, v)
	}
	return uint16(v), nil
}

// toUint32 narrows an int to uint32, returning an error if it does not fit.
// Same rationale as toUint16.
func toUint32(name string, v int) (uint32, error) {
	if v < 0 || v > math.MaxUint32 {
		return 0, fmt.Errorf("%s (%d) does not fit in a uint32", name, v)
	}
	return uint32(v), nil
}

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
	DynPortMin              int    `json:"-"`  // Dynamic port range lower bound, inclusive (0 = default 10000)
	DynPortMax              int    `json:"-"`  // Dynamic port range upper bound, inclusive (0 = default 65000)
}

// bundleMagic identifies a binary activation bundle.
var bundleMagic = []byte("SPK")

// encMagic identifies an encrypted binary bundle.
var encMagic = []byte("SPKE")

// bundleVersion is the current activation bundle format version. Version 2
// made the dynamic port range an inclusive, always-present field; version 1
// bundles are rejected with a re-export hint.
const bundleVersion = 2

const (
	argon2Time    = 3
	argon2Memory  = 64 * 1024 // 64 MB
	argon2Threads = 4
	argon2KeyLen  = 32
	saltSize      = 32
	crc32Size     = 4 // CRC32/IEEE checksum appended at end of raw binary bundle
)

// CreateExportBundle creates a base64-encoded compact bundle for client provisioning.
// Uses compact binary format; ML-KEM encapsulation keys are near-random and do not compress.
func CreateExportBundle(ek EncapsulationKey, port int, customDuration, customPort, openAll bool) (string, error) {
	return CreateExportBundleWithWindow(ek, port, customDuration, customPort, openAll, nil, false, 0, 0)
}

// CreateExportBundleWithWindow creates a compact binary bundle with all metadata including custom rotation window.
func CreateExportBundleWithWindow(ek EncapsulationKey, port int, customDuration, customPort, openAll bool,
	portSeed []byte, dynamicPort bool, defaultOpenDuration int, dynPortWindow int) (string, error) {
	return CreateExportBundleWithRange(ek, port, customDuration, customPort, openAll,
		portSeed, dynamicPort, defaultOpenDuration, dynPortWindow, 0, 0)
}

// CreateExportBundleWithRange creates a compact binary bundle including the
// dynamic port range (both bounds inclusive). Pass 0, 0 to use the defaults.
func CreateExportBundleWithRange(ek EncapsulationKey, port int, customDuration, customPort, openAll bool,
	portSeed []byte, dynamicPort bool, defaultOpenDuration int, dynPortWindow int, dynPortMin, dynPortMax int) (string, error) {

	raw, err := encodeBinary(ek, port, customDuration, customPort, openAll, portSeed, dynamicPort, defaultOpenDuration, dynPortWindow, dynPortMin, dynPortMax)
	if err != nil {
		return "", err
	}

	// encodeBinary already includes the "SPK" magic prefix.
	return base64.StdEncoding.EncodeToString(raw), nil
}

// CreateExportBundleRawWithWindow returns the raw binary with custom rotation window (for QR codes).
func CreateExportBundleRawWithWindow(ek EncapsulationKey, port int, customDuration, customPort, openAll bool,
	portSeed []byte, dynamicPort bool, defaultOpenDuration int, dynPortWindow int) ([]byte, error) {
	return CreateExportBundleRawWithRange(ek, port, customDuration, customPort, openAll,
		portSeed, dynamicPort, defaultOpenDuration, dynPortWindow, 0, 0)
}

// CreateExportBundleRawWithRange returns the raw binary including the dynamic
// port range (for QR codes). Pass 0, 0 to use the defaults.
func CreateExportBundleRawWithRange(ek EncapsulationKey, port int, customDuration, customPort, openAll bool,
	portSeed []byte, dynamicPort bool, defaultOpenDuration int, dynPortWindow int, dynPortMin, dynPortMax int) ([]byte, error) {

	raw, err := encodeBinary(ek, port, customDuration, customPort, openAll, portSeed, dynamicPort, defaultOpenDuration, dynPortWindow, dynPortMin, dynPortMax)
	if err != nil {
		return nil, err
	}

	// encodeBinary already includes the "SPK" magic prefix.
	return raw, nil
}

// CreateEncryptedExportBundleRawWithWindow returns a password-encrypted raw binary bundle (for QR codes).
// Uses the same SPKE format as the base64 variant but returns raw bytes instead of base64.
func CreateEncryptedExportBundleRawWithWindow(ek EncapsulationKey, port int, customDuration, customPort, openAll bool,
	password string, portSeed []byte, dynamicPort bool, defaultOpenDuration int, dynPortWindow int) ([]byte, error) {
	return CreateEncryptedExportBundleRawWithRange(ek, port, customDuration, customPort, openAll,
		password, portSeed, dynamicPort, defaultOpenDuration, dynPortWindow, 0, 0)
}

// CreateEncryptedExportBundleRawWithRange returns a password-encrypted raw
// binary bundle including the dynamic port range (for QR codes).
func CreateEncryptedExportBundleRawWithRange(ek EncapsulationKey, port int, customDuration, customPort, openAll bool,
	password string, portSeed []byte, dynamicPort bool, defaultOpenDuration int, dynPortWindow int, dynPortMin, dynPortMax int) ([]byte, error) {

	raw, err := encodeBinary(ek, port, customDuration, customPort, openAll, portSeed, dynamicPort, defaultOpenDuration, dynPortWindow, dynPortMin, dynPortMax)
	if err != nil {
		return nil, err
	}

	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}

	key := argon2.IDKey([]byte(password), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)

	encrypted, err := SymmetricEncrypt(key, raw)
	if err != nil {
		return nil, fmt.Errorf("encrypt bundle: %w", err)
	}

	// "SPKE" + salt(32) + encrypted(nonce+ciphertext+tag)
	var buf bytes.Buffer
	buf.Write(encMagic) // "SPKE"
	buf.Write(salt)
	buf.Write(encrypted)

	return buf.Bytes(), nil
}

// encodeBinary creates the raw v2 binary bundle.
// Format: "SPK"(3) + ver(1=2) + flags(1) + [port(2)|seed(8)] + open_duration(4) + window(4)
//   - [range_min(2) + range_max(2), dynamic bundles only, both inclusive]
//   - kem_size(2) + ek(variable) + crc32(4)
//
// The final 4 bytes are a CRC32/IEEE checksum (big-endian) of all preceding bytes.
func encodeBinary(ek EncapsulationKey, port int, customDuration, customPort, openAll bool,
	portSeed []byte, dynamicPort bool, defaultOpenDuration int, dynPortWindow int, dynPortMin, dynPortMax int) ([]byte, error) {

	var buf bytes.Buffer

	// Magic + version
	buf.Write(bundleMagic) // "SPK"
	buf.WriteByte(bundleVersion)

	// Flags (1 byte); bits 4-7 are reserved and must stay zero.
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
		portU, err := toUint16("listen port", port)
		if err != nil {
			return nil, err
		}
		portBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(portBytes, portU)
		buf.Write(portBytes)
	}

	// Default open duration (4 bytes big-endian)
	durU, err := toUint32("open duration", defaultOpenDuration)
	if err != nil {
		return nil, err
	}
	toBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(toBytes, durU)
	buf.Write(toBytes)

	// Dynamic port window (4 bytes big-endian, 0 = default 600s)
	winU, err := toUint32("dynamic port window", dynPortWindow)
	if err != nil {
		return nil, err
	}
	wBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(wBytes, winU)
	buf.Write(wBytes)

	// Dynamic port range (2 + 2 bytes big-endian, dynamic bundles only).
	// Both bounds inclusive; unset or invalid input falls back to the defaults.
	if dynamicPort {
		nMin, nMax := NormalizeDynPortRange(dynPortMin, dynPortMax)
		minU, err := toUint16("dynamic_port_min", nMin)
		if err != nil {
			return nil, err
		}
		maxU, err := toUint16("dynamic_port_max", nMax)
		if err != nil {
			return nil, err
		}
		rBytes := make([]byte, 4)
		binary.BigEndian.PutUint16(rBytes[:2], minU)
		binary.BigEndian.PutUint16(rBytes[2:], maxU)
		buf.Write(rBytes)
	}

	// KEM size (2 bytes big-endian)
	kemU, err := toUint16("kem size", int(ek.KEMSize()))
	if err != nil {
		return nil, err
	}
	ksBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(ksBytes, kemU)
	buf.Write(ksBytes)

	// Encapsulation key (variable size: 1184 for 768, 1568 for 1024)
	ekBytes := ek.Bytes()
	buf.Write(ekBytes)

	// CRC32/IEEE checksum (4 bytes, big-endian) over all preceding bytes.
	// Allows the parser to detect corruption or unintended modification in transit.
	payload := buf.Bytes()
	checksum := crc32.ChecksumIEEE(payload)
	crcBytes := make([]byte, crc32Size)
	binary.BigEndian.PutUint32(crcBytes, checksum)
	buf.Write(crcBytes)

	return buf.Bytes(), nil
}

// readBundleHeader consumes and validates the magic, version, and flags bytes,
// returning the flags. Version 1 bundles are rejected with a re-export hint;
// reserved flag bits (4-7) must be zero.
func readBundleHeader(r *bytes.Reader) (byte, error) {
	magic := make([]byte, 3)
	if _, err := io.ReadFull(r, magic); err != nil {
		return 0, fmt.Errorf("read magic: %w", err)
	}
	ver, err := r.ReadByte()
	if err != nil {
		return 0, fmt.Errorf("read version: %w", err)
	}
	if ver == 1 {
		return 0, fmt.Errorf("bundle version 1 is no longer supported - re-export the activation bundle on the server (spk --server --export) and import the new one")
	}
	if ver != bundleVersion {
		return 0, fmt.Errorf("unsupported bundle version: %d (expected %d)", ver, bundleVersion)
	}
	flags, err := r.ReadByte()
	if err != nil {
		return 0, fmt.Errorf("read flags: %w", err)
	}
	if flags&0xF0 != 0 {
		return 0, fmt.Errorf("bundle has unknown flag bits set: 0x%02x", flags)
	}
	return flags, nil
}

// decodeBinary parses a v2 binary bundle (see encodeBinary for the layout).
// The final 4 bytes MUST be the CRC32/IEEE checksum (big-endian) of all preceding
// bytes; bundles missing it are rejected.
func decodeBinary(data []byte) (*ExportBundle, error) {
	// Minimum size: magic(3) + ver(1) + flags(1) + port(2) + open_duration(4) = 11 + some EK
	if len(data) < 11 {
		return nil, fmt.Errorf("bundle too short: %d bytes", len(data))
	}

	r := bytes.NewReader(data)
	flags, err := readBundleHeader(r)
	if err != nil {
		return nil, err
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

	// Dynamic port range: min(2) + max(2), big-endian, both inclusive.
	// Present for every dynamic-port bundle.
	var dynPortMin, dynPortMax int
	if dynPort {
		rBytes := make([]byte, 4)
		if _, err := io.ReadFull(r, rBytes); err != nil {
			return nil, fmt.Errorf("read port range: %w", err)
		}
		dynPortMin = int(binary.BigEndian.Uint16(rBytes[:2]))
		dynPortMax = int(binary.BigEndian.Uint16(rBytes[2:]))
		if dynPortMin < 1 || dynPortMin >= dynPortMax {
			return nil, fmt.Errorf("invalid port range in bundle: %d-%d", dynPortMin, dynPortMax)
		}
	}

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

	// CRC32 trailer (4 bytes, big-endian) MUST be present.
	// CRC32 covers all bytes preceding the 4-byte checksum field.
	if r.Len() != crc32Size {
		return nil, fmt.Errorf("bundle has %d trailing bytes after encapsulation key, want exactly %d (CRC32)", r.Len(), crc32Size)
	}
	crcBuf := make([]byte, crc32Size)
	if _, err := io.ReadFull(r, crcBuf); err != nil {
		return nil, fmt.Errorf("read crc32: %w", err)
	}
	storedCRC := binary.BigEndian.Uint32(crcBuf)
	actualCRC := crc32.ChecksumIEEE(data[:len(data)-crc32Size])
	if actualCRC != storedCRC {
		return nil, fmt.Errorf("bundle CRC32 mismatch: data corrupted or modified")
	}

	bundle := &ExportBundle{
		Version:                 bundleVersion,
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
		DynPortMin:              dynPortMin,
		DynPortMax:              dynPortMax,
	}
	return bundle, nil
}

// maxBundleRawSize caps the decoded size of any bundle input.
// A v1 binary bundle with ML-KEM-1024 is ~1594 bytes raw (including 4-byte CRC32);
// an encrypted wrapper adds ~75 bytes of overhead. 4 KB is a generous upper bound
// that still prevents large-allocation attacks from malformed input.
const maxBundleRawSize = 4 * 1024

// CreateEncryptedExportBundle creates a password-encrypted base64-encoded bundle.
// Uses Argon2id for key derivation (PQC-safe symmetric algorithm) + AES-256-GCM.
func CreateEncryptedExportBundle(ek EncapsulationKey, port int, customDuration, customPort, openAll bool, password string) (string, error) {
	return CreateEncryptedExportBundleWithWindow(ek, port, customDuration, customPort, openAll, password, nil, false, 0, 0)
}

// CreateEncryptedExportBundleWithWindow creates a password-encrypted bundle with custom rotation window.
func CreateEncryptedExportBundleWithWindow(ek EncapsulationKey, port int, customDuration, customPort, openAll bool,
	password string, portSeed []byte, dynamicPort bool, defaultOpenDuration int, dynPortWindow int) (string, error) {
	return CreateEncryptedExportBundleWithRange(ek, port, customDuration, customPort, openAll,
		password, portSeed, dynamicPort, defaultOpenDuration, dynPortWindow, 0, 0)
}

// CreateEncryptedExportBundleWithRange creates a password-encrypted bundle
// including the dynamic port range. Pass 0, 0 to use the defaults.
func CreateEncryptedExportBundleWithRange(ek EncapsulationKey, port int, customDuration, customPort, openAll bool,
	password string, portSeed []byte, dynamicPort bool, defaultOpenDuration int, dynPortWindow int, dynPortMin, dynPortMax int) (string, error) {

	// First create the raw v1 binary bundle
	raw, err := encodeBinary(ek, port, customDuration, customPort, openAll, portSeed, dynamicPort, defaultOpenDuration, dynPortWindow, dynPortMin, dynPortMax)
	if err != nil {
		return "", err
	}

	// Generate salt
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}

	// Derive key using Argon2id (quantum-resistant KDF)
	key := argon2.IDKey([]byte(password), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)

	// Encrypt with AES-256-GCM
	encrypted, err := SymmetricEncrypt(key, raw)
	if err != nil {
		return "", fmt.Errorf("encrypt bundle: %w", err)
	}

	// Encrypted binary: "SPKE" + salt(32) + encrypted(nonce+ciphertext+tag)
	var encBuf bytes.Buffer
	encBuf.Write(encMagic) // "SPKE"
	encBuf.Write(salt)
	encBuf.Write(encrypted)

	return base64.StdEncoding.EncodeToString(encBuf.Bytes()), nil
}

// ParseExportBundle parses a base64-encoded export bundle.
// Supports plain binary and encrypted formats.
// If encrypted, password is required.
func ParseExportBundle(b64Data string, password string) (*ExportBundle, error) {
	data, err := base64.StdEncoding.DecodeString(b64Data)
	if err != nil {
		return nil, fmt.Errorf("invalid base64: %w", err)
	}

	if len(data) > maxBundleRawSize {
		return nil, fmt.Errorf("bundle too large: %d bytes (max %d)", len(data), maxBundleRawSize)
	}

	// Detect format from first bytes
	if len(data) >= 4 && string(data[:4]) == "SPKE" {
		// Encrypted bundle
		return parseEncrypted(data, password)
	}
	if len(data) >= 3 && string(data[:3]) == "SPK" {
		// Plain binary bundle (starts with "SPK" but NOT "SPKE").
		// Pass the full data; decodeBinary reads and verifies the magic.
		return decodeBinary(data)
	}

	return nil, fmt.Errorf("unrecognized bundle format")
}

// parseEncrypted decrypts an encrypted bundle.
func parseEncrypted(data []byte, password string) (*ExportBundle, error) {
	if password == "" {
		return nil, fmt.Errorf("bundle is encrypted - password required")
	}

	// Format: "SPKE"(4) + salt(32) + encrypted_data(variable)
	if len(data) < 4+saltSize+12+16 {
		return nil, fmt.Errorf("encrypted bundle too short")
	}

	salt := data[4 : 4+saltSize]
	encData := data[4+saltSize:]

	key := argon2.IDKey([]byte(password), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)

	raw, err := SymmetricDecrypt(key, encData)
	if err != nil {
		return nil, fmt.Errorf("decrypt failed - wrong password or corrupted data: %w", err)
	}

	return decodeBinary(raw)
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
	if len(data) > maxBundleRawSize {
		return nil, fmt.Errorf("bundle too large: %d bytes (max %d)", len(data), maxBundleRawSize)
	}
	// Detect format from first bytes
	if len(data) >= 4 && string(data[:4]) == "SPKE" {
		return parseEncrypted(data, password)
	}
	if len(data) >= 3 && string(data[:3]) == "SPK" {
		// Plain binary bundle; decodeBinary reads and verifies the magic.
		return decodeBinary(data)
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
