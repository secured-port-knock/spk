// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
// Package protocol defines the knock packet format and anti-replay tracking.
package protocol

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"spk/internal/crypto"
)

const (
	// Binary payload flags
	flagIPv6    = 1 << 0 // ClientIP is 16 bytes (IPv6) instead of 4 (IPv4)
	flagTOTP    = 1 << 1 // 6-byte TOTP code follows command
	flagPadding = 1 << 2 // Random padding fills remaining bytes

	// Minimum binary payload: version(1) + flags(1) + timestamp(8) + nonce(32) + ipv4(4) + open_duration(4) + cmdlen(1) = 51
	minPayloadSize = 51
)

const (
	// ProtocolVersion is the current wire protocol version.
	// Commands use binary type byte (0=open, 1=close, 2=cust).
	ProtocolVersion = 1

	// NonceBytes is the size of the random nonce in knock payloads.
	NonceBytes = 32

	// MaxPacketSize is the maximum valid knock packet size.
	// Increased to accommodate anti-DPI garbage padding (up to ~1024 hex chars).
	MaxPacketSize = 8192
)

// Command type constants for binary encoding.
const (
	CmdTypeOpen  byte = 0x00 // open port(s)
	CmdTypeClose byte = 0x01 // close port(s)
	CmdTypeCust  byte = 0x02 // custom command
)

// KnockPayload is the plaintext content of a knock packet.
// Wire format is compact binary, not JSON.
type KnockPayload struct {
	Version      int    // Protocol version
	Timestamp    int64  // Unix timestamp (seconds)
	Nonce        string // Random hex nonce (anti-replay)
	ClientIP     string // Client's own IP address (anti-spoofing)
	Command      string // Command: "open-t22", "close-u53", "open-all", "close-all", "restart_ssh"
	OpenDuration int    // Requested open duration in seconds (0 = use default)
	TOTP         string // TOTP code for two-factor authentication
	Padding      string // Random hex padding (variable-size packets)
}

// PaddingConfig controls packet padding.
type PaddingConfig struct {
	Enabled  bool // Whether to add random padding
	MinBytes int  // Minimum padding bytes (default: 64)
	MaxBytes int  // Maximum padding bytes (default: 512)
}

// DefaultPaddingConfig returns padding config with sensible defaults.
func DefaultPaddingConfig() PaddingConfig {
	return PaddingConfig{
		Enabled:  false,
		MinBytes: 64,
		MaxBytes: 512,
	}
}

// KnockOptions holds optional parameters for building a knock packet.
type KnockOptions struct {
	Padding PaddingConfig // Padding configuration
	TOTP    string        // 6-digit TOTP code (empty = no TOTP)
}

// ValidateCommand checks that a command string is well-formed before sending.
// Accepted forms: open-<portspecs>, close-<portspecs>, cust-<id>
// Port specs: t<1-65535>, u<1-65535>, or "all"; comma-separated for batches.
// Custom command IDs must be printable ASCII (0x20-0x7E).
func ValidateCommand(cmd string) error {
	lower := strings.ToLower(cmd)
	switch {
	case strings.HasPrefix(lower, "open-"):
		return validatePortSpecs(lower[5:])
	case strings.HasPrefix(lower, "close-"):
		return validatePortSpecs(lower[6:])
	case strings.HasPrefix(lower, "cust-"):
		return validateASCII(cmd[5:]) // preserve original case for lookup
	default:
		return fmt.Errorf("unknown command prefix %q: must start with open-, close-, or cust-", cmd)
	}
}

func validatePortSpecs(specs string) error {
	if specs == "" {
		return fmt.Errorf("empty port specification")
	}
	if specs == "all" {
		return nil
	}
	parts := strings.Split(specs, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if part == "all" {
			continue
		}
		if len(part) < 2 {
			return fmt.Errorf("invalid port spec %q: too short", part)
		}
		prefix := part[0]
		if prefix != 't' && prefix != 'u' {
			return fmt.Errorf("invalid port spec %q: protocol must be 't' (TCP) or 'u' (UDP)", part)
		}
		portStr := part[1:]
		port := 0
		for _, c := range portStr {
			if c < '0' || c > '9' {
				return fmt.Errorf("invalid port spec %q: port number must be numeric", part)
			}
			port = port*10 + int(c-'0')
			if port > 65535 {
				return fmt.Errorf("invalid port spec %q: port exceeds 65535", part)
			}
		}
		if port < 1 {
			return fmt.Errorf("invalid port spec %q: port must be 1-65535", part)
		}
	}
	return nil
}

func validateASCII(s string) error {
	if len(s) == 0 {
		return fmt.Errorf("empty custom command ID")
	}
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b < 0x20 || b > 0x7E {
			return fmt.Errorf("custom command ID contains non-printable byte 0x%02x at position %d", b, i)
		}
	}
	return nil
}

// encodeCommandBinary converts a user-facing command string to binary type + data.
// "open-t22" -> (CmdTypeOpen, "t22")
// "close-all" -> (CmdTypeClose, "all")
// "cust-ping" -> (CmdTypeCust, "ping")
func encodeCommandBinary(cmd string) (byte, string, error) {
	lower := strings.ToLower(cmd)
	switch {
	case strings.HasPrefix(lower, "open-"):
		return CmdTypeOpen, cmd[5:], nil
	case strings.HasPrefix(lower, "close-"):
		return CmdTypeClose, cmd[6:], nil
	case strings.HasPrefix(lower, "cust-"):
		return CmdTypeCust, cmd[5:], nil
	}
	return 0xFF, "", fmt.Errorf("cannot encode command: %q", cmd)
}

// decodeCommandBinary reconstructs a user-facing command string from binary type + data.
func decodeCommandBinary(cmdType byte, cmdData string) (string, error) {
	switch cmdType {
	case CmdTypeOpen:
		return "open-" + cmdData, nil
	case CmdTypeClose:
		return "close-" + cmdData, nil
	case CmdTypeCust:
		return "cust-" + cmdData, nil
	}
	return "", fmt.Errorf("unsupported command type: 0x%02x", cmdType)
}

// BuildKnockPacket creates an encrypted knock packet for sending to the server.
// Options include padding for variable packet sizes and TOTP for two-factor auth.
func BuildKnockPacket(ek crypto.EncapsulationKey, clientIP, command string, openDuration int, opts ...KnockOptions) ([]byte, error) {
	// Generate random nonce
	nonceBytes := make([]byte, NonceBytes)
	if _, err := io.ReadFull(rand.Reader, nonceBytes); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	payload := KnockPayload{
		Version:      ProtocolVersion,
		Timestamp:    time.Now().Unix(),
		Nonce:        hex.EncodeToString(nonceBytes),
		ClientIP:     clientIP,
		Command:      command,
		OpenDuration: openDuration,
	}

	// Apply options
	if len(opts) > 0 {
		opt := opts[0]

		// TOTP code
		if opt.TOTP != "" {
			payload.TOTP = opt.TOTP
		}

		// Random padding
		if opt.Padding.Enabled {
			pc := opt.Padding
			minB := pc.MinBytes
			maxB := pc.MaxBytes
			if minB < 1 {
				minB = 64
			}
			if maxB < minB {
				maxB = minB + 256
			}
			padLen := minB
			if maxB > minB {
				var lenBuf [2]byte
				if _, err := io.ReadFull(rand.Reader, lenBuf[:]); err != nil {
					return nil, fmt.Errorf("generate padding length: %w", err)
				}
				padLen = minB + int(int(lenBuf[0])<<8|int(lenBuf[1]))%(maxB-minB+1)
			}
			padBytes := make([]byte, padLen)
			if _, err := io.ReadFull(rand.Reader, padBytes); err != nil {
				return nil, fmt.Errorf("generate padding: %w", err)
			}
			payload.Padding = hex.EncodeToString(padBytes)
		}
	}

	plaintext, err := encodePayload(&payload)
	if err != nil {
		return nil, fmt.Errorf("encode payload: %w", err)
	}

	// Encrypt with ML-KEM + AES-256-GCM
	packet, err := crypto.EncapsulateAndEncrypt(ek, plaintext)
	if err != nil {
		return nil, fmt.Errorf("encrypt knock: %w", err)
	}

	return packet, nil
}

// ParseKnockPacket decrypts and validates a knock packet.
// Returns the payload and nil error on success.
// sourceIP is the UDP source address for anti-spoofing verification.
// Set skipIPVerify to true to skip IP match check (e.g., when clients are behind NAT).
func ParseKnockPacket(dk crypto.DecapsulationKey, packet []byte, sourceIP string, timestampTolerance int64, skipIPVerify ...bool) (*KnockPayload, error) {
	if len(packet) > MaxPacketSize {
		return nil, fmt.Errorf("packet too large: %d bytes", len(packet))
	}

	// Decrypt
	plaintext, err := crypto.DecapsulateAndDecrypt(dk, packet)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	// Decode compact binary payload
	payload, err := decodePayload(plaintext)
	if err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}

	// Verify protocol version
	if payload.Version != ProtocolVersion {
		return nil, fmt.Errorf("unsupported protocol version: %d", payload.Version)
	}

	// Validate field lengths to prevent abuse
	if len(payload.Nonce) != NonceBytes*2 { // hex-encoded
		return nil, fmt.Errorf("invalid nonce length: %d", len(payload.Nonce))
	}
	if len(payload.Command) > 255 {
		return nil, fmt.Errorf("command too long: %d chars", len(payload.Command))
	}
	if len(payload.ClientIP) > 45 { // max IPv6 string length
		return nil, fmt.Errorf("client IP too long: %d", len(payload.ClientIP))
	}
	if payload.OpenDuration < 0 || payload.OpenDuration > 604800 { // max 7 days
		return nil, fmt.Errorf("open duration out of range: %d", payload.OpenDuration)
	}

	// Verify timestamp (anti-replay)
	now := time.Now().Unix()
	diff := now - payload.Timestamp
	if diff < 0 {
		diff = -diff
	}
	if diff > timestampTolerance {
		if payload.Timestamp < now {
			return nil, fmt.Errorf("timestamp too old: packet is %ds in the past (tolerance: %ds)  -- possible replay attack or clock skew", diff, timestampTolerance)
		}
		return nil, fmt.Errorf("timestamp too far in future: packet is %ds ahead (tolerance: %ds)  -- possible clock skew", diff, timestampTolerance)
	}

	// Verify client IP (anti-spoofing)
	// Strip zone ID from both addresses for comparison (zone is local, not on wire)
	doIPCheck := true
	if len(skipIPVerify) > 0 && skipIPVerify[0] {
		doIPCheck = false
	}
	if doIPCheck {
		payloadIP := payload.ClientIP
		compareIP := sourceIP
		if idx := strings.IndexByte(compareIP, '%'); idx >= 0 {
			compareIP = compareIP[:idx]
		}
		if payloadIP != compareIP {
			return nil, fmt.Errorf("IP mismatch: payload claims %s but packet from %s (possible spoofing/relay/NAT)", payload.ClientIP, sourceIP)
		}
	}

	return payload, nil
}

// encodePayload serializes a KnockPayload to compact binary format.
//
// Wire format: [Version:1][Flags:1][Timestamp:8][Nonce:32][IP:4|16][OpenDuration:4][CmdLen:1][Cmd:N][TOTP:6?][Pad:rest]
func encodePayload(p *KnockPayload) ([]byte, error) {
	var flags byte

	// Parse and encode IP (strip zone ID for link-local IPv6)
	ipStr := p.ClientIP
	if idx := strings.IndexByte(ipStr, '%'); idx >= 0 {
		ipStr = ipStr[:idx]
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid client IP: %s", p.ClientIP)
	}
	ip4 := ip.To4()
	var ipBytes []byte
	if ip4 != nil {
		ipBytes = ip4 // 4 bytes
	} else {
		ipBytes = ip.To16() // 16 bytes
		if ipBytes == nil {
			return nil, fmt.Errorf("cannot encode IP: %s", p.ClientIP)
		}
		flags |= flagIPv6
	}

	if p.TOTP != "" {
		flags |= flagTOTP
	}

	// Decode nonce from hex to raw bytes
	nonceBytes, err := hex.DecodeString(p.Nonce)
	if err != nil || len(nonceBytes) != NonceBytes {
		return nil, fmt.Errorf("invalid nonce: %s", p.Nonce)
	}

	// Decode padding from hex to raw bytes
	var padBytes []byte
	if p.Padding != "" {
		padBytes, err = hex.DecodeString(p.Padding)
		if err != nil {
			return nil, fmt.Errorf("invalid padding: %w", err)
		}
		flags |= flagPadding
	}

	cmdType, cmdData, encErr := encodeCommandBinary(p.Command)
	if encErr != nil {
		return nil, fmt.Errorf("encode command: %w", encErr)
	}
	cmdDataBytes := []byte(cmdData)
	// CmdLen = 1 (type byte) + len(data)
	totalCmdLen := 1 + len(cmdDataBytes)
	if totalCmdLen > 255 {
		return nil, fmt.Errorf("command too long: %d bytes (max 255)", totalCmdLen)
	}

	// Build binary payload
	size := 1 + 1 + 8 + NonceBytes + len(ipBytes) + 4 + 1 + totalCmdLen
	if flags&flagTOTP != 0 {
		size += 6
	}
	size += len(padBytes)

	buf := make([]byte, 0, size)
	buf = append(buf, byte(p.Version))
	buf = append(buf, flags)

	var tsBuf [8]byte
	binary.BigEndian.PutUint64(tsBuf[:], uint64(p.Timestamp))
	buf = append(buf, tsBuf[:]...)

	buf = append(buf, nonceBytes...)
	buf = append(buf, ipBytes...)

	var toBuf [4]byte
	binary.BigEndian.PutUint32(toBuf[:], uint32(p.OpenDuration))
	buf = append(buf, toBuf[:]...)

	buf = append(buf, byte(totalCmdLen))
	buf = append(buf, cmdType)
	buf = append(buf, cmdDataBytes...)

	if flags&flagTOTP != 0 {
		totpBytes := []byte(p.TOTP)
		if len(totpBytes) != 6 {
			return nil, fmt.Errorf("TOTP must be 6 digits, got %d", len(totpBytes))
		}
		buf = append(buf, totpBytes...)
	}

	buf = append(buf, padBytes...)
	return buf, nil
}

// decodePayload deserializes a compact binary payload into a KnockPayload.
func decodePayload(data []byte) (*KnockPayload, error) {
	if len(data) < minPayloadSize {
		return nil, fmt.Errorf("payload too short: %d bytes (min %d)", len(data), minPayloadSize)
	}

	p := &KnockPayload{}
	pos := 0

	p.Version = int(data[pos])
	pos++
	flags := data[pos]
	pos++

	// Timestamp
	p.Timestamp = int64(binary.BigEndian.Uint64(data[pos : pos+8]))
	pos += 8

	// Nonce (raw bytes -> hex string)
	if pos+NonceBytes > len(data) {
		return nil, fmt.Errorf("truncated nonce at offset %d", pos)
	}
	p.Nonce = hex.EncodeToString(data[pos : pos+NonceBytes])
	pos += NonceBytes

	// Client IP
	ipLen := 4
	if flags&flagIPv6 != 0 {
		ipLen = 16
	}
	if pos+ipLen > len(data) {
		return nil, fmt.Errorf("truncated IP at offset %d", pos)
	}
	p.ClientIP = net.IP(data[pos : pos+ipLen]).String()
	pos += ipLen

	// OpenDuration
	if pos+4 > len(data) {
		return nil, fmt.Errorf("truncated open_duration at offset %d", pos)
	}
	p.OpenDuration = int(binary.BigEndian.Uint32(data[pos : pos+4]))
	pos += 4

	// Command (binary type byte + data)
	if pos >= len(data) {
		return nil, fmt.Errorf("truncated command length at offset %d", pos)
	}
	cmdLen := int(data[pos])
	pos++
	if cmdLen < 1 {
		return nil, fmt.Errorf("command length must be >= 1 (need type byte)")
	}
	if pos+cmdLen > len(data) {
		return nil, fmt.Errorf("truncated command at offset %d (need %d, have %d)", pos, cmdLen, len(data)-pos)
	}
	cmdType := data[pos]
	pos++
	cmdData := string(data[pos : pos+cmdLen-1])
	pos += cmdLen - 1
	fullCmd, cmdErr := decodeCommandBinary(cmdType, cmdData)
	if cmdErr != nil {
		return nil, fmt.Errorf("decode command: %w", cmdErr)
	}
	p.Command = fullCmd

	// TOTP (optional, 6 bytes)
	if flags&flagTOTP != 0 {
		if pos+6 > len(data) {
			return nil, fmt.Errorf("truncated TOTP at offset %d", pos)
		}
		p.TOTP = string(data[pos : pos+6])
		pos += 6
	}

	// Padding (optional, remaining bytes -> hex)
	if flags&flagPadding != 0 && pos < len(data) {
		p.Padding = hex.EncodeToString(data[pos:])
	}

	return p, nil
}

// NonceTracker tracks seen nonces to prevent replay attacks.
type NonceTracker struct {
	mu       sync.Mutex
	nonces   map[string]time.Time
	expiry   time.Duration
	maxCache int // 0 = unlimited
}

// NewNonceTracker creates a tracker that expires nonces after the given duration.
func NewNonceTracker(expiry time.Duration) *NonceTracker {
	return NewNonceTrackerWithLimit(expiry, 0)
}

// NewNonceTrackerWithLimit creates a tracker with a max cache size.
// When the cache exceeds maxCache, the oldest entries are evicted.
func NewNonceTrackerWithLimit(expiry time.Duration, maxCache int) *NonceTracker {
	nt := &NonceTracker{
		nonces:   make(map[string]time.Time),
		expiry:   expiry,
		maxCache: maxCache,
	}
	// Start cleanup goroutine
	go nt.cleanup()
	return nt
}

// Check returns true if the nonce has NOT been seen before (valid).
// Returns false if the nonce was already used (replay attempt).
func (nt *NonceTracker) Check(nonce string) bool {
	nt.mu.Lock()
	defer nt.mu.Unlock()

	if _, exists := nt.nonces[nonce]; exists {
		return false // Replay!
	}

	// Enforce max cache size - evict oldest entries if over limit
	if nt.maxCache > 0 && len(nt.nonces) >= nt.maxCache {
		nt.evictOldest()
	}

	nt.nonces[nonce] = time.Now()
	return true
}

// evictOldest removes expired entries first, then evicts the oldest N entries when cache is full.
// Uses a two-pass approach: first sweep expired entries (single O(n) pass),
// then if still over limit, find and remove the oldest 10% using a selection buffer.
// Must be called with lock held.
func (nt *NonceTracker) evictOldest() {
	now := time.Now()
	// Pass 1: remove anything expired
	for k, v := range nt.nonces {
		if now.Sub(v) > nt.expiry {
			delete(nt.nonces, k)
		}
	}
	if nt.maxCache <= 0 || len(nt.nonces) < nt.maxCache {
		return
	}
	// Pass 2: find and remove the oldest 10% using a selection buffer.
	toEvict := len(nt.nonces) / 10
	if toEvict < 1 {
		toEvict = 1
	}
	// Collect timestamps to find the Nth oldest
	type entry struct {
		key  string
		time time.Time
	}
	oldest := make([]entry, 0, toEvict+1)
	for k, v := range nt.nonces {
		if len(oldest) < toEvict {
			oldest = append(oldest, entry{k, v})
		} else {
			// Find the newest in our "oldest" slice and replace if current is older
			maxIdx := 0
			for i := 1; i < len(oldest); i++ {
				if oldest[i].time.After(oldest[maxIdx].time) {
					maxIdx = i
				}
			}
			if v.Before(oldest[maxIdx].time) {
				oldest[maxIdx] = entry{k, v}
			}
		}
	}
	for _, e := range oldest {
		delete(nt.nonces, e.key)
	}
}

// cleanup periodically removes expired nonces.
func (nt *NonceTracker) cleanup() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		nt.mu.Lock()
		cutoff := time.Now().Add(-nt.expiry)
		for nonce, ts := range nt.nonces {
			if ts.Before(cutoff) {
				delete(nt.nonces, nonce)
			}
		}
		nt.mu.Unlock()
	}
}

// Size returns the number of tracked nonces.
func (nt *NonceTracker) Size() int {
	nt.mu.Lock()
	defer nt.mu.Unlock()
	return len(nt.nonces)
}
