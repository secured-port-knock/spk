// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package protocol

import (
	"encoding/hex"
	"strings"
	"testing"
)

// Test encode/decode edge cases for the compact binary payload format.

func TestEncodePayloadInvalidIP(t *testing.T) {
	p := &KnockPayload{
		Version:   1,
		Timestamp: 1000000,
		Nonce:     hex.EncodeToString(make([]byte, 32)),
		ClientIP:  "not-an-ip",
		Command:   "open-t22",
	}
	_, err := encodePayload(p)
	if err == nil {
		t.Fatal("expected error for invalid IP")
	}
	if !strings.Contains(err.Error(), "invalid client IP") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEncodePayloadIPv6ZoneIDStripped(t *testing.T) {
	nonce := hex.EncodeToString(make([]byte, 32))
	p := &KnockPayload{
		Version:      1,
		Timestamp:    1000000,
		Nonce:        nonce,
		ClientIP:     "fe80::1%eth0",
		Command:      "open-t22",
		OpenDuration: 60,
	}
	data, err := encodePayload(p)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := decodePayload(data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Zone ID should be stripped; fe80::1 is the canonical form
	if decoded.ClientIP != "fe80::1" {
		t.Errorf("ClientIP = %q, want %q", decoded.ClientIP, "fe80::1")
	}
}

func TestEncodePayloadTOTPWrongLength(t *testing.T) {
	p := &KnockPayload{
		Version:   1,
		Timestamp: 1000000,
		Nonce:     hex.EncodeToString(make([]byte, 32)),
		ClientIP:  "10.0.0.1",
		Command:   "open-t22",
		TOTP:      "12345", // 5 digits, not 6
	}
	_, err := encodePayload(p)
	if err == nil {
		t.Fatal("expected error for 5-digit TOTP")
	}
	if !strings.Contains(err.Error(), "TOTP must be 6 digits") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEncodePayloadInvalidNonce(t *testing.T) {
	p := &KnockPayload{
		Version:   1,
		Timestamp: 1000000,
		Nonce:     "xyz",
		ClientIP:  "10.0.0.1",
		Command:   "open-t22",
	}
	_, err := encodePayload(p)
	if err == nil {
		t.Fatal("expected error for invalid nonce hex")
	}
}

func TestEncodePayloadCommandTooLong(t *testing.T) {
	p := &KnockPayload{
		Version:   1,
		Timestamp: 1000000,
		Nonce:     hex.EncodeToString(make([]byte, 32)),
		ClientIP:  "10.0.0.1",
		Command:   "cust-" + strings.Repeat("x", 255),
	}
	_, err := encodePayload(p)
	if err == nil {
		t.Fatal("expected error for too-long command")
	}
	if !strings.Contains(err.Error(), "command too long") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEncodePayloadCommand255Bytes(t *testing.T) {
	// Max valid: type(1) + 249 data = 250 cmdLen, encoded from "cust-" + 249 chars = 254 string bytes
	cmd := "cust-" + strings.Repeat("a", 249)
	p := &KnockPayload{
		Version:   1,
		Timestamp: 1000000,
		Nonce:     hex.EncodeToString(make([]byte, 32)),
		ClientIP:  "10.0.0.1",
		Command:   cmd,
	}
	data, err := encodePayload(p)
	if err != nil {
		t.Fatalf("encode max command should work: %v", err)
	}
	decoded, err := decodePayload(data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.Command != cmd {
		t.Errorf("command length = %d, want %d", len(decoded.Command), len(cmd))
	}
}

func TestDecodePayloadTruncatedNonce(t *testing.T) {
	// 1 (ver) + 1 (flags) + 8 (ts) + 5 bytes (truncated nonce) = 15 bytes
	buf := make([]byte, 15)
	buf[0] = 1 // version
	_, err := decodePayload(buf)
	if err == nil {
		t.Fatal("expected error for truncated nonce")
	}
}

func TestDecodePayloadTruncatedIPv6(t *testing.T) {
	// Build a payload that's long enough to pass minPayloadSize (51) check
	// but has IPv6 flag with insufficient IP bytes.
	// Need: ver(1) + flags(1) + ts(8) + nonce(32) + ipv6(16b needed, provide < 16)
	// Total minimum needed for IPv6: 1+1+8+32+16 = 58, so 52 bytes should trigger truncated IP
	buf := make([]byte, 52) // enough for minPayloadSize but not for IPv6
	buf[0] = 1              // version
	buf[1] = flagIPv6       // needs 16 bytes but we only have 52-42=10 IP bytes available
	_, err := decodePayload(buf)
	if err == nil {
		t.Fatal("expected error for truncated IPv6 IP")
	}
	if !strings.Contains(err.Error(), "truncated IP") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDecodePayloadTruncatedOpenDuration(t *testing.T) {
	// Need: ver(1)+flags(1)+ts(8)+nonce(32)+ipv4(4) = 46, then need 4 for open_duration
	// But must be >= 51 (minPayloadSize) to pass the first check
	// minPayloadSize already requires open_duration bytes, so a buffer at exactly 50
	// will fail with "payload too short" not "truncated open_duration".
	// Test that the too-short check is working:
	buf := make([]byte, 50) // under minPayloadSize of 51
	buf[0] = 1              // version
	_, err := decodePayload(buf)
	if err == nil {
		t.Fatal("expected error for truncated payload")
	}
	// Should be "payload too short" since 50 < 51 minPayloadSize
	if !strings.Contains(err.Error(), "payload too short") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDecodePayloadTruncatedCommand(t *testing.T) {
	// Build valid header through open_duration, then cmdLen=10 but only 5 bytes
	buf := make([]byte, 51+5) // 51 = min payload (with cmdlen=0) + 5
	buf[0] = 1                // version
	buf[50] = 10              // cmdLen = 10, but only 5 bytes remain
	_, err := decodePayload(buf)
	if err == nil {
		t.Fatal("expected error for truncated command")
	}
	if !strings.Contains(err.Error(), "truncated command") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDecodePayloadTruncatedTOTP(t *testing.T) {
	// Build valid payload with TOTP flag but no TOTP bytes after command
	nonce := make([]byte, 32)
	ipv4 := []byte{10, 0, 0, 1}
	buf := []byte{1, flagTOTP}            // version=1, flags=TOTP
	buf = append(buf, make([]byte, 8)...) // timestamp
	buf = append(buf, nonce...)
	buf = append(buf, ipv4...)
	buf = append(buf, 0, 0, 0, 60) // open_duration = 60
	buf = append(buf, 1)           // cmdLen = 1 (type byte only)
	buf = append(buf, CmdTypeOpen) // command type = open
	// No TOTP bytes follow
	_, err := decodePayload(buf)
	if err == nil {
		t.Fatal("expected error for truncated TOTP")
	}
	if !strings.Contains(err.Error(), "truncated TOTP") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEncodeDecodeRoundTripIPv4(t *testing.T) {
	nonce := hex.EncodeToString(make([]byte, 32))
	p := &KnockPayload{
		Version:      1,
		Timestamp:    1700000000,
		Nonce:        nonce,
		ClientIP:     "192.168.1.100",
		Command:      "open-t22",
		OpenDuration: 3600,
	}
	data, err := encodePayload(p)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := decodePayload(data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.Version != 1 {
		t.Errorf("Version = %d, want 1", decoded.Version)
	}
	if decoded.Timestamp != 1700000000 {
		t.Errorf("Timestamp = %d, want 1700000000", decoded.Timestamp)
	}
	if decoded.ClientIP != "192.168.1.100" {
		t.Errorf("ClientIP = %q, want %q", decoded.ClientIP, "192.168.1.100")
	}
	if decoded.Command != "open-t22" {
		t.Errorf("Command = %q, want %q", decoded.Command, "open-t22")
	}
	if decoded.OpenDuration != 3600 {
		t.Errorf("OpenDuration = %d, want 3600", decoded.OpenDuration)
	}
}

func TestEncodeDecodeRoundTripIPv6(t *testing.T) {
	nonce := hex.EncodeToString(make([]byte, 32))
	p := &KnockPayload{
		Version:      1,
		Timestamp:    1700000000,
		Nonce:        nonce,
		ClientIP:     "2001:db8::1",
		Command:      "close-all",
		OpenDuration: 0,
	}
	data, err := encodePayload(p)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := decodePayload(data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.ClientIP != "2001:db8::1" {
		t.Errorf("ClientIP = %q, want %q", decoded.ClientIP, "2001:db8::1")
	}
}

func TestEncodeDecodeWithTOTPAndPadding(t *testing.T) {
	nonce := hex.EncodeToString(make([]byte, 32))
	p := &KnockPayload{
		Version:      1,
		Timestamp:    1700000000,
		Nonce:        nonce,
		ClientIP:     "10.0.0.1",
		Command:      "open-t443",
		OpenDuration: 7200,
		TOTP:         "482901",
		Padding:      hex.EncodeToString(make([]byte, 100)),
	}
	data, err := encodePayload(p)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := decodePayload(data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.TOTP != "482901" {
		t.Errorf("TOTP = %q, want %q", decoded.TOTP, "482901")
	}
	if decoded.Padding == "" {
		t.Error("expected padding to be present")
	}
	// Padding should be hex of 100 zero bytes
	padBytes, _ := hex.DecodeString(decoded.Padding)
	if len(padBytes) != 100 {
		t.Errorf("padding length = %d bytes, want 100", len(padBytes))
	}
}

func TestDecodePayloadTooShort(t *testing.T) {
	_, err := decodePayload(make([]byte, 10))
	if err == nil {
		t.Fatal("expected error for payload shorter than minimum")
	}
	if !strings.Contains(err.Error(), "payload too short") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// --- Comprehensive compact binary protocol tests ---

func TestEncodePayloadBatchCommand(t *testing.T) {
	// Realistic batch command with many ports
	cmd := "open-t22,t80,t443,t3306,t5432,t8080,t8443,u53,u123,u161"
	if len(cmd) > 255 {
		t.Fatalf("test command is %d bytes, should be < 255", len(cmd))
	}
	p := &KnockPayload{
		Version:      1,
		Timestamp:    1700000000,
		Nonce:        hex.EncodeToString(make([]byte, 32)),
		ClientIP:     "10.0.0.1",
		Command:      cmd,
		OpenDuration: 3600,
	}
	data, err := encodePayload(p)
	if err != nil {
		t.Fatalf("encode batch command: %v", err)
	}
	decoded, err := decodePayload(data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.Command != cmd {
		t.Errorf("Command = %q, want %q", decoded.Command, cmd)
	}
}

func TestEncodePayloadCustomCommand(t *testing.T) {
	cmds := []string{
		"cust-1",
		"cust-restartSSH",
		"cust-deploy_production_v2",
		"cust-ping",
	}
	for _, cmd := range cmds {
		p := &KnockPayload{
			Version:   1,
			Timestamp: 1700000000,
			Nonce:     hex.EncodeToString(make([]byte, 32)),
			ClientIP:  "10.0.0.1",
			Command:   cmd,
		}
		data, err := encodePayload(p)
		if err != nil {
			t.Fatalf("encode %q: %v", cmd, err)
		}
		decoded, err := decodePayload(data)
		if err != nil {
			t.Fatalf("decode %q: %v", cmd, err)
		}
		if decoded.Command != cmd {
			t.Errorf("Command = %q, want %q", decoded.Command, cmd)
		}
	}
}

func TestEncodePayloadEmptyCommand(t *testing.T) {
	p := &KnockPayload{
		Version:      1,
		Timestamp:    1700000000,
		Nonce:        hex.EncodeToString(make([]byte, 32)),
		ClientIP:     "10.0.0.1",
		Command:      "",
		OpenDuration: 60,
	}
	_, err := encodePayload(p)
	if err == nil {
		t.Fatal("expected error for empty command")
	}
}

func TestEncodePayloadOpenDurationMaxValue(t *testing.T) {
	p := &KnockPayload{
		Version:      1,
		Timestamp:    1700000000,
		Nonce:        hex.EncodeToString(make([]byte, 32)),
		ClientIP:     "10.0.0.1",
		Command:      "open-t22",
		OpenDuration: 604800, // max 7 days
	}
	data, err := encodePayload(p)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := decodePayload(data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.OpenDuration != 604800 {
		t.Errorf("OpenDuration = %d, want 604800", decoded.OpenDuration)
	}
}

func TestEncodePayloadOpenDurationZero(t *testing.T) {
	p := &KnockPayload{
		Version:      1,
		Timestamp:    1700000000,
		Nonce:        hex.EncodeToString(make([]byte, 32)),
		ClientIP:     "10.0.0.1",
		Command:      "open-t22",
		OpenDuration: 0,
	}
	data, err := encodePayload(p)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := decodePayload(data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.OpenDuration != 0 {
		t.Errorf("OpenDuration = %d, want 0", decoded.OpenDuration)
	}
}

func TestEncodePayloadAllFlagCombinations(t *testing.T) {
	// Test all 8 combinations of 3 flags (IPv6, TOTP, Padding)
	tests := []struct {
		name    string
		ipv6    bool
		totp    bool
		padding bool
	}{
		{"none", false, false, false},
		{"ipv6", true, false, false},
		{"totp", false, true, false},
		{"padding", false, false, true},
		{"ipv6+totp", true, true, false},
		{"ipv6+padding", true, false, true},
		{"totp+padding", false, true, true},
		{"all", true, true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := "10.0.0.1"
			if tt.ipv6 {
				ip = "2001:db8::1"
			}
			p := &KnockPayload{
				Version:      1,
				Timestamp:    1700000000,
				Nonce:        hex.EncodeToString(make([]byte, 32)),
				ClientIP:     ip,
				Command:      "open-t22",
				OpenDuration: 60,
			}
			if tt.totp {
				p.TOTP = "123456"
			}
			if tt.padding {
				p.Padding = hex.EncodeToString(make([]byte, 50))
			}
			data, err := encodePayload(p)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			decoded, err := decodePayload(data)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if tt.totp && decoded.TOTP != "123456" {
				t.Errorf("TOTP = %q, want %q", decoded.TOTP, "123456")
			}
			if !tt.totp && decoded.TOTP != "" {
				t.Errorf("TOTP = %q, want empty", decoded.TOTP)
			}
			if tt.padding && decoded.Padding == "" {
				t.Error("expected padding")
			}
			if !tt.padding && decoded.Padding != "" {
				t.Error("unexpected padding")
			}
		})
	}
}

func TestBinaryPayloadSizeIPv4Minimal(t *testing.T) {
	// Minimum: version(1) + flags(1) + ts(8) + nonce(32) + ipv4(4) + open_duration(4) + cmdlen(1) + cmdType(1) = 52
	p := &KnockPayload{
		Version:      1,
		Timestamp:    1700000000,
		Nonce:        hex.EncodeToString(make([]byte, 32)),
		ClientIP:     "10.0.0.1",
		Command:      "open-",
		OpenDuration: 0,
	}
	data, err := encodePayload(p)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if len(data) != 52 {
		t.Errorf("minimal IPv4 payload = %d bytes, want 52", len(data))
	}
}

func TestBinaryPayloadSizeIPv6Minimal(t *testing.T) {
	// IPv6 minimum: version(1) + flags(1) + ts(8) + nonce(32) + ipv6(16) + open_duration(4) + cmdlen(1) + cmdType(1) = 64
	p := &KnockPayload{
		Version:      1,
		Timestamp:    1700000000,
		Nonce:        hex.EncodeToString(make([]byte, 32)),
		ClientIP:     "2001:db8::1",
		Command:      "open-",
		OpenDuration: 0,
	}
	data, err := encodePayload(p)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if len(data) != 64 {
		t.Errorf("minimal IPv6 payload = %d bytes, want 64", len(data))
	}
}

func TestBinaryPayloadSizeTypical(t *testing.T) {
	// Typical: IPv4 + "open-t22" -> type(1) + "t22"(3) = 4 cmdLen -> 51 + 4 = 55
	p := &KnockPayload{
		Version:      1,
		Timestamp:    1700000000,
		Nonce:        hex.EncodeToString(make([]byte, 32)),
		ClientIP:     "192.168.1.1",
		Command:      "open-t22",
		OpenDuration: 3600,
	}
	data, err := encodePayload(p)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	// 51 base + 1 type byte + 3 data bytes ("t22") = 55
	expected := 51 + 1 + len("t22")
	if len(data) != expected {
		t.Errorf("typical payload = %d bytes, want %d", len(data), expected)
	}
}

func TestBinaryPayloadSizeWithTOTP(t *testing.T) {
	// TOTP adds 6 bytes
	p := &KnockPayload{
		Version:      1,
		Timestamp:    1700000000,
		Nonce:        hex.EncodeToString(make([]byte, 32)),
		ClientIP:     "10.0.0.1",
		Command:      "open-t22",
		OpenDuration: 60,
		TOTP:         "482901",
	}
	data, err := encodePayload(p)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	// 51 base + 1 type + 3 data ("t22") + 6 TOTP = 61
	expected := 51 + 1 + len("t22") + 6
	if len(data) != expected {
		t.Errorf("TOTP payload = %d bytes, want %d", len(data), expected)
	}
}

func TestBinaryPayloadSizeWithPadding(t *testing.T) {
	padLen := 100
	p := &KnockPayload{
		Version:      1,
		Timestamp:    1700000000,
		Nonce:        hex.EncodeToString(make([]byte, 32)),
		ClientIP:     "10.0.0.1",
		Command:      "open-t22",
		OpenDuration: 60,
		Padding:      hex.EncodeToString(make([]byte, padLen)),
	}
	data, err := encodePayload(p)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	// 51 base + 1 type + 3 data ("t22") + 100 padding = 155
	expected := 51 + 1 + len("t22") + padLen
	if len(data) != expected {
		t.Errorf("padded payload = %d bytes, want %d", len(data), expected)
	}
}

func TestBinaryPayloadSizeMax(t *testing.T) {
	// Maximum valid: "cust-" + 249 chars -> type(1) + 249 data = 250 cmdLen
	padLen := 2048
	cmd := "cust-" + strings.Repeat("x", 249)
	p := &KnockPayload{
		Version:      1,
		Timestamp:    1700000000,
		Nonce:        hex.EncodeToString(make([]byte, 32)),
		ClientIP:     "2001:db8::1",
		Command:      cmd,
		OpenDuration: 604800,
		TOTP:         "999999",
		Padding:      hex.EncodeToString(make([]byte, padLen)),
	}
	data, err := encodePayload(p)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	// 63 (ipv6 base) + 250 (1 type + 249 data) + 6 (totp) + 2048 (pad) = 2367
	expected := 63 + 250 + 6 + padLen
	if len(data) != expected {
		t.Errorf("max payload = %d bytes, want %d", len(data), expected)
	}
}

func TestDecodePayloadVersionField(t *testing.T) {
	// Encode version 1 payload and verify version is preserved
	p := &KnockPayload{
		Version:   1,
		Timestamp: 1700000000,
		Nonce:     hex.EncodeToString(make([]byte, 32)),
		ClientIP:  "10.0.0.1",
		Command:   "open-t22",
	}
	data, err := encodePayload(p)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	// Version is the first byte
	if data[0] != 1 {
		t.Errorf("version byte = %d, want 1", data[0])
	}
	// Manually set version to 2 and decode
	data[0] = 2
	decoded, err := decodePayload(data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.Version != 2 {
		t.Errorf("decoded version = %d, want 2", decoded.Version)
	}
}

func TestDecodePayloadFlagsField(t *testing.T) {
	// Verify flags byte is at offset 1
	p := &KnockPayload{
		Version:   1,
		Timestamp: 1700000000,
		Nonce:     hex.EncodeToString(make([]byte, 32)),
		ClientIP:  "2001:db8::1", // IPv6 -> flag bit 0
		Command:   "open-t22",
		TOTP:      "123456", // -> flag bit 1
	}
	data, err := encodePayload(p)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	wantFlags := byte(flagIPv6 | flagTOTP)
	if data[1] != wantFlags {
		t.Errorf("flags byte = 0x%02x, want 0x%02x", data[1], wantFlags)
	}
}

func TestEncodePayloadIPv4Loopback(t *testing.T) {
	p := &KnockPayload{
		Version:   1,
		Timestamp: 1700000000,
		Nonce:     hex.EncodeToString(make([]byte, 32)),
		ClientIP:  "127.0.0.1",
		Command:   "open-t22",
	}
	data, err := encodePayload(p)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := decodePayload(data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.ClientIP != "127.0.0.1" {
		t.Errorf("ClientIP = %q, want 127.0.0.1", decoded.ClientIP)
	}
}

func TestEncodePayloadIPv6Loopback(t *testing.T) {
	p := &KnockPayload{
		Version:   1,
		Timestamp: 1700000000,
		Nonce:     hex.EncodeToString(make([]byte, 32)),
		ClientIP:  "::1",
		Command:   "open-t22",
	}
	data, err := encodePayload(p)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := decodePayload(data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.ClientIP != "::1" {
		t.Errorf("ClientIP = %q, want ::1", decoded.ClientIP)
	}
}

func TestEncodePayloadLargeTimestamp(t *testing.T) {
	// Year 2100 timestamp
	ts := int64(4102444800)
	p := &KnockPayload{
		Version:   1,
		Timestamp: ts,
		Nonce:     hex.EncodeToString(make([]byte, 32)),
		ClientIP:  "10.0.0.1",
		Command:   "open-t22",
	}
	data, err := encodePayload(p)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := decodePayload(data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.Timestamp != ts {
		t.Errorf("Timestamp = %d, want %d", decoded.Timestamp, ts)
	}
}

func TestDecodePayloadZeroLength(t *testing.T) {
	_, err := decodePayload(nil)
	if err == nil {
		t.Fatal("expected error for nil payload")
	}
	_, err = decodePayload([]byte{})
	if err == nil {
		t.Fatal("expected error for empty payload")
	}
}

func TestEncodePayloadIPv4MappedIPv6(t *testing.T) {
	// ::ffff:192.168.1.1 should be encoded as IPv4 (4 bytes)
	p := &KnockPayload{
		Version:   1,
		Timestamp: 1700000000,
		Nonce:     hex.EncodeToString(make([]byte, 32)),
		ClientIP:  "::ffff:192.168.1.1",
		Command:   "open-t22",
	}
	data, err := encodePayload(p)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	// Should be encoded as IPv4 (flags bit 0 = 0)
	if data[1]&flagIPv6 != 0 {
		t.Error("IPv4-mapped-IPv6 should be encoded as IPv4 (flagIPv6 should be 0)")
	}
	decoded, err := decodePayload(data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	// net.IP.To4() converts ::ffff:x.x.x.x to x.x.x.x
	if decoded.ClientIP != "192.168.1.1" {
		t.Errorf("ClientIP = %q, want 192.168.1.1", decoded.ClientIP)
	}
}

func TestEncodePayloadInvalidPaddingHex(t *testing.T) {
	p := &KnockPayload{
		Version:   1,
		Timestamp: 1700000000,
		Nonce:     hex.EncodeToString(make([]byte, 32)),
		ClientIP:  "10.0.0.1",
		Command:   "open-t22",
		Padding:   "not-valid-hex!!",
	}
	_, err := encodePayload(p)
	if err == nil {
		t.Fatal("expected error for invalid padding hex")
	}
}

func TestEncodePayloadNonceWrongLength(t *testing.T) {
	// Nonce must be exactly 32 bytes (64 hex chars)
	p := &KnockPayload{
		Version:   1,
		Timestamp: 1700000000,
		Nonce:     hex.EncodeToString(make([]byte, 16)), // 16 bytes, not 32
		ClientIP:  "10.0.0.1",
		Command:   "open-t22",
	}
	_, err := encodePayload(p)
	if err == nil {
		t.Fatal("expected error for 16-byte nonce")
	}
}

func TestBinaryProtocolDeterministic(t *testing.T) {
	// Same inputs must produce identical binary output
	nonce := hex.EncodeToString(make([]byte, 32))
	p := &KnockPayload{
		Version:      1,
		Timestamp:    1700000000,
		Nonce:        nonce,
		ClientIP:     "10.0.0.1",
		Command:      "open-t22",
		OpenDuration: 100,
	}
	data1, err := encodePayload(p)
	if err != nil {
		t.Fatalf("encode 1: %v", err)
	}
	data2, err := encodePayload(p)
	if err != nil {
		t.Fatalf("encode 2: %v", err)
	}
	if hex.EncodeToString(data1) != hex.EncodeToString(data2) {
		t.Error("encoding is not deterministic")
	}
}
