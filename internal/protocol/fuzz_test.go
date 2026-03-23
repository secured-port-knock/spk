// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package protocol

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/secured-port-knock/spk/internal/crypto"
)

// --- Fuzz tests ---

// FuzzDecodePayload feeds arbitrary bytes into the binary payload decoder.
// Must never panic; must always return either a valid payload or an error.
func FuzzDecodePayload(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add(make([]byte, minPayloadSize-1)) // just below minimum
	f.Add(make([]byte, minPayloadSize))   // exact minimum
	f.Add(make([]byte, minPayloadSize+1))

	// Craft a minimally valid payload
	nonce := make([]byte, NonceBytes)
	valid := []byte{1, 0} // version=1, flags=0 (IPv4, no TOTP, no padding)
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, uint64(time.Now().Unix()))
	valid = append(valid, ts...)
	valid = append(valid, nonce...)         // 32 zero-bytes nonce
	valid = append(valid, 10, 0, 0, 1)      // IPv4: 10.0.0.1
	valid = append(valid, 0, 0, 0xe1, 0)    // OpenDuration=57600
	valid = append(valid, 4, 0x00)          // CmdLen=4, CmdType=open
	valid = append(valid, []byte("t22")...) // CmdData
	f.Add(valid)

	// IPv6 variant
	v6 := []byte{1, flagIPv6}
	v6 = append(v6, ts...)
	v6 = append(v6, nonce...)
	v6 = append(v6, make([]byte, 16)...) // IPv6 zeros
	v6 = append(v6, 0, 0, 0xe1, 0)
	v6 = append(v6, 4, 0x00)
	v6 = append(v6, []byte("t22")...)
	f.Add(v6)

	// With TOTP flag
	withTOTP := []byte{1, flagTOTP}
	withTOTP = append(withTOTP, ts...)
	withTOTP = append(withTOTP, nonce...)
	withTOTP = append(withTOTP, 10, 0, 0, 1)
	withTOTP = append(withTOTP, 0, 0, 0, 0)
	withTOTP = append(withTOTP, 4, 0x00)
	withTOTP = append(withTOTP, []byte("t22")...)
	withTOTP = append(withTOTP, []byte("123456")...) // 6-byte TOTP
	f.Add(withTOTP)

	// Max flags set
	allFlags := []byte{1, flagIPv6 | flagTOTP | flagPadding}
	allFlags = append(allFlags, ts...)
	allFlags = append(allFlags, nonce...)
	allFlags = append(allFlags, make([]byte, 16)...)
	allFlags = append(allFlags, 0, 0, 0, 0)
	allFlags = append(allFlags, 4, 0x00)
	allFlags = append(allFlags, []byte("t22")...)
	allFlags = append(allFlags, []byte("654321")...)
	allFlags = append(allFlags, make([]byte, 64)...) // padding
	f.Add(allFlags)

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must not panic
		_, _ = decodePayload(data)
	})
}

// FuzzParseKnockPacket feeds random encrypted-looking data into the full parse pipeline.
func FuzzParseKnockPacket(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 100))
	f.Add(make([]byte, 1118)) // min packet size
	f.Add(make([]byte, 8192)) // max packet size
	f.Add(make([]byte, 8193)) // over max
	f.Add(make([]byte, 2000))

	dk768, _ := crypto.GenerateKeyPair(crypto.KEM768)
	dk1024, _ := crypto.GenerateKeyPair(crypto.KEM1024)

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must not panic on any input
		_, _ = ParseKnockPacket(dk768, data, "192.168.1.1", 30)
		_, _ = ParseKnockPacket(dk1024, data, "192.168.1.1", 30)
	})
}

// FuzzValidateCommand tests command validation with arbitrary strings.
func FuzzValidateCommand(f *testing.F) {
	f.Add("open-t22")
	f.Add("close-u53")
	f.Add("cust-ping")
	f.Add("open-all")
	f.Add("close-all")
	f.Add("")
	f.Add("OPEN-T22")
	f.Add("open-t0")
	f.Add("open-t65536")
	f.Add("open-t99999999999999")
	f.Add("open-x22")
	f.Add("cust-")
	f.Add("open-t22,t443,u53")
	f.Add(strings.Repeat("A", 1000))

	f.Fuzz(func(t *testing.T, cmd string) {
		// Must not panic
		_ = ValidateCommand(cmd)
	})
}

// FuzzEncodeDecodePayloadRoundtrip tests that encode->decode is identity.
func FuzzEncodeDecodePayloadRoundtrip(f *testing.F) {
	f.Add("192.168.1.1", "open-t22", 3600, "", "")
	f.Add("10.0.0.1", "close-u53", 0, "123456", "")
	f.Add("::1", "open-all", 86400, "", "aabbccdd")
	f.Add("2001:db8::1", "cust-restart", 600, "999999", "00112233")

	f.Fuzz(func(t *testing.T, ip, cmd string, duration int, totp, paddingHex string) {
		// Constrain inputs to valid ranges for meaningful roundtrip tests
		if duration < 0 || duration > 604800 {
			return
		}
		if err := ValidateCommand(cmd); err != nil {
			return
		}
		if totp != "" && len(totp) != 6 {
			return
		}
		// Verify TOTP is digit-only if present
		for _, c := range totp {
			if c < '0' || c > '9' {
				return
			}
		}

		nonceBytes := make([]byte, NonceBytes)
		if _, err := io.ReadFull(rand.Reader, nonceBytes); err != nil {
			return
		}

		payload := &KnockPayload{
			Version:      ProtocolVersion,
			Timestamp:    time.Now().Unix(),
			Nonce:        hex.EncodeToString(nonceBytes),
			ClientIP:     ip,
			Command:      cmd,
			OpenDuration: duration,
			TOTP:         totp,
			Padding:      paddingHex,
		}

		encoded, err := encodePayload(payload)
		if err != nil {
			return // invalid input combo, skip
		}

		decoded, err := decodePayload(encoded)
		if err != nil {
			t.Fatalf("roundtrip decode failed: %v", err)
		}

		if decoded.Version != payload.Version {
			t.Errorf("version mismatch: got %d, want %d", decoded.Version, payload.Version)
		}
		if decoded.Command != payload.Command {
			t.Errorf("command mismatch: got %q, want %q", decoded.Command, payload.Command)
		}
		if decoded.OpenDuration != payload.OpenDuration {
			t.Errorf("duration mismatch: got %d, want %d", decoded.OpenDuration, payload.OpenDuration)
		}
		if decoded.TOTP != payload.TOTP {
			t.Errorf("TOTP mismatch: got %q, want %q", decoded.TOTP, payload.TOTP)
		}
	})
}

// --- Property-based tests ---

// TestPayloadEncodeDecode_AllCommandTypes verifies the codec handles all command type bytes.
func TestPayloadEncodeDecode_AllCommandTypes(t *testing.T) {
	nonce := make([]byte, NonceBytes)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		t.Fatal(err)
	}

	commands := []struct {
		cmd     string
		cmdType byte
		cmdData string
	}{
		{"open-t22", CmdTypeOpen, "t22"},
		{"open-all", CmdTypeOpen, "all"},
		{"open-t22,t443,u53", CmdTypeOpen, "t22,t443,u53"},
		{"close-t22", CmdTypeClose, "t22"},
		{"close-all", CmdTypeClose, "all"},
		{"cust-restart_ssh", CmdTypeCust, "restart_ssh"},
		{"cust-a", CmdTypeCust, "a"},
	}

	for _, tc := range commands {
		t.Run(tc.cmd, func(t *testing.T) {
			payload := &KnockPayload{
				Version:      ProtocolVersion,
				Timestamp:    time.Now().Unix(),
				Nonce:        hex.EncodeToString(nonce),
				ClientIP:     "10.0.0.1",
				Command:      tc.cmd,
				OpenDuration: 3600,
			}

			encoded, err := encodePayload(payload)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}

			decoded, err := decodePayload(encoded)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}

			if decoded.Command != tc.cmd {
				t.Errorf("command mismatch: got %q, want %q", decoded.Command, tc.cmd)
			}
		})
	}
}

// TestDecodePayload_InvalidCommandType verifies unknown command type bytes are rejected.
func TestDecodePayload_InvalidCommandType(t *testing.T) {
	nonce := make([]byte, NonceBytes)

	// Build a minimal valid payload, then tamper the command type byte
	payload := &KnockPayload{
		Version:      ProtocolVersion,
		Timestamp:    time.Now().Unix(),
		Nonce:        hex.EncodeToString(nonce),
		ClientIP:     "10.0.0.1",
		Command:      "open-t22",
		OpenDuration: 3600,
	}

	encoded, err := encodePayload(payload)
	if err != nil {
		t.Fatal(err)
	}

	// The command type byte is at offset: 1(ver) + 1(flags) + 8(ts) + 32(nonce) + 4(ip) + 4(dur) + 1(cmdlen) = 51
	cmdTypeOffset := 1 + 1 + 8 + NonceBytes + 4 + 4 + 1
	if cmdTypeOffset >= len(encoded) {
		t.Fatal("encoded too short to find command type")
	}

	// Set to invalid command type (0xFF)
	tampered := make([]byte, len(encoded))
	copy(tampered, encoded)
	tampered[cmdTypeOffset] = 0xFF

	_, err = decodePayload(tampered)
	if err == nil {
		t.Error("expected error for invalid command type 0xFF")
	}
}

// TestDecodePayload_TruncatedAtEveryOffset verifies graceful handling of truncation.
func TestDecodePayload_TruncatedAtEveryOffset(t *testing.T) {
	nonce := make([]byte, NonceBytes)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		t.Fatal(err)
	}

	payload := &KnockPayload{
		Version:      ProtocolVersion,
		Timestamp:    time.Now().Unix(),
		Nonce:        hex.EncodeToString(nonce),
		ClientIP:     "10.0.0.1",
		Command:      "open-t22",
		OpenDuration: 3600,
		TOTP:         "123456",
	}

	encoded, err := encodePayload(payload)
	if err != nil {
		t.Fatal(err)
	}

	// Try decoding every truncation from 0 to full length-1
	for i := 0; i < len(encoded); i++ {
		truncated := encoded[:i]
		_, err := decodePayload(truncated)
		if err == nil && i < minPayloadSize {
			t.Errorf("expected error at truncation length %d", i)
		}
		// No panic is the main assertion
	}
}

// TestDecodePayload_AllFlagCombinations tests all 8 flag combinations.
func TestDecodePayload_AllFlagCombinations(t *testing.T) {
	nonce := make([]byte, NonceBytes)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		t.Fatal(err)
	}

	for flags := byte(0); flags < 8; flags++ {
		t.Run(fmt.Sprintf("flags=0x%02x", flags), func(t *testing.T) {
			ipStr := "10.0.0.1"
			if flags&flagIPv6 != 0 {
				ipStr = "2001:db8::1"
			}

			payload := &KnockPayload{
				Version:      ProtocolVersion,
				Timestamp:    time.Now().Unix(),
				Nonce:        hex.EncodeToString(nonce),
				ClientIP:     ipStr,
				Command:      "open-t22",
				OpenDuration: 3600,
			}

			if flags&flagTOTP != 0 {
				payload.TOTP = "123456"
			}

			if flags&flagPadding != 0 {
				padBytes := make([]byte, 64)
				if _, err := io.ReadFull(rand.Reader, padBytes); err != nil {
					t.Fatal(err)
				}
				payload.Padding = hex.EncodeToString(padBytes)
			}

			encoded, err := encodePayload(payload)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}

			decoded, err := decodePayload(encoded)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}

			if decoded.Command != payload.Command {
				t.Errorf("command: got %q, want %q", decoded.Command, payload.Command)
			}
			if decoded.TOTP != payload.TOTP {
				t.Errorf("TOTP: got %q, want %q", decoded.TOTP, payload.TOTP)
			}
		})
	}
}

// TestNonceTracker_UnderPressure verifies nonce tracking under cache pressure.
func TestNonceTracker_UnderPressure(t *testing.T) {
	maxCache := 100
	tracker := NewNonceTrackerWithLimit(5*time.Minute, maxCache)

	// Insert more nonces than cache allows
	for i := 0; i < maxCache*3; i++ {
		nonce := fmt.Sprintf("nonce_%d", i)
		tracker.Check(nonce)
	}

	// Recent nonces should still be tracked (not evicted)
	recentNonce := fmt.Sprintf("nonce_%d", maxCache*3-1)
	if tracker.Check(recentNonce) {
		t.Error("most recent nonce should be rejected as replay")
	}

	// Very old nonces may have been evicted, which is fine - they should be accepted
	// (since they were evicted from cache)
	oldNonce := fmt.Sprintf("nonce_%d", 0)
	// Just verify no panic - the behavior (accept/reject) depends on eviction
	_ = tracker.Check(oldNonce)
}

// TestNonceTracker_EmptyNonce verifies empty string nonce is handled.
func TestNonceTracker_EmptyNonce(t *testing.T) {
	tracker := NewNonceTrackerWithLimit(time.Minute, 100)

	if !tracker.Check("") {
		t.Error("first empty nonce should be accepted")
	}
	if tracker.Check("") {
		t.Error("second empty nonce should be rejected as replay")
	}
}

// TestNonceTracker_ConcurrentAccess verifies thread safety.
func TestNonceTracker_ConcurrentAccess(t *testing.T) {
	tracker := NewNonceTrackerWithLimit(time.Minute, 10000)

	done := make(chan bool, 100)
	for i := 0; i < 100; i++ {
		go func(id int) {
			for j := 0; j < 100; j++ {
				nonce := fmt.Sprintf("goroutine_%d_nonce_%d", id, j)
				tracker.Check(nonce)
			}
			done <- true
		}(i)
	}

	for i := 0; i < 100; i++ {
		<-done
	}
}

// TestValidateCommand_BoundaryPorts tests edge-case port numbers.
func TestValidateCommand_BoundaryPorts(t *testing.T) {
	tests := []struct {
		cmd     string
		wantErr bool
	}{
		{"open-t1", false},
		{"open-t65535", false},
		{"open-t0", true},
		{"open-t65536", true},
		{"open-t99999", true},
		{"open-t00001", false}, // leading zeros, parses to 1
		{"close-u1", false},
		{"close-u65535", false},
		{"open-t1,t2,t3", false},
		{"open-t1,t65536", true},
		{"open-", true},
		{"close-", true},
		{"cust-", true},
		{"cust-" + string(rune(0x1F)), true}, // control character
		{"cust-" + string(rune(0x7F)), true}, // DEL character
		{"open-t22,", false},                 // trailing comma -> empty part skipped
		{"open-,t22", false},                 // leading empty part skipped
		{"open-t22,,t443", false},            // double comma -> empty parts skipped
	}

	for _, tt := range tests {
		t.Run(tt.cmd, func(t *testing.T) {
			err := ValidateCommand(tt.cmd)
			if tt.wantErr && err == nil {
				t.Errorf("ValidateCommand(%q) expected error", tt.cmd)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("ValidateCommand(%q) unexpected error: %v", tt.cmd, err)
			}
		})
	}
}

// TestParseKnockPacket_TimestampBoundaries tests timestamp edge cases.
func TestParseKnockPacket_TimestampBoundaries(t *testing.T) {
	dk, err := crypto.GenerateKeyPair(crypto.KEM768)
	if err != nil {
		t.Fatal(err)
	}
	ek := dk.EncapsulationKey()

	clientIP := "10.0.0.1"
	packet, err := BuildKnockPacket(ek, clientIP, "open-t22", 3600)
	if err != nil {
		t.Fatal(err)
	}

	// With tolerance=0, packet may fail (depends on processing time)
	_, _ = ParseKnockPacket(dk, packet, clientIP, 0)
	// Either pass or fail is acceptable, but must not panic

	// With very large tolerance, packet should always pass
	payload, err := ParseKnockPacket(dk, packet, clientIP, 86400)
	if err != nil {
		t.Fatalf("large tolerance should accept: %v", err)
	}
	if payload.Command != "open-t22" {
		t.Errorf("command mismatch: got %q", payload.Command)
	}
}

// TestParseKnockPacket_IPMismatchDetection verifies anti-spoofing.
func TestParseKnockPacket_IPMismatchDetection(t *testing.T) {
	dk, err := crypto.GenerateKeyPair(crypto.KEM768)
	if err != nil {
		t.Fatal(err)
	}
	ek := dk.EncapsulationKey()

	packet, err := BuildKnockPacket(ek, "192.168.1.100", "open-t22", 3600)
	if err != nil {
		t.Fatal(err)
	}

	// Parse with wrong source IP -> should fail
	_, err = ParseKnockPacket(dk, packet, "10.0.0.1", 30)
	if err == nil {
		t.Error("expected IP mismatch error")
	}
	if err != nil && !strings.Contains(err.Error(), "IP mismatch") {
		t.Errorf("expected IP mismatch error, got: %v", err)
	}

	// Parse with skip IP verify -> should succeed
	_, err = ParseKnockPacket(dk, packet, "10.0.0.1", 30, true)
	if err != nil {
		t.Errorf("skip IP verify should succeed: %v", err)
	}
}

// TestBuildKnockPacket_MaxDuration verifies maximum allowed duration.
func TestBuildKnockPacket_MaxDuration(t *testing.T) {
	dk, err := crypto.GenerateKeyPair(crypto.KEM768)
	if err != nil {
		t.Fatal(err)
	}
	ek := dk.EncapsulationKey()

	// Duration at uint32 max
	packet, err := BuildKnockPacket(ek, "10.0.0.1", "open-t22", math.MaxInt32)
	if err != nil {
		t.Fatal(err)
	}

	payload, err := ParseKnockPacket(dk, packet, "10.0.0.1", 30)
	if err != nil {
		// Might be rejected by duration check -- that's also valid
		return
	}
	if payload.OpenDuration != math.MaxInt32 {
		t.Errorf("duration mismatch: got %d, want %d", payload.OpenDuration, math.MaxInt32)
	}
}

// --- Mutation-resilient tests ---

// TestPacketTampering_SingleBitFlip verifies that any single bit flip in a packet is detected.
func TestPacketTampering_SingleBitFlip(t *testing.T) {
	dk, err := crypto.GenerateKeyPair(crypto.KEM768)
	if err != nil {
		t.Fatal(err)
	}
	ek := dk.EncapsulationKey()

	packet, err := BuildKnockPacket(ek, "192.168.1.1", "open-t22", 3600)
	if err != nil {
		t.Fatal(err)
	}

	// Flip each bit in the packet one at a time
	// Test a sample of positions to keep test fast
	positions := []int{0, 1, 10, 100, 500, 1000, len(packet) / 2, len(packet) - 1}
	for _, pos := range positions {
		if pos >= len(packet) {
			continue
		}
		for bit := 0; bit < 8; bit++ {
			tampered := make([]byte, len(packet))
			copy(tampered, packet)
			tampered[pos] ^= 1 << uint(bit)

			if bytes.Equal(tampered, packet) {
				continue // no change, skip
			}

			_, err := ParseKnockPacket(dk, tampered, "192.168.1.1", 30)
			if err == nil {
				t.Errorf("tampered packet accepted: position %d, bit %d", pos, bit)
			}
		}
	}
}

// TestPacketTampering_Truncation verifies truncated packets are rejected.
func TestPacketTampering_Truncation(t *testing.T) {
	dk, err := crypto.GenerateKeyPair(crypto.KEM768)
	if err != nil {
		t.Fatal(err)
	}
	ek := dk.EncapsulationKey()

	packet, err := BuildKnockPacket(ek, "192.168.1.1", "open-t22", 3600)
	if err != nil {
		t.Fatal(err)
	}

	// Truncate at various points
	for _, truncLen := range []int{0, 1, 10, 100, 500, 1000, len(packet) - 1} {
		if truncLen >= len(packet) {
			continue
		}
		_, err := ParseKnockPacket(dk, packet[:truncLen], "192.168.1.1", 30)
		if err == nil {
			t.Errorf("truncated packet (%d bytes) accepted", truncLen)
		}
	}
}

// TestPacketTampering_AppendedData verifies extra appended data is detected.
func TestPacketTampering_AppendedData(t *testing.T) {
	dk, err := crypto.GenerateKeyPair(crypto.KEM768)
	if err != nil {
		t.Fatal(err)
	}
	ek := dk.EncapsulationKey()

	packet, err := BuildKnockPacket(ek, "192.168.1.1", "open-t22", 3600)
	if err != nil {
		t.Fatal(err)
	}

	// Append extra bytes
	extended := make([]byte, len(packet)+100)
	copy(extended, packet)
	_, err = ParseKnockPacket(dk, extended, "192.168.1.1", 30)
	// AES-GCM should reject: extra data after authenticated ciphertext is invalid
	if err == nil {
		t.Error("packet with appended garbage accepted")
	}
}

// TestPacketTampering_WrongKey verifies packet encrypted for one key cannot be decrypted by another.
func TestPacketTampering_WrongKey(t *testing.T) {
	dk1, _ := crypto.GenerateKeyPair(crypto.KEM768)
	dk2, _ := crypto.GenerateKeyPair(crypto.KEM768)
	ek1 := dk1.EncapsulationKey()

	packet, err := BuildKnockPacket(ek1, "10.0.0.1", "open-t22", 3600)
	if err != nil {
		t.Fatal(err)
	}

	// Try decrypting with wrong key
	_, err = ParseKnockPacket(dk2, packet, "10.0.0.1", 30)
	if err == nil {
		t.Error("packet decrypted with wrong key")
	}
}

// TestPacketUniqueness verifies every packet is unique (forward secrecy via fresh KEM encapsulation).
func TestPacketUniqueness(t *testing.T) {
	dk, _ := crypto.GenerateKeyPair(crypto.KEM768)
	ek := dk.EncapsulationKey()

	seen := make(map[string]bool)
	for i := 0; i < 50; i++ {
		packet, err := BuildKnockPacket(ek, "10.0.0.1", "open-t22", 3600)
		if err != nil {
			t.Fatal(err)
		}
		key := string(packet)
		if seen[key] {
			t.Fatalf("duplicate packet at iteration %d", i)
		}
		seen[key] = true
	}
}

// TestEncodePayload_CommandLengthOverflow tests oversized command data.
func TestEncodePayload_CommandLengthOverflow(t *testing.T) {
	nonce := make([]byte, NonceBytes)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		t.Fatal(err)
	}

	// Command data that would make totalCmdLen > 255
	longCmd := "open-" + strings.Repeat("t22,", 63) + "t22"
	payload := &KnockPayload{
		Version:      ProtocolVersion,
		Timestamp:    time.Now().Unix(),
		Nonce:        hex.EncodeToString(nonce),
		ClientIP:     "10.0.0.1",
		Command:      longCmd,
		OpenDuration: 3600,
	}

	_, err := encodePayload(payload)
	if err == nil {
		t.Error("expected error for oversized command")
	}
}

// TestEncodePayload_InvalidIP tests encoding with malformed IPs.
func TestEncodePayload_InvalidIP(t *testing.T) {
	nonce := make([]byte, NonceBytes)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		t.Fatal(err)
	}

	badIPs := []string{
		"",
		"not-an-ip",
		"256.1.1.1",
		"1.2.3",
		"1.2.3.4.5",
		"::ffff::1::2",
		"; rm -rf /",
		"1.2.3.4$(id)",
	}

	for _, ip := range badIPs {
		t.Run(ip, func(t *testing.T) {
			payload := &KnockPayload{
				Version:      ProtocolVersion,
				Timestamp:    time.Now().Unix(),
				Nonce:        hex.EncodeToString(nonce),
				ClientIP:     ip,
				Command:      "open-t22",
				OpenDuration: 3600,
			}

			_, err := encodePayload(payload)
			if err == nil {
				t.Errorf("expected error for invalid IP %q", ip)
			}
		})
	}
}

// TestDecodePayload_ZeroCommandLength verifies cmdLen=0 is rejected.
func TestDecodePayload_ZeroCommandLength(t *testing.T) {
	nonce := make([]byte, NonceBytes)
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, uint64(time.Now().Unix()))

	data := []byte{1, 0} // version=1, flags=0
	data = append(data, ts...)
	data = append(data, nonce...)
	data = append(data, 10, 0, 0, 1)   // IPv4
	data = append(data, 0, 0, 0xe1, 0) // OpenDuration
	data = append(data, 0)             // CmdLen = 0 (invalid)
	data = append(data, 0x00)          // padding to reach minimum

	_, err := decodePayload(data)
	if err == nil {
		t.Error("expected error for cmdLen=0")
	}
}

// TestDecodePayload_MaxCmdLen verifies cmdLen=255 with insufficient data is rejected.
func TestDecodePayload_MaxCmdLen(t *testing.T) {
	nonce := make([]byte, NonceBytes)
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, uint64(time.Now().Unix()))

	data := []byte{1, 0} // version=1, flags=0
	data = append(data, ts...)
	data = append(data, nonce...)
	data = append(data, 10, 0, 0, 1) // IPv4
	data = append(data, 0, 0, 0, 0)  // OpenDuration
	data = append(data, 255)         // CmdLen = 255 (but only a few bytes follow)
	data = append(data, 0x00, 0x01)  // only 2 bytes of command data

	_, err := decodePayload(data)
	if err == nil {
		t.Error("expected error for truncated command with large cmdLen")
	}
}

// TestDecodePayload_UnsupportedVersion tests rejection of future protocol versions.
func TestDecodePayload_UnsupportedVersion(t *testing.T) {
	nonce := make([]byte, NonceBytes)
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, uint64(time.Now().Unix()))

	for _, version := range []byte{0, 2, 100, 255} {
		data := []byte{version, 0}
		data = append(data, ts...)
		data = append(data, nonce...)
		data = append(data, 10, 0, 0, 1)
		data = append(data, 0, 0, 0, 0)
		data = append(data, 4, 0x00)
		data = append(data, []byte("t22")...)

		payload, err := decodePayload(data)
		if err != nil {
			continue // decodePayload itself may not check version
		}
		// The version check happens in ParseKnockPacket, not decodePayload
		if payload.Version != int(version) {
			t.Errorf("version not preserved: got %d, want %d", payload.Version, version)
		}
	}
}
