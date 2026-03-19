// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package protocol

import (
	"testing"
	"time"

	"spk/internal/crypto"
)

// =============================================================================
// Multi-KEM Protocol Packet Tests
// =============================================================================

func TestBuildParseKnockPacket768(t *testing.T) {
	dk, err := crypto.GenerateKeyPair(crypto.KEM768)
	if err != nil {
		t.Fatalf("GenerateKeyPair(KEM768): %v", err)
	}
	ek := dk.EncapsulationKey()

	clientIP := "192.168.1.100"
	command := "open-t22"
	timeout := 3600

	packet, err := BuildKnockPacket(ek, clientIP, command, timeout)
	if err != nil {
		t.Fatalf("BuildKnockPacket: %v", err)
	}

	// KEM-768 packet: ciphertext(1088) + nonce(12) + AES(GCM tag 16 + payload)
	expectedMin := crypto.CiphertextSize768 + 12 + 16
	if len(packet) < expectedMin {
		t.Errorf("KEM-768 packet too small: %d < %d", len(packet), expectedMin)
	}

	payload, err := ParseKnockPacket(dk, packet, clientIP, 30)
	if err != nil {
		t.Fatalf("ParseKnockPacket: %v", err)
	}

	if payload.Version != ProtocolVersion {
		t.Errorf("version = %d, want %d", payload.Version, ProtocolVersion)
	}
	if payload.ClientIP != clientIP {
		t.Errorf("ClientIP = %s, want %s", payload.ClientIP, clientIP)
	}
	if payload.Command != command {
		t.Errorf("Command = %s, want %s", payload.Command, command)
	}
	if payload.OpenDuration != timeout {
		t.Errorf("OpenDuration = %d, want %d", payload.OpenDuration, timeout)
	}
	if payload.Nonce == "" {
		t.Error("Nonce should not be empty")
	}

	// Verify timestamp is recent
	now := time.Now().Unix()
	if abs(now-payload.Timestamp) > 5 {
		t.Errorf("timestamp drift too large: %d", abs(now-payload.Timestamp))
	}
}

func TestBuildParseKnockPacket1024(t *testing.T) {
	dk, err := crypto.GenerateKeyPair(crypto.KEM1024)
	if err != nil {
		t.Fatalf("GenerateKeyPair(KEM1024): %v", err)
	}
	ek := dk.EncapsulationKey()

	clientIP := "10.0.0.1"
	command := "open-t443"

	packet, err := BuildKnockPacket(ek, clientIP, command, 7200)
	if err != nil {
		t.Fatalf("BuildKnockPacket: %v", err)
	}

	expectedMin := crypto.CiphertextSize1024 + 12 + 16
	if len(packet) < expectedMin {
		t.Errorf("KEM-1024 packet too small: %d < %d", len(packet), expectedMin)
	}

	payload, err := ParseKnockPacket(dk, packet, clientIP, 30)
	if err != nil {
		t.Fatalf("ParseKnockPacket: %v", err)
	}

	if payload.Command != command {
		t.Errorf("Command = %s, want %s", payload.Command, command)
	}
}

func TestKEM768PacketSmallerThan1024(t *testing.T) {
	dk768, _ := crypto.GenerateKeyPair(crypto.KEM768)
	dk1024, _ := crypto.GenerateKeyPair(crypto.KEM1024)

	samePayload := "open-t22"
	clientIP := "192.168.1.1"

	pkt768, _ := BuildKnockPacket(dk768.EncapsulationKey(), clientIP, samePayload, 3600)
	pkt1024, _ := BuildKnockPacket(dk1024.EncapsulationKey(), clientIP, samePayload, 3600)

	if len(pkt768) >= len(pkt1024) {
		t.Errorf("KEM-768 packet (%d bytes) should be smaller than KEM-1024 (%d bytes)",
			len(pkt768), len(pkt1024))
	}

	// The size difference should be roughly CiphertextSize1024 - CiphertextSize768
	expectedDiff := crypto.CiphertextSize1024 - crypto.CiphertextSize768
	actualDiff := len(pkt1024) - len(pkt768)
	if actualDiff != expectedDiff {
		t.Errorf("size difference = %d, want %d (ciphertext size difference)", actualDiff, expectedDiff)
	}

	t.Logf("KEM-768: %d bytes, KEM-1024: %d bytes, diff: %d", len(pkt768), len(pkt1024), actualDiff)
}

func TestKEM768PacketFitsMTU(t *testing.T) {
	dk, _ := crypto.GenerateKeyPair(crypto.KEM768)
	ek := dk.EncapsulationKey()

	// Build with typical command (no padding)
	packet, _ := BuildKnockPacket(ek, "192.168.1.100", "open-t22", 3600)

	// IP(20) + UDP(8) + payload <=1500
	maxUDP := 1500 - 28
	if len(packet) > maxUDP {
		t.Errorf("KEM-768 packet %d bytes exceeds 1500 MTU (max UDP payload %d)", len(packet), maxUDP)
	}
}

func TestKEM768WithPaddingMTU(t *testing.T) {
	dk, _ := crypto.GenerateKeyPair(crypto.KEM768)
	ek := dk.EncapsulationKey()

	// 96 bytes is the defined safe maximum (MaxPaddingMTUSafe768).
	// With compact binary encoding, padding bytes are stored raw (not hex-encoded),
	// so 96 raw bytes -> 96 wire bytes keeping total packet well under 1472.
	opts := KnockOptions{
		Padding: PaddingConfig{
			Enabled:  true,
			MinBytes: 64,
			MaxBytes: 96,
		},
	}

	packet, err := BuildKnockPacket(ek, "192.168.1.100", "open-t22", 3600, opts)
	if err != nil {
		t.Fatalf("BuildKnockPacket with padding: %v", err)
	}

	maxUDP := 1500 - 28
	if len(packet) > maxUDP {
		t.Errorf("KEM-768 + 96-byte padding (%d bytes) exceeds MTU", len(packet))
	}
	t.Logf("KEM-768 with padding: %d bytes (max %d)", len(packet), maxUDP)
}

func TestCrossKEMPacketRejection(t *testing.T) {
	dk768, _ := crypto.GenerateKeyPair(crypto.KEM768)
	dk1024, _ := crypto.GenerateKeyPair(crypto.KEM1024)

	// Build with KEM-768 key, try to parse with KEM-1024 key
	packet, _ := BuildKnockPacket(dk768.EncapsulationKey(), "192.168.1.1", "open-t22", 0)
	_, err := ParseKnockPacket(dk1024, packet, "192.168.1.1", 30)
	if err == nil {
		t.Error("expected error parsing KEM-768 packet with KEM-1024 key")
	}

	// Build with KEM-1024 key, try to parse with KEM-768 key
	packet2, _ := BuildKnockPacket(dk1024.EncapsulationKey(), "10.0.0.1", "open-t443", 0)
	_, err = ParseKnockPacket(dk768, packet2, "10.0.0.1", 30)
	if err == nil {
		t.Error("expected error parsing KEM-1024 packet with KEM-768 key")
	}
}

func TestIPv6SupportMultiKEM(t *testing.T) {
	for _, size := range []crypto.KEMSize{crypto.KEM768, crypto.KEM1024} {
		dk, _ := crypto.GenerateKeyPair(size)
		ek := dk.EncapsulationKey()

		ipv6 := "2001:db8::1"
		packet, err := BuildKnockPacket(ek, ipv6, "open-t22", 3600)
		if err != nil {
			t.Fatalf("KEM-%d IPv6 BuildKnockPacket: %v", size, err)
		}

		payload, err := ParseKnockPacket(dk, packet, ipv6, 30)
		if err != nil {
			t.Fatalf("KEM-%d IPv6 ParseKnockPacket: %v", size, err)
		}
		if payload.ClientIP != ipv6 {
			t.Errorf("KEM-%d IPv6 ClientIP = %s, want %s", size, payload.ClientIP, ipv6)
		}
	}
}

func TestBatchCommandMultiKEM(t *testing.T) {
	for _, size := range []crypto.KEMSize{crypto.KEM768, crypto.KEM1024} {
		dk, _ := crypto.GenerateKeyPair(size)
		ek := dk.EncapsulationKey()

		// Test with a batch command containing multiple ports
		command := "open-t22,t443,t8080"
		packet, err := BuildKnockPacket(ek, "192.168.1.1", command, 3600)
		if err != nil {
			t.Fatalf("KEM-%d batch Build: %v", size, err)
		}
		payload, err := ParseKnockPacket(dk, packet, "192.168.1.1", 30)
		if err != nil {
			t.Fatalf("KEM-%d batch Parse: %v", size, err)
		}
		if payload.Command != command {
			t.Errorf("KEM-%d batch Command = %s, want %s", size, payload.Command, command)
		}
	}
}
