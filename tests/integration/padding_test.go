// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package integration

import (
	"testing"

	"spk/internal/crypto"
	"spk/internal/protocol"
)

// ------------------------------------------------------------------------
// Anti-DPI Garbage Padding Tests
// Verify that:
//   - Padded packets decrypt correctly
//   - Unpadded packets still work
//   - Server accepts both padded and unpadded
//   - Padding varies in size (randomness)
//   - Padding is inside the encrypted envelope (invisible to DPI)
//   - Padded packets don't exceed MaxPacketSize
// ------------------------------------------------------------------------

// TestPaddedPacketDecryption verifies that a padded knock packet decrypts correctly.
func TestPaddedPacketDecryption(t *testing.T) {
	dk, _ := crypto.GenerateKeyPair()
	ek := dk.EncapsulationKey()

	padCfg := protocol.PaddingConfig{
		Enabled:  true,
		MinBytes: 64,
		MaxBytes: 256,
	}

	packet, err := protocol.BuildKnockPacket(ek, "10.0.0.1", "open-t22", 3600, protocol.KnockOptions{Padding: padCfg})
	if err != nil {
		t.Fatalf("BuildKnockPacket with padding: %v", err)
	}

	// Should be larger than an unpadded packet
	unpaddedPkt, _ := protocol.BuildKnockPacket(ek, "10.0.0.1", "open-t22", 3600)
	if len(packet) <= len(unpaddedPkt) {
		t.Errorf("padded packet (%d bytes) should be larger than unpadded (%d bytes)",
			len(packet), len(unpaddedPkt))
	}

	// Decrypt and verify
	payload, err := protocol.ParseKnockPacket(dk, packet, "10.0.0.1", 30)
	if err != nil {
		t.Fatalf("ParseKnockPacket (padded): %v", err)
	}

	if payload.Command != "open-t22" {
		t.Errorf("command = %q, want open-t22", payload.Command)
	}
	if payload.ClientIP != "10.0.0.1" {
		t.Errorf("IP = %q, want 10.0.0.1", payload.ClientIP)
	}
	if payload.OpenDuration != 3600 {
		t.Errorf("open duration = %d, want 3600", payload.OpenDuration)
	}
	if payload.Padding == "" {
		t.Error("padding should be present in decrypted payload")
	}
	t.Logf("Padded packet: %d bytes, padding: %d hex chars", len(packet), len(payload.Padding))
}

// TestUnpaddedPacketStillWorks verifies that packets without padding still work.
func TestUnpaddedPacketStillWorks(t *testing.T) {
	dk, _ := crypto.GenerateKeyPair()
	ek := dk.EncapsulationKey()

	// No padding
	packet, err := protocol.BuildKnockPacket(ek, "10.0.0.1", "open-t22", 0)
	if err != nil {
		t.Fatalf("BuildKnockPacket without padding: %v", err)
	}

	payload, err := protocol.ParseKnockPacket(dk, packet, "10.0.0.1", 30)
	if err != nil {
		t.Fatalf("ParseKnockPacket (unpadded): %v", err)
	}

	if payload.Command != "open-t22" {
		t.Errorf("command = %q, want open-t22", payload.Command)
	}
	if payload.Padding != "" {
		t.Error("unpadded packet should have empty padding")
	}
}

// TestPaddingDisabledByDefault verifies that without PaddingConfig, no padding is added.
func TestPaddingDisabledByDefault(t *testing.T) {
	dk, _ := crypto.GenerateKeyPair()
	ek := dk.EncapsulationKey()

	padCfg := protocol.PaddingConfig{Enabled: false}
	packet, _ := protocol.BuildKnockPacket(ek, "10.0.0.1", "open-t22", 0, protocol.KnockOptions{Padding: padCfg})

	payload, _ := protocol.ParseKnockPacket(dk, packet, "10.0.0.1", 30)
	if payload.Padding != "" {
		t.Error("disabled padding should not add padding")
	}
}

// TestPaddingVariableSize verifies that padding produces variable-size packets.
func TestPaddingVariableSize(t *testing.T) {
	dk, _ := crypto.GenerateKeyPair()
	ek := dk.EncapsulationKey()

	padCfg := protocol.PaddingConfig{
		Enabled:  true,
		MinBytes: 32,
		MaxBytes: 512,
	}

	sizes := make(map[int]bool)
	for i := 0; i < 50; i++ {
		pkt, _ := protocol.BuildKnockPacket(ek, "10.0.0.1", "open-t22", 0, protocol.KnockOptions{Padding: padCfg})
		sizes[len(pkt)] = true
	}

	// With 32-512 byte range, we should get at least 5 distinct sizes in 50 packets
	if len(sizes) < 5 {
		t.Errorf("expected at least 5 distinct packet sizes from 50 padded packets, got %d", len(sizes))
	}
	t.Logf("Got %d distinct packet sizes from 50 padded packets", len(sizes))
}

// TestPaddingInsideEncryption verifies that padding is inside the encrypted envelope.
// An observer can see the total packet size but not the padding content.
func TestPaddingInsideEncryption(t *testing.T) {
	dk, _ := crypto.GenerateKeyPair()
	ek := dk.EncapsulationKey()

	padCfg := protocol.PaddingConfig{
		Enabled:  true,
		MinBytes: 100,
		MaxBytes: 100, // Fixed size for this test
	}

	pkt1, _ := protocol.BuildKnockPacket(ek, "10.0.0.1", "open-t22", 0, protocol.KnockOptions{Padding: padCfg})
	pkt2, _ := protocol.BuildKnockPacket(ek, "10.0.0.1", "open-t22", 0, protocol.KnockOptions{Padding: padCfg})

	// Both packets have same command and same padding size, but the actual cipher
	// bytes should differ (different KEM + different random padding content)
	if string(pkt1) == string(pkt2) {
		t.Error("two padded packets should not be identical")
	}

	// Decrypt both - padding content should differ (random padding)
	p1, _ := protocol.ParseKnockPacket(dk, pkt1, "10.0.0.1", 30)
	p2, _ := protocol.ParseKnockPacket(dk, pkt2, "10.0.0.1", 30)

	if p1.Padding == p2.Padding {
		t.Error("padding content should be random and differ between packets")
	}
}

// TestPaddedPacketWithinMaxSize verifies padded packets don't exceed MaxPacketSize.
func TestPaddedPacketWithinMaxSize(t *testing.T) {
	dk, _ := crypto.GenerateKeyPair()
	ek := dk.EncapsulationKey()

	// Use maximum padding
	padCfg := protocol.PaddingConfig{
		Enabled:  true,
		MinBytes: 512,
		MaxBytes: 512,
	}

	for i := 0; i < 20; i++ {
		pkt, err := protocol.BuildKnockPacket(ek, "10.0.0.1", "open-t22,t443,t80,t8080,u53", 86400, protocol.KnockOptions{Padding: padCfg})
		if err != nil {
			t.Fatalf("BuildKnockPacket: %v", err)
		}
		if len(pkt) > protocol.MaxPacketSize {
			t.Errorf("packet %d bytes exceeds MaxPacketSize %d", len(pkt), protocol.MaxPacketSize)
		}
	}
}

// TestServerAcceptsBothPaddedAndUnpadded verifies mixed traffic works.
func TestServerAcceptsBothPaddedAndUnpadded(t *testing.T) {
	dk, _ := crypto.GenerateKeyPair()
	ek := dk.EncapsulationKey()

	tracker := protocol.NewNonceTrackerWithLimit(5*60*1000000000, 10000) // 5 min

	// Send alternating padded and unpadded packets
	for i := 0; i < 20; i++ {
		var pkt []byte
		var err error
		if i%2 == 0 {
			padCfg := protocol.PaddingConfig{Enabled: true, MinBytes: 64, MaxBytes: 256}
			pkt, err = protocol.BuildKnockPacket(ek, "10.0.0.1", "open-t22", 0, protocol.KnockOptions{Padding: padCfg})
		} else {
			pkt, err = protocol.BuildKnockPacket(ek, "10.0.0.1", "open-t22", 0)
		}
		if err != nil {
			t.Fatalf("build %d: %v", i, err)
		}

		payload, err := protocol.ParseKnockPacket(dk, pkt, "10.0.0.1", 30)
		if err != nil {
			t.Errorf("parse %d: %v", i, err)
			continue
		}

		if !tracker.Check(payload.Nonce) {
			t.Errorf("nonce %d should be unique", i)
		}

		if payload.Command != "open-t22" {
			t.Errorf("packet %d: command = %q, want open-t22", i, payload.Command)
		}
	}
}

// TestPaddingMinBytesDefault verifies that invalid min/max get sensible defaults.
func TestPaddingMinBytesDefault(t *testing.T) {
	dk, _ := crypto.GenerateKeyPair()
	ek := dk.EncapsulationKey()

	// MinBytes=0 should default to 64
	padCfg := protocol.PaddingConfig{
		Enabled:  true,
		MinBytes: 0,
		MaxBytes: 0,
	}

	pkt, err := protocol.BuildKnockPacket(ek, "10.0.0.1", "open-t22", 0, protocol.KnockOptions{Padding: padCfg})
	if err != nil {
		t.Fatalf("BuildKnockPacket with zero padding config: %v", err)
	}

	payload, err := protocol.ParseKnockPacket(dk, pkt, "10.0.0.1", 30)
	if err != nil {
		t.Fatalf("ParseKnockPacket: %v", err)
	}

	if payload.Padding == "" {
		t.Error("padding should be present even with zero min/max (defaults applied)")
	}
}

// TestPaddingWithIPv6 verifies padding works with IPv6 client addresses.
func TestPaddingWithIPv6(t *testing.T) {
	dk, _ := crypto.GenerateKeyPair()
	ek := dk.EncapsulationKey()

	padCfg := protocol.PaddingConfig{
		Enabled:  true,
		MinBytes: 100,
		MaxBytes: 300,
	}

	ipv6 := "2001:db8::1"
	pkt, err := protocol.BuildKnockPacket(ek, ipv6, "open-t22,t443", 7200, protocol.KnockOptions{Padding: padCfg})
	if err != nil {
		t.Fatalf("BuildKnockPacket IPv6 with padding: %v", err)
	}

	payload, err := protocol.ParseKnockPacket(dk, pkt, ipv6, 30)
	if err != nil {
		t.Fatalf("ParseKnockPacket IPv6: %v", err)
	}

	if payload.ClientIP != ipv6 {
		t.Errorf("client IP = %q, want %q", payload.ClientIP, ipv6)
	}
	if payload.Padding == "" {
		t.Error("padding should be present")
	}
}

// TestPaddingSecurityProperties verifies that padding doesn't weaken security.
func TestPaddingSecurityProperties(t *testing.T) {
	dk, _ := crypto.GenerateKeyPair()
	ek := dk.EncapsulationKey()

	padCfg := protocol.PaddingConfig{Enabled: true, MinBytes: 128, MaxBytes: 256}

	// Build padded packet
	pkt, _ := protocol.BuildKnockPacket(ek, "10.0.0.1", "open-t22", 0, protocol.KnockOptions{Padding: padCfg})

	// Tamper with packet - should fail
	tampered := make([]byte, len(pkt))
	copy(tampered, pkt)
	tampered[len(tampered)/2] ^= 0xFF
	_, err := protocol.ParseKnockPacket(dk, tampered, "10.0.0.1", 30)
	if err == nil {
		t.Error("tampered padded packet should fail authentication")
	}

	// Wrong key - should fail
	dk2, _ := crypto.GenerateKeyPair()
	_, err = protocol.ParseKnockPacket(dk2, pkt, "10.0.0.1", 30)
	if err == nil {
		t.Error("padded packet should not decrypt with wrong key")
	}

	// IP mismatch - should fail
	_, err = protocol.ParseKnockPacket(dk, pkt, "10.0.0.2", 30)
	if err == nil {
		t.Error("padded packet should fail IP binding check")
	}
}
