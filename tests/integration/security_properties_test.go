// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package integration

import (
	"testing"
	"time"

	"github.com/secured-port-knock/spk/internal/crypto"
	"github.com/secured-port-knock/spk/internal/protocol"
)

// ------------------------------------------------------------------------
// Security Property Tests
// These tests verify the cryptographic properties claimed in the README:
//   - No key reuse (every knock generates a new symmetric key)
//   - Key freshness (each knock generates a fresh, unrelated symmetric key)
//   - Replay prevention (nonce + timestamp)
//   - IP binding (encrypted IP verified against UDP source)
// ------------------------------------------------------------------------

// TestNoKeyReuse verifies that every knock packet uses a fresh ML-KEM
// encapsulation, producing a different ciphertext and thus a different
// symmetric key for AES-256-GCM.
func TestNoKeyReuse(t *testing.T) {
	dk, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	ek := dk.EncapsulationKey()

	ctSize := crypto.CiphertextSizeFor(dk.KEMSize())

	const n = 50
	ciphertexts := make([][]byte, n)
	for i := 0; i < n; i++ {
		packet, err := protocol.BuildKnockPacket(ek, "127.0.0.1", "open-t22", 3600)
		if err != nil {
			t.Fatalf("BuildKnockPacket #%d: %v", i, err)
		}
		ct := make([]byte, ctSize)
		copy(ct, packet[:ctSize])
		ciphertexts[i] = ct
	}

	// Every ciphertext must be unique (different KEM encapsulation = different shared key).
	seen := make(map[string]bool)
	for i, ct := range ciphertexts {
		if seen[string(ct)] {
			t.Errorf("ciphertext %d reuses a previous KEM encapsulation - key reuse detected!", i)
		}
		seen[string(ct)] = true
	}

	// Additionally verify at the cryptographic level: the derived AES-256-GCM
	// keys must all be distinct. Different ML-KEM ciphertexts always produce
	// different shared keys, but this check makes key freshness explicit.
	seenKeys := make(map[string]bool)
	for i, ct := range ciphertexts {
		sharedKey, err := dk.Decapsulate(ct)
		if err != nil {
			t.Fatalf("Decapsulate #%d: %v", i, err)
		}
		if seenKeys[string(sharedKey)] {
			t.Errorf("derived AES-GCM key %d is not unique - key freshness violated at cryptographic level", i)
		}
		seenKeys[string(sharedKey)] = true
	}
}

// TestKeyFreshness verifies that each packet's encryption is independent:
// knowing one decrypted packet gives no advantage in decrypting another.
// We verify this by showing each packet uses a completely different KEM
// ciphertext (and thus a different AES-256-GCM key).
func TestKeyFreshness(t *testing.T) {
	dk, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	ek := dk.EncapsulationKey()

	// Build two packets with identical content
	pkt1, err := protocol.BuildKnockPacket(ek, "10.0.0.1", "open-t22", 3600)
	if err != nil {
		t.Fatalf("BuildKnockPacket: %v", err)
	}
	pkt2, err := protocol.BuildKnockPacket(ek, "10.0.0.1", "open-t22", 3600)
	if err != nil {
		t.Fatalf("BuildKnockPacket: %v", err)
	}

	ctSize := crypto.CiphertextSizeFor(dk.KEMSize())

	// Ciphertexts must differ (fresh KEM encapsulation each time).
	ct1 := pkt1[:ctSize]
	ct2 := pkt2[:ctSize]
	if string(ct1) == string(ct2) {
		t.Fatal("two packets have identical KEM ciphertext - key freshness violated")
	}

	// AES-GCM nonces must differ.
	nonce1 := pkt1[ctSize : ctSize+12]
	nonce2 := pkt2[ctSize : ctSize+12]
	if string(nonce1) == string(nonce2) {
		t.Fatal("two packets have identical AES-GCM nonce")
	}

	// Encrypted payload must differ.
	enc1 := pkt1[ctSize+12:]
	enc2 := pkt2[ctSize+12:]
	if string(enc1) == string(enc2) {
		t.Fatal("two packets have identical encrypted payload - should differ due to different keys and nonces")
	}

	// Both must decrypt correctly with the same private key
	p1, err := protocol.ParseKnockPacket(dk, pkt1, "10.0.0.1", 30)
	if err != nil {
		t.Fatalf("decrypt pkt1: %v", err)
	}
	p2, err := protocol.ParseKnockPacket(dk, pkt2, "10.0.0.1", 30)
	if err != nil {
		t.Fatalf("decrypt pkt2: %v", err)
	}

	// Both should have the same command but different nonces
	if p1.Command != p2.Command {
		t.Errorf("command mismatch: %q vs %q", p1.Command, p2.Command)
	}
	if p1.Nonce == p2.Nonce {
		t.Error("two packets should have different payload nonces")
	}
}

// TestForwardSecrecyKeyCompromise verifies that having one decrypted session
// doesn't help decrypt any other session.
func TestForwardSecrecyKeyCompromise(t *testing.T) {
	dk, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	ek := dk.EncapsulationKey()

	// Build 10 packets
	packets := make([][]byte, 10)
	for i := range packets {
		pkt, err := protocol.BuildKnockPacket(ek, "127.0.0.1", "open-t22", 0)
		if err != nil {
			t.Fatalf("build %d: %v", i, err)
		}
		packets[i] = pkt
	}

	// Decrypt all - should succeed
	for i, pkt := range packets {
		_, err = protocol.ParseKnockPacket(dk, pkt, "127.0.0.1", 30)
		if err != nil {
			t.Errorf("decrypt %d: %v", i, err)
		}
	}

	// Wrong key can't decrypt any of them
	dk2, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	for i, pkt := range packets {
		_, err = protocol.ParseKnockPacket(dk2, pkt, "127.0.0.1", 30)
		if err == nil {
			t.Errorf("packet %d should NOT decrypt with wrong key", i)
		}
	}
}

// TestReplayPreventionNonceTracker verifies the nonce tracker rejects replays.
func TestReplayPreventionNonceTracker(t *testing.T) {
	dk, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	ek := dk.EncapsulationKey()

	tracker := protocol.NewNonceTrackerWithLimit(5*time.Minute, 10000)

	// Build and accept 100 unique packets; record the nonces.
	nonces := make([]string, 100)
	for i := 0; i < 100; i++ {
		pkt, err := protocol.BuildKnockPacket(ek, "127.0.0.1", "open-t22", 0)
		if err != nil {
			t.Fatalf("BuildKnockPacket: %v", err)
		}
		payload, err := protocol.ParseKnockPacket(dk, pkt, "127.0.0.1", 30)
		if err != nil {
			t.Fatalf("parse %d: %v", i, err)
		}
		if !tracker.Check(payload.Nonce) {
			t.Errorf("nonce %d should be unique and accepted", i)
		}
		nonces[i] = payload.Nonce
	}

	// Replay the original 100 nonces: every re-submission must be rejected.
	// This directly tests that previously seen nonces are blocked, simulating
	// an attacker replaying captured packets.
	for i, nonce := range nonces {
		if tracker.Check(nonce) {
			t.Errorf("replay of original nonce %d should be rejected", i)
		}
	}
}

// TestReplayPreventionTimestamp verifies packets outside the timestamp window are rejected.
func TestReplayPreventionTimestamp(t *testing.T) {
	dk, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	ek := dk.EncapsulationKey()

	pkt, err := protocol.BuildKnockPacket(ek, "127.0.0.1", "open-t22", 0)
	if err != nil {
		t.Fatalf("BuildKnockPacket: %v", err)
	}

	// With 30s tolerance - should pass
	_, err = protocol.ParseKnockPacket(dk, pkt, "127.0.0.1", 30)
	if err != nil {
		t.Fatalf("30s tolerance should pass: %v", err)
	}

	// Craft a packet with timestamp 10s in the past -- no sleep required.
	pastTimestampOpts := protocol.KnockOptions{Timestamp: time.Now().Unix() - 10}
	pkt2, err := protocol.BuildKnockPacket(ek, "127.0.0.1", "open-t22", 0, pastTimestampOpts)
	if err != nil {
		t.Fatalf("BuildKnockPacket with past timestamp: %v", err)
	}

	// With 1s tolerance, a 10s old packet should fail
	_, err = protocol.ParseKnockPacket(dk, pkt2, "127.0.0.1", 1)
	if err == nil {
		t.Error("packet older than tolerance should be rejected")
	}
}

// TestIPBindingEnforced verifies that the server rejects knock packets where the
// embedded client IP doesn't match the UDP source address.
func TestIPBindingEnforced(t *testing.T) {
	dk, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	ek := dk.EncapsulationKey()

	clientIP := "192.168.1.100"
	pkt, err := protocol.BuildKnockPacket(ek, clientIP, "open-t22", 3600)
	if err != nil {
		t.Fatalf("BuildKnockPacket: %v", err)
	}

	// Same IP: should pass
	_, err = protocol.ParseKnockPacket(dk, pkt, clientIP, 30)
	if err != nil {
		t.Fatalf("matching IP should succeed: %v", err)
	}

	// Different IP (spoofed source): should fail
	spoofedIPs := []string{
		"192.168.1.101", // Adjacent IP
		"10.0.0.1",      // Different subnet
		"203.0.113.5",   // Public IP
		"::1",           // IPv6 loopback
	}
	for _, spoofed := range spoofedIPs {
		_, err = protocol.ParseKnockPacket(dk, pkt, spoofed, 30)
		if err == nil {
			t.Errorf("packet from %q should be rejected (payload has %q)", spoofed, clientIP)
		}
	}
}

// TestIPBindingIPv6 verifies IP binding works with IPv6 addresses.
func TestIPBindingIPv6(t *testing.T) {
	dk, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	ek := dk.EncapsulationKey()

	ipv6 := "2001:db8::1"
	pkt, err := protocol.BuildKnockPacket(ek, ipv6, "open-t22", 0)
	if err != nil {
		t.Fatalf("BuildKnockPacket: %v", err)
	}

	// Matching IPv6: should pass
	_, err = protocol.ParseKnockPacket(dk, pkt, ipv6, 30)
	if err != nil {
		t.Fatalf("matching IPv6 should succeed: %v", err)
	}

	// Mismatched IPv6: should fail
	_, err = protocol.ParseKnockPacket(dk, pkt, "2001:db8::2", 30)
	if err == nil {
		t.Error("mismatched IPv6 should be rejected")
	}

	// IPv4 source with IPv6 payload: should fail
	_, err = protocol.ParseKnockPacket(dk, pkt, "192.168.1.1", 30)
	if err == nil {
		t.Error("IPv4 source with IPv6 payload should be rejected")
	}
}

// TestIPBindingSkipForNAT verifies that IP binding can be disabled.
func TestIPBindingSkipForNAT(t *testing.T) {
	dk, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	ek := dk.EncapsulationKey()

	lanIP := "192.168.1.100"
	pkt, err := protocol.BuildKnockPacket(ek, lanIP, "open-t22", 3600)
	if err != nil {
		t.Fatalf("BuildKnockPacket: %v", err)
	}

	// With skip=true, any source IP should work
	wanIPs := []string{"203.0.113.50", "10.0.0.1", "2001:db8::ff"}
	for _, wan := range wanIPs {
		payload, err := protocol.ParseKnockPacket(dk, pkt, wan, 30, true)
		if err != nil {
			t.Errorf("skipIPVerify=true should accept source %q: %v", wan, err)
			continue
		}
		if payload.ClientIP != lanIP {
			t.Errorf("payload IP should be %q, got %q", lanIP, payload.ClientIP)
		}
	}
}

// TestCiphertextAuthenticityPerPacket verifies that each packet's ciphertext
// is independently authenticated - modifying one packet doesn't help forge another.
func TestCiphertextAuthenticityPerPacket(t *testing.T) {
	dk, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	ek := dk.EncapsulationKey()

	pkt1, err := protocol.BuildKnockPacket(ek, "10.0.0.1", "open-t22", 0)
	if err != nil {
		t.Fatalf("BuildKnockPacket: %v", err)
	}
	pkt2, err := protocol.BuildKnockPacket(ek, "10.0.0.1", "open-t443", 0)
	if err != nil {
		t.Fatalf("BuildKnockPacket: %v", err)
	}

	ctSize := crypto.CiphertextSizeFor(dk.KEMSize())

	// Try swapping ciphertext from pkt1 with payload from pkt2.
	hybrid := make([]byte, len(pkt1))
	copy(hybrid[:ctSize], pkt1[:ctSize]) // KEM from pkt1
	copy(hybrid[ctSize:], pkt2[ctSize:]) // AES-GCM from pkt2
	_, err = protocol.ParseKnockPacket(dk, hybrid, "10.0.0.1", 30)
	if err == nil {
		t.Error("hybrid packet (KEM from pkt1 + AES-GCM from pkt2) should fail decryption")
	}

	// Swap the other way.
	hybrid2 := make([]byte, len(pkt2))
	copy(hybrid2[:ctSize], pkt2[:ctSize])
	copy(hybrid2[ctSize:], pkt1[ctSize:])
	_, err = protocol.ParseKnockPacket(dk, hybrid2, "10.0.0.1", 30)
	if err == nil {
		t.Error("reversed hybrid should also fail decryption")
	}
}

// TestKeyIndependence verifies that packets for two different servers are
// completely independent - no cross-decryption possible.
func TestKeyIndependence(t *testing.T) {
	dk1, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	ek1 := dk1.EncapsulationKey()
	dk2, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	ek2 := dk2.EncapsulationKey()

	pkt1, err := protocol.BuildKnockPacket(ek1, "10.0.0.1", "open-t22", 0)
	if err != nil {
		t.Fatalf("BuildKnockPacket: %v", err)
	}
	pkt2, err := protocol.BuildKnockPacket(ek2, "10.0.0.2", "open-t443", 0)
	if err != nil {
		t.Fatalf("BuildKnockPacket: %v", err)
	}

	// Each key only decrypts its own packets
	_, err = protocol.ParseKnockPacket(dk1, pkt1, "10.0.0.1", 30)
	if err != nil {
		t.Errorf("dk1 should decrypt pkt1: %v", err)
	}
	_, err = protocol.ParseKnockPacket(dk2, pkt2, "10.0.0.2", 30)
	if err != nil {
		t.Errorf("dk2 should decrypt pkt2: %v", err)
	}

	// Cross-decryption should fail
	_, err = protocol.ParseKnockPacket(dk1, pkt2, "10.0.0.2", 30)
	if err == nil {
		t.Error("dk1 should NOT decrypt pkt2")
	}
	_, err = protocol.ParseKnockPacket(dk2, pkt1, "10.0.0.1", 30)
	if err == nil {
		t.Error("dk2 should NOT decrypt pkt1")
	}
}
