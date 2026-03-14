// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package protocol

import (
	"fmt"
	"testing"
	"time"

	"spk/internal/crypto"
)

func TestNonceCacheLimit(t *testing.T) {
	maxCache := 100
	tracker := NewNonceTrackerWithLimit(5*time.Minute, maxCache)

	// Fill cache to the limit
	for i := 0; i < maxCache; i++ {
		nonce := fmt.Sprintf("nonce_%08d", i)
		if !tracker.Check(nonce) {
			t.Fatalf("fresh nonce %d rejected", i)
		}
	}

	if tracker.Size() != maxCache {
		t.Errorf("size = %d, want %d", tracker.Size(), maxCache)
	}

	// Adding one more should trigger eviction (removes 10% = 10)
	if !tracker.Check("overflow_nonce") {
		t.Error("overflow nonce rejected")
	}

	size := tracker.Size()
	// After eviction of 10 entries + adding 1, we should have 91
	expectedMax := maxCache - maxCache/10 + 1
	if size > expectedMax {
		t.Errorf("after eviction: size = %d, expected <= %d", size, expectedMax)
	}
}

func TestNonceCacheEvictionRemovesOldest(t *testing.T) {
	tracker := NewNonceTrackerWithLimit(5*time.Minute, 20)

	// Add nonces with artificial time gaps
	for i := 0; i < 20; i++ {
		tracker.Check(fmt.Sprintf("nonce_%d", i))
		// Small delay to ensure ordering (time.Now() resolution)
		time.Sleep(1 * time.Millisecond)
	}

	// Add an extra to trigger eviction (removes 2 oldest = 10%)
	tracker.Check("trigger_eviction")

	// The oldest nonces (nonce_0, nonce_1) should have been evicted
	// Their re-addition should succeed (they're no longer tracked)
	if !tracker.Check("nonce_0") {
		t.Error("evicted nonce_0 should be treated as new")
	}
	if !tracker.Check("nonce_1") {
		t.Error("evicted nonce_1 should be treated as new")
	}

	// A recent nonce should still be tracked (duplicate = rejected)
	if tracker.Check("nonce_19") {
		t.Error("recent nonce_19 should still be in cache (rejected as duplicate)")
	}
}

func TestNonceCacheUnlimited(t *testing.T) {
	// maxCache=0 means unlimited
	tracker := NewNonceTrackerWithLimit(5*time.Minute, 0)

	for i := 0; i < 1000; i++ {
		tracker.Check(fmt.Sprintf("nonce_%d", i))
	}

	if tracker.Size() != 1000 {
		t.Errorf("unlimited cache size = %d, want 1000", tracker.Size())
	}
}

func TestParseKnockPacketMatchIncomingIP(t *testing.T) {
	dk, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	ek := dk.EncapsulationKey()

	// Build a packet claiming to be from 10.0.0.1
	packet, err := BuildKnockPacket(ek, "10.0.0.1", "open-t22", 3600)
	if err != nil {
		t.Fatalf("BuildKnockPacket: %v", err)
	}

	// Parse with source IP 203.0.113.5 (NAT'd) - should fail with match_incoming_ip enabled
	_, err = ParseKnockPacket(dk, packet, "203.0.113.5", 30)
	if err == nil {
		t.Error("expected IP mismatch error with match_incoming_ip enabled")
	}

	// Parse with skipIPVerify=true (match_incoming_ip=false) - should succeed despite IP mismatch
	payload, err := ParseKnockPacket(dk, packet, "203.0.113.5", 30, true)
	if err != nil {
		t.Fatalf("ParseKnockPacket with match_incoming_ip=false: %v", err)
	}

	if payload.ClientIP != "10.0.0.1" {
		t.Errorf("ClientIP = %q, want %q", payload.ClientIP, "10.0.0.1")
	}
	if payload.Command != "open-t22" {
		t.Errorf("Command = %q, want %q", payload.Command, "open-t22")
	}
}

func TestParseKnockPacketMatchIncomingIPDefault(t *testing.T) {
	dk, _ := crypto.GenerateKeyPair()
	ek := dk.EncapsulationKey()

	packet, _ := BuildKnockPacket(ek, "192.168.1.1", "open-t22", 0)

	// With match_incoming_ip=true (default), matching IP should work
	_, err := ParseKnockPacket(dk, packet, "192.168.1.1", 30)
	if err != nil {
		t.Fatalf("matching IP should succeed: %v", err)
	}

	// With match_incoming_ip=true (default), mismatched IP should fail
	_, err = ParseKnockPacket(dk, packet, "192.168.1.2", 30)
	if err == nil {
		t.Error("mismatched IP should fail with match_incoming_ip=true")
	}
}

func TestNonceTrackerCleanup(t *testing.T) {
	// Very short expiry to test cleanup
	tracker := NewNonceTrackerWithLimit(100*time.Millisecond, 0)

	tracker.Check("nonce_1")
	tracker.Check("nonce_2")

	if tracker.Size() != 2 {
		t.Errorf("size = %d, want 2", tracker.Size())
	}

	// Wait for nonces to expire + cleanup cycle (30s in production, but
	// we test the expiry by re-checking)
	time.Sleep(200 * time.Millisecond)

	// After expiry, the same nonce should be accepted again
	// (cleanup happens on 30s ticker, so we access directly)
	tracker.mu.Lock()
	cutoff := time.Now().Add(-tracker.expiry)
	for nonce, ts := range tracker.nonces {
		if ts.Before(cutoff) {
			delete(tracker.nonces, nonce)
		}
	}
	tracker.mu.Unlock()

	// Now nonce_1 should be accepted (expired and cleaned)
	if !tracker.Check("nonce_1") {
		t.Error("expired nonce_1 should be accepted after cleanup")
	}
}

func TestNonceTrackerConcurrent(t *testing.T) {
	tracker := NewNonceTrackerWithLimit(5*time.Minute, 10000)

	// Concurrent nonce checking should not panic or deadlock
	done := make(chan bool)
	for g := 0; g < 10; g++ {
		go func(id int) {
			for i := 0; i < 100; i++ {
				tracker.Check(fmt.Sprintf("g%d_n%d", id, i))
			}
			done <- true
		}(g)
	}

	for g := 0; g < 10; g++ {
		<-done
	}

	// All 1000 unique nonces should be tracked
	if tracker.Size() != 1000 {
		t.Errorf("concurrent: size = %d, want 1000", tracker.Size())
	}
}
