// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

// --- Fuzz tests ---

// FuzzComputeDynamicPortForWindow ensures dynamic port computation never panics
// and always returns a port in the valid range.
func FuzzComputeDynamicPortForWindow(f *testing.F) {
	f.Add([]byte{}, int64(0))
	f.Add([]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}, int64(100))
	f.Add(make([]byte, 8), int64(-1))
	f.Add(make([]byte, 8), int64(1<<62))
	f.Add(make([]byte, 32), int64(42))

	f.Fuzz(func(t *testing.T, seed []byte, window int64) {
		port := computeDynamicPortForWindow(seed, window)
		if port < 10000 || port >= 65000 {
			t.Errorf("port %d outside valid range [10000, 65000) for seed=%x window=%d", port, seed, window)
		}
	})
}

// --- Property-based tests ---

// TestDynPort_Deterministic verifies same inputs always produce same port.
func TestDynPort_Deterministic(t *testing.T) {
	seed := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	window := int64(12345)

	port1 := computeDynamicPortForWindow(seed, window)
	port2 := computeDynamicPortForWindow(seed, window)
	if port1 != port2 {
		t.Errorf("non-deterministic: %d != %d", port1, port2)
	}
}

// TestDynPort_DifferentWindows verifies different time windows usually produce different ports.
func TestDynPort_DifferentWindows(t *testing.T) {
	seed := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	ports := make(map[int]int) // port -> count
	for w := int64(0); w < 1000; w++ {
		port := computeDynamicPortForWindow(seed, w)
		ports[port]++
	}
	// With 55000 possible ports and 1000 windows, collisions should be rare
	// At least 900 unique ports expected
	if len(ports) < 900 {
		t.Errorf("too few unique ports: %d out of 1000 windows", len(ports))
	}
}

// TestDynPort_DifferentSeeds verifies different seeds produce different ports for the same window.
func TestDynPort_DifferentSeeds(t *testing.T) {
	window := int64(42)
	ports := make(map[int]bool)
	for i := 0; i < 100; i++ {
		seed := make([]byte, 8)
		binary.BigEndian.PutUint64(seed, uint64(i))
		port := computeDynamicPortForWindow(seed, window)
		ports[port] = true
	}
	// At least 95 unique ports out of 100 seeds
	if len(ports) < 95 {
		t.Errorf("too many collisions: only %d unique ports from 100 seeds", len(ports))
	}
}

// TestDynPort_EmptySeed verifies empty seed does not panic.
func TestDynPort_EmptySeed(t *testing.T) {
	port := computeDynamicPortForWindow(nil, 0)
	if port < 10000 || port >= 65000 {
		t.Errorf("invalid port for nil seed: %d", port)
	}
	port2 := computeDynamicPortForWindow([]byte{}, 0)
	if port2 < 10000 || port2 >= 65000 {
		t.Errorf("invalid port for empty seed: %d", port2)
	}
}

// TestDynPort_MatchesHMACSHA256 verifies the computation matches expected HMAC-SHA256 derivation.
func TestDynPort_MatchesHMACSHA256(t *testing.T) {
	seed := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44}
	window := int64(999)

	// Compute expected
	h := hmac.New(sha256.New, seed)
	wb := make([]byte, 8)
	binary.BigEndian.PutUint64(wb, uint64(window))
	h.Write(wb)
	sum := h.Sum(nil)
	expected := int(binary.BigEndian.Uint16(sum[:2]))%55000 + 10000

	actual := computeDynamicPortForWindow(seed, window)
	if actual != expected {
		t.Errorf("port mismatch: got %d, want %d", actual, expected)
	}
}

// TestDynPort_WindowZeroFallback verifies windowSeconds<=0 uses default.
func TestDynPort_WindowZeroFallback(t *testing.T) {
	seed := []byte{1, 2, 3, 4, 5, 6, 7, 8}

	// ComputeDynamicPortWithWindow with 0 should use default (600)
	port0 := ComputeDynamicPortWithWindow(seed, 0)
	portNeg := ComputeDynamicPortWithWindow(seed, -100)

	if port0 < 10000 || port0 >= 65000 {
		t.Errorf("invalid port for window=0: %d", port0)
	}
	if portNeg < 10000 || portNeg >= 65000 {
		t.Errorf("invalid port for window=-100: %d", portNeg)
	}
	// Both should use default window and produce the same port
	if port0 != portNeg {
		t.Errorf("window=0 and window=-100 should produce same result: %d vs %d", port0, portNeg)
	}
}
