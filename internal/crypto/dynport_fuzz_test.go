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
		if port < 10000 || port > 65000 {
			t.Errorf("port %d outside valid range 10000-65000 inclusive for seed=%x window=%d", port, seed, window)
		}
	})
}

// FuzzComputeDynamicPortInRange ensures range-aware port computation never
// panics, always lands inside the normalized range, and is deterministic.
func FuzzComputeDynamicPortInRange(f *testing.F) {
	f.Add([]byte{}, int64(0), 0, 0)
	f.Add([]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}, int64(100), 30010, 30020)
	f.Add(make([]byte, 8), int64(-1), -100, 100)
	f.Add(make([]byte, 8), int64(1<<62), 65535, 1)
	f.Add(make([]byte, 32), int64(42), 1, 65535)
	f.Add(make([]byte, 8), int64(7), 40000, 40001)

	f.Fuzz(func(t *testing.T, seed []byte, window int64, minPort, maxPort int) {
		port := computeDynamicPortForWindowInRange(seed, window, minPort, maxPort)
		nMin, nMax := NormalizeDynPortRange(minPort, maxPort)
		if port < nMin || port > nMax {
			t.Errorf("port %d outside normalized range %d-%d for seed=%x window=%d min=%d max=%d",
				port, nMin, nMax, seed, window, minPort, maxPort)
		}
		if again := computeDynamicPortForWindowInRange(seed, window, minPort, maxPort); again != port {
			t.Errorf("non-deterministic: %d then %d", port, again)
		}
	})
}

// --- Property-based tests ---

// TestDynPort_EmptySeed verifies empty seed does not panic.
func TestDynPort_EmptySeed(t *testing.T) {
	port := computeDynamicPortForWindow(nil, 0)
	if port < 10000 || port > 65000 {
		t.Errorf("invalid port for nil seed: %d", port)
	}
	port2 := computeDynamicPortForWindow([]byte{}, 0)
	if port2 < 10000 || port2 > 65000 {
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
	expected := int(binary.BigEndian.Uint16(sum[:2]))%55001 + 10000 // width 55001: 10000-65000 inclusive

	actual := computeDynamicPortForWindow(seed, window)
	if actual != expected {
		t.Errorf("port mismatch: got %d, want %d", actual, expected)
	}
}
