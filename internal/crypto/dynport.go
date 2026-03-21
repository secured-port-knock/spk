// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"time"
)

// DynPortWindowSeconds is the default time window for dynamic port rotation (10 minutes).
const DynPortWindowSeconds = 600

// ComputeDynamicPort derives a deterministic port from a shared seed and time window.
// Uses the default window of 600 seconds.
func ComputeDynamicPort(seed []byte) int {
	return ComputeDynamicPortWithWindow(seed, DynPortWindowSeconds)
}

// ComputeDynamicPortWithWindow derives a deterministic port using a custom window period.
// Both server and client compute the same port given the same seed, time, and window.
// Port changes every `windowSeconds` seconds. Returns a port in range [10000, 65000).
func ComputeDynamicPortWithWindow(seed []byte, windowSeconds int) int {
	if windowSeconds <= 0 {
		windowSeconds = DynPortWindowSeconds
	}
	window := time.Now().Unix() / int64(windowSeconds)
	return computeDynamicPortForWindow(seed, window)
}

// computeDynamicPortForWindow computes the port for a specific time window (for testing).
func computeDynamicPortForWindow(seed []byte, window int64) int {
	h := hmac.New(sha256.New, seed)
	wb := make([]byte, 8)
	binary.BigEndian.PutUint64(wb, uint64(window))
	h.Write(wb)
	sum := h.Sum(nil)
	port := binary.BigEndian.Uint16(sum[:2])
	return int(port)%55000 + 10000 // range [10000, 65000)
}

// DynPortSecondsUntilChange returns how many seconds until the next port rotation.
func DynPortSecondsUntilChange() int {
	return DynPortSecondsUntilChangeWithWindow(DynPortWindowSeconds)
}

// DynPortSecondsUntilChangeWithWindow returns seconds until next rotation for a custom window.
// The result is capped at MaxDynPortWaitSeconds to prevent integer overflow
// when converting to time.Duration (nanoseconds).
func DynPortSecondsUntilChangeWithWindow(windowSeconds int) int {
	if windowSeconds <= 0 {
		windowSeconds = DynPortWindowSeconds
	}
	now := time.Now().Unix()
	ws := int64(windowSeconds)
	nextWindow := ((now / ws) + 1) * ws
	secs := nextWindow - now
	if secs > MaxDynPortWaitSeconds {
		secs = MaxDynPortWaitSeconds
	}
	if secs < 60 {
		secs = 60
	}
	return int(secs)
}

// MaxDynPortWaitSeconds is the maximum seconds DynPortSecondsUntilChangeWithWindow
// will return. This prevents integer overflow when the value is converted to
// time.Duration (nanoseconds). Capped at ~24 hours which is well beyond any
// reasonable rotation window.
const MaxDynPortWaitSeconds = 86400
