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

// DefaultDynPortMin is the default lower bound (inclusive) of the dynamic port range.
const DefaultDynPortMin = 10000

// DefaultDynPortMax is the default upper bound (inclusive) of the dynamic port range.
const DefaultDynPortMax = 65000

// MinDynPortWindowSeconds is the minimum allowed rotation window (60 seconds).
// The server setup wizard rejects values below this; callers that accept user
// input should validate against this constant.
const MinDynPortWindowSeconds = 60

// ComputeDynamicPort derives a deterministic port from a shared seed and time window.
// Uses the default window of 600 seconds.
func ComputeDynamicPort(seed []byte) int {
	return ComputeDynamicPortWithWindow(seed, DynPortWindowSeconds)
}

// ComputeDynamicPortWithWindow derives a deterministic port using a custom window period
// and the default port range. Port changes every `windowSeconds` seconds.
func ComputeDynamicPortWithWindow(seed []byte, windowSeconds int) int {
	return ComputeDynamicPortInRange(seed, windowSeconds, DefaultDynPortMin, DefaultDynPortMax)
}

// ComputeDynamicPortInRange derives a deterministic port within [minPort, maxPort],
// both bounds inclusive. Both server and client must use the same seed, window, and
// range or the computed ports will not match. Invalid ranges fall back to the
// defaults via NormalizeDynPortRange.
func ComputeDynamicPortInRange(seed []byte, windowSeconds, minPort, maxPort int) int {
	if windowSeconds <= 0 {
		windowSeconds = DynPortWindowSeconds
	}
	window := time.Now().Unix() / int64(windowSeconds)
	return computeDynamicPortForWindowInRange(seed, window, minPort, maxPort)
}

// NormalizeDynPortRange validates an inclusive dynamic port range and substitutes
// the defaults when the range is unset or invalid. A valid range satisfies
// 1 <= min < max <= 65535.
func NormalizeDynPortRange(minPort, maxPort int) (int, int) {
	if minPort < 1 || maxPort > 65535 || minPort >= maxPort {
		return DefaultDynPortMin, DefaultDynPortMax
	}
	return minPort, maxPort
}

// computeDynamicPortForWindow computes the default-range port for a specific time
// window (for testing).
func computeDynamicPortForWindow(seed []byte, window int64) int {
	return computeDynamicPortForWindowInRange(seed, window, DefaultDynPortMin, DefaultDynPortMax)
}

// computeDynamicPortForWindowInRange computes the port for a specific time window
// and inclusive range. The HMAC output is reduced with
// `uint16 % (max - min + 1) + min`, matching the wire-format contract documented
// in docs/integration.md.
func computeDynamicPortForWindowInRange(seed []byte, window int64, minPort, maxPort int) int {
	minPort, maxPort = NormalizeDynPortRange(minPort, maxPort)
	h := hmac.New(sha256.New, seed)
	wb := make([]byte, 8)
	binary.BigEndian.PutUint64(wb, uint64(window))
	h.Write(wb)
	sum := h.Sum(nil)
	port := binary.BigEndian.Uint16(sum[:2])
	return int(port)%(maxPort-minPort+1) + minPort
}

// DynPortSecondsUntilChange returns how many seconds until the next port rotation.
func DynPortSecondsUntilChange() int {
	return DynPortSecondsUntilChangeWithWindow(DynPortWindowSeconds)
}

// DynPortSecondsUntilChangeWithWindow returns seconds until next rotation for a custom window.
// The result is in [1, windowSeconds] and is capped at MaxDynPortWaitSeconds to prevent
// integer overflow when converting to time.Duration (nanoseconds).
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
	return int(secs)
}

// MaxDynPortWaitSeconds is the maximum seconds DynPortSecondsUntilChangeWithWindow
// will return. This prevents integer overflow when the value is converted to
// time.Duration (nanoseconds). Capped at ~24 hours which is well beyond any
// reasonable rotation window.
const MaxDynPortWaitSeconds = 86400

// MaxDynPortWindowSeconds is the maximum allowed dynamic port rotation window.
// User-facing validation (setup wizard, config) must reject values above this.
// Kept in sync with MaxDynPortWaitSeconds; the two constants have distinct roles:
// MaxDynPortWaitSeconds caps the sleep duration, MaxDynPortWindowSeconds caps
// the user-configurable window.
const MaxDynPortWindowSeconds = 86400
