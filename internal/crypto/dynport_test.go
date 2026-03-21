// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package crypto

import (
	"crypto/rand"
	"testing"
	"time"
)

func TestDynPortDeterminism(t *testing.T) {
	// Same seed + same time = same port, every time
	seed := make([]byte, 8)
	rand.Read(seed)

	window := time.Now().Unix() / int64(DynPortWindowSeconds)
	port1 := computeDynamicPortForWindow(seed, window)
	port2 := computeDynamicPortForWindow(seed, window)
	port3 := computeDynamicPortForWindow(seed, window)

	if port1 != port2 || port2 != port3 {
		t.Errorf("determinism failed: got %d, %d, %d - all should be equal", port1, port2, port3)
	}
}

func TestDynPortWithWindowDeterminism(t *testing.T) {
	seed := make([]byte, 8)
	rand.Read(seed)

	// Custom windows should also produce deterministic results
	for _, windowSec := range []int{60, 120, 300, 600, 900, 3600} {
		window := time.Now().Unix() / int64(windowSec)
		p1 := computeDynamicPortForWindow(seed, window)
		p2 := computeDynamicPortForWindow(seed, window)
		if p1 != p2 {
			t.Errorf("window=%d: port mismatch %d vs %d", windowSec, p1, p2)
		}
	}
}

func TestDynPortDifferentWindowsProduceDifferentPorts(t *testing.T) {
	seed := make([]byte, 8)
	rand.Read(seed)

	// Different time windows should (almost always) produce different ports
	// Use specific window numbers to avoid time-based flakiness
	ports := make(map[int]bool)
	for w := int64(1); w <= 100; w++ {
		p := computeDynamicPortForWindow(seed, w)
		ports[p] = true
	}

	// With 55000 possible ports and 100 windows, collisions are possible but
	// we should see at least 50 unique ports
	if len(ports) < 50 {
		t.Errorf("too few unique ports from 100 windows: got %d, expected >= 50", len(ports))
	}
}

func TestDynPortRange(t *testing.T) {
	seed := make([]byte, 8)
	rand.Read(seed)

	// Run 1000 iterations with different windows and verify all ports in range
	for w := int64(0); w < 1000; w++ {
		port := computeDynamicPortForWindow(seed, w)
		if port < 10000 || port >= 65000 {
			t.Errorf("window=%d: port %d out of range [10000, 65000)", w, port)
		}
	}
}

func TestDynPortDifferentSeeds(t *testing.T) {
	seed1 := make([]byte, 8)
	seed2 := make([]byte, 8)
	rand.Read(seed1)
	rand.Read(seed2)

	window := time.Now().Unix() / int64(DynPortWindowSeconds)
	port1 := computeDynamicPortForWindow(seed1, window)
	port2 := computeDynamicPortForWindow(seed2, window)

	// Different seeds should produce different ports (extremely high probability)
	if port1 == port2 {
		t.Logf("WARNING: same port %d from two random seeds (possible but unlikely)", port1)
	}
}

func TestDynPortSecondsUntilChange(t *testing.T) {
	remaining := DynPortSecondsUntilChange()
	if remaining < 0 || remaining > DynPortWindowSeconds {
		t.Errorf("DynPortSecondsUntilChange() = %d, expected in [0, %d]", remaining, DynPortWindowSeconds)
	}
}

func TestDynPortSecondsUntilChangeWithWindow(t *testing.T) {
	for _, ws := range []int{60, 120, 600, 3600} {
		remaining := DynPortSecondsUntilChangeWithWindow(ws)
		if remaining < 0 || remaining > ws {
			t.Errorf("DynPortSecondsUntilChangeWithWindow(%d) = %d, expected in [0, %d]", ws, remaining, ws)
		}
	}
}

func TestDynPortDefaultWindowFallback(t *testing.T) {
	seed := make([]byte, 8)
	rand.Read(seed)

	// Zero and negative window should fall back to default
	p1 := ComputeDynamicPortWithWindow(seed, 0)
	p2 := ComputeDynamicPort(seed)
	if p1 != p2 {
		t.Errorf("window=0 (%d) should produce same port as default (%d)", p1, p2)
	}

	p3 := ComputeDynamicPortWithWindow(seed, -1)
	if p3 != p2 {
		t.Errorf("window=-1 (%d) should produce same port as default (%d)", p3, p2)
	}
}

func TestDynPortWindowSecondsUntilChangeFallback(t *testing.T) {
	// Zero window should return a reasonable value
	r := DynPortSecondsUntilChangeWithWindow(0)
	if r < 0 || r > DynPortWindowSeconds {
		t.Errorf("DynPortSecondsUntilChangeWithWindow(0) = %d, expected [0, %d]", r, DynPortWindowSeconds)
	}
}

// TestRotationSleepLandsPastBoundary verifies that sleeping secsUntil+1 seconds
// always places us in the next window, for all window sizes.
func TestRotationSleepLandsPastBoundary(t *testing.T) {
	for _, ws := range []int{60, 120, 300, 600, 900, 3600, 86400} {
		now := time.Now().Unix()
		wsi := int64(ws)
		// Replicate the exact server arithmetic
		secsUntil := DynPortSecondsUntilChangeWithWindow(ws)
		futureTime := now + int64(secsUntil) + 1

		currentWindow := now / wsi
		futureWindow := futureTime / wsi

		if futureWindow != currentWindow+1 {
			t.Errorf("window=%ds: sleep(%d+1) lands in window %d, want %d (now=%d, boundary=%d)",
				ws, secsUntil, futureWindow, currentWindow+1, now, (currentWindow+1)*wsi)
		}
	}
}

// TestRotationSleepNeverExceedsWindow verifies secsUntil is always <= windowSeconds
// (so sleep duration is at most windowSeconds+1).
// When now falls exactly on a window boundary, secsUntil equals windowSeconds.
func TestRotationSleepNeverExceedsWindow(t *testing.T) {
	for _, ws := range []int{60, 120, 300, 600, 3600} {
		secsUntil := DynPortSecondsUntilChangeWithWindow(ws)
		if secsUntil < 0 || secsUntil > ws {
			t.Errorf("window=%ds: secsUntil=%d not in [0, %d]", ws, secsUntil, ws)
		}
	}
}

// TestRotationSleepPortChanges verifies that after sleeping secsUntil+1 seconds
// (simulated via time arithmetic, no actual sleep), the computed port changes.
func TestRotationSleepPortChanges(t *testing.T) {
	seed := make([]byte, 8)
	rand.Read(seed)

	for _, ws := range []int{60, 120, 300, 600} {
		now := time.Now().Unix()
		wsi := int64(ws)

		secsUntil := DynPortSecondsUntilChangeWithWindow(ws)
		futureTime := now + int64(secsUntil) + 1

		currentWindow := now / wsi
		futureWindow := futureTime / wsi

		portNow := computeDynamicPortForWindow(seed, currentWindow)
		portAfter := computeDynamicPortForWindow(seed, futureWindow)

		// Ports almost certainly differ (they're independent HMAC outputs);
		// log but don't fail on the vanishingly-rare collision.
		if portNow == portAfter {
			t.Logf("window=%ds: same port %d in windows %d and %d (rare hash collision, not a bug)",
				ws, portNow, currentWindow, futureWindow)
		}

		// The most important invariant: futureWindow is exactly currentWindow+1
		if futureWindow != currentWindow+1 {
			t.Errorf("window=%ds: expected futureWindow=%d, got %d", ws, currentWindow+1, futureWindow)
		}
	}
}

// TestRotationSleepArithmeticAtBoundary verifies the calculation is correct
// for synthetic boundary-condition times, without relying on time.Now().
func TestRotationSleepArithmeticAtBoundary(t *testing.T) {
	// secsUntil formula (mirrors DynPortSecondsUntilChangeWithWindow):
	//   secsUntil = ((now/ws + 1) * ws) - now
	// After sleep(secsUntil + 1), futureTime = now + secsUntil + 1.
	// Invariant: futureTime/ws == now/ws + 1 (exactly one window forward).
	for _, ws := range []int{60, 300, 600} {
		wsi := int64(ws)
		// Test several synthetic "now" values covering key edge cases:
		//   k*ws - 1 : 1 second before boundary (secsUntil = 1, minimum)
		//   k*ws     : exactly at window start (secsUntil = ws, maximum)
		//   k*ws + 1 : 1 second past window start
		for _, k := range []int64{1, 2, 100, 1000} {
			for _, offset := range []int64{-1, 0, 1, wsi / 2} {
				now := k*wsi + offset
				secsUntil := ((now/wsi + 1) * wsi) - now
				futureTime := now + secsUntil + 1
				wantWindow := now/wsi + 1
				if futureTime/wsi != wantWindow {
					t.Errorf("ws=%d now=%d (offset=%d): sleep(%d+1) -> window %d, want %d",
						ws, now, offset, secsUntil, futureTime/wsi, wantWindow)
				}
				// secsUntil must be in [1, ws]
				if secsUntil < 1 || secsUntil > wsi {
					t.Errorf("ws=%d now=%d: secsUntil=%d out of [1,%d]", ws, now, secsUntil, ws)
				}
			}
		}
	}
}

func TestDynPortConsistencyAcrossCalls(t *testing.T) {
	// Verify that ComputeDynamicPort and ComputeDynamicPortWithWindow(seed, 600) agree
	seed := make([]byte, 8)
	rand.Read(seed)

	p1 := ComputeDynamicPort(seed)
	p2 := ComputeDynamicPortWithWindow(seed, DynPortWindowSeconds)

	if p1 != p2 {
		t.Errorf("ComputeDynamicPort=%d vs ComputeDynamicPortWithWindow(600)=%d", p1, p2)
	}
}

func TestDynPortSecondsUntilChangeCapped(t *testing.T) {
	// A very large window should be capped at MaxDynPortWaitSeconds
	// to prevent integer overflow when multiplied by time.Second (nanoseconds).
	hugeWindow := MaxDynPortWaitSeconds * 100
	result := DynPortSecondsUntilChangeWithWindow(hugeWindow)
	if result > MaxDynPortWaitSeconds {
		t.Errorf("DynPortSecondsUntilChangeWithWindow(%d) = %d, want <= %d", hugeWindow, result, MaxDynPortWaitSeconds)
	}
	if result < 0 {
		t.Errorf("DynPortSecondsUntilChangeWithWindow(%d) = %d, want >= 0", hugeWindow, result)
	}
}

func TestDynPortSecondsUntilChangeNoOverflow(t *testing.T) {
	// Verify that (secsUntil + 1) * time.Second does not overflow int64
	// for any valid return value from DynPortSecondsUntilChangeWithWindow.
	for _, ws := range []int{1, 60, 600, 3600, 86400, MaxDynPortWaitSeconds * 10} {
		secs := DynPortSecondsUntilChangeWithWindow(ws)
		dur := time.Duration(secs+1) * time.Second
		if dur <= 0 {
			t.Errorf("window=%d: (secsUntil=%d + 1) * time.Second overflowed to %v", ws, secs, dur)
		}
	}
}
