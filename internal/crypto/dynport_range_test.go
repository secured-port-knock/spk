// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package crypto

import (
	"crypto/rand"
	"testing"
	"time"
)

func TestNormalizeDynPortRange(t *testing.T) {
	cases := []struct {
		name             string
		min, max         int
		wantMin, wantMax int
	}{
		{"unset zeros fall back", 0, 0, DefaultDynPortMin, DefaultDynPortMax},
		{"defaults pass through", 10000, 65000, 10000, 65000},
		{"custom range passes through", 30010, 30020, 30010, 30020},
		{"two-port range passes through", 40000, 40001, 40000, 40001},
		{"full range passes through", 1, 65535, 1, 65535},
		{"negative min falls back", -5, 100, DefaultDynPortMin, DefaultDynPortMax},
		{"zero min falls back", 0, 30000, DefaultDynPortMin, DefaultDynPortMax},
		{"min equals max falls back", 30000, 30000, DefaultDynPortMin, DefaultDynPortMax},
		{"min greater than max falls back", 50000, 40000, DefaultDynPortMin, DefaultDynPortMax},
		{"max beyond uint16 falls back", 10, 70000, DefaultDynPortMin, DefaultDynPortMax},
		{"max 65536 falls back", 10, 65536, DefaultDynPortMin, DefaultDynPortMax},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotMin, gotMax := NormalizeDynPortRange(tc.min, tc.max)
			if gotMin != tc.wantMin || gotMax != tc.wantMax {
				t.Errorf("NormalizeDynPortRange(%d, %d) = (%d, %d), want (%d, %d)",
					tc.min, tc.max, gotMin, gotMax, tc.wantMin, tc.wantMax)
			}
		})
	}
}

func TestComputeDynamicPortInRangeBounds(t *testing.T) {
	seed := make([]byte, 8)
	rand.Read(seed)

	ranges := []struct{ min, max int }{
		{30010, 30020},
		{10000, 65000},
		{1, 65535},
		{1024, 2048},
		{40000, 40001}, // two possible ports
	}
	for _, r := range ranges {
		for w := int64(0); w < 500; w++ {
			port := computeDynamicPortForWindowInRange(seed, w, r.min, r.max)
			if port < r.min || port > r.max {
				t.Fatalf("range %d-%d window %d: port %d out of bounds", r.min, r.max, w, port)
			}
		}
	}
}

func TestComputeDynamicPortInRangeDeterminism(t *testing.T) {
	seed := make([]byte, 8)
	rand.Read(seed)

	for w := int64(0); w < 50; w++ {
		p1 := computeDynamicPortForWindowInRange(seed, w, 30010, 30020)
		p2 := computeDynamicPortForWindowInRange(seed, w, 30010, 30020)
		if p1 != p2 {
			t.Fatalf("window %d: non-deterministic ports %d vs %d", w, p1, p2)
		}
	}
}

func TestComputeDynamicPortInRangeInvalidFallsBackToDefault(t *testing.T) {
	seed := make([]byte, 8)
	rand.Read(seed)

	invalid := []struct{ min, max int }{
		{0, 0},
		{-1, 30000},
		{50000, 40000},
		{30000, 30000},
		{10, 70000},
	}
	for _, r := range invalid {
		for w := int64(0); w < 20; w++ {
			got := computeDynamicPortForWindowInRange(seed, w, r.min, r.max)
			want := computeDynamicPortForWindow(seed, w)
			if got != want {
				t.Fatalf("invalid range (%d, %d) window %d: got %d, want default-range port %d",
					r.min, r.max, w, got, want)
			}
		}
	}
}

// TestComputeDynamicPortInRangeCoversAllPortsInclusive verifies a narrow range
// rotates across every port in the range over enough windows, INCLUDING both
// the min and max bounds.
func TestComputeDynamicPortInRangeCoversAllPortsInclusive(t *testing.T) {
	seed := make([]byte, 8)
	rand.Read(seed)

	minP, maxP := 30010, 30020 // 11 possible ports, inclusive
	seen := make(map[int]bool)
	for w := int64(0); w < 2000; w++ {
		seen[computeDynamicPortForWindowInRange(seed, w, minP, maxP)] = true
	}
	if len(seen) != maxP-minP+1 {
		t.Errorf("expected all %d ports of %d-%d (inclusive) to appear over 2000 windows, saw %d",
			maxP-minP+1, minP, maxP, len(seen))
	}
	if !seen[minP] {
		t.Errorf("lower bound %d never produced", minP)
	}
	if !seen[maxP] {
		t.Errorf("upper bound %d never produced (max must be inclusive)", maxP)
	}
}

// TestComputeDynamicPortInRangeLive verifies the exported time-based function
// agrees with the window-based computation and stays in the inclusive range.
func TestComputeDynamicPortInRangeLive(t *testing.T) {
	seed := make([]byte, 8)
	rand.Read(seed)

	windowSecs := 600
	port := ComputeDynamicPortInRange(seed, windowSecs, 30010, 30020)
	if port < 30010 || port > 30020 {
		t.Fatalf("live port %d out of range 30010-30020", port)
	}
	window := time.Now().Unix() / int64(windowSecs)
	want := computeDynamicPortForWindowInRange(seed, window, 30010, 30020)
	if port != want {
		// Tolerate a window boundary between the two computations.
		want2 := computeDynamicPortForWindowInRange(seed, window+1, 30010, 30020)
		if port != want2 {
			t.Fatalf("live port %d matches neither window %d (%d) nor %d (%d)",
				port, window, want, window+1, want2)
		}
	}
}

// TestComputeDynamicPortWithWindowDelegates verifies the default-range entry
// point is exactly the range computation with the default bounds.
func TestComputeDynamicPortWithWindowDelegates(t *testing.T) {
	seed := make([]byte, 8)
	rand.Read(seed)

	p1 := ComputeDynamicPortWithWindow(seed, 600)
	p2 := ComputeDynamicPortInRange(seed, 600, DefaultDynPortMin, DefaultDynPortMax)
	if p1 != p2 {
		t.Fatalf("ComputeDynamicPortWithWindow (%d) != ComputeDynamicPortInRange with defaults (%d)", p1, p2)
	}
}

// TestCrossImplementationVectors pins the port computation to fixed vectors
// shared with the spk-mobile client (DynamicPortTest.matchesGoServerVectors).
// Any change that breaks these breaks port agreement with deployed clients.
func TestCrossImplementationVectors(t *testing.T) {
	seed := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	vectors := []struct {
		window   int64
		min, max int
		want     int
	}{
		{0, 30010, 30020, 30020},
		{1, 30010, 30020, 30018},
		{12345, 30010, 30020, 30019},
		{0, 10000, 65000, 40227},
		{12345, 10000, 65000, 54669},
		{999, 1024, 2048, 1435},
	}
	for _, v := range vectors {
		got := computeDynamicPortForWindowInRange(seed, v.window, v.min, v.max)
		if got != v.want {
			t.Errorf("window=%d range=%d-%d: got %d, want %d", v.window, v.min, v.max, got, v.want)
		}
	}
}
