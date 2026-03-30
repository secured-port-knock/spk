// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package protocol

import (
	"encoding/hex"
	"testing"
)

// =============================================================================
// generateRandomPadding
// =============================================================================

func TestGenerateRandomPadding_DefaultBounds(t *testing.T) {
	// MinBytes=0 and MaxBytes=0 -> defaults: min=64, max=64+256=320
	pc := PaddingConfig{Enabled: true, MinBytes: 0, MaxBytes: 0}
	hexStr, err := generateRandomPadding(pc)
	if err != nil {
		t.Fatalf("generateRandomPadding: %v", err)
	}
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		t.Fatalf("result is not valid hex: %v", err)
	}
	// With defaults: min=64, max=64+256=320; hex is 2x the raw bytes
	if len(b) < 64 || len(b) > 320 {
		t.Errorf("padding length %d out of expected default range [64, 320]", len(b))
	}
}

func TestGenerateRandomPadding_ExactBounds(t *testing.T) {
	// min == max -> always produces exactly min bytes
	pc := PaddingConfig{Enabled: true, MinBytes: 128, MaxBytes: 128}
	hexStr, err := generateRandomPadding(pc)
	if err != nil {
		t.Fatalf("generateRandomPadding: %v", err)
	}
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		t.Fatalf("result is not valid hex: %v", err)
	}
	if len(b) != 128 {
		t.Errorf("expected exactly 128 bytes, got %d", len(b))
	}
}

func TestGenerateRandomPadding_WithinRange(t *testing.T) {
	pc := PaddingConfig{Enabled: true, MinBytes: 32, MaxBytes: 64}
	// Run several times to increase confidence that bounds are respected.
	for i := 0; i < 20; i++ {
		hexStr, err := generateRandomPadding(pc)
		if err != nil {
			t.Fatalf("iteration %d: generateRandomPadding: %v", i, err)
		}
		b, err := hex.DecodeString(hexStr)
		if err != nil {
			t.Fatalf("iteration %d: result is not valid hex: %v", i, err)
		}
		if len(b) < 32 || len(b) > 64 {
			t.Errorf("iteration %d: padding length %d outside [32, 64]", i, len(b))
		}
	}
}

func TestGenerateRandomPadding_MaxBelowMinClamped(t *testing.T) {
	// When MaxBytes < MinBytes, MaxBytes is set to MinBytes+256
	pc := PaddingConfig{Enabled: true, MinBytes: 100, MaxBytes: 10}
	hexStr, err := generateRandomPadding(pc)
	if err != nil {
		t.Fatalf("generateRandomPadding: %v", err)
	}
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		t.Fatalf("result is not valid hex: %v", err)
	}
	// effective max = 100 + 256 = 356
	if len(b) < 100 || len(b) > 356 {
		t.Errorf("padding length %d outside clamped range [100, 356]", len(b))
	}
}

func TestGenerateRandomPadding_IsHexEncoded(t *testing.T) {
	pc := PaddingConfig{Enabled: true, MinBytes: 16, MaxBytes: 16}
	hexStr, err := generateRandomPadding(pc)
	if err != nil {
		t.Fatalf("generateRandomPadding: %v", err)
	}
	// Hex string must be exactly 2*MinBytes characters
	if len(hexStr) != 32 {
		t.Errorf("hex string length = %d, want 32 (2*16)", len(hexStr))
	}
	// Must be decodable
	if _, err := hex.DecodeString(hexStr); err != nil {
		t.Errorf("not valid hex: %v", err)
	}
}

func TestGenerateRandomPadding_Randomness(t *testing.T) {
	// Two calls should very rarely produce the same output for 32+ byte padding
	pc := PaddingConfig{Enabled: true, MinBytes: 32, MaxBytes: 32}
	h1, err1 := generateRandomPadding(pc)
	h2, err2 := generateRandomPadding(pc)
	if err1 != nil || err2 != nil {
		t.Fatalf("generateRandomPadding errors: %v %v", err1, err2)
	}
	if h1 == h2 {
		t.Error("two consecutive padding values are identical (expected randomness)")
	}
}
