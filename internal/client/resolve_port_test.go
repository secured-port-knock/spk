// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package client

import (
	"encoding/hex"
	"testing"

	"spk/internal/config"
	"spk/internal/crypto"
)

func TestResolvePortWithWindowStatic(t *testing.T) {
	cfg := &config.Config{
		DynamicPort: false,
		ServerPort:  12345,
	}
	got := resolvePortWithWindow(cfg, 600)
	if got != 12345 {
		t.Errorf("static port: got %d, want 12345", got)
	}
}

func TestResolvePortWithWindowDynamic(t *testing.T) {
	seed := "0102030405060708"
	seedBytes, _ := hex.DecodeString(seed)

	cfg := &config.Config{
		DynamicPort: true,
		PortSeed:    seed,
		ServerPort:  9999,
	}
	got := resolvePortWithWindow(cfg, 600)
	want := crypto.ComputeDynamicPortWithWindow(seedBytes, 600)
	if got != want {
		t.Errorf("dynamic port: got %d, want %d", got, want)
	}
	// Must not return the static port
	if got == 9999 {
		t.Error("dynamic port should not equal static port (extremely unlikely)")
	}
}

func TestResolvePortWithWindowInvalidSeed(t *testing.T) {
	cfg := &config.Config{
		DynamicPort: true,
		PortSeed:    "ZZZZ", // invalid hex
		ServerPort:  54321,
	}
	got := resolvePortWithWindow(cfg, 600)
	if got != 54321 {
		t.Errorf("invalid seed should fall back to static port: got %d, want 54321", got)
	}
}

func TestResolvePortWithWindowShortSeed(t *testing.T) {
	cfg := &config.Config{
		DynamicPort: true,
		PortSeed:    "0102", // only 2 bytes, need >= 8
		ServerPort:  11111,
	}
	got := resolvePortWithWindow(cfg, 600)
	if got != 11111 {
		t.Errorf("short seed should fall back to static port: got %d, want 11111", got)
	}
}

func TestResolvePortWithWindowEmptySeed(t *testing.T) {
	cfg := &config.Config{
		DynamicPort: true,
		PortSeed:    "",
		ServerPort:  22222,
	}
	got := resolvePortWithWindow(cfg, 600)
	if got != 22222 {
		t.Errorf("empty seed should fall back to static port: got %d, want 22222", got)
	}
}
