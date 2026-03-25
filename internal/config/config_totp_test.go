// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package config

import (
	"os"
	"path/filepath"
	"testing"
)

// ------------------------------------------------------------------------
// TOTP Config Field Tests
// ------------------------------------------------------------------------

func TestTOTPFieldsDefaultOff(t *testing.T) {
	cfg := DefaultServerConfig()

	if cfg.TOTPEnabled {
		t.Error("TOTP should be disabled by default")
	}
	if cfg.TOTPSecret != "" {
		t.Error("TOTP secret should be empty by default")
	}
}

func TestTOTPConfigRoundTrip(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.TOTPEnabled = true
	cfg.TOTPSecret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"

	path := filepath.Join(t.TempDir(), "totp_test.toml")
	if err := cfg.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if !loaded.TOTPEnabled {
		t.Error("TOTPEnabled should be true after round-trip")
	}
	if loaded.TOTPSecret != "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP" {
		t.Errorf("TOTPSecret = %q, want original secret", loaded.TOTPSecret)
	}
}

func TestTOTPConfigDisabledRoundTrip(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.TOTPEnabled = false
	cfg.TOTPSecret = "" // no secret

	path := filepath.Join(t.TempDir(), "totp_disabled.toml")
	if err := cfg.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if loaded.TOTPEnabled {
		t.Error("TOTPEnabled should remain false")
	}
	if loaded.TOTPSecret != "" {
		t.Errorf("TOTPSecret should be empty, got %q", loaded.TOTPSecret)
	}
}

// ------------------------------------------------------------------------
// Padding Config Field Tests
// ------------------------------------------------------------------------

func TestPaddingFieldsDefaultOff(t *testing.T) {
	cfg := DefaultClientConfig()

	if cfg.PaddingEnabled {
		t.Error("padding should be disabled by default for client")
	}
	if cfg.PaddingMinBytes != 0 {
		t.Errorf("PaddingMinBytes = %d, want 0 (uses code default of 64)", cfg.PaddingMinBytes)
	}
}

func TestPaddingConfigRoundTrip(t *testing.T) {
	cfg := DefaultClientConfig()
	cfg.PaddingEnabled = true
	cfg.PaddingMinBytes = 100
	cfg.PaddingMaxBytes = 500
	cfg.ServerHost = "test.example.com"
	cfg.ServerPort = 12345

	path := filepath.Join(t.TempDir(), "padding_test.toml")
	if err := cfg.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if !loaded.PaddingEnabled {
		t.Error("PaddingEnabled should be true")
	}
	if loaded.PaddingMinBytes != 100 {
		t.Errorf("PaddingMinBytes = %d, want 100", loaded.PaddingMinBytes)
	}
	if loaded.PaddingMaxBytes != 500 {
		t.Errorf("PaddingMaxBytes = %d, want 500", loaded.PaddingMaxBytes)
	}
}

// ------------------------------------------------------------------------
// WaitForUserOrTimeout exists test (compile-time check)
// ------------------------------------------------------------------------

func TestWaitForUserOrTimeoutExists(t *testing.T) {
	// This test verifies the function exists and compiles.
	// We can't test stdin interaction, but we verify the function signature.
	_ = WaitForUserOrTimeout // compile check
}

// ------------------------------------------------------------------------
// Config with TOTP and other new fields - full save/load
// ------------------------------------------------------------------------

func TestServerConfigWithAllNewFields(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.TOTPEnabled = true
	cfg.TOTPSecret = "TESTTOTP1234567890ABCDEFGHIJKLMN"
	cfg.ClosePortsOnCrash = false
	cfg.MatchIncomingIP = false
	cfg.MaxNonceCache = 50000
	cfg.LogFloodLimit = 200
	cfg.LogCommandOutput = true

	path := filepath.Join(t.TempDir(), "full_config.toml")
	if err := cfg.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if !loaded.TOTPEnabled {
		t.Error("TOTPEnabled")
	}
	if loaded.TOTPSecret != "TESTTOTP1234567890ABCDEFGHIJKLMN" {
		t.Error("TOTPSecret")
	}
	if loaded.ClosePortsOnCrash {
		t.Error("ClosePortsOnCrash should be false")
	}
	if loaded.MatchIncomingIP {
		t.Error("MatchIncomingIP should be false")
	}
	if loaded.MaxNonceCache != 50000 {
		t.Errorf("MaxNonceCache = %d, want 50000", loaded.MaxNonceCache)
	}
	if loaded.LogFloodLimit != 200 {
		t.Errorf("LogFloodLimit = %d, want 200", loaded.LogFloodLimit)
	}
	if !loaded.LogCommandOutput {
		t.Error("LogCommandOutput should be true")
	}
}

// ------------------------------------------------------------------------
// Commented config includes TOTP section
// ------------------------------------------------------------------------

func TestWriteServerConfigContainsTOTPFields(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.TOTPEnabled = true
	cfg.TOTPSecret = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

	path := filepath.Join(t.TempDir(), "commented.toml")
	if err := WriteServerConfigWithComments(path, cfg); err != nil {
		t.Fatalf("WriteServerConfigWithComments: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)

	// Verify TOTP fields appear in the file
	if !containsString(content, "totp_enabled") {
		t.Error("config file should contain totp_enabled field")
	}
	if !containsString(content, "totp_secret") {
		t.Error("config file should contain totp_secret field")
	}
}

func containsString(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && contains(s, substr)
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
