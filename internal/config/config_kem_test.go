// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// =============================================================================
// KEMSize Config Defaults
// =============================================================================

func TestDefaultServerConfigKEMSize(t *testing.T) {
	cfg := DefaultServerConfig()
	if cfg.KEMSize != 768 {
		t.Errorf("server default KEMSize = %d, want 768", cfg.KEMSize)
	}
}

func TestDefaultClientConfigKEMSize(t *testing.T) {
	cfg := DefaultClientConfig()
	if cfg.KEMSize != 768 {
		t.Errorf("client default KEMSize = %d, want 768", cfg.KEMSize)
	}
}

// =============================================================================
// KEMSize TOML Round Trip
// =============================================================================

func TestKEMSizeTOMLRoundTrip768(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.KEMSize = 768
	cfg.ListenPort = 11111

	path := filepath.Join(t.TempDir(), "config.toml")
	if err := cfg.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.KEMSize != 768 {
		t.Errorf("loaded KEMSize = %d, want 768", loaded.KEMSize)
	}
}

func TestKEMSizeTOMLRoundTrip1024(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.KEMSize = 1024
	cfg.ListenPort = 22222

	path := filepath.Join(t.TempDir(), "config.toml")
	if err := cfg.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.KEMSize != 1024 {
		t.Errorf("loaded KEMSize = %d, want 1024", loaded.KEMSize)
	}
}

// =============================================================================
// Config Validate
// =============================================================================

func TestValidateKEMSizeValid(t *testing.T) {
	// KEMSize is no longer validated in config (derived from key files at runtime).
	// Any value should pass validation.
	for _, size := range []int{768, 1024, 0, 999} {
		cfg := DefaultServerConfig()
		cfg.KEMSize = size
		errs := cfg.Validate()
		for _, e := range errs {
			if strings.Contains(e, "kem_size") {
				t.Errorf("KEMSize %d should pass validation (no longer validated), got error: %s", size, e)
			}
		}
	}
}

func TestKEMSizeNotInValidation(t *testing.T) {
	// Verify kem_size is NOT validated since it's derived from key files
	cfg := DefaultServerConfig()
	cfg.KEMSize = 9999 // intentionally invalid
	errs := cfg.Validate()
	for _, e := range errs {
		if strings.Contains(e, "kem_size") {
			t.Errorf("kem_size should not be validated, got: %s", e)
		}
	}
}

func TestValidateKEMSizeZeroIsValid(t *testing.T) {
	// KEMSize 0 means "not set" and should not fail validation
	cfg := DefaultServerConfig()
	cfg.KEMSize = 0
	errs := cfg.Validate()
	for _, e := range errs {
		if strings.Contains(e, "kem_size") {
			t.Errorf("KEMSize 0 (unset) should pass validation, got error: %s", e)
		}
	}
}

func TestValidateDynPortMinMax(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.DynPortMin = 50000
	cfg.DynPortMax = 30000
	errs := cfg.Validate()
	found := false
	for _, e := range errs {
		if strings.Contains(e, "dynamic_port_min") {
			found = true
			break
		}
	}
	if !found {
		t.Error("should report error when dynamic_port_min >= dynamic_port_max")
	}
}

func TestValidateListenPortRange(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.ListenPort = 70000
	errs := cfg.Validate()
	found := false
	for _, e := range errs {
		if strings.Contains(e, "listen_port") {
			found = true
			break
		}
	}
	if !found {
		t.Error("should report error for listen_port > 65535")
	}
}

func TestValidatePaddingConfig(t *testing.T) {
	cfg := DefaultClientConfig()
	cfg.PaddingEnabled = true
	cfg.PaddingMinBytes = 100
	cfg.PaddingMaxBytes = 50
	errs := cfg.Validate()
	found := false
	for _, e := range errs {
		if strings.Contains(e, "padding_min_bytes") {
			found = true
			break
		}
	}
	if !found {
		t.Error("should report error when padding_min_bytes > padding_max_bytes")
	}
}

func TestValidateOpenDurationValues(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.DefaultOpenDuration = -1
	cfg.MaxOpenDuration = -1
	errs := cfg.Validate()
	if len(errs) < 2 {
		t.Errorf("expected at least 2 errors, got %d: %v", len(errs), errs)
	}
}

func TestValidateCleanConfig(t *testing.T) {
	cfg := DefaultServerConfig()
	errs := cfg.Validate()
	if len(errs) != 0 {
		t.Errorf("default server config should have no validation errors, got: %v", errs)
	}

	cfg = DefaultClientConfig()
	errs = cfg.Validate()
	if len(errs) != 0 {
		t.Errorf("default client config should have no validation errors, got: %v", errs)
	}
}

// =============================================================================
// STUN Server Defaults
// =============================================================================

func TestDefaultStunServersNotEmpty(t *testing.T) {
	if len(DefaultStunServers) == 0 {
		t.Error("DefaultStunServers should not be empty")
	}
}

func TestDefaultStunServersInClientConfig(t *testing.T) {
	cfg := DefaultClientConfig()
	if len(cfg.StunServers) == 0 {
		t.Error("client config should have default STUN servers")
	}
	if len(cfg.StunServers) != len(DefaultStunServers) {
		t.Errorf("client STUN servers = %d, want %d", len(cfg.StunServers), len(DefaultStunServers))
	}
}

func TestStunServersTOMLRoundTrip(t *testing.T) {
	cfg := DefaultClientConfig()
	cfg.StunServers = []string{"stun.example.com:3478", "stun2.example.com:3478"}
	cfg.ServerHost = "test.example.com"
	cfg.ServerPort = 12345

	path := filepath.Join(t.TempDir(), "client.toml")
	if err := cfg.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(loaded.StunServers) != 2 {
		t.Errorf("loaded STUN servers = %d, want 2", len(loaded.StunServers))
	}
	if loaded.StunServers[0] != "stun.example.com:3478" {
		t.Errorf("STUN server[0] = %s, want stun.example.com:3478", loaded.StunServers[0])
	}
}

// =============================================================================
// MaxPaddingMTUSafe768 Constant
// =============================================================================

func TestMaxPaddingMTUSafe768(t *testing.T) {
	if MaxPaddingMTUSafe768 <= 0 {
		t.Error("MaxPaddingMTUSafe768 should be positive")
	}
	if MaxPaddingMTUSafe768 > 512 {
		t.Errorf("MaxPaddingMTUSafe768 = %d, should be reasonable (<=12)", MaxPaddingMTUSafe768)
	}
}

// =============================================================================
// WriteServerConfigWithComments - KEM Size Section
// =============================================================================

func TestWriteServerConfigKEMSizeSection(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.ListenPort = 55555

	path := filepath.Join(t.TempDir(), "server.toml")
	if err := WriteServerConfigWithComments(path, cfg); err != nil {
		t.Fatalf("WriteServerConfigWithComments: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	content := string(data)

	// kem_size is no longer written to config (derived from key files)
	if strings.Contains(content, "kem_size") {
		t.Error("server config should NOT contain kem_size (removed, derived from key files)")
	}
	// Config should still be valid TOML
	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load server config: %v", err)
	}
	if loaded.ListenPort != 55555 {
		t.Errorf("ListenPort = %d, want 55555", loaded.ListenPort)
	}
}

func TestWriteClientConfigStunAndKEMSection(t *testing.T) {
	cfg := DefaultClientConfig()
	cfg.ServerHost = "example.com"
	cfg.ServerPort = 12345
	cfg.KEMSize = 768

	path := filepath.Join(t.TempDir(), "client.toml")
	if err := WriteClientConfigWithComments(path, cfg); err != nil {
		t.Fatalf("WriteClientConfigWithComments: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	content := string(data)

	// Should contain STUN servers (not commented out)
	if !strings.Contains(content, "stun_servers") {
		t.Error("client config should contain stun_servers")
	}
	// kem_size is no longer written to config
	if strings.Contains(content, "kem_size") {
		t.Error("client config should NOT contain kem_size (removed, derived from key files)")
	}
}
