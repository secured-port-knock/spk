// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- Fuzz tests ---

// FuzzConfigValidate tests config validation with random field values.
func FuzzConfigValidate(f *testing.F) {
	f.Add(0, 0, 0, 0, 60, 0, 0, "udp", false, 0, 0, "", 0, 0, false)
	f.Add(22, 80, 3600, 86400, 30, 120, 10000, "pcap", true, 64, 512, "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP", 768, 0, true)
	f.Add(-1, -1, -1, -1, -1, -1, -1, "invalid", true, -1, -1, "short", 0, -1, false)
	f.Add(65535, 65535, 604800, 604800, 3600, 3600, 100000, "afpacket", false, 2048, 2048, "", 1024, 65000, false)
	f.Add(65536, 65536, 0, 0, 0, 0, 0, "windivert", true, 0, 0, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 512, 100, true)

	f.Fuzz(func(t *testing.T, listenPort, serverPort, defaultDur, maxDur, tsTolerance,
		nonceExpiry, maxNonceCache int, snifferMode string, paddingEnabled bool,
		paddingMin, paddingMax int, totpSecret string, kemSize, dynPortWindow int, totpEnabled bool) {

		cfg := &Config{
			ListenPort:          listenPort,
			ServerPort:          serverPort,
			DefaultOpenDuration: defaultDur,
			MaxOpenDuration:     maxDur,
			TimestampTolerance:  tsTolerance,
			NonceExpiry:         nonceExpiry,
			MaxNonceCache:       maxNonceCache,
			SnifferMode:         snifferMode,
			PaddingEnabled:      paddingEnabled,
			PaddingMinBytes:     paddingMin,
			PaddingMaxBytes:     paddingMax,
			TOTPSecret:          totpSecret,
			TOTPEnabled:         totpEnabled,
			KEMSize:             kemSize,
			DynPortWindow:       dynPortWindow,
		}

		// Must not panic
		errs := cfg.Validate()
		_ = errs
	})
}

// FuzzConfigLoad tests TOML config loading with arbitrary content.
func FuzzConfigLoad(f *testing.F) {
	f.Add("")
	f.Add("listen_port = 22\n")
	f.Add("listen_port = \"dynamic\"\n")
	f.Add("sniffer_mode = \"udp\"\nkem_size = 768\n")
	f.Add("[custom_commands]\nping = \"ping -c 1 {{IP}}\"\n")
	f.Add("kem_size = 1024\nlisten_port = 0\nport_seed = \"0123456789abcdef\"\n")
	f.Add(strings.Repeat("a", 10000)) // large garbage
	f.Add("listen_port = 99999999\n")
	f.Add("listen_port = -1\n")

	f.Fuzz(func(t *testing.T, content string) {
		dir := t.TempDir()
		path := filepath.Join(dir, "test.toml")
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			return
		}
		// Must not panic
		_, _ = Load(path)
	})
}

// --- Property-based tests ---

// TestConfigValidate_AllSnifferModes tests all valid and invalid sniffer modes.
func TestConfigValidate_AllSnifferModes(t *testing.T) {
	validModes := []string{"udp", "afpacket", "pcap", "windivert"}
	invalidModes := []string{"raw", "npcap", "UDP", "PCAP", "", "libpcap", "socket"}

	for _, mode := range validModes {
		cfg := DefaultServerConfig()
		cfg.SnifferMode = mode
		errs := cfg.Validate()
		for _, e := range errs {
			if strings.Contains(e, "sniffer_mode") {
				t.Errorf("valid mode %q rejected: %s", mode, e)
			}
		}
	}

	for _, mode := range invalidModes {
		cfg := DefaultServerConfig()
		cfg.SnifferMode = mode
		errs := cfg.Validate()
		if mode == "" {
			// Empty mode is valid (uses default)
			continue
		}
		found := false
		for _, e := range errs {
			if strings.Contains(e, "sniffer_mode") {
				found = true
			}
		}
		if !found {
			t.Errorf("invalid mode %q not rejected", mode)
		}
	}
}

// TestConfigValidate_PortRanges tests port validation boundaries.
func TestConfigValidate_PortRanges(t *testing.T) {
	tests := []struct {
		port    int
		wantErr bool
	}{
		{-1, true},
		{0, false},
		{1, false},
		{65535, false},
		{65536, true},
		{100000, true},
		{-65536, true},
	}

	for _, tt := range tests {
		cfg := DefaultServerConfig()
		cfg.ListenPort = tt.port
		errs := cfg.Validate()
		hasPortErr := false
		for _, e := range errs {
			if strings.Contains(e, "listen_port") {
				hasPortErr = true
			}
		}
		if tt.wantErr && !hasPortErr {
			t.Errorf("port %d: expected validation error", tt.port)
		}
		if !tt.wantErr && hasPortErr {
			t.Errorf("port %d: unexpected validation error", tt.port)
		}
	}
}

// TestConfigValidate_DurationConstraints tests open duration validation.
func TestConfigValidate_DurationConstraints(t *testing.T) {
	tests := []struct {
		name       string
		defaultDur int
		maxDur     int
		wantErr    bool
	}{
		{"default < max", 3600, 86400, false},
		{"default == max", 3600, 3600, false},
		{"default > max (both positive)", 86400, 3600, true},
		{"both zero", 0, 0, false},
		{"negative default", -1, 3600, true},
		{"negative max", 3600, -1, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultServerConfig()
			cfg.DefaultOpenDuration = tt.defaultDur
			cfg.MaxOpenDuration = tt.maxDur
			errs := cfg.Validate()
			hasErr := false
			for _, e := range errs {
				if strings.Contains(e, "duration") {
					hasErr = true
				}
			}
			if tt.wantErr && !hasErr {
				t.Error("expected duration validation error")
			}
			if !tt.wantErr && hasErr {
				t.Errorf("unexpected duration error: %v", errs)
			}
		})
	}
}

// TestConfigValidate_PaddingConstraints tests padding validation.
func TestConfigValidate_PaddingConstraints(t *testing.T) {
	tests := []struct {
		name    string
		enabled bool
		min     int
		max     int
		wantErr bool
	}{
		{"disabled_ignored", false, -100, -200, false},
		{"valid_range", true, 64, 512, false},
		{"min_exceeds_max", true, 512, 64, true},
		{"exceeds_limit", true, 0, MaxPaddingBytes + 1, true},
		{"at_limit", true, 0, MaxPaddingBytes, false},
		{"negative_min", true, -1, 100, true},
		{"zero_range", true, 0, 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultServerConfig()
			cfg.PaddingEnabled = tt.enabled
			cfg.PaddingMinBytes = tt.min
			cfg.PaddingMaxBytes = tt.max
			errs := cfg.Validate()
			hasPadErr := false
			for _, e := range errs {
				if strings.Contains(e, "padding") {
					hasPadErr = true
				}
			}
			if tt.wantErr && !hasPadErr {
				t.Error("expected padding validation error")
			}
			if !tt.wantErr && hasPadErr {
				t.Errorf("unexpected padding error: %v", errs)
			}
		})
	}
}

// TestConfigValidate_TOTPSecret tests TOTP secret validation.
func TestConfigValidate_TOTPSecret(t *testing.T) {
	tests := []struct {
		name    string
		enabled bool
		secret  string
		wantErr bool
	}{
		{"disabled_no_secret", false, "", false},
		{"disabled_with_secret", false, "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP", false},
		{"valid_32char", true, "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP", false},
		{"sixteen_chars_too_short", true, "JBSWY3DPEHPK3PXP", true},  // was incorrectly accepted before
		{"too_short", true, "JBSWY3D", true},
		{"invalid_chars", true, "jbswy3dpehpk3pxp", true}, // lowercase not valid base32
		{"numbers_invalid", true, "1234567890123456", true},
		{"empty_enabled", true, "", false}, // empty but enabled = no validation on empty
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultServerConfig()
			cfg.TOTPEnabled = tt.enabled
			cfg.TOTPSecret = tt.secret
			errs := cfg.Validate()
			hasTOTPErr := false
			for _, e := range errs {
				if strings.Contains(e, "totp") {
					hasTOTPErr = true
				}
			}
			if tt.wantErr && !hasTOTPErr {
				t.Errorf("expected TOTP validation error for secret=%q", tt.secret)
			}
			if !tt.wantErr && hasTOTPErr {
				t.Errorf("unexpected TOTP error for secret=%q: %v", tt.secret, errs)
			}
		})
	}
}

// TestConfigValidate_PortSeed tests port seed validation.
func TestConfigValidate_PortSeed(t *testing.T) {
	tests := []struct {
		name    string
		seed    string
		wantErr bool
	}{
		{"empty", "", false},
		{"valid_16_hex", "0123456789abcdef", false},
		{"valid_32_hex", "0123456789abcdef0123456789abcdef", false},
		{"too_short", "0123456789abcde", true},      // 15 chars
		{"invalid_chars", "0123456789abcdeg", true}, // 'g' invalid
		{"uppercase_valid", "0123456789ABCDEF", false},
		{"mixed_case", "0123456789AbCdEf", false},
		{"spaces", "01234567 89abcdef", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultServerConfig()
			cfg.PortSeed = tt.seed
			errs := cfg.Validate()
			hasSeedErr := false
			for _, e := range errs {
				if strings.Contains(e, "port_seed") {
					hasSeedErr = true
				}
			}
			if tt.wantErr && !hasSeedErr {
				t.Errorf("expected seed error for %q", tt.seed)
			}
			if !tt.wantErr && hasSeedErr {
				t.Errorf("unexpected seed error for %q: %v", tt.seed, errs)
			}
		})
	}
}

// TestConfigValidate_ListenAddresses tests listen address validation.
func TestConfigValidate_ListenAddresses(t *testing.T) {
	tests := []struct {
		name    string
		addrs   []string
		wantErr bool
	}{
		{"valid_ipv4", []string{"0.0.0.0"}, false},
		{"valid_ipv6", []string{"::"}, false},
		{"valid_both", []string{"0.0.0.0", "::"}, false},
		{"invalid_hostname", []string{"localhost"}, true},
		{"invalid_string", []string{"not-an-ip"}, true},
		{"empty_list", []string{}, false},
		{"mixed_valid_invalid", []string{"0.0.0.0", "bad"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultServerConfig()
			cfg.ListenAddresses = tt.addrs
			errs := cfg.Validate()
			hasAddrErr := false
			for _, e := range errs {
				if strings.Contains(e, "listen address") {
					hasAddrErr = true
				}
			}
			if tt.wantErr && !hasAddrErr {
				t.Error("expected listen address error")
			}
			if !tt.wantErr && hasAddrErr {
				t.Errorf("unexpected listen address error: %v", errs)
			}
		})
	}
}

// TestConfigValidate_DynPortRange tests dynamic port range validation.
func TestConfigValidate_DynPortRange(t *testing.T) {
	tests := []struct {
		name    string
		min     int
		max     int
		wantErr bool
	}{
		{"valid", 10000, 65000, false},
		{"min_equals_max", 50000, 50000, true},
		{"min_greater_than_max", 65000, 10000, true},
		{"both_zero", 0, 0, false},
		{"min_negative", -1, 65000, true},
		{"max_negative", 10000, -1, true},
		{"min_too_large", 65536, 65000, true},
		{"max_too_large", 10000, 99999, true},
		{"both_valid_small", 1024, 2048, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultServerConfig()
			cfg.DynPortMin = tt.min
			cfg.DynPortMax = tt.max
			errs := cfg.Validate()
			hasDynErr := false
			for _, e := range errs {
				if strings.Contains(e, "dynamic_port") {
					hasDynErr = true
				}
			}
			if tt.wantErr && !hasDynErr {
				t.Error("expected dynamic port range error")
			}
			if !tt.wantErr && hasDynErr {
				t.Errorf("unexpected dynamic port error: %v", errs)
			}
		})
	}
}

// TestConfigLoad_DynamicPortString tests loading "dynamic" as listen_port.
func TestConfigLoad_DynamicPortString(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.toml")
	content := `listen_port = "dynamic"
port_seed = "0123456789abcdef"
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if !cfg.DynamicPort {
		t.Error("expected DynamicPort=true")
	}
	if cfg.ListenPort != 0 {
		t.Errorf("expected ListenPort=0, got %d", cfg.ListenPort)
	}
}

// TestConfigLoad_LegacyDynamicPort tests legacy dynamic_port=true handling.
func TestConfigLoad_LegacyDynamicPort(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.toml")
	content := `listen_port = 0
dynamic_port = true
port_seed = "0123456789abcdef"
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if !cfg.DynamicPort {
		t.Error("expected DynamicPort=true for legacy field")
	}
}

// --- Mutation-resilient tests ---

// TestDefaultServerConfig_SafeDefaults verifies defaults are security-focused.
func TestDefaultServerConfig_SafeDefaults(t *testing.T) {
	cfg := DefaultServerConfig()

	if cfg.AllowCustomPort {
		t.Error("default should not allow custom port")
	}
	if cfg.AllowCustomOpenDuration {
		t.Error("default should not allow custom open duration")
	}
	if cfg.AllowOpenAll {
		t.Error("default should not allow open-all")
	}
	if !cfg.MatchIncomingIP {
		t.Error("default should match incoming IP")
	}
	if !cfg.ClosePortsOnCrash {
		t.Error("default should close ports on crash")
	}
	if cfg.KEMSize != 768 {
		t.Errorf("default KEM size should be 768, got %d", cfg.KEMSize)
	}
	if cfg.TimestampTolerance != 30 {
		t.Errorf("default timestamp tolerance should be 30, got %d", cfg.TimestampTolerance)
	}
	if cfg.NonceExpiry != 120 {
		t.Errorf("default nonce expiry should be 120, got %d", cfg.NonceExpiry)
	}
	if cfg.DefaultOpenDuration > cfg.MaxOpenDuration {
		t.Error("default open duration exceeds max")
	}
	if cfg.MaxNonceCache != 10000 {
		t.Errorf("default max nonce cache should be 10000, got %d", cfg.MaxNonceCache)
	}
	if len(cfg.AllowedPorts) == 0 {
		t.Error("default should have at least one allowed port")
	}
	errs := cfg.Validate()
	if len(errs) > 0 {
		t.Errorf("default config has validation errors: %v", errs)
	}
}

// TestRandomPort_Range verifies RandomPort stays within bounds.
func TestRandomPort_Range(t *testing.T) {
	for i := 0; i < 1000; i++ {
		port := RandomPort()
		if port < 10000 || port >= 65000 {
			t.Errorf("RandomPort() = %d, outside [10000, 65000)", port)
		}
	}
}
