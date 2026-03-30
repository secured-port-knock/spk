// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package config

import (
	"strings"
	"testing"
)

// =============================================================================
// validatePortSeed (direct)
// =============================================================================

func TestValidatePortSeed_Empty(t *testing.T) {
	errs := validatePortSeed("")
	if len(errs) != 0 {
		t.Errorf("expected no errors for empty seed, got %v", errs)
	}
}

func TestValidatePortSeed_Valid16Char(t *testing.T) {
	errs := validatePortSeed("abcdef0123456789")
	if len(errs) != 0 {
		t.Errorf("expected no errors for valid 16-char hex seed, got %v", errs)
	}
}

func TestValidatePortSeed_ValidUpperCase(t *testing.T) {
	errs := validatePortSeed("ABCDEF0123456789")
	if len(errs) != 0 {
		t.Errorf("expected no errors for uppercase hex seed, got %v", errs)
	}
}

func TestValidatePortSeed_TooShort(t *testing.T) {
	errs := validatePortSeed("abcd")
	found := false
	for _, e := range errs {
		if strings.Contains(e, "short") || strings.Contains(e, "too short") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'too short' error, got %v", errs)
	}
}

func TestValidatePortSeed_InvalidChar(t *testing.T) {
	errs := validatePortSeed("gggggggggggggggg") // 'g' is not hex
	found := false
	for _, e := range errs {
		if strings.Contains(e, "invalid char") || strings.Contains(e, "hex") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected hex error, got %v", errs)
	}
}

func TestValidatePortSeed_ShortAndInvalid(t *testing.T) {
	// "g!" -- invalid char AND too short
	errs := validatePortSeed("g!")
	if len(errs) == 0 {
		t.Error("expected errors for short and invalid seed")
	}
}

// =============================================================================
// preprocessDynPortFlags (direct)
// =============================================================================

func TestPreprocessDynPortFlags_ListenPortDynamic(t *testing.T) {
	raw := map[string]interface{}{
		"listen_port": "dynamic",
	}
	isDynamic, isClientDynamic := preprocessDynPortFlags(raw)
	if !isDynamic {
		t.Error("expected isDynamic=true when listen_port='dynamic'")
	}
	if isClientDynamic {
		t.Error("expected isClientDynamic=false when only listen_port is dynamic")
	}
	// The raw map should now have listen_port = int64(0)
	if raw["listen_port"] != int64(0) {
		t.Errorf("expected listen_port replaced with 0, got %v", raw["listen_port"])
	}
}

func TestPreprocessDynPortFlags_ServerPortDynamic(t *testing.T) {
	raw := map[string]interface{}{
		"server_port": "dynamic",
	}
	isDynamic, isClientDynamic := preprocessDynPortFlags(raw)
	if isDynamic {
		t.Error("expected isDynamic=false when only server_port is dynamic")
	}
	if !isClientDynamic {
		t.Error("expected isClientDynamic=true when server_port='dynamic'")
	}
	if raw["server_port"] != int64(0) {
		t.Errorf("expected server_port replaced with 0, got %v", raw["server_port"])
	}
}

func TestPreprocessDynPortFlags_LegacyDynamicPortBool(t *testing.T) {
	raw := map[string]interface{}{
		"dynamic_port": true,
	}
	isDynamic, isClientDynamic := preprocessDynPortFlags(raw)
	if !isDynamic {
		t.Error("expected isDynamic=true for legacy dynamic_port=true")
	}
	if !isClientDynamic {
		t.Error("expected isClientDynamic=true for legacy dynamic_port=true")
	}
	// The legacy key should have been removed
	if _, present := raw["dynamic_port"]; present {
		t.Error("expected dynamic_port key to be deleted from raw map")
	}
}

func TestPreprocessDynPortFlags_NoSpecialValues(t *testing.T) {
	raw := map[string]interface{}{
		"listen_port": int64(9000),
		"server_port": int64(9001),
	}
	isDynamic, isClientDynamic := preprocessDynPortFlags(raw)
	if isDynamic || isClientDynamic {
		t.Errorf("expected both flags false, got isDynamic=%v isClientDynamic=%v", isDynamic, isClientDynamic)
	}
}

func TestPreprocessDynPortFlags_BothDynamic(t *testing.T) {
	raw := map[string]interface{}{
		"listen_port": "dynamic",
		"server_port": "dynamic",
	}
	isDynamic, isClientDynamic := preprocessDynPortFlags(raw)
	if !isDynamic {
		t.Error("expected isDynamic=true")
	}
	if !isClientDynamic {
		t.Error("expected isClientDynamic=true")
	}
}

// =============================================================================
// migrateLegacyConfigKeys (direct)
// =============================================================================

func TestMigrateLegacyConfigKeys_SingleAddress(t *testing.T) {
	raw := map[string]interface{}{
		"listen_address": "0.0.0.0",
	}
	migrateLegacyConfigKeys(raw)

	if _, present := raw["listen_address"]; present {
		t.Error("expected listen_address key to be removed after migration")
	}
	addrs, ok := raw["listen_addresses"]
	if !ok {
		t.Fatal("expected listen_addresses key to be created")
	}
	slice, ok := addrs.([]interface{})
	if !ok {
		t.Fatalf("expected listen_addresses to be []interface{}, got %T", addrs)
	}
	if len(slice) != 1 || slice[0] != "0.0.0.0" {
		t.Errorf("unexpected listen_addresses value: %v", slice)
	}
}

func TestMigrateLegacyConfigKeys_NoLegacyKey(t *testing.T) {
	raw := map[string]interface{}{
		"listen_addresses": []interface{}{"0.0.0.0"},
	}
	migrateLegacyConfigKeys(raw)
	// Should not change anything
	if addrs, ok := raw["listen_addresses"]; !ok {
		t.Error("listen_addresses should remain unchanged")
	} else if slice, ok := addrs.([]interface{}); !ok || len(slice) != 1 {
		t.Errorf("unexpected listen_addresses after no-op migration: %v", addrs)
	}
}

func TestMigrateLegacyConfigKeys_NonStringIgnored(t *testing.T) {
	// listen_address as a non-string value (edge case) -- should not panic
	raw := map[string]interface{}{
		"listen_address": 42,
	}
	migrateLegacyConfigKeys(raw) // should not panic
	// Since it's not a string, it must not be migrated to listen_addresses
	if _, present := raw["listen_addresses"]; present {
		t.Error("non-string listen_address should not be migrated")
	}
}

// =============================================================================
// Config.validateDynPortParams (direct)
// =============================================================================

func TestValidateDynPortParams_Valid(t *testing.T) {
	c := &Config{DynPortMin: 1024, DynPortMax: 49151, DynPortWindow: 120}
	errs := c.validateDynPortParams()
	if len(errs) != 0 {
		t.Errorf("expected no errors for valid dyn port params, got %v", errs)
	}
}

func TestValidateDynPortParams_MinOutOfRange(t *testing.T) {
	c := &Config{DynPortMin: 70000}
	errs := c.validateDynPortParams()
	if len(errs) == 0 {
		t.Error("expected error for DynPortMin > 65535")
	}
}

func TestValidateDynPortParams_MaxOutOfRange(t *testing.T) {
	c := &Config{DynPortMax: 70000}
	errs := c.validateDynPortParams()
	if len(errs) == 0 {
		t.Error("expected error for DynPortMax > 65535")
	}
}

func TestValidateDynPortParams_MinGreaterThanMax(t *testing.T) {
	c := &Config{DynPortMin: 9000, DynPortMax: 8000}
	errs := c.validateDynPortParams()
	found := false
	for _, e := range errs {
		if strings.Contains(e, "less than") || strings.Contains(e, "dynamic_port_min") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected min>=max error, got %v", errs)
	}
}

func TestValidateDynPortParams_WindowTooSmall(t *testing.T) {
	c := &Config{DynPortWindow: 10} // below 60
	errs := c.validateDynPortParams()
	found := false
	for _, e := range errs {
		if strings.Contains(e, "dynamic_port_window") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected window out-of-range error, got %v", errs)
	}
}

func TestValidateDynPortParams_WindowTooLarge(t *testing.T) {
	c := &Config{DynPortWindow: 100000} // above 86400
	errs := c.validateDynPortParams()
	found := false
	for _, e := range errs {
		if strings.Contains(e, "dynamic_port_window") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected window out-of-range error, got %v", errs)
	}
}

// =============================================================================
// Config.validatePaddingCfg (direct)
// =============================================================================

func TestValidatePaddingCfg_Disabled(t *testing.T) {
	c := &Config{PaddingEnabled: false, PaddingMinBytes: -5, PaddingMaxBytes: 99999}
	errs := c.validatePaddingCfg()
	if len(errs) != 0 {
		t.Errorf("expected no errors when padding is disabled, got %v", errs)
	}
}

func TestValidatePaddingCfg_Valid(t *testing.T) {
	c := &Config{PaddingEnabled: true, PaddingMinBytes: 64, PaddingMaxBytes: 256}
	errs := c.validatePaddingCfg()
	if len(errs) != 0 {
		t.Errorf("expected no errors for valid padding config, got %v", errs)
	}
}

func TestValidatePaddingCfg_NegativeMin(t *testing.T) {
	c := &Config{PaddingEnabled: true, PaddingMinBytes: -1, PaddingMaxBytes: 128}
	errs := c.validatePaddingCfg()
	found := false
	for _, e := range errs {
		if strings.Contains(e, "padding_min_bytes") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected error for negative padding_min_bytes, got %v", errs)
	}
}

func TestValidatePaddingCfg_ExceedsMax(t *testing.T) {
	c := &Config{PaddingEnabled: true, PaddingMinBytes: 0, PaddingMaxBytes: MaxPaddingBytes + 1}
	errs := c.validatePaddingCfg()
	found := false
	for _, e := range errs {
		if strings.Contains(e, "padding_max_bytes") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected error for padding_max_bytes > MaxPaddingBytes, got %v", errs)
	}
}

func TestValidatePaddingCfg_MinGreaterThanMax(t *testing.T) {
	c := &Config{PaddingEnabled: true, PaddingMinBytes: 200, PaddingMaxBytes: 100}
	errs := c.validatePaddingCfg()
	found := false
	for _, e := range errs {
		if strings.Contains(e, "padding_min_bytes") && strings.Contains(e, "<=") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected min > max error, got %v", errs)
	}
}

// =============================================================================
// Config.validateDurationCfg (direct)
// =============================================================================

func TestValidateDurationCfg_Valid(t *testing.T) {
	c := &Config{DefaultOpenDuration: 30, MaxOpenDuration: 3600}
	errs := c.validateDurationCfg()
	if len(errs) != 0 {
		t.Errorf("expected no errors for valid duration config, got %v", errs)
	}
}

func TestValidateDurationCfg_NegativeDefault(t *testing.T) {
	c := &Config{DefaultOpenDuration: -1}
	errs := c.validateDurationCfg()
	found := false
	for _, e := range errs {
		if strings.Contains(e, "default_open_duration") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected error for negative default_open_duration, got %v", errs)
	}
}

func TestValidateDurationCfg_NegativeMax(t *testing.T) {
	c := &Config{MaxOpenDuration: -1}
	errs := c.validateDurationCfg()
	found := false
	for _, e := range errs {
		if strings.Contains(e, "max_open_duration") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected error for negative max_open_duration, got %v", errs)
	}
}

func TestValidateDurationCfg_DefaultExceedsMax(t *testing.T) {
	c := &Config{DefaultOpenDuration: 200, MaxOpenDuration: 100}
	errs := c.validateDurationCfg()
	found := false
	for _, e := range errs {
		if strings.Contains(e, "default_open_duration") && strings.Contains(e, "max_open_duration") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected exceeds-max error, got %v", errs)
	}
}

// =============================================================================
// Config.validateTOTPCfg (direct)
// =============================================================================

func TestValidateTOTPCfg_Disabled(t *testing.T) {
	c := &Config{TOTPEnabled: false, TOTPSecret: ""}
	errs := c.validateTOTPCfg()
	if len(errs) != 0 {
		t.Errorf("expected no errors when TOTP is disabled, got %v", errs)
	}
}

func TestValidateTOTPCfg_EnabledNoSecret(t *testing.T) {
	c := &Config{TOTPEnabled: true, TOTPSecret: ""}
	errs := c.validateTOTPCfg()
	if len(errs) != 0 {
		t.Errorf("expected no errors when TOTP enabled but secret empty, got %v", errs)
	}
}

func TestValidateTOTPCfg_ValidSecret(t *testing.T) {
	// 32-char base32 secret
	c := &Config{TOTPEnabled: true, TOTPSecret: "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"}
	errs := c.validateTOTPCfg()
	if len(errs) != 0 {
		t.Errorf("expected no errors for valid base32 secret, got %v", errs)
	}
}

func TestValidateTOTPCfg_TooShort(t *testing.T) {
	c := &Config{TOTPEnabled: true, TOTPSecret: "ABCDEFGHIJ234567"} // 16 chars
	errs := c.validateTOTPCfg()
	found := false
	for _, e := range errs {
		if strings.Contains(e, "totp_secret") && strings.Contains(e, "short") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected too-short error, got %v", errs)
	}
}

func TestValidateTOTPCfg_InvalidBase32(t *testing.T) {
	// Contains '1', '8', '9' which are not valid base32 chars
	c := &Config{TOTPEnabled: true, TOTPSecret: "ABCDEFGHIJKLMNO1PQR89STUVWXYZ234"}
	errs := c.validateTOTPCfg()
	found := false
	for _, e := range errs {
		if strings.Contains(e, "totp_secret") && strings.Contains(e, "base32") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected base32 format error, got %v", errs)
	}
}
