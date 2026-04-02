// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/secured-port-knock/spk/internal/config"
)

// TestKeyStorageLabelPersistedInConfig verifies that WriteClientConfigWithComments
// writes the key_storage_label field and that a subsequent Load reads it back intact.
func TestKeyStorageLabelPersistedInConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "client.toml")

	cfg := config.DefaultClientConfig()
	cfg.KeyStorageLabel = "SPK_ServerKey_deadbeefcafe0123"

	if err := config.WriteClientConfigWithComments(cfgPath, cfg); err != nil {
		t.Fatalf("WriteClientConfigWithComments: %v", err)
	}

	loaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.KeyStorageLabel != cfg.KeyStorageLabel {
		t.Errorf("KeyStorageLabel: got %q want %q", loaded.KeyStorageLabel, cfg.KeyStorageLabel)
	}
}

// TestKeyStorageLabelWrittenToTOML verifies the raw TOML file text contains
// the key_storage_label entry.
func TestKeyStorageLabelWrittenToTOML(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "client.toml")

	cfg := config.DefaultClientConfig()
	cfg.KeyStorageLabel = "SPK_ServerKey_aabbccddeeff0011"
	if err := config.WriteClientConfigWithComments(cfgPath, cfg); err != nil {
		t.Fatalf("WriteClientConfigWithComments: %v", err)
	}

	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !strings.Contains(string(raw), `key_storage_label = "SPK_ServerKey_aabbccddeeff0011"`) {
		t.Errorf("TOML file missing expected key_storage_label entry; content:\n%s", raw)
	}
}

// TestKeyStorageLabelOmittedWhenEmpty verifies that when KeyStorageLabel is
// empty the field is not written to the TOML file (omitempty behaviour).
func TestKeyStorageLabelOmittedWhenEmpty(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "client.toml")

	cfg := config.DefaultClientConfig()
	cfg.KeyStorageLabel = ""
	if err := config.WriteClientConfigWithComments(cfgPath, cfg); err != nil {
		t.Fatalf("WriteClientConfigWithComments: %v", err)
	}

	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if strings.Contains(string(raw), "key_storage_label") {
		t.Errorf("TOML file should not contain key_storage_label when empty; content:\n%s", raw)
	}
}

// TestKeyStorageLabelSurvivesConfigDirChange verifies that the label stored
// in the TOML is not a function of the config directory — the same TOML file
// read from a different directory path still carries the same label value.
func TestKeyStorageLabelSurvivesConfigDirChange(t *testing.T) {
	dir1 := t.TempDir()
	dir2 := t.TempDir()

	cfgPath1 := filepath.Join(dir1, "client.toml")
	label := "SPK_ServerKey_1122334455667788"

	cfg := config.DefaultClientConfig()
	cfg.KeyStorageLabel = label
	if err := config.WriteClientConfigWithComments(cfgPath1, cfg); err != nil {
		t.Fatalf("WriteClientConfigWithComments: %v", err)
	}

	// Copy the TOML to dir2 (simulating a config-dir move).
	data, err := os.ReadFile(cfgPath1)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	cfgPath2 := filepath.Join(dir2, "client.toml")
	if err := os.WriteFile(cfgPath2, data, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Load from the new location and verify label is unchanged.
	loaded, err := config.Load(cfgPath2)
	if err != nil {
		t.Fatalf("Load from new dir: %v", err)
	}
	if loaded.KeyStorageLabel != label {
		t.Errorf("label changed after move: got %q want %q", loaded.KeyStorageLabel, label)
	}
}
