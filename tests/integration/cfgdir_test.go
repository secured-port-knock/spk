// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"spk/internal/config"
	"spk/internal/logging"
	"spk/internal/service"
)

// ---------------------------------------------------------------------------
// --cfgdir / --logdir custom directory tests
// ---------------------------------------------------------------------------

// TestSetConfigDirOverridesDefault verifies SetConfigDir overrides defaults.
func TestSetConfigDirOverridesDefault(t *testing.T) {
	dir := t.TempDir()
	origDir := getConfigDirForRestore()
	defer restoreConfigDir(origDir)

	config.SetConfigDir(dir)
	if got := config.ConfigDir(); got != dir {
		t.Errorf("ConfigDir() = %q, want %q", got, dir)
	}
}

// TestSetConfigDirCreatesNestedPath verifies that SetConfigDir creates
// intermediate directories.
func TestSetConfigDirCreatesNestedPath(t *testing.T) {
	base := t.TempDir()
	nested := filepath.Join(base, "deep", "nested", "config")
	origDir := getConfigDirForRestore()
	defer restoreConfigDir(origDir)

	config.SetConfigDir(nested)
	info, err := os.Stat(nested)
	if err != nil {
		t.Fatalf("directory not created: %v", err)
	}
	if !info.IsDir() {
		t.Error("expected directory, got file")
	}
}

// TestConfigPathsRespectOverride verifies that ServerConfigPath, ClientConfigPath,
// and StatePath all use the overridden directory.
func TestConfigPathsRespectOverride(t *testing.T) {
	dir := t.TempDir()
	origDir := getConfigDirForRestore()
	defer restoreConfigDir(origDir)

	config.SetConfigDir(dir)

	if got := config.ServerConfigPath(); got != filepath.Join(dir, "spk_server.toml") {
		t.Errorf("ServerConfigPath() = %q", got)
	}
	if got := config.ClientConfigPath(); got != filepath.Join(dir, "spk_client.toml") {
		t.Errorf("ClientConfigPath() = %q", got)
	}
	if got := config.StatePath(); got != filepath.Join(dir, "state.json") {
		t.Errorf("StatePath() = %q", got)
	}
}

// TestSetLogDirOverridesDefault verifies SetLogDir overrides defaults.
func TestSetLogDirOverridesDefault(t *testing.T) {
	dir := t.TempDir()
	origDir := getLogDirForRestore()
	defer restoreLogDir(origDir)

	logging.SetLogDir(dir)
	if got := logging.LogDir(); got != dir {
		t.Errorf("LogDir() = %q, want %q", got, dir)
	}
}

// TestSetLogDirCreatesNestedPath verifies directory creation.
func TestSetLogDirCreatesNestedPath(t *testing.T) {
	base := t.TempDir()
	nested := filepath.Join(base, "deep", "nested", "log")
	origDir := getLogDirForRestore()
	defer restoreLogDir(origDir)

	logging.SetLogDir(nested)
	info, err := os.Stat(nested)
	if err != nil {
		t.Fatalf("directory not created: %v", err)
	}
	if !info.IsDir() {
		t.Error("expected directory, got file")
	}
}

// TestLoggerUsesCustomLogDir verifies that creating a logger with a custom
// log directory actually writes the log file there.
func TestLoggerUsesCustomLogDir(t *testing.T) {
	dir := t.TempDir()
	origDir := getLogDirForRestore()
	defer restoreLogDir(origDir)

	logging.SetLogDir(dir)

	l, err := logging.New("custom_test.log", logging.DefaultConfig(), "test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer l.Close()

	l.Infof("test message from custom dir")

	expected := filepath.Join(dir, "custom_test.log")
	if l.FilePath() != expected {
		t.Errorf("FilePath() = %q, want %q", l.FilePath(), expected)
	}

	// Verify file actually exists
	if _, err := os.Stat(expected); err != nil {
		t.Errorf("log file not found: %v", err)
	}
}

// TestSaveAndLoadConfigInCustomDir verifies that config save/load works
// correctly when a custom config directory is set.
func TestSaveAndLoadConfigInCustomDir(t *testing.T) {
	dir := t.TempDir()
	origDir := getConfigDirForRestore()
	defer restoreConfigDir(origDir)

	config.SetConfigDir(dir)

	cfg := config.DefaultServerConfig()
	cfg.ListenPort = 55555
	cfg.AllowedPorts = []string{"t22", "t443"}

	path := config.ServerConfigPath()
	if err := config.WriteServerConfigWithComments(path, cfg); err != nil {
		t.Fatalf("WriteServerConfigWithComments: %v", err)
	}

	loaded, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.ListenPort != 55555 {
		t.Errorf("loaded.ListenPort = %d, want 55555", loaded.ListenPort)
	}
}

// ---------------------------------------------------------------------------
// Service config tests (no actual service install -- just config building)
// ---------------------------------------------------------------------------

// TestServiceConfigServerArgsDefault verifies default args include only --server.
func TestServiceConfigServerArgsDefault(t *testing.T) {
	sc := service.ServiceConfig{}
	args := sc.ServerArgs()
	if len(args) != 1 || args[0] != "--server" {
		t.Errorf("ServerArgs() = %v, want [--server]", args)
	}
}

// TestServiceConfigServerArgsCustomDirs verifies --cfgdir/--logdir are included.
func TestServiceConfigServerArgsCustomDirs(t *testing.T) {
	sc := service.ServiceConfig{
		CfgDir: "/opt/spk/config",
		LogDir: "/opt/spk/log",
	}
	args := sc.ServerArgs()
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "--cfgdir /opt/spk/config") {
		t.Errorf("args should contain --cfgdir: %v", args)
	}
	if !strings.Contains(joined, "--logdir /opt/spk/log") {
		t.Errorf("args should contain --logdir: %v", args)
	}
}

// TestServiceDisplayNameDefault verifies the default service name.
func TestServiceDisplayNameDefault(t *testing.T) {
	sc := service.ServiceConfig{}
	want := "Secured Port Knock"
	if got := sc.DisplayName(); got != want {
		t.Errorf("DisplayName() = %q, want %q", got, want)
	}
}

// TestServiceDisplayNameCustomLabel verifies labeled service name.
func TestServiceDisplayNameCustomLabel(t *testing.T) {
	sc := service.ServiceConfig{DisplayLabel: "Production"}
	want := "Secured Port Knock (Production)"
	if got := sc.DisplayName(); got != want {
		t.Errorf("DisplayName() = %q, want %q", got, want)
	}
}

// ---------------------------------------------------------------------------
// Helpers -- save/restore global state for parallel-safe tests
// ---------------------------------------------------------------------------

func getConfigDirForRestore() string {
	return config.ConfigDir()
}

func restoreConfigDir(dir string) {
	config.SetConfigDir(dir)
}

func getLogDirForRestore() string {
	return logging.LogDir()
}

func restoreLogDir(dir string) {
	logging.SetLogDir(dir)
}

// ---------------------------------------------------------------------------
// Directory auto-creation tests (regression: "system cannot find the path")
// ---------------------------------------------------------------------------

// TestConfigDirAlwaysExists verifies that ConfigDir() always returns an existing
// directory, whether using the default or a custom override.
// Regression test for: "Error saving key: open .../config/server.crt: The system
// cannot find the path specified."
func TestConfigDirAlwaysExists(t *testing.T) {
	// Default path
	dir := config.ConfigDir()
	if dir == "" {
		t.Fatal("ConfigDir() returned empty string")
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("ConfigDir() returned %q which does not exist on disk: %v", dir, err)
	}
	if !info.IsDir() {
		t.Fatalf("ConfigDir() returned %q which is not a directory", dir)
	}

	// Custom nested path
	base := t.TempDir()
	nested := filepath.Join(base, "a", "b", "c")
	config.SetConfigDir(nested)
	defer config.SetConfigDir(dir) // restore

	got := config.ConfigDir()
	if got != nested {
		t.Fatalf("ConfigDir() = %q, want %q", got, nested)
	}
	info2, err := os.Stat(nested)
	if err != nil {
		t.Fatalf("after SetConfigDir(%q), directory does not exist: %v", nested, err)
	}
	if !info2.IsDir() {
		t.Fatalf("path %q is not a directory", nested)
	}
}

// TestLogDirAlwaysExists verifies that LogDir() always returns an existing directory.
func TestLogDirAlwaysExists(t *testing.T) {
	dir := logging.LogDir()
	if dir == "" {
		t.Fatal("LogDir() returned empty string")
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("LogDir() returned %q which does not exist on disk: %v", dir, err)
	}
	if !info.IsDir() {
		t.Fatalf("LogDir() returned %q which is not a directory", dir)
	}
}

// TestClientSetupDirCreation simulates the exact scenario that failed:
// writing server.crt into a config subdirectory that doesn't exist yet.
// On Windows this maps to <exe_dir>/config/server.crt.
func TestClientSetupDirCreation(t *testing.T) {
	base := t.TempDir()
	cfgDir := filepath.Join(base, "config") // does not exist yet

	saved := config.ConfigDir()
	config.SetConfigDir(cfgDir)
	defer config.SetConfigDir(saved)

	// Simulate what client setup does: write server.crt into ConfigDir()
	certPath := filepath.Join(config.ConfigDir(), "server.crt")
	if err := os.MkdirAll(filepath.Dir(certPath), 0750); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}
	if err := os.WriteFile(certPath, []byte("fake-pem-data"), 0600); err != nil {
		t.Fatalf("WriteFile failed (directory not created): %v", err)
	}
	if _, err := os.Stat(certPath); err != nil {
		t.Errorf("server.crt not found after write: %v", err)
	}
}

// TestWriteConfigsCreateParentDirs verifies that WriteServerConfigWithComments,
// WriteClientConfigWithComments, and Config.Save all create missing parent
// directories automatically without requiring the caller to pre-create them.
func TestWriteConfigsCreateParentDirs(t *testing.T) {
	base := t.TempDir()

	tests := []struct {
		name string
		path string
		fn   func(string) error
	}{
		{
			name: "WriteServerConfigWithComments",
			path: filepath.Join(base, "server", "sub", "spk_server.toml"),
			fn: func(p string) error {
				return config.WriteServerConfigWithComments(p, config.DefaultServerConfig())
			},
		},
		{
			name: "WriteClientConfigWithComments",
			path: filepath.Join(base, "client", "sub", "spk_client.toml"),
			fn: func(p string) error {
				cfg := config.DefaultClientConfig()
				cfg.ServerHost = "example.com"
				return config.WriteClientConfigWithComments(p, cfg)
			},
		},
		{
			name: "Config.Save",
			path: filepath.Join(base, "save", "sub", "state.json"),
			fn: func(p string) error {
				return config.DefaultServerConfig().Save(p)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.fn(tc.path); err != nil {
				t.Fatalf("%s: unexpected error on missing parent dir: %v", tc.name, err)
			}
			if _, err := os.Stat(tc.path); err != nil {
				t.Errorf("%s: file not created at %q: %v", tc.name, tc.path, err)
			}
		})
	}
}
