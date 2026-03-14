// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
// Package service provides --install / --uninstall support for running SPK
// as an OS service on Linux (systemd), Windows (SCM), macOS (launchd),
// and OpenWRT (init.d + procd).
//
// Each platform implementation detects the init system at runtime and writes
// the appropriate service definition. Custom --cfgdir and --logdir are
// embedded in the service command so the service respects the same paths.
package service

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// platformInstall and platformUninstall are set by platform-specific init() functions.
var platformInstall func(ServiceConfig) error
var platformUninstall func(ServiceConfig) error

// ServiceConfig holds parameters for service installation.
type ServiceConfig struct {
	// CfgDir is the custom config directory (empty = platform default).
	CfgDir string

	// LogDir is the custom log directory (empty = platform default).
	LogDir string

	// ExePath is the absolute path to the spk binary.
	// Auto-detected if empty.
	ExePath string

	// DisplayLabel is the user-chosen label for the service.
	// Empty means no custom label.
	DisplayLabel string
}

// ServiceName returns the service identifier used by the init system.
// When a DisplayLabel is set, the name is "spk_<sanitized-label>" so that
// multiple SPK instances can coexist without a name conflict.
func (sc *ServiceConfig) ServiceName() string {
	if sc.DisplayLabel != "" {
		return "spk_" + sanitizeServiceLabel(sc.DisplayLabel)
	}
	return "spk"
}

// sanitizeServiceLabel lowercases the label and replaces characters that are
// not safe for service names / file names with underscores.
func sanitizeServiceLabel(label string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(label)) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	return b.String()
}

// DisplayName returns a human-readable service name.
// Format: "Secured Port Knock" or "Secured Port Knock (LABEL)" if a label is set.
func (sc *ServiceConfig) DisplayName() string {
	base := "Secured Port Knock"
	if sc.DisplayLabel != "" {
		return base + " (" + sc.DisplayLabel + ")"
	}
	return base
}

// ServerArgs returns the command line arguments for the service executable.
// Always includes --server, plus --cfgdir/--logdir if non-empty.
func (sc *ServiceConfig) ServerArgs() []string {
	args := []string{"--server"}
	if sc.CfgDir != "" {
		args = append(args, "--cfgdir", sc.CfgDir)
	}
	if sc.LogDir != "" {
		args = append(args, "--logdir", sc.LogDir)
	}
	return args
}

// Install registers SPK as a system service.
// Validates that the config and key files exist before installing.
// Prompts the user for an optional service display name.
func Install(cfg ServiceConfig) error {
	if err := fillDefaults(&cfg); err != nil {
		return err
	}

	// Validate config and key files exist
	if err := validateServerFiles(cfg); err != nil {
		return err
	}

	// Prompt for display name
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("Service Display Name")
	fmt.Println("  The service will be named \"Secured Port Knock\".")
	fmt.Print("  Enter a custom label (or press Enter to skip): ")
	label := strings.TrimSpace(readLine(reader))
	if label != "" {
		cfg.DisplayLabel = label
		fmt.Printf("  -> Service name: %s\n", cfg.DisplayName())
	} else {
		fmt.Printf("  -> Service name: %s\n", cfg.DisplayName())
	}

	return platformInstall(cfg)
}

// Uninstall removes the SPK system service.
// Lists all SPK-related services and prompts the user to pick one.
func Uninstall(cfg ServiceConfig) error {
	if err := fillDefaults(&cfg); err != nil {
		return err
	}
	return platformUninstall(cfg)
}

// fillDefaults populates missing fields.
func fillDefaults(cfg *ServiceConfig) error {
	if cfg.ExePath == "" {
		exe, err := os.Executable()
		if err != nil {
			return fmt.Errorf("detect executable path: %w", err)
		}
		exe, err = filepath.EvalSymlinks(exe)
		if err != nil {
			return fmt.Errorf("resolve executable path: %w", err)
		}
		cfg.ExePath = exe
	}
	return nil
}

// validateServerFiles checks that spk_server.toml, server.key, and server.crt
// exist in the resolved config directory.
func validateServerFiles(cfg ServiceConfig) error {
	cfgDir := cfg.CfgDir
	if cfgDir == "" {
		// Use platform default detection (same logic as config.ConfigDir)
		cfgDir = detectDefaultCfgDir(cfg.ExePath)
	}

	required := []string{"spk_server.toml", "server.key", "server.crt"}
	var missing []string
	for _, f := range required {
		path := filepath.Join(cfgDir, f)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			missing = append(missing, path)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("required files not found in %s:\n  %s\nRun 'spk --server --setup' first",
			cfgDir, strings.Join(missing, "\n  "))
	}
	return nil
}

// detectDefaultCfgDir returns the default config dir for validation purposes.
// This mirrors config.ConfigDir() logic without importing it (to avoid cycles).
func detectDefaultCfgDir(exePath string) string {
	if isUnixLike() {
		if info, err := os.Stat("/etc/spk"); err == nil && info.IsDir() {
			return "/etc/spk"
		}
	}
	dir := filepath.Dir(exePath)
	if isWindows() {
		return filepath.Join(dir, "config")
	}
	return dir
}

func isUnixLike() bool {
	// Check /etc existence as heuristic for Unix-like
	_, err := os.Stat("/etc")
	return err == nil
}

func isWindows() bool {
	return os.PathSeparator == '\\'
}

func readLine(reader *bufio.Reader) string {
	line, _ := reader.ReadString('\n')
	return strings.TrimSpace(line)
}
