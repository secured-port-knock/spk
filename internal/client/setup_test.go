// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package client

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/secured-port-knock/spk/internal/config"
)

// exeDir returns the directory containing the test binary.
func exeDir(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	return filepath.Dir(exe)
}

// TestActivationBundleCandidatesContainsExeDir verifies that the exe directory
// is always included in the candidate list.
func TestActivationBundleCandidatesContainsExeDir(t *testing.T) {
	candidates := ActivationBundleCandidates()
	if len(candidates) == 0 {
		t.Fatal("ActivationBundleCandidates returned empty slice")
	}
	dir := exeDir(t)
	found := false
	for _, c := range candidates {
		if filepath.Dir(c) == dir {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("exe directory %q not found in candidates: %v", dir, candidates)
	}
}

// TestActivationBundleCandidatesContainsClientConfigDir verifies the client
// config directory is included.
func TestActivationBundleCandidatesContainsClientConfigDir(t *testing.T) {
	dir := t.TempDir()
	origDir := config.ClientConfigDir()
	config.SetConfigDir(dir)
	defer config.SetConfigDir(origDir)

	candidates := ActivationBundleCandidates()
	found := false
	for _, c := range candidates {
		if filepath.Dir(c) == dir {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("client config dir %q not found in candidates: %v", dir, candidates)
	}
}

// TestActivationBundleCandidatesNoDuplicates verifies that no path appears
// more than once even when exe_dir == client_config_dir.
func TestActivationBundleCandidatesNoDuplicates(t *testing.T) {
	// Point client config dir to the exe directory so they match.
	dir := exeDir(t)
	origDir := config.ClientConfigDir()
	config.SetConfigDir(dir)
	defer config.SetConfigDir(origDir)

	candidates := ActivationBundleCandidates()
	seen := make(map[string]bool)
	for _, c := range candidates {
		if seen[c] {
			t.Errorf("duplicate candidate path: %q", c)
		}
		seen[c] = true
	}
}

// TestActivationBundleCandidatesNeverSearchesServerConfigDir verifies that when
// the server config dir differs from the client config dir (as on Linux where
// the server uses /etc/spk and the client uses ~/.config/spk), the server
// directory is not present in the candidate list.
func TestActivationBundleCandidatesNeverSearchesServerConfigDir(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("server/client config dir split only applies on Linux/macOS")
	}

	// Override client config dir to a temp directory.
	clientDir := t.TempDir()
	origDir := config.ClientConfigDir()
	config.SetConfigDir(clientDir)
	defer config.SetConfigDir(origDir)

	candidates := ActivationBundleCandidates()

	// The server config dir on Linux/macOS is /etc/spk.
	serverConfigDir := "/etc/spk"
	for _, c := range candidates {
		if strings.HasPrefix(c, serverConfigDir) {
			t.Errorf("candidate %q is inside server config dir %q -- must not search there", c, serverConfigDir)
		}
	}
}

// TestActivationBundleCandidatesCfgdirOverride verifies that when --cfgdir is
// specified, the override directory is used as the client config directory.
func TestActivationBundleCandidatesCfgdirOverride(t *testing.T) {
	customDir := t.TempDir()
	origDir := config.ClientConfigDir()
	config.SetConfigDir(customDir)
	defer config.SetConfigDir(origDir)

	candidates := ActivationBundleCandidates()

	foundCustom := false
	for _, c := range candidates {
		if filepath.Dir(c) == customDir {
			foundCustom = true
			break
		}
	}
	if !foundCustom {
		t.Errorf("--cfgdir override %q not in candidates: %v", customDir, candidates)
	}
}

// TestActivationBundleCandidatesBothNames verifies "activation.b64" is included.
func TestActivationBundleCandidatesBothNames(t *testing.T) {
	candidates := ActivationBundleCandidates()
	hasActivation := false
	for _, c := range candidates {
		if filepath.Base(c) == "activation.b64" {
			hasActivation = true
		}
	}
	if !hasActivation {
		t.Error("candidates missing activation.b64")
	}
	for _, c := range candidates {
		if filepath.Base(c) == "public.b64" {
			t.Errorf("candidates must not include legacy public.b64, got %q", c)
		}
	}
}

// TestActivationBundleCandidatesExeDirBeforeConfigDir verifies that exe
// directory entries appear before client config directory entries (so the
// bundle dropped next to the binary is preferred).
func TestActivationBundleCandidatesExeDirBeforeConfigDir(t *testing.T) {
	cfgDir := t.TempDir()
	origDir := config.ClientConfigDir()
	config.SetConfigDir(cfgDir)
	defer config.SetConfigDir(origDir)

	candidates := ActivationBundleCandidates()
	if len(candidates) < 2 {
		t.Skip("not enough candidates to test ordering")
	}

	dir := exeDir(t)
	if dir == cfgDir {
		t.Skip("exe dir and config dir are the same in this environment")
	}

	// Find index of first exe-dir entry and first config-dir entry.
	exeIdx := -1
	cfgIdx := -1
	for i, c := range candidates {
		if filepath.Dir(c) == dir && exeIdx == -1 {
			exeIdx = i
		}
		if filepath.Dir(c) == cfgDir && cfgIdx == -1 {
			cfgIdx = i
		}
	}
	if exeIdx == -1 {
		t.Fatalf("no exe-dir candidate found in %v", candidates)
	}
	if cfgIdx == -1 {
		t.Fatalf("no cfg-dir candidate found in %v", candidates)
	}
	if exeIdx > cfgIdx {
		t.Errorf("exe-dir entry (index %d) should come before cfg-dir entry (index %d)", exeIdx, cfgIdx)
	}
}
