// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package client

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/secured-port-knock/spk/internal/config"
)

func requireWindowsSecureStorageTools(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "windows" {
		t.Skip("Windows-specific secure storage test")
	}
	if _, err := exec.LookPath("powershell"); err != nil {
		t.Skipf("powershell not found: %v", err)
	}
}

func TestLoadWindowsCredentialMissingReturnsError(t *testing.T) {
	requireWindowsSecureStorageTools(t)

	cfgDir := t.TempDir()
	origDir := config.ClientConfigDir()
	config.SetConfigDir(cfgDir)
	defer config.SetConfigDir(origDir)

	_, err := loadWindowsCredential("SPK_Missing_Credential_For_Test")
	if err == nil {
		t.Fatal("expected error for missing credential")
	}
}

func TestSaveWindowsCredentialLargeValueCreatesDPAPIFile(t *testing.T) {
	requireWindowsSecureStorageTools(t)

	cfgDir := t.TempDir()
	origDir := config.ClientConfigDir()
	config.SetConfigDir(cfgDir)
	defer config.SetConfigDir(origDir)

	name := "SPK_TestLargeCredential"
	value := strings.Repeat("A", 3001) // >2000 triggers DPAPI path

	if err := saveWindowsCredential(name, value); err != nil {
		t.Fatalf("saveWindowsCredential: %v", err)
	}

	dpapiPath := filepath.Join(cfgDir, name+".dpapi")
	if _, err := os.Stat(dpapiPath); err != nil {
		t.Fatalf("expected DPAPI file %q to exist: %v", dpapiPath, err)
	}
}

func TestLoadWindowsCredentialUsesDPAPIWhenPresent(t *testing.T) {
	requireWindowsSecureStorageTools(t)

	cfgDir := t.TempDir()
	origDir := config.ClientConfigDir()
	config.SetConfigDir(cfgDir)
	defer config.SetConfigDir(origDir)

	name := "SPK_Test_DPAPI_Load"
	want := "test-credential-data"

	if err := saveWindowsDPAPI(name, want); err != nil {
		t.Fatalf("saveWindowsDPAPI: %v", err)
	}

	got, err := loadWindowsCredential(name)
	if err != nil {
		t.Fatalf("loadWindowsCredential: %v", err)
	}
	if got != want {
		t.Fatalf("credential mismatch: got %q want %q", got, want)
	}
}

func TestLoadKeySecureCreatesDestinationDir(t *testing.T) {
	requireWindowsSecureStorageTools(t)

	cfgDir := t.TempDir()
	origDir := config.ClientConfigDir()
	config.SetConfigDir(cfgDir)
	defer config.SetConfigDir(origDir)

	want := "test-public-key-material"
	if err := saveWindowsDPAPI(storageLabelKey, want); err != nil {
		t.Fatalf("saveWindowsDPAPI: %v", err)
	}

	dst := filepath.Join(cfgDir, "nested", "path", "server.crt")
	if err := LoadKeySecure(dst); err != nil {
		t.Fatalf("LoadKeySecure: %v", err)
	}

	gotBytes, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read restored key: %v", err)
	}
	if string(gotBytes) != want {
		t.Fatalf("restored key mismatch: got %q want %q", string(gotBytes), want)
	}
}
