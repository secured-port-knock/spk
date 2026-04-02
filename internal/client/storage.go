// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package client

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/secured-port-knock/spk/internal/config"
)

// Secure storage backend identifiers used in the client config KeyStorageMode field.
const (
	StorageFile          = "file"
	StorageCredentialMgr = "credential_manager"
	StorageKeychain      = "keychain"
	StorageSecretService = "secret_service"
	storageLabelTest     = "SPK_StorageTest"
	storageKeyPrefix     = "SPK_ServerKey"
	storageTestValue     = "spk_storage_test_ok"
)

// newStorageLabel returns a fresh, randomly-generated credential slot label.
// The label is ASCII-safe and begins with storageKeyPrefix so it is easily
// identifiable in OS credential stores.  Each client instance generates its
// own label at setup time and persists it in the client TOML config under the
// key_storage_label field.  Because the label is independent of the config
// directory path, moving or copying the config directory to a new location
// does not invalidate the stored credential.
//
// Format: SPK_ServerKey_<16 lowercase hex chars>   (8 bytes of entropy)
func newStorageLabel() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate storage label: %w", err)
	}
	return storageKeyPrefix + "_" + hex.EncodeToString(b), nil
}

// escapePSQuote escapes single quotes within a string for use inside a
// PowerShell single-quoted string literal.  Single quotes are doubled
// because PowerShell's only escape sequence inside '...' is ”.
func escapePSQuote(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}

// TestSecureStorage verifies the platform's secure storage is accessible.
// Writes a test credential, verifies it, then cleans up.
// Returns nil on success, or an error describing what went wrong.
func TestSecureStorage() error {
	switch runtime.GOOS {
	case "windows":
		return testWindowsDPAPI()
	case "darwin":
		return testMacOSKeychain()
	case "linux":
		return testLinuxSecretService()
	default:
		return fmt.Errorf("secure storage not supported on %s", runtime.GOOS)
	}
}

// SaveKeySecure stores the ML-KEM public key in the platform's secure storage
// under the given label.  The label must be the value stored in
// cfg.KeyStorageLabel, which was generated at client setup time by
// newStorageLabel() and written to the client TOML config file.
func SaveKeySecure(keyPath, label string) error {
	if label == "" {
		return fmt.Errorf("storage label is empty; re-run 'spk --client --setup'")
	}
	data, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("read key file: %w", err)
	}
	switch runtime.GOOS {
	case "windows":
		return saveWindowsDPAPI(label, string(data))
	case "darwin":
		return saveMacOSKeychain(label, string(data))
	case "linux":
		return saveLinuxSecret(label, string(data))
	default:
		return fmt.Errorf("secure storage not supported on %s", runtime.GOOS)
	}
}

// LoadKeySecure retrieves the key from secure storage and writes it to
// keyPath.  label must match the value in cfg.KeyStorageLabel.
func LoadKeySecure(keyPath, label string) error {
	if label == "" {
		return fmt.Errorf("storage label is empty; re-run 'spk --client --setup'")
	}
	var data string
	var err error
	switch runtime.GOOS {
	case "windows":
		data, err = loadWindowsDPAPI(label)
	case "darwin":
		data, err = loadMacOSKeychain(label)
	case "linux":
		data, err = loadLinuxSecret(label)
	default:
		return fmt.Errorf("secure storage not supported on %s", runtime.GOOS)
	}
	if err != nil {
		return fmt.Errorf("load from secure storage: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0750); err != nil {
		return fmt.Errorf("create key directory: %w", err)
	}
	return os.WriteFile(keyPath, []byte(data), 0600)
}

// DeleteKeySecure removes the credential identified by label from the
// platform's secure storage.  Returns nil when the credential does not exist
// or was successfully deleted.
func DeleteKeySecure(label string) error {
	if label == "" {
		return fmt.Errorf("storage label is empty; nothing to delete")
	}
	switch runtime.GOOS {
	case "windows":
		return deleteWindowsDPAPI(label)
	case "darwin":
		return deleteMacOSKeychain(label)
	case "linux":
		return deleteLinuxSecret(label)
	default:
		return fmt.Errorf("secure storage not supported on %s", runtime.GOOS)
	}
}

// --- Windows: DPAPI via PowerShell ---
//
// DPAPI ties encryption to the current Windows user account and machine.
// Key material is passed via stdin so it is never exposed on the process
// command line.  The encrypted blob is stored as a file in the client config
// directory, named after the label stored in key_storage_label in the client
// TOML config.  Because the label is random and persisted in the TOML file,
// moving the config directory does not affect the ability to find the blob.
//
// cmdkey is NOT used: it cannot store multi-line PEM data reliably because the
// dashes and embedded newlines in PEM blocks confuse cmdkey's argument parser.

func testWindowsDPAPI() error {
	if err := saveWindowsDPAPI(storageLabelTest, storageTestValue); err != nil {
		return fmt.Errorf("DPAPI write test failed: %w", err)
	}
	testPath := filepath.Join(config.ClientConfigDir(), storageLabelTest+".dpapi")
	defer os.Remove(testPath)

	got, err := loadWindowsDPAPI(storageLabelTest)
	if err != nil {
		return fmt.Errorf("DPAPI read test failed: %w", err)
	}
	if got != storageTestValue {
		return fmt.Errorf("DPAPI read mismatch: got %q want %q", got, storageTestValue)
	}
	return nil
}

func saveWindowsDPAPI(name, value string) error {
	dpapiPath := filepath.Join(config.ClientConfigDir(), name+".dpapi")
	if err := os.MkdirAll(filepath.Dir(dpapiPath), 0750); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	psCmd := fmt.Sprintf(
		`Add-Type -AssemblyName System.Security;`+
			`$raw = [Console]::In.ReadToEnd();`+
			`$data = [System.Text.Encoding]::UTF8.GetBytes($raw);`+
			`$enc = [System.Security.Cryptography.ProtectedData]::Protect($data, $null, 'CurrentUser');`+
			`[System.IO.File]::WriteAllBytes('%s', $enc)`,
		escapePSQuote(dpapiPath))
	cmd := exec.Command("powershell", "-NoProfile", "-Command", psCmd)
	cmd.Stdin = strings.NewReader(value)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("DPAPI encrypt: %v\n%s", err, string(out))
	}
	return nil
}

func loadWindowsDPAPI(name string) (string, error) {
	dpapiPath := filepath.Join(config.ClientConfigDir(), name+".dpapi")
	psCmd := fmt.Sprintf(
		`Add-Type -AssemblyName System.Security;`+
			`$enc = [System.IO.File]::ReadAllBytes('%s');`+
			`$dec = [System.Security.Cryptography.ProtectedData]::Unprotect($enc, $null, 'CurrentUser');`+
			`[System.Text.Encoding]::UTF8.GetString($dec)`,
		escapePSQuote(dpapiPath))
	cmd := exec.Command("powershell", "-NoProfile", "-Command", psCmd)
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("DPAPI decrypt: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

func deleteWindowsDPAPI(name string) error {
	dpapiPath := filepath.Join(config.ClientConfigDir(), name+".dpapi")
	if err := os.Remove(dpapiPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("delete DPAPI file: %w", err)
	}
	return nil
}

// --- macOS: Keychain ---
//
// PEM key data is base64-encoded before being stored so that the value passed
// to security's -w flag is a single line of printable ASCII.  This avoids
// any ambiguity around embedded newlines in PEM blocks and ensures a clean
// roundtrip through the Keychain API.

func testMacOSKeychain() error {
	if err := saveMacOSKeychain(storageLabelTest, storageTestValue); err != nil {
		return fmt.Errorf("Keychain write failed: %w", err)
	}
	got, err := loadMacOSKeychain(storageLabelTest)
	deleteMacOSKeychain(storageLabelTest) //nolint:errcheck
	if err != nil {
		return fmt.Errorf("Keychain read failed: %w", err)
	}
	if got != storageTestValue {
		return fmt.Errorf("Keychain read mismatch: got %q want %q", got, storageTestValue)
	}
	return nil
}

func saveMacOSKeychain(name, value string) error {
	encoded := base64.StdEncoding.EncodeToString([]byte(value))
	cmd := exec.Command("security", "add-generic-password", "-U",
		"-s", name, "-a", "spk", "-w", encoded)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("Keychain save: %v\n%s", err, string(out))
	}
	return nil
}

func loadMacOSKeychain(name string) (string, error) {
	cmd := exec.Command("security", "find-generic-password",
		"-s", name, "-a", "spk", "-w")
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("Keychain load: %w", err)
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(out)))
	if err != nil {
		return "", fmt.Errorf("Keychain base64 decode: %w", err)
	}
	return string(decoded), nil
}

func deleteMacOSKeychain(name string) error {
	cmd := exec.Command("security", "delete-generic-password", "-s", name, "-a", "spk")
	out, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}
	// exit status 44 means the item was not found; treat as success.
	outStr := strings.ToLower(string(out))
	if strings.Contains(outStr, "could not be found") || strings.Contains(outStr, "not found") {
		return nil
	}
	return fmt.Errorf("Keychain delete: %v\n%s", err, string(out))
}

// --- Linux: Secret Service (gnome-keyring, KDE Wallet) ---

func testLinuxSecretService() error {
	if _, err := exec.LookPath("secret-tool"); err != nil {
		return fmt.Errorf("secret-tool not found - install gnome-keyring or libsecret-tools")
	}
	cmd := exec.Command("secret-tool", "store",
		"--label="+storageLabelTest, "app", "SPK", "key", storageLabelTest)
	cmd.Stdin = strings.NewReader(storageTestValue)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("Secret Service write failed: %v\n%s", err, string(out))
	}
	got, err := loadLinuxSecret(storageLabelTest)
	deleteLinuxSecret(storageLabelTest) //nolint:errcheck
	if err != nil {
		return fmt.Errorf("Secret Service read failed: %w", err)
	}
	if got != storageTestValue {
		return fmt.Errorf("Secret Service read mismatch: got %q want %q", got, storageTestValue)
	}
	return nil
}

func saveLinuxSecret(name, value string) error {
	cmd := exec.Command("secret-tool", "store",
		"--label=SPK Server Key", "app", "SPK", "key", name)
	cmd.Stdin = strings.NewReader(value)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("Secret Service save: %v\n%s", err, string(out))
	}
	return nil
}

func loadLinuxSecret(name string) (string, error) {
	cmd := exec.Command("secret-tool", "lookup", "app", "SPK", "key", name)
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("Secret Service load: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

func deleteLinuxSecret(name string) error {
	cmd := exec.Command("secret-tool", "clear", "app", "SPK", "key", name)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("Secret Service delete: %v\n%s", err, string(out))
	}
	return nil
}
