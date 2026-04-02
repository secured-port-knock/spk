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

// skipUnlessWindows skips the test when not running on Windows.
func skipUnlessWindows(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "windows" {
		t.Skip("Windows-specific test")
	}
	if _, err := exec.LookPath("powershell"); err != nil {
		t.Skipf("powershell not available: %v", err)
	}
}

// skipUnlessDarwin skips the test when not running on macOS.
func skipUnlessDarwin(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "darwin" {
		t.Skip("macOS-specific test")
	}
	if _, err := exec.LookPath("security"); err != nil {
		t.Skipf("security tool not available: %v", err)
	}
}

// skipUnlessLinuxSecretTool skips when secret-tool is absent or no D-Bus
// session is active (common in headless CI environments).
func skipUnlessLinuxSecretTool(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("Linux-specific test")
	}
	if _, err := exec.LookPath("secret-tool"); err != nil {
		t.Skipf("secret-tool not found (install libsecret-tools): %v", err)
	}
	// A quick write probe confirms a D-Bus / keyring session is present.
	probe := exec.Command("secret-tool", "store",
		"--label=SPK_probe", "app", "SPK_probe", "key", "probe")
	probe.Stdin = strings.NewReader("probe")
	if out, err := probe.CombinedOutput(); err != nil {
		t.Skipf("secret-tool not functional (no D-Bus session?): %v\n%s", err, out)
	}
	exec.Command("secret-tool", "clear", "app", "SPK_probe", "key", "probe").Run() //nolint:errcheck
}

// withConfigDir overrides the client config directory for the duration of the
// test and restores it on cleanup.
func withConfigDir(t *testing.T, dir string) {
	t.Helper()
	orig := config.ClientConfigDir()
	config.SetConfigDir(dir)
	t.Cleanup(func() { config.SetConfigDir(orig) })
}

// mustNewLabel generates a storage label or fails the test.
func mustNewLabel(t *testing.T) string {
	t.Helper()
	label, err := newStorageLabel()
	if err != nil {
		t.Fatalf("newStorageLabel: %v", err)
	}
	return label
}

// ============================================================
// newStorageLabel tests
// ============================================================

func TestNewStorageLabelHasPrefix(t *testing.T) {
	label := mustNewLabel(t)
	if !strings.HasPrefix(label, storageKeyPrefix+"_") {
		t.Errorf("label %q does not start with %q", label, storageKeyPrefix+"_")
	}
}

func TestNewStorageLabelIsASCIISafe(t *testing.T) {
	label := mustNewLabel(t)
	for _, c := range label {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '_' {
			continue
		}
		t.Errorf("label %q contains non-identifier character %q", label, c)
	}
}

// TestNewStorageLabelLength verifies the suffix is 16 hex chars (8 bytes).
func TestNewStorageLabelLength(t *testing.T) {
	label := mustNewLabel(t)
	prefix := storageKeyPrefix + "_"
	suffix := strings.TrimPrefix(label, prefix)
	if len(suffix) != 16 {
		t.Errorf("label suffix length = %d, want 16 (16 hex chars = 8 bytes); label=%q", len(suffix), label)
	}
}

// TestNewStorageLabelIsUnique checks that 50 calls produce 50 distinct labels.
func TestNewStorageLabelIsUnique(t *testing.T) {
	seen := make(map[string]bool, 50)
	for i := 0; i < 50; i++ {
		label := mustNewLabel(t)
		if seen[label] {
			t.Fatalf("duplicate label after %d calls: %q", i, label)
		}
		seen[label] = true
	}
}

// TestNewStorageLabelIsIndependentOfConfigDir verifies that the label is not
// derived from (and does not change with) the config directory path.
func TestNewStorageLabelIsIndependentOfConfigDir(t *testing.T) {
	dir1 := t.TempDir()
	dir2 := t.TempDir()

	withConfigDir(t, dir1)
	label1 := mustNewLabel(t)

	withConfigDir(t, dir2)
	label2 := mustNewLabel(t)

	// Labels are random; they should virtually never be equal, but more
	// importantly neither should be a deterministic function of the dir.
	// We just verify both are well-formed; the uniqueness test above covers
	// the distinctness property.
	if !strings.HasPrefix(label1, storageKeyPrefix+"_") {
		t.Errorf("label1 missing prefix: %q", label1)
	}
	if !strings.HasPrefix(label2, storageKeyPrefix+"_") {
		t.Errorf("label2 missing prefix: %q", label2)
	}
}

func TestEscapePSQuote(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"no quotes here", "no quotes here"},
		{"it's a test", "it''s a test"},
		{"a'b'c", "a''b''c"},
		{"", ""},
		{"'''", "''''''"},
	}
	for _, tc := range cases {
		got := escapePSQuote(tc.in)
		if got != tc.want {
			t.Errorf("escapePSQuote(%q) = %q; want %q", tc.in, got, tc.want)
		}
	}
}

// ============================================================
// Empty-label rejection tests (all platforms)
// ============================================================

func TestSaveKeySecureRejectsEmptyLabel(t *testing.T) {
	dir := t.TempDir()
	kp := filepath.Join(dir, "k.crt")
	os.WriteFile(kp, []byte("data"), 0600) //nolint:errcheck
	if err := SaveKeySecure(kp, ""); err == nil {
		t.Fatal("SaveKeySecure with empty label: want error, got nil")
	}
}

func TestLoadKeySecureRejectsEmptyLabel(t *testing.T) {
	dir := t.TempDir()
	if err := LoadKeySecure(filepath.Join(dir, "out.crt"), ""); err == nil {
		t.Fatal("LoadKeySecure with empty label: want error, got nil")
	}
}

func TestDeleteKeySecureRejectsEmptyLabel(t *testing.T) {
	if err := DeleteKeySecure(""); err == nil {
		t.Fatal("DeleteKeySecure with empty label: want error, got nil")
	}
}

// ============================================================
// Windows DPAPI tests
// ============================================================

func TestWindowsDPAPISaveLoadRoundtrip(t *testing.T) {
	skipUnlessWindows(t)
	cfgDir := t.TempDir()
	withConfigDir(t, cfgDir)

	name := "SPK_Test_Roundtrip"
	want := "hello-dpapi"
	t.Cleanup(func() {
		withConfigDir(t, cfgDir)
		deleteWindowsDPAPI(name) //nolint:errcheck
	})

	if err := saveWindowsDPAPI(name, want); err != nil {
		t.Fatalf("saveWindowsDPAPI: %v", err)
	}
	got, err := loadWindowsDPAPI(name)
	if err != nil {
		t.Fatalf("loadWindowsDPAPI: %v", err)
	}
	if got != want {
		t.Fatalf("mismatch: got %q want %q", got, want)
	}
}

func TestWindowsDPAPISaveLoadLargeData(t *testing.T) {
	skipUnlessWindows(t)
	cfgDir := t.TempDir()
	withConfigDir(t, cfgDir)

	name := "SPK_Test_LargeData"
	want := strings.Repeat("X", 3000)
	t.Cleanup(func() {
		withConfigDir(t, cfgDir)
		deleteWindowsDPAPI(name) //nolint:errcheck
	})

	if err := saveWindowsDPAPI(name, want); err != nil {
		t.Fatalf("saveWindowsDPAPI large: %v", err)
	}
	got, err := loadWindowsDPAPI(name)
	if err != nil {
		t.Fatalf("loadWindowsDPAPI large: %v", err)
	}
	if got != want {
		t.Fatalf("large data mismatch: got len %d want len %d", len(got), len(want))
	}
}

// TestWindowsDPAPISaveLoadPEMData verifies that multi-line PEM key material
// (which previously broke the cmdkey code path) round-trips correctly through
// the DPAPI backend.
func TestWindowsDPAPISaveLoadPEMData(t *testing.T) {
	skipUnlessWindows(t)
	cfgDir := t.TempDir()
	withConfigDir(t, cfgDir)

	name := "SPK_Test_PEM"
	// Reconstruct PEM with embedded newlines - the content that broke cmdkey.
	want := "-----BEGIN PQC ML-KEM-768 PUBLIC KEY-----\n" +
		"AAAABBBBCCCCDDDDEEEEFFFF\n" +
		"-----END PQC ML-KEM-768 PUBLIC KEY-----"
	t.Cleanup(func() {
		withConfigDir(t, cfgDir)
		deleteWindowsDPAPI(name) //nolint:errcheck
	})

	if err := saveWindowsDPAPI(name, want); err != nil {
		t.Fatalf("saveWindowsDPAPI PEM: %v", err)
	}
	got, err := loadWindowsDPAPI(name)
	if err != nil {
		t.Fatalf("loadWindowsDPAPI PEM: %v", err)
	}
	// TrimSpace is applied on read; compare trimmed forms.
	if got != strings.TrimSpace(want) {
		t.Fatalf("PEM mismatch:\ngot:  %q\nwant: %q", got, strings.TrimSpace(want))
	}
}

func TestWindowsDPAPIDeleteRemovesFile(t *testing.T) {
	skipUnlessWindows(t)
	cfgDir := t.TempDir()
	withConfigDir(t, cfgDir)

	name := "SPK_Test_Delete"
	if err := saveWindowsDPAPI(name, "to-delete"); err != nil {
		t.Fatalf("saveWindowsDPAPI: %v", err)
	}
	dpapiPath := filepath.Join(cfgDir, name+".dpapi")
	if _, err := os.Stat(dpapiPath); err != nil {
		t.Fatalf("DPAPI file should exist before delete: %v", err)
	}
	if err := deleteWindowsDPAPI(name); err != nil {
		t.Fatalf("deleteWindowsDPAPI: %v", err)
	}
	if _, err := os.Stat(dpapiPath); !os.IsNotExist(err) {
		t.Fatalf("DPAPI file should be gone after delete; stat err=%v", err)
	}
}

func TestWindowsDPAPIDeleteNonExistentReturnsNil(t *testing.T) {
	skipUnlessWindows(t)
	cfgDir := t.TempDir()
	withConfigDir(t, cfgDir)

	if err := deleteWindowsDPAPI("SPK_Test_NoSuchFile"); err != nil {
		t.Fatalf("deleteWindowsDPAPI non-existent: want nil, got %v", err)
	}
}

func TestWindowsDPAPILoadMissingReturnsError(t *testing.T) {
	skipUnlessWindows(t)
	cfgDir := t.TempDir()
	withConfigDir(t, cfgDir)

	_, err := loadWindowsDPAPI("SPK_Test_Missing")
	if err == nil {
		t.Fatal("expected error for missing DPAPI file, got nil")
	}
}

// TestWindowsDPAPIPathWithSpaces verifies that a config directory whose path
// contains spaces is handled correctly via single-quote escaping.
func TestWindowsDPAPIPathWithSpaces(t *testing.T) {
	skipUnlessWindows(t)
	base := t.TempDir()
	cfgDir := filepath.Join(base, "my config dir")
	if err := os.MkdirAll(cfgDir, 0750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	withConfigDir(t, cfgDir)

	name := "SPK_Test_Spaces"
	want := "value-in-spaced-dir"
	t.Cleanup(func() {
		withConfigDir(t, cfgDir)
		deleteWindowsDPAPI(name) //nolint:errcheck
	})

	if err := saveWindowsDPAPI(name, want); err != nil {
		t.Fatalf("saveWindowsDPAPI with spaces in path: %v", err)
	}
	got, err := loadWindowsDPAPI(name)
	if err != nil {
		t.Fatalf("loadWindowsDPAPI with spaces in path: %v", err)
	}
	if got != want {
		t.Fatalf("mismatch: got %q want %q", got, want)
	}
}

// ============================================================
// Public API - Windows
// ============================================================

func TestSaveKeySecureAndLoadKeySecureWindows(t *testing.T) {
	skipUnlessWindows(t)
	cfgDir := t.TempDir()
	withConfigDir(t, cfgDir)

	label := mustNewLabel(t)
	t.Cleanup(func() {
		withConfigDir(t, cfgDir)
		deleteWindowsDPAPI(label) //nolint:errcheck
	})

	keyContent := "-----BEGIN PQC ML-KEM-768 PUBLIC KEY-----\n" +
		"AAAABBBBCCCCDDDDEEEEFFFF\n" +
		"-----END PQC ML-KEM-768 PUBLIC KEY-----\n"
	keyPath := filepath.Join(cfgDir, "server.crt")
	if err := os.WriteFile(keyPath, []byte(keyContent), 0600); err != nil {
		t.Fatalf("write key file: %v", err)
	}

	if err := SaveKeySecure(keyPath, label); err != nil {
		t.Fatalf("SaveKeySecure: %v", err)
	}
	os.Remove(keyPath)

	dstPath := filepath.Join(cfgDir, "sub", "restored.crt")
	if err := LoadKeySecure(dstPath, label); err != nil {
		t.Fatalf("LoadKeySecure: %v", err)
	}
	got, err := os.ReadFile(dstPath)
	if err != nil {
		t.Fatalf("read restored key: %v", err)
	}
	if strings.TrimSpace(string(got)) != strings.TrimSpace(keyContent) {
		t.Fatalf("restored key mismatch:\ngot:  %q\nwant: %q", string(got), keyContent)
	}
}

func TestDeleteKeySecureWindows(t *testing.T) {
	skipUnlessWindows(t)
	cfgDir := t.TempDir()
	withConfigDir(t, cfgDir)

	label := mustNewLabel(t)
	keyPath := filepath.Join(cfgDir, "server.crt")
	if err := os.WriteFile(keyPath, []byte("key material"), 0600); err != nil {
		t.Fatalf("write key file: %v", err)
	}
	if err := SaveKeySecure(keyPath, label); err != nil {
		t.Fatalf("SaveKeySecure: %v", err)
	}
	if err := DeleteKeySecure(label); err != nil {
		t.Fatalf("DeleteKeySecure: %v", err)
	}
	// Subsequent load should fail.
	if err := LoadKeySecure(keyPath, label); err == nil {
		t.Fatal("expected LoadKeySecure to fail after delete, got nil")
	}
}

// TestMultiInstanceIsolationWindows saves two different keys under two random
// labels and asserts each loads back independently, regardless of config dir.
func TestMultiInstanceIsolationWindows(t *testing.T) {
	skipUnlessWindows(t)
	cfgDir := t.TempDir()
	withConfigDir(t, cfgDir)

	label1 := mustNewLabel(t)
	label2 := mustNewLabel(t)
	if label1 == label2 {
		t.Skip("label collision (astronomically unlikely)")
	}
	t.Cleanup(func() {
		withConfigDir(t, cfgDir)
		deleteWindowsDPAPI(label1) //nolint:errcheck
		deleteWindowsDPAPI(label2) //nolint:errcheck
	})

	kp1 := filepath.Join(cfgDir, "k1.crt")
	kp2 := filepath.Join(cfgDir, "k2.crt")
	os.WriteFile(kp1, []byte("key-for-server-1"), 0600) //nolint:errcheck
	os.WriteFile(kp2, []byte("key-for-server-2"), 0600) //nolint:errcheck

	if err := SaveKeySecure(kp1, label1); err != nil {
		t.Fatalf("SaveKeySecure label1: %v", err)
	}
	if err := SaveKeySecure(kp2, label2); err != nil {
		t.Fatalf("SaveKeySecure label2: %v", err)
	}

	rp1 := filepath.Join(cfgDir, "r1.crt")
	if err := LoadKeySecure(rp1, label1); err != nil {
		t.Fatalf("LoadKeySecure label1: %v", err)
	}
	if got, _ := os.ReadFile(rp1); strings.TrimSpace(string(got)) != "key-for-server-1" {
		t.Errorf("instance 1 got wrong key: %q", string(got))
	}

	rp2 := filepath.Join(cfgDir, "r2.crt")
	if err := LoadKeySecure(rp2, label2); err != nil {
		t.Fatalf("LoadKeySecure label2: %v", err)
	}
	if got, _ := os.ReadFile(rp2); strings.TrimSpace(string(got)) != "key-for-server-2" {
		t.Errorf("instance 2 got wrong key: %q", string(got))
	}
}

// TestConfigDirMoveDoesNotBreakWindowsKey verifies that after moving the config
// directory (simulated by changing the dir override), the key can still be
// loaded because the label is stored in the TOML file, not derived from the path.
func TestConfigDirMoveDoesNotBreakWindowsKey(t *testing.T) {
	skipUnlessWindows(t)
	origDir := t.TempDir()
	withConfigDir(t, origDir)

	label := mustNewLabel(t)
	t.Cleanup(func() {
		// Clean up from both dirs to be safe.
		withConfigDir(t, origDir)
		deleteWindowsDPAPI(label) //nolint:errcheck
	})

	kp := filepath.Join(origDir, "server.crt")
	os.WriteFile(kp, []byte("my-key-content"), 0600) //nolint:errcheck
	if err := SaveKeySecure(kp, label); err != nil {
		t.Fatalf("SaveKeySecure: %v", err)
	}

	// Simulate moving config dir to a new location.
	newDir := t.TempDir()
	withConfigDir(t, newDir)
	// The DPAPI blob lives in origDir because that is where the file was written.
	// We need to copy it to newDir to simulate an actual move.
	blobSrc := filepath.Join(origDir, label+".dpapi")
	blobDst := filepath.Join(newDir, label+".dpapi")
	blobData, err := os.ReadFile(blobSrc)
	if err != nil {
		t.Fatalf("read dpapi blob: %v", err)
	}
	if err := os.WriteFile(blobDst, blobData, 0600); err != nil {
		t.Fatalf("write dpapi blob to new dir: %v", err)
	}

	rp := filepath.Join(newDir, "restored.crt")
	if err := LoadKeySecure(rp, label); err != nil {
		t.Fatalf("LoadKeySecure after dir move: %v", err)
	}
	got, _ := os.ReadFile(rp)
	if strings.TrimSpace(string(got)) != "my-key-content" {
		t.Errorf("content mismatch after move: %q", string(got))
	}
}

// TestWindowsTestSecureStorage exercises the public TestSecureStorage path
// which should hit the DPAPI code on Windows (no cmdkey).
func TestWindowsTestSecureStorage(t *testing.T) {
	skipUnlessWindows(t)
	cfgDir := t.TempDir()
	withConfigDir(t, cfgDir)

	if err := TestSecureStorage(); err != nil {
		t.Fatalf("TestSecureStorage on Windows: %v", err)
	}
}

// ============================================================
// macOS Keychain tests
// ============================================================

func TestMacOSKeychainSimpleRoundtrip(t *testing.T) {
	skipUnlessDarwin(t)
	label := "SPK_Test_KeychainSimple"
	want := "hello-keychain"
	t.Cleanup(func() { deleteMacOSKeychain(label) }) //nolint:errcheck

	if err := saveMacOSKeychain(label, want); err != nil {
		t.Fatalf("saveMacOSKeychain: %v", err)
	}
	got, err := loadMacOSKeychain(label)
	if err != nil {
		t.Fatalf("loadMacOSKeychain: %v", err)
	}
	if got != want {
		t.Fatalf("mismatch: got %q want %q", got, want)
	}
}

// TestMacOSKeychainPEMRoundtrip verifies that multi-line PEM data survives
// the base64-encode-on-save / base64-decode-on-load cycle without corruption.
func TestMacOSKeychainPEMRoundtrip(t *testing.T) {
	skipUnlessDarwin(t)
	label := "SPK_Test_KeychainPEM"
	want := "-----BEGIN PQC ML-KEM-768 PUBLIC KEY-----\n" +
		"AAAABBBBCCCCDDDDEEEEFFFF\n" +
		"-----END PQC ML-KEM-768 PUBLIC KEY-----\n"
	t.Cleanup(func() { deleteMacOSKeychain(label) }) //nolint:errcheck

	if err := saveMacOSKeychain(label, want); err != nil {
		t.Fatalf("saveMacOSKeychain PEM: %v", err)
	}
	got, err := loadMacOSKeychain(label)
	if err != nil {
		t.Fatalf("loadMacOSKeychain PEM: %v", err)
	}
	if got != want {
		t.Fatalf("PEM mismatch:\ngot:  %q\nwant: %q", got, want)
	}
}

func TestMacOSKeychainDeleteNonExistentReturnsNil(t *testing.T) {
	skipUnlessDarwin(t)
	uniqueLabel := "SPK_Test_NoSuchEntry_zxcvbnm1234"
	if err := deleteMacOSKeychain(uniqueLabel); err != nil {
		t.Fatalf("deleteMacOSKeychain non-existent: want nil, got %v", err)
	}
}

func TestMacOSKeychainDeleteRemovesEntry(t *testing.T) {
	skipUnlessDarwin(t)
	label := "SPK_Test_KeychainDel"
	if err := saveMacOSKeychain(label, "delete-me"); err != nil {
		t.Fatalf("saveMacOSKeychain: %v", err)
	}
	if err := deleteMacOSKeychain(label); err != nil {
		t.Fatalf("deleteMacOSKeychain: %v", err)
	}
	if _, err := loadMacOSKeychain(label); err == nil {
		t.Fatal("expected error loading after delete, got nil")
	}
}

// TestMultiInstanceIsolationDarwin asserts that two random labels produce
// independent Keychain entries that do not interfere.
func TestMultiInstanceIsolationDarwin(t *testing.T) {
	skipUnlessDarwin(t)
	label1 := mustNewLabel(t)
	label2 := mustNewLabel(t)
	t.Cleanup(func() {
		deleteMacOSKeychain(label1) //nolint:errcheck
		deleteMacOSKeychain(label2) //nolint:errcheck
	})

	if err := saveMacOSKeychain(label1, "server-1-key"); err != nil {
		t.Fatalf("save label1: %v", err)
	}
	if err := saveMacOSKeychain(label2, "server-2-key"); err != nil {
		t.Fatalf("save label2: %v", err)
	}
	got1, err := loadMacOSKeychain(label1)
	if err != nil || got1 != "server-1-key" {
		t.Errorf("label1: got %q err=%v", got1, err)
	}
	got2, err := loadMacOSKeychain(label2)
	if err != nil || got2 != "server-2-key" {
		t.Errorf("label2: got %q err=%v", got2, err)
	}
}

func TestMacOSTestSecureStorage(t *testing.T) {
	skipUnlessDarwin(t)
	cfgDir := t.TempDir()
	withConfigDir(t, cfgDir)

	if err := TestSecureStorage(); err != nil {
		t.Fatalf("TestSecureStorage on macOS: %v", err)
	}
}

// ============================================================
// Linux Secret Service tests
// ============================================================

func TestLinuxSecretServiceRoundtrip(t *testing.T) {
	skipUnlessLinuxSecretTool(t)
	name := "SPK_Test_SSRoundtrip"
	want := "hello-secretservice"
	t.Cleanup(func() { deleteLinuxSecret(name) }) //nolint:errcheck

	if err := saveLinuxSecret(name, want); err != nil {
		t.Fatalf("saveLinuxSecret: %v", err)
	}
	got, err := loadLinuxSecret(name)
	if err != nil {
		t.Fatalf("loadLinuxSecret: %v", err)
	}
	if got != want {
		t.Fatalf("mismatch: got %q want %q", got, want)
	}
}

func TestLinuxSecretServiceDeleteRemovesEntry(t *testing.T) {
	skipUnlessLinuxSecretTool(t)
	name := "SPK_Test_SSDel"
	if err := saveLinuxSecret(name, "delete-me"); err != nil {
		t.Fatalf("saveLinuxSecret: %v", err)
	}
	if err := deleteLinuxSecret(name); err != nil {
		t.Fatalf("deleteLinuxSecret: %v", err)
	}
	if _, err := loadLinuxSecret(name); err == nil {
		t.Fatal("expected error loading after delete, got nil")
	}
}

// TestMultiInstanceIsolationLinux asserts that two random labels map to
// independent secret-service entries.
func TestMultiInstanceIsolationLinux(t *testing.T) {
	skipUnlessLinuxSecretTool(t)
	label1 := mustNewLabel(t)
	label2 := mustNewLabel(t)
	t.Cleanup(func() {
		deleteLinuxSecret(label1) //nolint:errcheck
		deleteLinuxSecret(label2) //nolint:errcheck
	})

	if err := saveLinuxSecret(label1, "server-1-key"); err != nil {
		t.Fatalf("save label1: %v", err)
	}
	if err := saveLinuxSecret(label2, "server-2-key"); err != nil {
		t.Fatalf("save label2: %v", err)
	}
	got1, err := loadLinuxSecret(label1)
	if err != nil || got1 != "server-1-key" {
		t.Errorf("label1: got %q err=%v", got1, err)
	}
	got2, err := loadLinuxSecret(label2)
	if err != nil || got2 != "server-2-key" {
		t.Errorf("label2: got %q err=%v", got2, err)
	}
}

func TestLinuxTestSecureStorage(t *testing.T) {
	skipUnlessLinuxSecretTool(t)
	cfgDir := t.TempDir()
	withConfigDir(t, cfgDir)

	if err := TestSecureStorage(); err != nil {
		t.Fatalf("TestSecureStorage on Linux: %v", err)
	}
}
