// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

//go:build linux || darwin

package config

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// =============================================================================
// checkPerms unit tests (ownership and permission logic, no real files needed)
// =============================================================================

// TestCheckPerms_SameOwnerMaxPerm verifies that a file owned by the process
// user/group with permission 0600 is accepted.
func TestCheckPerms_SameOwnerMaxPerm(t *testing.T) {
	err := checkPerms("/fake/path", 1000, 1000, 1000, 1000, fs.FileMode(0600))
	if err != nil {
		t.Errorf("expected nil for same owner, perm 0600, got: %v", err)
	}
}

// TestCheckPerms_SameOwnerMinPerm verifies that a more restrictive permission
// (0400 -- read-only for owner) is also accepted.
func TestCheckPerms_SameOwnerMinPerm(t *testing.T) {
	err := checkPerms("/fake/path", 500, 500, 500, 500, fs.FileMode(0400))
	if err != nil {
		t.Errorf("expected nil for same owner, perm 0400, got: %v", err)
	}
}

// TestCheckPerms_SameOwnerZeroPerm verifies that permission 0000 is accepted.
func TestCheckPerms_SameOwnerZeroPerm(t *testing.T) {
	err := checkPerms("/fake/path", 0, 0, 0, 0, fs.FileMode(0000))
	if err != nil {
		t.Errorf("expected nil for same owner (root), perm 0000, got: %v", err)
	}
}

// TestCheckPerms_WrongUID_SameGID: file owned by user B (uid=1000), running as
// user A (uid=0). Should fail with uid mismatch.
func TestCheckPerms_WrongUID_SameGID(t *testing.T) {
	err := checkPerms("/etc/spk/spk_server.toml", 1000, 0, 0, 0, fs.FileMode(0600))
	if err == nil {
		t.Error("expected error: file owned by uid 1000, process uid 0")
	}
	if err != nil && err.Path != "/etc/spk/spk_server.toml" {
		t.Errorf("error path = %q, want /etc/spk/spk_server.toml", err.Path)
	}
}

// TestCheckPerms_SameUID_WrongGID: file owned by user A but a different group.
// Should fail with gid mismatch.
func TestCheckPerms_SameUID_WrongGID(t *testing.T) {
	err := checkPerms("/fake/server.key", 0, 1000, 0, 0, fs.FileMode(0600))
	if err == nil {
		t.Error("expected error: file gid 1000, process gid 0")
	}
}

// TestCheckPerms_WrongUID_WrongGID: file owned by user C (uid=2000), group D
// (gid=3000), running as user A (uid=1000), group A (gid=1000). Both should
// fail; uid is reported first.
func TestCheckPerms_WrongUID_WrongGID(t *testing.T) {
	err := checkPerms("/fake/path", 2000, 3000, 1000, 1000, fs.FileMode(0600))
	if err == nil {
		t.Error("expected error: file uid 2000, gid 3000, process uid 1000, gid 1000")
	}
	// uid mismatch is reported first
	if err != nil {
		want := "owner uid 2000 does not match process uid 1000"
		if err.Reason != want {
			t.Errorf("reason = %q, want %q", err.Reason, want)
		}
	}
}

// TestCheckPerms_GroupReadBit: same owner but perm 0640 (group read). Fail.
func TestCheckPerms_GroupReadBit(t *testing.T) {
	err := checkPerms("/fake/path", 100, 100, 100, 100, fs.FileMode(0640))
	if err == nil {
		t.Error("expected error for perm 0640 (group read bit set)")
	}
}

// TestCheckPerms_GroupWriteBit: same owner but perm 0620 (group write). Fail.
func TestCheckPerms_GroupWriteBit(t *testing.T) {
	err := checkPerms("/fake/path", 100, 100, 100, 100, fs.FileMode(0620))
	if err == nil {
		t.Error("expected error for perm 0620 (group write bit set)")
	}
}

// TestCheckPerms_GroupExecBit: same owner but perm 0610 (group execute). Fail.
func TestCheckPerms_GroupExecBit(t *testing.T) {
	err := checkPerms("/fake/path", 100, 100, 100, 100, fs.FileMode(0610))
	if err == nil {
		t.Error("expected error for perm 0610 (group execute bit set)")
	}
}

// TestCheckPerms_OtherReadBit: same owner but perm 0604 (other read). Fail.
func TestCheckPerms_OtherReadBit(t *testing.T) {
	err := checkPerms("/fake/path", 100, 100, 100, 100, fs.FileMode(0604))
	if err == nil {
		t.Error("expected error for perm 0604 (other read bit set)")
	}
}

// TestCheckPerms_OtherWriteBit: perm 0602 (other write). Fail.
func TestCheckPerms_OtherWriteBit(t *testing.T) {
	err := checkPerms("/fake/path", 100, 100, 100, 100, fs.FileMode(0602))
	if err == nil {
		t.Error("expected error for perm 0602 (other write bit set)")
	}
}

// TestCheckPerms_OtherExecBit: perm 0601 (other execute). Fail.
func TestCheckPerms_OtherExecBit(t *testing.T) {
	err := checkPerms("/fake/path", 100, 100, 100, 100, fs.FileMode(0601))
	if err == nil {
		t.Error("expected error for perm 0601 (other execute bit set)")
	}
}

// TestCheckPerms_OwnerExecBit: perm 0700 (owner rwx). Fail.
func TestCheckPerms_OwnerExecBit(t *testing.T) {
	err := checkPerms("/fake/path", 100, 100, 100, 100, fs.FileMode(0700))
	if err == nil {
		t.Error("expected error for perm 0700 (owner execute bit set)")
	}
}

// TestCheckPerms_Perm0644: world-readable. Fail.
func TestCheckPerms_Perm0644(t *testing.T) {
	err := checkPerms("/fake/path", 100, 100, 100, 100, fs.FileMode(0644))
	if err == nil {
		t.Error("expected error for perm 0644")
	}
}

// TestCheckPerms_Perm0777: world rwx. Fail.
func TestCheckPerms_Perm0777(t *testing.T) {
	err := checkPerms("/fake/path", 100, 100, 100, 100, fs.FileMode(0777))
	if err == nil {
		t.Error("expected error for perm 0777")
	}
}

// TestCheckPerms_Perm0755: typical directory-style perm. Fail.
func TestCheckPerms_Perm0755(t *testing.T) {
	err := checkPerms("/fake/path", 100, 100, 100, 100, fs.FileMode(0755))
	if err == nil {
		t.Error("expected error for perm 0755")
	}
}

// TestCheckPerms_Perm0400: read-only for owner. Accept.
func TestCheckPerms_Perm0400(t *testing.T) {
	err := checkPerms("/fake/path", 100, 100, 100, 100, fs.FileMode(0400))
	if err != nil {
		t.Errorf("expected nil for perm 0400, got: %v", err)
	}
}

// TestCheckPerms_Perm0200: write-only for owner. Accept (no group/other bits).
func TestCheckPerms_Perm0200(t *testing.T) {
	err := checkPerms("/fake/path", 100, 100, 100, 100, fs.FileMode(0200))
	if err != nil {
		t.Errorf("expected nil for perm 0200, got: %v", err)
	}
}

// TestCheckPerms_ErrorMessage verifies the error Path field is set correctly.
func TestCheckPerms_ErrorMessage(t *testing.T) {
	const testPath = "/etc/spk/server.key"
	err := checkPerms(testPath, 1000, 0, 0, 0, fs.FileMode(0600))
	if err == nil {
		t.Fatal("expected error")
	}
	if err.Path != testPath {
		t.Errorf("Path = %q, want %q", err.Path, testPath)
	}
	if err.Error() == "" {
		t.Error("Error() returned empty string")
	}
}

// =============================================================================
// CheckSensitiveFile integration tests (real files on disk)
// =============================================================================

// writeFile creates a temp file with the given content and chmod.
func writeFilePerm(t *testing.T, dir, name, content string, perm fs.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), perm); err != nil {
		t.Fatalf("writeFilePerm: %v", err)
	}
	// WriteFile respects umask, so force the exact perm via Chmod.
	if err := os.Chmod(path, perm); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	return path
}

// TestCheckSensitiveFile_NotExist returns nil for a missing file.
func TestCheckSensitiveFile_NotExist(t *testing.T) {
	err := CheckSensitiveFile(filepath.Join(t.TempDir(), "nonexistent.txt"))
	if err != nil {
		t.Errorf("expected nil for non-existent file, got: %v", err)
	}
}

// TestCheckSensitiveFile_CorrectOwnerAndPerm: current user, perm 0600.
func TestCheckSensitiveFile_CorrectOwnerAndPerm(t *testing.T) {
	dir := t.TempDir()
	path := writeFilePerm(t, dir, "secret.toml", "key=val", 0600)
	err := CheckSensitiveFile(path)
	if err != nil {
		t.Errorf("expected nil for current-user 0600 file, got: %v", err)
	}
}

// TestCheckSensitiveFile_Perm0400: read-only for owner. Accept.
func TestCheckSensitiveFile_Perm0400(t *testing.T) {
	dir := t.TempDir()
	path := writeFilePerm(t, dir, "secret.toml", "key=val", 0400)
	err := CheckSensitiveFile(path)
	if err != nil {
		t.Errorf("expected nil for perm 0400, got: %v", err)
	}
}

// TestCheckSensitiveFile_Perm0640: group read. Fail.
func TestCheckSensitiveFile_Perm0640(t *testing.T) {
	dir := t.TempDir()
	path := writeFilePerm(t, dir, "secret.toml", "key=val", 0640)
	err := CheckSensitiveFile(path)
	if err == nil {
		t.Error("expected error for perm 0640")
	}
}

// TestCheckSensitiveFile_Perm0644: world read. Fail.
func TestCheckSensitiveFile_Perm0644(t *testing.T) {
	dir := t.TempDir()
	path := writeFilePerm(t, dir, "secret.toml", "key=val", 0644)
	err := CheckSensitiveFile(path)
	if err == nil {
		t.Error("expected error for perm 0644")
	}
}

// TestCheckSensitiveFile_Perm0660: group rw. Fail.
func TestCheckSensitiveFile_Perm0660(t *testing.T) {
	dir := t.TempDir()
	path := writeFilePerm(t, dir, "secret.toml", "key=val", 0660)
	err := CheckSensitiveFile(path)
	if err == nil {
		t.Error("expected error for perm 0660")
	}
}

// TestCheckSensitiveFile_Perm0700: owner rwx. Fail.
func TestCheckSensitiveFile_Perm0700(t *testing.T) {
	dir := t.TempDir()
	path := writeFilePerm(t, dir, "secret.toml", "key=val", 0700)
	err := CheckSensitiveFile(path)
	if err == nil {
		t.Error("expected error for perm 0700")
	}
}

// TestCheckSensitiveFile_Perm0755: typical dir-style. Fail.
func TestCheckSensitiveFile_Perm0755(t *testing.T) {
	dir := t.TempDir()
	path := writeFilePerm(t, dir, "secret.toml", "key=val", 0755)
	err := CheckSensitiveFile(path)
	if err == nil {
		t.Error("expected error for perm 0755")
	}
}

// TestCheckSensitiveFile_Perm0777: world rwx. Fail.
func TestCheckSensitiveFile_Perm0777(t *testing.T) {
	dir := t.TempDir()
	path := writeFilePerm(t, dir, "secret.toml", "key=val", 0777)
	err := CheckSensitiveFile(path)
	if err == nil {
		t.Error("expected error for perm 0777")
	}
}

// TestCheckSensitiveFile_Perm0604: other read. Fail.
func TestCheckSensitiveFile_Perm0604(t *testing.T) {
	dir := t.TempDir()
	path := writeFilePerm(t, dir, "secret.toml", "key=val", 0604)
	err := CheckSensitiveFile(path)
	if err == nil {
		t.Error("expected error for perm 0604")
	}
}

// TestCheckSensitiveFile_Perm0606: owner rw + other rw. Fail.
func TestCheckSensitiveFile_Perm0606(t *testing.T) {
	dir := t.TempDir()
	path := writeFilePerm(t, dir, "secret.toml", "key=val", 0606)
	err := CheckSensitiveFile(path)
	if err == nil {
		t.Error("expected error for perm 0606")
	}
}

// TestCheckSensitiveFile_ErrorPath verifies the returned error contains the path.
func TestCheckSensitiveFile_ErrorPath(t *testing.T) {
	dir := t.TempDir()
	path := writeFilePerm(t, dir, "secret.toml", "key=val", 0644)
	err := CheckSensitiveFile(path)
	if err == nil {
		t.Fatal("expected error")
	}
	if err.Path != path {
		t.Errorf("error.Path = %q, want %q", err.Path, path)
	}
}

// =============================================================================
// CheckSensitiveFiles (batch) tests
// =============================================================================

// TestCheckSensitiveFiles_AllGood: all files pass.
func TestCheckSensitiveFiles_AllGood(t *testing.T) {
	dir := t.TempDir()
	p1 := writeFilePerm(t, dir, "a.toml", "a", 0600)
	p2 := writeFilePerm(t, dir, "b.key", "b", 0600)
	errs := CheckSensitiveFiles(p1, p2)
	if len(errs) != 0 {
		t.Errorf("expected no errors, got %d: %v", len(errs), errs)
	}
}

// TestCheckSensitiveFiles_OneFails: one bad permission among several files.
func TestCheckSensitiveFiles_OneFails(t *testing.T) {
	dir := t.TempDir()
	p1 := writeFilePerm(t, dir, "a.toml", "a", 0600)
	p2 := writeFilePerm(t, dir, "b.key", "b", 0644) // bad
	p3 := writeFilePerm(t, dir, "c.key", "c", 0600)
	errs := CheckSensitiveFiles(p1, p2, p3)
	if len(errs) != 1 {
		t.Errorf("expected 1 error, got %d: %v", len(errs), errs)
	}
	if errs[0].Path != p2 {
		t.Errorf("expected error for %q, got %q", p2, errs[0].Path)
	}
}

// TestCheckSensitiveFiles_MultipleFail: two files with bad permissions.
func TestCheckSensitiveFiles_MultipleFail(t *testing.T) {
	dir := t.TempDir()
	p1 := writeFilePerm(t, dir, "a.toml", "a", 0644) // bad
	p2 := writeFilePerm(t, dir, "b.key", "b", 0600)
	p3 := writeFilePerm(t, dir, "c.crt", "c", 0755) // bad
	errs := CheckSensitiveFiles(p1, p2, p3)
	if len(errs) != 2 {
		t.Errorf("expected 2 errors, got %d: %v", len(errs), errs)
	}
}

// TestCheckSensitiveFiles_SkipMissing: non-existent files are skipped.
func TestCheckSensitiveFiles_SkipMissing(t *testing.T) {
	dir := t.TempDir()
	p1 := writeFilePerm(t, dir, "a.toml", "a", 0600)
	missing := filepath.Join(dir, "doesnotexist.json")
	errs := CheckSensitiveFiles(p1, missing)
	if len(errs) != 0 {
		t.Errorf("expected no errors (missing file skipped), got %d: %v", len(errs), errs)
	}
}

// TestCheckSensitiveFiles_Empty: no paths returns no errors.
func TestCheckSensitiveFiles_Empty(t *testing.T) {
	errs := CheckSensitiveFiles()
	if len(errs) != 0 {
		t.Errorf("expected no errors for empty call, got %d", len(errs))
	}
}

// =============================================================================
// Ownership mismatch tests (via checkPerms with synthetic UIDs/GIDs)
// =============================================================================

// TestCheckPerms_UserA_FileOwnedByUserB: process=uid1000/gid1000, file uid2000/gid2000.
func TestCheckPerms_UserA_FileOwnedByUserB(t *testing.T) {
	// Scenario: run by user A (uid=1000, gid=1000), file owned by user B (uid=2000, gid=2000)
	err := checkPerms("/etc/spk/spk_server.toml", 2000, 2000, 1000, 1000, fs.FileMode(0600))
	if err == nil {
		t.Error("expected error: file uid 2000 != process uid 1000")
	}
	if err != nil && err.Reason == "" {
		t.Error("error reason should not be empty")
	}
}

// TestCheckPerms_UserA_FileOwnedByUserC_GroupD: mixed uid and gid mismatch.
func TestCheckPerms_UserA_FileOwnedByUserC_GroupD(t *testing.T) {
	// Scenario: run by user A (uid=1000, gid=1000), file owned by user C (uid=3000), group D (gid=4000)
	err := checkPerms("/etc/spk/server.key", 3000, 4000, 1000, 1000, fs.FileMode(0600))
	if err == nil {
		t.Error("expected error: file uid 3000 != process uid 1000")
	}
}

// TestCheckPerms_UserA_FileOwnedByUserA_Perm0600: correct owner and max perm.
func TestCheckPerms_UserA_FileOwnedByUserA_Perm0600(t *testing.T) {
	// Scenario: run by user A (uid=1000, gid=1000), file owned by user A. perm 0600.
	err := checkPerms("/etc/spk/spk_server.toml", 1000, 1000, 1000, 1000, fs.FileMode(0600))
	if err != nil {
		t.Errorf("expected nil for correct owner + perm 0600, got: %v", err)
	}
}

// TestCheckPerms_UserA_FileOwnedByUserA_Perm0640: correct owner but group read.
func TestCheckPerms_UserA_FileOwnedByUserA_Perm0640(t *testing.T) {
	// Scenario: run by user A (uid=1000, gid=1000), file owned by user A. perm 0640. Fail.
	err := checkPerms("/etc/spk/spk_server.toml", 1000, 1000, 1000, 1000, fs.FileMode(0640))
	if err == nil {
		t.Error("expected error for perm 0640")
	}
}

// TestCheckPerms_UserA_FileOwnedByUserA_Perm0644: correct owner but world read.
func TestCheckPerms_UserA_FileOwnedByUserA_Perm0644(t *testing.T) {
	err := checkPerms("/etc/spk/spk_server.toml", 1000, 1000, 1000, 1000, fs.FileMode(0644))
	if err == nil {
		t.Error("expected error for perm 0644")
	}
}

// TestCheckPerms_UserA_FileOwnedByUserA_Perm0777: correct owner but world rwx.
func TestCheckPerms_UserA_FileOwnedByUserA_Perm0777(t *testing.T) {
	err := checkPerms("/etc/spk/spk_server.toml", 1000, 1000, 1000, 1000, fs.FileMode(0777))
	if err == nil {
		t.Error("expected error for perm 0777")
	}
}

// TestCheckPerms_Root_FileOwnedByRoot_Perm0600: root running, root-owned file, 0600.
func TestCheckPerms_Root_FileOwnedByRoot_Perm0600(t *testing.T) {
	err := checkPerms("/etc/spk/spk_server.toml", 0, 0, 0, 0, fs.FileMode(0600))
	if err != nil {
		t.Errorf("expected nil for root-owned 0600 file, got: %v", err)
	}
}

// TestCheckPerms_Root_FileOwnedByNonRoot: root running, file owned by uid=1000.
func TestCheckPerms_Root_FileOwnedByNonRoot(t *testing.T) {
	err := checkPerms("/etc/spk/spk_server.toml", 1000, 0, 0, 0, fs.FileMode(0600))
	if err == nil {
		t.Error("expected error: file uid 1000 != process uid 0 (root)")
	}
}

// TestCheckPerms_NonRoot_FileOwnedByRoot: non-root running, root-owned file.
func TestCheckPerms_NonRoot_FileOwnedByRoot(t *testing.T) {
	err := checkPerms("/etc/spk/spk_server.toml", 0, 0, 1000, 1000, fs.FileMode(0600))
	if err == nil {
		t.Error("expected error: file uid 0 (root) != process uid 1000")
	}
}

// TestCheckPerms_SameUID_WrongGID_GoodPerm: uid matches but gid differs.
func TestCheckPerms_SameUID_WrongGID_GoodPerm(t *testing.T) {
	// file owned by uid=500, gid=999; process uid=500, gid=500
	err := checkPerms("/fake/path", 500, 999, 500, 500, fs.FileMode(0600))
	if err == nil {
		t.Error("expected error: file gid 999 != process gid 500")
	}
	if err != nil {
		// Should mention gid
		want := "owner gid 999 does not match process gid 500"
		if err.Reason != want {
			t.Errorf("Reason = %q, want %q", err.Reason, want)
		}
	}
}

// TestCheckPerms_SameUID_SameGID_BadPerm: owner matches but permission too broad.
func TestCheckPerms_SameUID_SameGID_BadPerm(t *testing.T) {
	err := checkPerms("/fake/path", 500, 500, 500, 500, fs.FileMode(0660))
	if err == nil {
		t.Error("expected error: perm 0660 too permissive")
	}
}

// =============================================================================
// FilePermError type tests
// =============================================================================

// TestFilePermError_Error verifies the Error() string format.
func TestFilePermError_Error(t *testing.T) {
	e := &FilePermError{Path: "/etc/spk/server.key", Reason: "permission 0644 too permissive (max 0600)"}
	got := e.Error()
	if got != "/etc/spk/server.key: permission 0644 too permissive (max 0600)" {
		t.Errorf("Error() = %q", got)
	}
}
