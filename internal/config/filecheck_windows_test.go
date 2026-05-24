// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

//go:build windows

package config

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

// ---------------------------------------------------------------------------
// Integration tests -- require actual Windows file system
// ---------------------------------------------------------------------------

// TestCheckSensitiveFile_Windows_NotExist verifies that a non-existent file
// returns nil (optional files such as state.json may be absent).
func TestCheckSensitiveFile_Windows_NotExist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nonexistent.toml")
	if err := CheckSensitiveFile(path); err != nil {
		t.Errorf("expected nil for non-existent file, got: %v", err)
	}
}

// TestCheckSensitiveFile_Windows_CurrentUser verifies that a file with
// owner-only permissions (no ACE for Anyone, Authenticated Users, or
// BUILTIN\Users) passes the check.  Inherited ACEs are stripped and the DACL
// is rebuilt with only the current user holding full control.
func TestCheckSensitiveFile_Windows_CurrentUser(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.toml")
	if err := os.WriteFile(path, []byte("key = \"val\""), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Strip all inherited ACEs and grant only the current user full control.
	// This mirrors the permission model that CheckSensitiveFile enforces and
	// avoids test flakiness on systems where temp directories have inherited
	// BUILTIN\Users read ACEs.
	username := currentWindowsUsername(t)
	if err := exec.Command("icacls", path,
		"/inheritance:r",
		"/grant:r", username+":(F)").Run(); err != nil {
		t.Skipf("icacls failed to set owner-only permissions: %v", err)
	}
	if err := CheckSensitiveFile(path); err != nil {
		t.Errorf("expected nil for owner-only permissions, got: %v", err)
	}
}

// TestCheckSensitiveFile_Windows_EveryoneWrite verifies that granting
// Everyone write access causes the check to fail.
func TestCheckSensitiveFile_Windows_EveryoneWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.toml")
	if err := os.WriteFile(path, []byte("key = \"val\""), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := exec.Command("icacls", path, "/grant", "Everyone:(W)").Run(); err != nil {
		t.Skipf("icacls write grant failed: %v", err)
	}
	if err := CheckSensitiveFile(path); err == nil {
		t.Error("expected error for Everyone Write ACE, got nil")
	}
}

// TestCheckSensitiveFile_Windows_EveryoneReadOnly verifies that granting
// Everyone read-only access DOES cause a failure.  A read ACE for Everyone on
// a private key file is equivalent to a world-readable file on Linux (mode
// 0644), which fails the 0600 check.  Any local account could read the key.
func TestCheckSensitiveFile_Windows_EveryoneReadOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.toml")
	if err := os.WriteFile(path, []byte("key = \"val\""), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	username := currentWindowsUsername(t)
	// Strip inherited ACEs, grant owner full control, and grant Everyone
	// read-only -- all in one icacls call so the file never enters a state
	// where the owner has no access (which would block temp-dir cleanup).
	if err := exec.Command("icacls", path,
		"/inheritance:r",
		"/grant:r", username+":(F)",
		"/grant:r", "Everyone:(R)").Run(); err != nil {
		t.Skipf("icacls read grant failed: %v", err)
	}
	// Safety net: restore inheritable permissions so temp-dir cleanup succeeds.
	t.Cleanup(func() { exec.Command("icacls", path, "/reset").Run() })
	if err := CheckSensitiveFile(path); err == nil {
		t.Error("expected error for Everyone Read-Only ACE, got nil")
	}
}

// TestCheckSensitiveFile_Windows_UsersReadOnly verifies that granting
// BUILTIN\Users read-only access DOES cause a failure.  This is the common
// inherited-read scenario when config files are stored on a drive whose root
// folder grants BUILTIN\Users Read by default (e.g. D:\).
func TestCheckSensitiveFile_Windows_UsersReadOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.toml")
	if err := os.WriteFile(path, []byte("key = \"val\""), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	username := currentWindowsUsername(t)
	if err := exec.Command("icacls", path,
		"/inheritance:r",
		"/grant:r", username+":(F)",
		"/grant:r", "BUILTIN\\Users:(R)").Run(); err != nil {
		t.Skipf("icacls read grant failed: %v", err)
	}
	t.Cleanup(func() { exec.Command("icacls", path, "/reset").Run() })
	if err := CheckSensitiveFile(path); err == nil {
		t.Error("expected error for BUILTIN\\Users Read-Only ACE, got nil")
	}
}

// TestCheckSensitiveFile_Windows_AuthenticatedUsersReadOnly verifies that
// granting Authenticated Users read-only access DOES cause a failure.
// Uses the well-known SID *S-1-5-11 to avoid localized account-name issues
// (error 1332) on non-English Windows installations.
func TestCheckSensitiveFile_Windows_AuthenticatedUsersReadOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.toml")
	if err := os.WriteFile(path, []byte("key = \"val\""), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	username := currentWindowsUsername(t)
	// *S-1-5-11 is the well-known SID for Authenticated Users; using the SID
	// directly avoids locale-specific name resolution failures (icacls 1332).
	if err := exec.Command("icacls", path,
		"/inheritance:r",
		"/grant:r", username+":(F)",
		"/grant:r", "*S-1-5-11:(R)").Run(); err != nil {
		t.Skipf("icacls read grant failed: %v", err)
	}
	t.Cleanup(func() { exec.Command("icacls", path, "/reset").Run() })
	if err := CheckSensitiveFile(path); err == nil {
		t.Error("expected error for Authenticated Users Read-Only ACE, got nil")
	}
}

// TestCheckSensitiveFile_Windows_OwnerOnly verifies that a file restricted
// strictly to the current user (no other ACEs) passes the check.
func TestCheckSensitiveFile_Windows_OwnerOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.toml")
	if err := os.WriteFile(path, []byte("key = \"val\""), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	username := currentWindowsUsername(t)
	if err := exec.Command("icacls", path,
		"/inheritance:r",
		"/grant:r", username+":(F)").Run(); err != nil {
		t.Skipf("icacls owner-only grant failed: %v", err)
	}
	t.Cleanup(func() { exec.Command("icacls", path, "/reset").Run() })
	if err := CheckSensitiveFile(path); err != nil {
		t.Errorf("expected nil for owner-only DACL, got: %v", err)
	}
}

// TestCheckSensitiveFile_Windows_AuthenticatedUsersWrite verifies that
// granting Authenticated Users write access causes the check to fail.
func TestCheckSensitiveFile_Windows_AuthenticatedUsersWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.toml")
	if err := os.WriteFile(path, []byte("key = \"val\""), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := exec.Command("icacls", path,
		"/grant", "\"Authenticated Users\":(W)").Run(); err != nil {
		t.Skipf("icacls write grant failed: %v", err)
	}
	if err := CheckSensitiveFile(path); err == nil {
		t.Error("expected error for Authenticated Users Write ACE, got nil")
	}
}

// TestCheckSensitiveFile_Windows_UsersWriteInherited tests a scenario that
// mirrors a writable shared directory (e.g. a misconfigured D:\ where Users
// has Modify or higher): the check must reject the file.
func TestCheckSensitiveFile_Windows_UsersWriteInherited(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.toml")
	if err := os.WriteFile(path, []byte("key = \"val\""), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := exec.Command("icacls", path,
		"/grant", "BUILTIN\\Users:(M)").Run(); err != nil {
		t.Skipf("icacls modify grant failed: %v", err)
	}
	if err := CheckSensitiveFile(path); err == nil {
		t.Error("expected error for BUILTIN\\Users Modify ACE, got nil")
	}
}

// ---------------------------------------------------------------------------
// checkWindowsOwnerSIDs unit tests
// ---------------------------------------------------------------------------

// TestCheckWindowsOwnerSIDs_CurrentUser verifies that the current process
// user is always accepted as owner.
func TestCheckWindowsOwnerSIDs_CurrentUser(t *testing.T) {
	tok := windows.GetCurrentProcessToken()
	tu, err := tok.GetTokenUser()
	if err != nil {
		t.Skip("GetTokenUser:", err)
	}
	if e := checkWindowsOwnerSIDs("fake", tu.User.Sid, tu.User.Sid); e != nil {
		t.Errorf("expected nil for current user as owner, got: %v", e)
	}
}

// TestCheckWindowsOwnerSIDs_SystemOwner verifies that NT AUTHORITY\SYSTEM is
// accepted as a trusted file owner regardless of the current process SID.
func TestCheckWindowsOwnerSIDs_SystemOwner(t *testing.T) {
	systemSID := mustWellKnownSID(t, windows.WinLocalSystemSid)
	tok := windows.GetCurrentProcessToken()
	tu, err := tok.GetTokenUser()
	if err != nil {
		t.Skip("GetTokenUser:", err)
	}
	if e := checkWindowsOwnerSIDs("fake", systemSID, tu.User.Sid); e != nil {
		t.Errorf("expected nil for SYSTEM owner, got: %v", e)
	}
}

// TestCheckWindowsOwnerSIDs_LocalServiceOwner verifies that NT
// AUTHORITY\LocalService is accepted as a trusted owner.
func TestCheckWindowsOwnerSIDs_LocalServiceOwner(t *testing.T) {
	lsSID := mustWellKnownSID(t, windows.WinLocalServiceSid)
	tok := windows.GetCurrentProcessToken()
	tu, err := tok.GetTokenUser()
	if err != nil {
		t.Skip("GetTokenUser:", err)
	}
	if e := checkWindowsOwnerSIDs("fake", lsSID, tu.User.Sid); e != nil {
		t.Errorf("expected nil for LocalService owner, got: %v", e)
	}
}

// TestCheckWindowsOwnerSIDs_NetworkServiceOwner verifies that NT
// AUTHORITY\NetworkService is accepted as a trusted owner.
func TestCheckWindowsOwnerSIDs_NetworkServiceOwner(t *testing.T) {
	nsSID := mustWellKnownSID(t, windows.WinNetworkServiceSid)
	tok := windows.GetCurrentProcessToken()
	tu, err := tok.GetTokenUser()
	if err != nil {
		t.Skip("GetTokenUser:", err)
	}
	if e := checkWindowsOwnerSIDs("fake", nsSID, tu.User.Sid); e != nil {
		t.Errorf("expected nil for NetworkService owner, got: %v", e)
	}
}

// TestCheckWindowsOwnerSIDs_AdministratorsOwner verifies that
// BUILTIN\Administrators is accepted as a trusted owner.
func TestCheckWindowsOwnerSIDs_AdministratorsOwner(t *testing.T) {
	adminsSID := mustWellKnownSID(t, windows.WinBuiltinAdministratorsSid)
	tok := windows.GetCurrentProcessToken()
	tu, err := tok.GetTokenUser()
	if err != nil {
		t.Skip("GetTokenUser:", err)
	}
	if e := checkWindowsOwnerSIDs("fake", adminsSID, tu.User.Sid); e != nil {
		t.Errorf("expected nil for Administrators owner, got: %v", e)
	}
}

// TestCheckWindowsOwnerSIDs_UntrustedOwner_RegularUser verifies that a file
// owned by an untrusted SID (e.g. Everyone) is rejected when the process is
// running as a regular user (not a service account).
func TestCheckWindowsOwnerSIDs_UntrustedOwner_RegularUser(t *testing.T) {
	tok := windows.GetCurrentProcessToken()
	tu, err := tok.GetTokenUser()
	if err != nil {
		t.Skip("GetTokenUser:", err)
	}
	currentSID := tu.User.Sid

	// Skip this test if the current user IS a service account; in that case
	// the owner check is intentionally skipped.
	for _, wk := range []windows.WELL_KNOWN_SID_TYPE{
		windows.WinLocalSystemSid,
		windows.WinLocalServiceSid,
		windows.WinNetworkServiceSid,
	} {
		if currentSID.IsWellKnown(wk) {
			t.Skipf("test process is a service account (%s); owner check is skipped by design", currentSID.String())
		}
	}

	everyoneSID := mustWellKnownSID(t, windows.WinWorldSid)
	if e := checkWindowsOwnerSIDs("fake", everyoneSID, currentSID); e == nil {
		t.Error("expected error for Everyone as file owner, got nil")
	}
}

// TestCheckWindowsOwnerSIDs_ServiceProcess_SkipsOwnerCheck verifies that
// when the process is running as a service account (SYSTEM simulated), the
// owner check is skipped even if the file is owned by an unrecognised SID.
// This models the case where an admin installs SPK, creates config files
// (owned by the admin's SID), and the service runs as LocalSystem.
func TestCheckWindowsOwnerSIDs_ServiceProcess_SkipsOwnerCheck(t *testing.T) {
	systemSID := mustWellKnownSID(t, windows.WinLocalSystemSid)
	// Use the Users group SID as a stand-in for "some admin's personal SID
	// that is not SYSTEM, LocalService, NetworkService, or Administrators
	// group".  In a real deployment this would be e.g. S-1-5-21-...-1001.
	ownerSID := mustWellKnownSID(t, windows.WinBuiltinUsersSid)

	if e := checkWindowsOwnerSIDs("fake", ownerSID, systemSID); e != nil {
		t.Errorf("expected nil for service account process (owner check skipped), got: %v", e)
	}
}

// ---------------------------------------------------------------------------
// checkWindowsDACL unit tests
// ---------------------------------------------------------------------------

// TestCheckWindowsDACL_Nil verifies that a nil DACL (NULL DACL = unrestricted
// access) is always rejected.
func TestCheckWindowsDACL_Nil(t *testing.T) {
	if e := checkWindowsDACL("fake", nil); e == nil {
		t.Error("expected error for nil DACL, got nil")
	}
}

// TestCheckWindowsDACL_EveryoneWriteAccess verifies that an Allow ACE for
// Everyone with write access is rejected.
func TestCheckWindowsDACL_EveryoneWriteAccess(t *testing.T) {
	dacl := buildSingleAllowDACL(t, windows.WinWorldSid, windows.GENERIC_WRITE)
	if e := checkWindowsDACL("fake", dacl); e == nil {
		t.Error("expected error for Everyone GENERIC_WRITE ACE, got nil")
	}
}

// TestCheckWindowsDACL_EveryoneFullControl verifies that an Allow ACE for
// Everyone with full control is rejected.
func TestCheckWindowsDACL_EveryoneFullControl(t *testing.T) {
	dacl := buildSingleAllowDACL(t, windows.WinWorldSid, windows.GENERIC_ALL)
	if e := checkWindowsDACL("fake", dacl); e == nil {
		t.Error("expected error for Everyone GENERIC_ALL ACE, got nil")
	}
}

// TestCheckWindowsDACL_EveryoneReadOnly verifies that a read-only Allow ACE
// for Everyone DOES trigger an error.  A world-readable private key file is
// the Windows equivalent of Linux mode 0644, violating the 0600 requirement.
func TestCheckWindowsDACL_EveryoneReadOnly(t *testing.T) {
	dacl := buildSingleAllowDACL(t, windows.WinWorldSid, windows.GENERIC_READ)
	if e := checkWindowsDACL("fake", dacl); e == nil {
		t.Error("expected error for Everyone GENERIC_READ ACE, got nil")
	}
}

// TestCheckWindowsDACL_EveryoneFileReadData verifies that a FILE_READ_DATA
// Allow ACE for Everyone is rejected (explicit read of file contents).
func TestCheckWindowsDACL_EveryoneFileReadData(t *testing.T) {
	dacl := buildSingleAllowDACL(t, windows.WinWorldSid, windows.FILE_READ_DATA)
	if e := checkWindowsDACL("fake", dacl); e == nil {
		t.Error("expected error for Everyone FILE_READ_DATA ACE, got nil")
	}
}

// TestCheckWindowsDACL_AuthenticatedUsersWrite verifies that an Allow ACE
// for Authenticated Users with write access is rejected.
func TestCheckWindowsDACL_AuthenticatedUsersWrite(t *testing.T) {
	dacl := buildSingleAllowDACL(t, windows.WinAuthenticatedUserSid, windows.GENERIC_WRITE)
	if e := checkWindowsDACL("fake", dacl); e == nil {
		t.Error("expected error for Authenticated Users GENERIC_WRITE ACE, got nil")
	}
}

// TestCheckWindowsDACL_AuthenticatedUsersReadOnly verifies that a read-only
// Allow ACE for Authenticated Users DOES trigger an error.
func TestCheckWindowsDACL_AuthenticatedUsersReadOnly(t *testing.T) {
	dacl := buildSingleAllowDACL(t, windows.WinAuthenticatedUserSid, windows.GENERIC_READ)
	if e := checkWindowsDACL("fake", dacl); e == nil {
		t.Error("expected error for Authenticated Users GENERIC_READ ACE, got nil")
	}
}

// TestCheckWindowsDACL_AuthenticatedUsersFileReadData verifies that a
// FILE_READ_DATA Allow ACE for Authenticated Users is rejected.
func TestCheckWindowsDACL_AuthenticatedUsersFileReadData(t *testing.T) {
	dacl := buildSingleAllowDACL(t, windows.WinAuthenticatedUserSid, windows.FILE_READ_DATA)
	if e := checkWindowsDACL("fake", dacl); e == nil {
		t.Error("expected error for Authenticated Users FILE_READ_DATA ACE, got nil")
	}
}

// TestCheckWindowsDACL_UsersWrite verifies that an Allow ACE for
// BUILTIN\Users with write access is rejected.
func TestCheckWindowsDACL_UsersWrite(t *testing.T) {
	dacl := buildSingleAllowDACL(t, windows.WinBuiltinUsersSid, windows.GENERIC_WRITE)
	if e := checkWindowsDACL("fake", dacl); e == nil {
		t.Error("expected error for BUILTIN\\Users GENERIC_WRITE ACE, got nil")
	}
}

// TestCheckWindowsDACL_UsersReadOnly verifies that a read-only Allow ACE for
// BUILTIN\Users DOES trigger an error.  D:\ commonly grants BUILTIN\Users
// inherited Read, which would expose private key material to all local users.
func TestCheckWindowsDACL_UsersReadOnly(t *testing.T) {
	dacl := buildSingleAllowDACL(t, windows.WinBuiltinUsersSid, windows.GENERIC_READ)
	if e := checkWindowsDACL("fake", dacl); e == nil {
		t.Error("expected error for BUILTIN\\Users GENERIC_READ ACE, got nil")
	}
}

// TestCheckWindowsDACL_UsersFileReadData verifies that a FILE_READ_DATA Allow
// ACE for BUILTIN\Users is rejected.
func TestCheckWindowsDACL_UsersFileReadData(t *testing.T) {
	dacl := buildSingleAllowDACL(t, windows.WinBuiltinUsersSid, windows.FILE_READ_DATA)
	if e := checkWindowsDACL("fake", dacl); e == nil {
		t.Error("expected error for BUILTIN\\Users FILE_READ_DATA ACE, got nil")
	}
}

// TestCheckWindowsDACL_SystemReadOnly verifies that SYSTEM retains read access
// (SYSTEM is a trusted identity, not a low-privilege account).
func TestCheckWindowsDACL_SystemReadOnly(t *testing.T) {
	dacl := buildSingleAllowDACL(t, windows.WinLocalSystemSid, windows.GENERIC_READ)
	if e := checkWindowsDACL("fake", dacl); e != nil {
		t.Errorf("expected nil for SYSTEM GENERIC_READ ACE, got: %v", e)
	}
}

// TestCheckWindowsDACL_AdminsReadOnly verifies that BUILTIN\Administrators
// retains read access (Administrators are trusted).
func TestCheckWindowsDACL_AdminsReadOnly(t *testing.T) {
	dacl := buildSingleAllowDACL(t, windows.WinBuiltinAdministratorsSid, windows.GENERIC_READ)
	if e := checkWindowsDACL("fake", dacl); e != nil {
		t.Errorf("expected nil for Administrators GENERIC_READ ACE, got: %v", e)
	}
}

// TestCheckWindowsDACL_SystemFullControl verifies that a full-control Allow
// ACE for NT AUTHORITY\SYSTEM does not cause a failure.
func TestCheckWindowsDACL_SystemFullControl(t *testing.T) {
	dacl := buildSingleAllowDACL(t, windows.WinLocalSystemSid, windows.GENERIC_ALL)
	if e := checkWindowsDACL("fake", dacl); e != nil {
		t.Errorf("expected nil for SYSTEM GENERIC_ALL ACE, got: %v", e)
	}
}

// TestCheckWindowsDACL_AdminsFullControl verifies that a full-control Allow
// ACE for BUILTIN\Administrators does not cause a failure.
func TestCheckWindowsDACL_AdminsFullControl(t *testing.T) {
	dacl := buildSingleAllowDACL(t, windows.WinBuiltinAdministratorsSid, windows.GENERIC_ALL)
	if e := checkWindowsDACL("fake", dacl); e != nil {
		t.Errorf("expected nil for Administrators GENERIC_ALL ACE, got: %v", e)
	}
}

// ---------------------------------------------------------------------------
// Misc / error formatting
// ---------------------------------------------------------------------------

// TestFilePermError_Error_Windows verifies that FilePermError.Error() formats
// the path and reason correctly.
func TestFilePermError_Error_Windows(t *testing.T) {
	e := &FilePermError{Path: `C:\foo\bar.toml`, Reason: "bad owner"}
	want := `C:\foo\bar.toml: bad owner`
	if got := e.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

// TestCheckSensitiveFiles_Windows_Empty verifies that an empty input returns
// nil.
func TestCheckSensitiveFiles_Windows_Empty(t *testing.T) {
	if errs := CheckSensitiveFiles(); errs != nil {
		t.Errorf("expected nil, got: %v", errs)
	}
}

// TestCheckSensitiveFiles_Windows_MultipleNonExistent verifies that all
// non-existent paths are silently skipped.
func TestCheckSensitiveFiles_Windows_MultipleNonExistent(t *testing.T) {
	dir := t.TempDir()
	errs := CheckSensitiveFiles(
		filepath.Join(dir, "a.toml"),
		filepath.Join(dir, "b.key"),
		filepath.Join(dir, "c.json"),
	)
	if len(errs) != 0 {
		t.Errorf("expected no errors for non-existent files, got: %v", errs)
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// mustWellKnownSID creates a well-known SID or skips the test if unavailable.
func mustWellKnownSID(t *testing.T, sidType windows.WELL_KNOWN_SID_TYPE) *windows.SID {
	t.Helper()
	sid, err := windows.CreateWellKnownSid(sidType)
	if err != nil {
		t.Skipf("CreateWellKnownSid(%d): %v", sidType, err)
	}
	return sid
}

// buildSingleAllowDACL creates an ACL with a single Allow ACE for the given
// well-known SID type and access mask.  Used to construct controlled DACL
// inputs for unit tests without touching the file system.
func buildSingleAllowDACL(t *testing.T, sidType windows.WELL_KNOWN_SID_TYPE, mask windows.ACCESS_MASK) *windows.ACL {
	t.Helper()
	sid := mustWellKnownSID(t, sidType)
	ea := []windows.EXPLICIT_ACCESS{
		{
			AccessPermissions: mask,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.NO_INHERITANCE,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
				TrusteeValue: windows.TrusteeValueFromSID(sid),
			},
		},
	}
	acl, err := windows.ACLFromEntries(ea, nil)
	if err != nil {
		t.Skipf("ACLFromEntries: %v", err)
	}
	return acl
}

// currentWindowsUsername returns the current user's display name for icacls.
func currentWindowsUsername(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("whoami").Output()
	if err != nil {
		t.Skipf("whoami: %v", err)
	}
	// whoami returns "DOMAIN\user" or "host\user"; trim trailing newline.
	name := string(out)
	for len(name) > 0 && (name[len(name)-1] == '\n' || name[len(name)-1] == '\r') {
		name = name[:len(name)-1]
	}
	return name
}
