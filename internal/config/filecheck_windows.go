// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

//go:build windows

package config

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// FilePermError describes a file that failed the permission/ownership check.
type FilePermError struct {
	Path   string
	Reason string
}

func (e *FilePermError) Error() string {
	return e.Path + ": " + e.Reason
}

// anyWriteMask is the set of Windows Access Mask bits that confer the ability
// to modify or delete a file's contents, attributes, or security descriptor.
const anyWriteMask = windows.ACCESS_MASK(
	windows.FILE_WRITE_DATA |
		windows.FILE_APPEND_DATA |
		windows.FILE_WRITE_EA |
		windows.FILE_WRITE_ATTRIBUTES |
		windows.DELETE |
		windows.WRITE_DAC |
		windows.WRITE_OWNER |
		windows.GENERIC_WRITE |
		windows.GENERIC_ALL,
)

// anyReadMask is the set of Windows Access Mask bits that allow reading file
// contents or extended attributes.  On Linux the equivalent is the group-read
// and other-read bits that are absent in a 0600 permission mode.  Granting
// these bits to a low-privilege account (Everyone, Authenticated Users, or
// BUILTIN\Users) on a private key or server config file is a security
// violation: an attacker who compromises any local account can exfiltrate
// the key material.
//
// Industry reference:
//   - Win32-OpenSSH refuses to load a private key if any SID outside the
//     owner, SYSTEM, and Administrators has read access.
//   - Cygwin maps Unix 0600 to a Windows DACL containing only the owner
//     and SYSTEM; the BUILTIN\Users group receives no ACE at all.
//
// Note: FILE_READ_ATTRIBUTES (metadata: size, timestamps) is intentionally
// excluded because it does not expose file contents and is used by many
// system-level tools for directory enumeration.  The goal here is to prevent
// private key material from being read, not to hide file existence.
const anyReadMask = windows.ACCESS_MASK(
	windows.FILE_READ_DATA | // read file bytes
		windows.FILE_READ_EA | // read extended attributes
		windows.GENERIC_READ, // generic read (includes FILE_READ_DATA + FILE_READ_EA)
)

// dangerousAccessMask is the union of anyReadMask and anyWriteMask.  An Allow
// ACE for a low-privilege account that includes any of these bits is treated
// as a security violation.
const dangerousAccessMask = anyReadMask | anyWriteMask

// checkWindowsOwnerSIDs is the testable core of the owner check.
// It returns a non-nil error when the file owner is untrusted.
//
// Trusted owners:
//   - currentSID (the current process user, always trusted)
//   - NT AUTHORITY\SYSTEM (WinLocalSystemSid)
//   - NT AUTHORITY\LocalService (WinLocalServiceSid)
//   - NT AUTHORITY\NetworkService (WinNetworkServiceSid)
//   - BUILTIN\Administrators (WinBuiltinAdministratorsSid)
//
// When the current process itself is a service account (SYSTEM, LocalService,
// NetworkService), the owner check is skipped entirely.  Service processes
// regularly access config files created by an administrator during setup, whose
// individual user SID will not match the service SID.  DACL write-protection
// is the primary security control in that scenario.
func checkWindowsOwnerSIDs(path string, ownerSID, currentSID *windows.SID) *FilePermError {
	// File owned by the current process user.
	if windows.EqualSid(ownerSID, currentSID) {
		return nil
	}

	// File owned by a well-known trusted service or admin identity.
	trustedOwnerSIDs := []windows.WELL_KNOWN_SID_TYPE{
		windows.WinLocalSystemSid,           // NT AUTHORITY\SYSTEM
		windows.WinLocalServiceSid,          // NT AUTHORITY\LocalService
		windows.WinNetworkServiceSid,        // NT AUTHORITY\NetworkService
		windows.WinBuiltinAdministratorsSid, // BUILTIN\Administrators
	}
	for _, wk := range trustedOwnerSIDs {
		if ownerSID.IsWellKnown(wk) {
			return nil
		}
	}

	// When the running process is itself a service account, skip the ownership
	// check.  Admin-created setup files are owned by the admin's personal SID
	// rather than the service account SID, and that is expected and correct.
	serviceAccountSIDs := []windows.WELL_KNOWN_SID_TYPE{
		windows.WinLocalSystemSid,    // NT AUTHORITY\SYSTEM
		windows.WinLocalServiceSid,   // NT AUTHORITY\LocalService
		windows.WinNetworkServiceSid, // NT AUTHORITY\NetworkService
	}
	for _, wk := range serviceAccountSIDs {
		if currentSID.IsWellKnown(wk) {
			return nil
		}
	}

	return &FilePermError{
		Path:   path,
		Reason: fmt.Sprintf("owner SID %s is not the current user, SYSTEM, or Administrators", ownerSID.String()),
	}
}

// checkWindowsOwner reads the current process token and delegates to
// checkWindowsOwnerSIDs.  Returns nil if the token cannot be inspected
// (fail-open on token errors rather than blocking startup).
func checkWindowsOwner(path string, ownerSID *windows.SID) *FilePermError {
	tok := windows.GetCurrentProcessToken()
	tu, err := tok.GetTokenUser()
	if err != nil {
		return nil // cannot determine current user; skip rather than block
	}
	return checkWindowsOwnerSIDs(path, ownerSID, tu.User.Sid)
}

// checkWindowsDACL scans dacl for Allow ACEs that grant read or write access
// to low-privilege well-known accounts.  The accounts checked are:
//
//   - Everyone (S-1-1-0)
//   - Authenticated Users (S-1-5-11)
//   - BUILTIN\Users (S-1-5-32-545)
//
// Both read access (FILE_READ_DATA, FILE_READ_EA, GENERIC_READ) and write/
// modification access are rejected.  A read-only ACE from a parent directory
// (e.g. an inherited BUILTIN\Users Read ACE from D:\) is still rejected
// because a local attacker who is a member of that group can read private
// key material directly.  This policy mirrors Win32-OpenSSH and Cygwin, which
// require that private key files are accessible only by the owner, SYSTEM,
// and Administrators.
//
// A nil DACL (NULL DACL) is always rejected because it grants unrestricted
// access to every user on the system.
func checkWindowsDACL(path string, dacl *windows.ACL) *FilePermError {
	if dacl == nil {
		return &FilePermError{
			Path:   path,
			Reason: "NULL DACL grants unrestricted access to all users",
		}
	}

	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue // ignore Deny and Audit ACEs
		}

		aceSID := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		isDangerous := aceSID.IsWellKnown(windows.WinWorldSid) ||
			aceSID.IsWellKnown(windows.WinAuthenticatedUserSid) ||
			aceSID.IsWellKnown(windows.WinBuiltinUsersSid)

		if isDangerous && ace.Mask&dangerousAccessMask != 0 {
			return &FilePermError{
				Path:   path,
				Reason: fmt.Sprintf("DACL grants read or write access to low-privilege SID %s", aceSID.String()),
			}
		}
	}
	return nil
}

// CheckSensitiveFile validates that the file at path has a secure Windows
// security descriptor.
//
// Owner check: the file owner must be the current process user, NT
// AUTHORITY\SYSTEM, NT AUTHORITY\LocalService, NT AUTHORITY\NetworkService, or
// BUILTIN\Administrators.  When the process itself is a service account
// (SYSTEM, LocalService, NetworkService), the owner check is relaxed: service
// processes use config files created by an administrator during setup, and
// those files are owned by the admin's individual SID.
//
// DACL check: no Allow ACE for Everyone, Authenticated Users, or
// BUILTIN\Users may include read access (FILE_READ_DATA, FILE_READ_EA,
// GENERIC_READ) or write/modification access.  Inherited read ACEs from a
// parent directory (e.g. D:\bob\ where BUILTIN\Users has Read) are rejected
// because any local account in that group can exfiltrate private key material.
// A NULL DACL is always rejected.
//
// This policy matches Win32-OpenSSH and Cygwin: private keys must be
// accessible only by the file owner, SYSTEM, and Administrators.
//
// Returns nil when the file does not exist; non-existence is not an error
// because optional files (state.json) may be absent.
func CheckSensitiveFile(path string) *FilePermError {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return &FilePermError{Path: path, Reason: fmt.Sprintf("stat: %v", err)}
	}

	sd, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return &FilePermError{Path: path, Reason: fmt.Sprintf("GetNamedSecurityInfo: %v", err)}
	}

	ownerSID, _, err := sd.Owner()
	if err != nil {
		return &FilePermError{Path: path, Reason: fmt.Sprintf("get owner SID: %v", err)}
	}
	if e := checkWindowsOwner(path, ownerSID); e != nil {
		return e
	}

	dacl, _, err := sd.DACL()
	if err != nil {
		return &FilePermError{Path: path, Reason: fmt.Sprintf("get DACL: %v", err)}
	}
	return checkWindowsDACL(path, dacl)
}

// CheckSensitiveFiles checks all provided paths and collects all errors.
// Non-existent files are silently skipped (see CheckSensitiveFile).
func CheckSensitiveFiles(paths ...string) []*FilePermError {
	var errs []*FilePermError
	for _, p := range paths {
		if e := CheckSensitiveFile(p); e != nil {
			errs = append(errs, e)
		}
	}
	return errs
}
