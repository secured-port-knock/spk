// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

//go:build linux || darwin

package config

import (
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

// FilePermError describes a file that failed the permission/ownership check.
type FilePermError struct {
	Path   string
	Reason string
}

func (e *FilePermError) Error() string {
	return e.Path + ": " + e.Reason
}

// checkPerms validates that the file's owner UID, owner GID, and permission
// bits are acceptable for a sensitive SPK file.
//
// Rules:
//   - fileUID must equal procUID (file owned by the running process user)
//   - fileGID must equal procGID (file group matches the running process group)
//   - mode permission bits must have no group or other bits set, and no
//     execute bit set for owner (max allowed is 0600)
//
// path is used only in the returned error message.
func checkPerms(path string, fileUID, fileGID, procUID, procGID uint32, mode fs.FileMode) *FilePermError {
	if fileUID != procUID {
		return &FilePermError{
			Path:   path,
			Reason: fmt.Sprintf("owner uid %d does not match process uid %d", fileUID, procUID),
		}
	}
	if fileGID != procGID {
		return &FilePermError{
			Path:   path,
			Reason: fmt.Sprintf("owner gid %d does not match process gid %d", fileGID, procGID),
		}
	}
	// 0177 covers: owner-execute (0100) + group-rwx (0070) + other-rwx (0007)
	if mode.Perm()&fs.FileMode(0177) != 0 {
		return &FilePermError{
			Path:   path,
			Reason: fmt.Sprintf("permission %04o too permissive (max 0600)", mode.Perm()),
		}
	}
	return nil
}

// CheckSensitiveFile validates that path is:
//   - owned by the effective UID of the running process
//   - owned by the effective GID of the running process
//   - has permission bits no more than 0600
//
// Returns nil when the file does not exist (caller decides if that is an error).
// Returns nil when stat succeeds but the OS does not provide a syscall.Stat_t
// (should not happen on Linux/macOS but handled defensively).
func CheckSensitiveFile(path string) *FilePermError {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return &FilePermError{Path: path, Reason: fmt.Sprintf("stat: %v", err)}
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	procUID := uint32(os.Geteuid())
	procGID := uint32(os.Getegid())
	return checkPerms(path, st.Uid, st.Gid, procUID, procGID, info.Mode())
}

// CheckSensitiveFiles calls CheckSensitiveFile for every path and collects all
// errors. Non-existent files are silently skipped.
func CheckSensitiveFiles(paths ...string) []*FilePermError {
	var errs []*FilePermError
	for _, p := range paths {
		if e := CheckSensitiveFile(p); e != nil {
			errs = append(errs, e)
		}
	}
	return errs
}
