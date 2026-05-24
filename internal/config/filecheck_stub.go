// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

//go:build !linux && !darwin

package config

// FilePermError describes a file that failed the permission/ownership check.
// On non-Unix platforms the checks are not enforced; this type is defined here
// so callers compile on all platforms.
type FilePermError struct {
	Path   string
	Reason string
}

func (e *FilePermError) Error() string {
	return e.Path + ": " + e.Reason
}

// CheckSensitiveFile is a no-op on non-Unix platforms. Always returns nil.
func CheckSensitiveFile(_ string) *FilePermError { return nil }

// CheckSensitiveFiles is a no-op on non-Unix platforms. Always returns nil.
func CheckSensitiveFiles(_ ...string) []*FilePermError { return nil }
