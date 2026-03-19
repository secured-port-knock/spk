//go:build !windows

// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package main

// runAsWindowsService is a no-op on non-Windows platforms.
// Returns (false, nil) so callers can always branch on `ran`.
func runAsWindowsService(svcName string, runFn func(), stopFn func()) (bool, error) {
	return false, nil
}
