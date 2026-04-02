// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

//go:build testsmoke

// Package smoke_test contains end-to-end smoke tests for the SPK binary.
//
// These tests build the SPK binary, start it as a server subprocess, send
// actual UDP knock packets, and verify that open/close firewall commands
// execute correctly. They cover all sniffer modes that are available on the
// current platform, dynamic port negotiation, TOTP authentication, port
// policy enforcement, and graceful close-on-expiry / close-on-shutdown.
//
// Run with:
//
//	go test -buildvcs=false -count=1 -timeout 300s -tags testsmoke ./tests/smoke/
//
// Or via the build script:
//
//	./build.sh -testsmoke          # Linux / macOS
//	.\build.ps1 -testsmoke         # Windows
package smoke_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// spkBinary is the path to the compiled SPK binary, set once in TestMain.
var spkBinary string

// TestMain builds the SPK binary before running any smoke tests.
func TestMain(m *testing.M) {
	root, err := findModuleRoot()
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL smoke: find module root: %v\n", err)
		os.Exit(1)
	}

	spkBase := filepath.Join(os.TempDir(), "spk")
	if err := os.MkdirAll(spkBase, 0700); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL smoke: create spk temp dir: %v\n", err)
		os.Exit(1)
	}
	tmpDir, err := os.MkdirTemp(spkBase, "smoke_build_")
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL smoke: create temp dir: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(tmpDir)

	binName := "spk"
	if runtime.GOOS == "windows" {
		binName = "spk.exe"
	}
	spkBinary = filepath.Join(tmpDir, binName)

	fmt.Printf("=== SMOKE building SPK binary -> %s\n", spkBinary)
	buildCmd := exec.Command("go", "build", "-buildvcs=false", "-o", spkBinary, ".")
	buildCmd.Dir = root
	buildCmd.Stdout = os.Stdout
	buildCmd.Stderr = os.Stderr
	if err := buildCmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL smoke: build failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("=== SMOKE build complete")

	os.Exit(m.Run())
}

// findModuleRoot locates the go.mod file and returns its directory.
func findModuleRoot() (string, error) {
	out, err := exec.Command("go", "env", "GOMOD").Output()
	if err != nil {
		return "", fmt.Errorf("go env GOMOD: %w", err)
	}
	modPath := strings.TrimSpace(string(out))
	if modPath == "" || modPath == os.DevNull {
		return "", fmt.Errorf("go.mod not found (not in a module)")
	}
	return filepath.Dir(modPath), nil
}
