// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestGovulncheck runs govulncheck on the entire module and logs any
// called vulnerabilities as warnings. The test always passes -- it
// serves as a visibility check rather than a gate. If govulncheck is
// not installed, the test is skipped.
//
// Install govulncheck:
//
//	go install golang.org/x/vuln/cmd/govulncheck@latest
func TestGovulncheck(t *testing.T) {
	bin := "govulncheck"
	if runtime.GOOS == "windows" {
		bin = "govulncheck.exe"
	}
	path, err := exec.LookPath(bin)
	if err != nil {
		t.Skipf("govulncheck not found in PATH: %v", err)
	}
	t.Logf("using govulncheck at %s", path)

	// Find the module root (directory containing go.mod).
	modRoot := findModuleRoot(t)

	cmd := exec.Command(path, "./...")
	cmd.Dir = modRoot
	out, err := cmd.CombinedOutput()
	output := string(out)

	if err != nil {
		if strings.Contains(output, "Your code is affected by") {
			t.Logf("WARNING: govulncheck found called vulnerabilities:\n%s", output)
			return
		}
		// Other failures (network, parse, etc.)
		t.Logf("WARNING: govulncheck failed: %v\n%s", err, output)
		return
	}

	t.Log("govulncheck: no called vulnerabilities found")
}

// findModuleRoot walks up from the test file's directory to locate go.mod.
func findModuleRoot(t *testing.T) string {
	t.Helper()

	// Start from the directory of this source file.
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(thisFile)

	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatal("could not find go.mod in any parent directory")
	return ""
}
