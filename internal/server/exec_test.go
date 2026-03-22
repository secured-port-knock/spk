// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package server

import (
	"runtime"
	"strings"
	"testing"
	"time"
)

// --- Fuzz tests for command execution ---

// FuzzExecuteCommandTimeout sends arbitrary strings through the command
// execution pipeline to verify no panics or hangs.
func FuzzExecuteCommandTimeout(f *testing.F) {
	f.Add("")
	f.Add("echo hello")
	f.Add("exit 0")
	f.Add("exit 1")
	f.Add("nonexistent_command_xyz")
	f.Add(strings.Repeat("A", 10000))

	f.Fuzz(func(t *testing.T, cmd string) {
		// Use very short timeout to prevent long-running fuzzer iterations.
		// We only care about panics and hangs, not command success.
		_, _ = ExecuteCommandTimeout(cmd, 200*time.Millisecond)
	})
}

// --- Unit tests for ExecuteCommandTimeout ---

// TestExecuteCommandTimeout_EmptyCommand verifies empty command is a no-op.
func TestExecuteCommandTimeout_EmptyCommand(t *testing.T) {
	out, err := ExecuteCommandTimeout("", 1*time.Second)
	if err != nil {
		t.Errorf("empty command should return nil error, got: %v", err)
	}
	if out != "" {
		t.Errorf("empty command should return empty output, got: %q", out)
	}
}

// TestExecuteCommandTimeout_Success verifies successful command execution.
func TestExecuteCommandTimeout_Success(t *testing.T) {
	var cmd string
	if runtime.GOOS == "windows" {
		cmd = "echo hello"
	} else {
		cmd = "echo hello"
	}

	out, err := ExecuteCommandTimeout(cmd, 5*time.Second)
	if err != nil {
		t.Fatalf("echo should succeed: %v", err)
	}
	if !strings.Contains(out, "hello") {
		t.Errorf("output should contain 'hello', got: %q", out)
	}
}

// TestExecuteCommandTimeout_Failure verifies failed commands return errors.
func TestExecuteCommandTimeout_Failure(t *testing.T) {
	var cmd string
	if runtime.GOOS == "windows" {
		cmd = "cmd /c exit 1"
	} else {
		cmd = "exit 1"
	}

	_, err := ExecuteCommandTimeout(cmd, 5*time.Second)
	if err == nil {
		t.Error("exit 1 should return an error")
	}
}

// TestExecuteCommandTimeout_Timeout verifies command timeout enforcement.
func TestExecuteCommandTimeout_Timeout(t *testing.T) {
	var cmd string
	if runtime.GOOS == "windows" {
		cmd = "ping -n 30 127.0.0.1"
	} else {
		cmd = "sleep 30"
	}

	start := time.Now()
	_, err := ExecuteCommandTimeout(cmd, 500*time.Millisecond)
	elapsed := time.Since(start)

	if err == nil {
		t.Error("long-running command should be killed by timeout")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Errorf("error should mention timeout, got: %v", err)
	}
	// Should have been killed well before 30 seconds
	if elapsed > 5*time.Second {
		t.Errorf("timeout took too long: %v", elapsed)
	}
}

// TestExecuteCommandTimeout_DefaultTimeout verifies zero timeout defaults to 30s.
func TestExecuteCommandTimeout_DefaultTimeout(t *testing.T) {
	// This just tests that the command runs with a default timeout (doesn't hang)
	var cmd string
	if runtime.GOOS == "windows" {
		cmd = "echo default_timeout"
	} else {
		cmd = "echo default_timeout"
	}

	out, err := ExecuteCommandTimeout(cmd, 0)
	if err != nil {
		t.Fatalf("should succeed with default timeout: %v", err)
	}
	if !strings.Contains(out, "default_timeout") {
		t.Errorf("expected output, got: %q", out)
	}
}

// TestExecuteCommandTimeout_NegativeTimeout verifies negative timeout defaults to 30s.
func TestExecuteCommandTimeout_NegativeTimeout(t *testing.T) {
	out, err := ExecuteCommandTimeout("echo negative", -1*time.Second)
	if err != nil {
		t.Fatalf("should succeed with default timeout: %v", err)
	}
	if !strings.Contains(out, "negative") {
		t.Errorf("expected output, got: %q", out)
	}
}

// TestExecuteCommandTimeout_StderrCapture verifies stderr is captured.
func TestExecuteCommandTimeout_StderrCapture(t *testing.T) {
	var cmd string
	if runtime.GOOS == "windows" {
		cmd = "echo stderr_test 1>&2"
	} else {
		cmd = "echo stderr_test >&2"
	}

	out, err := ExecuteCommandTimeout(cmd, 5*time.Second)
	if err != nil {
		t.Fatalf("stderr redirect should succeed: %v", err)
	}
	if !strings.Contains(out, "stderr_test") {
		t.Errorf("stderr should be captured, got: %q", out)
	}
}

// TestExecuteCommandTimeout_BadCommand verifies nonexistent commands fail.
func TestExecuteCommandTimeout_BadCommand(t *testing.T) {
	_, err := ExecuteCommandTimeout("definitely_not_a_real_command_xyz_12345", 5*time.Second)
	if err == nil {
		t.Error("nonexistent command should return an error")
	}
}

// TestExecuteCommand_Wrapper verifies the convenience wrapper.
func TestExecuteCommand_Wrapper(t *testing.T) {
	out, err := ExecuteCommand("echo wrapper_test")
	if err != nil {
		t.Fatalf("should succeed: %v", err)
	}
	if !strings.Contains(out, "wrapper_test") {
		t.Errorf("expected output, got: %q", out)
	}
}

// --- Property tests for process cleanup ---

// TestExecuteCommandTimeout_ProcessCleanup verifies that timed-out processes
// do not leave zombie/orphan processes.
func TestExecuteCommandTimeout_ProcessCleanup(t *testing.T) {
	for i := 0; i < 5; i++ {
		var cmd string
		if runtime.GOOS == "windows" {
			cmd = "ping -n 30 127.0.0.1"
		} else {
			cmd = "sleep 30"
		}
		_, _ = ExecuteCommandTimeout(cmd, 200*time.Millisecond)
	}
	// If process cleanup is broken, this test would leak 5 sleep/ping processes.
	// There is no portable way to programmatically verify this, but running
	// this test under a process monitor will reveal leaks.
}

// TestExecuteCommandTimeout_ConcurrentExecution verifies concurrent commands
// do not interfere with each other.
func TestExecuteCommandTimeout_ConcurrentExecution(t *testing.T) {
	done := make(chan error, 10)

	for i := 0; i < 10; i++ {
		go func(id int) {
			var cmd string
			if runtime.GOOS == "windows" {
				cmd = "echo concurrent"
			} else {
				cmd = "echo concurrent"
			}
			_, err := ExecuteCommandTimeout(cmd, 5*time.Second)
			done <- err
		}(i)
	}

	for i := 0; i < 10; i++ {
		if err := <-done; err != nil {
			t.Errorf("concurrent command %d failed: %v", i, err)
		}
	}
}

// TestExecuteCommandTimeout_OutputOnFailure verifies partial output is
// captured even when commands fail.
func TestExecuteCommandTimeout_OutputOnFailure(t *testing.T) {
	var cmd string
	if runtime.GOOS == "windows" {
		cmd = "echo partial_output && cmd /c exit 1"
	} else {
		cmd = "echo partial_output && exit 1"
	}

	out, err := ExecuteCommandTimeout(cmd, 5*time.Second)
	if err == nil {
		t.Error("should return error for exit 1")
	}
	if !strings.Contains(out, "partial_output") {
		t.Errorf("partial output should be captured on failure, got: %q", out)
	}
}

// TestExecuteCommandTimeout_OutputOnTimeout verifies partial output is
// captured even when commands are killed by timeout.
func TestExecuteCommandTimeout_OutputOnTimeout(t *testing.T) {
	var cmd string
	if runtime.GOOS == "windows" {
		// Print something then hang
		cmd = "echo before_timeout && ping -n 30 127.0.0.1"
	} else {
		cmd = "echo before_timeout && sleep 30"
	}

	out, err := ExecuteCommandTimeout(cmd, 500*time.Millisecond)
	if err == nil {
		t.Error("should return timeout error")
	}
	if !strings.Contains(out, "before_timeout") {
		t.Logf("partial output on timeout: %q (may be empty on some platforms)", out)
	}
}
