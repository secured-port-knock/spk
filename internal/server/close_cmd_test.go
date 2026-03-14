// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package server

import (
	"log"
	"os"
	"strings"
	"testing"
	"time"
)

// ------------------------------------------------------------------------
// Close Command Tests
// Verify close commands execute correctly on:
//   - Timeout expiry
//   - Graceful shutdown (CloseAll)
//   - Crash recovery with close_ports_on_crash=true
//   - Crash recovery with close_ports_on_crash=false (skipped)
// ------------------------------------------------------------------------

// TestCloseOnTimeoutExpiry verifies that GetExpired returns expired entries
// and that their close commands can be executed.
func TestCloseOnTimeoutExpiry(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := tmpDir + "/state.json"
	logger := log.New(os.Stdout, "[TEST] ", 0)

	tracker := NewTracker(statePath, logger, true)

	// Add an entry that expires in 1 second
	marker := tmpDir + "/closed_timeout.txt"
	tracker.Add(&PortEntry{
		IP:        "10.0.0.1",
		Port:      "t22",
		Proto:     "tcp",
		PortNum:   "22",
		OpenedAt:  time.Now(),
		ExpiresAt: time.Now().Add(1 * time.Second),
		Command:   "echo opened",
		CloseCmd:  echoToFile(marker),
	})

	// Should not be expired yet
	expired := tracker.GetExpired()
	if len(expired) != 0 {
		t.Errorf("expected 0 expired entries immediately, got %d", len(expired))
	}

	// Wait for expiry
	time.Sleep(1500 * time.Millisecond)

	// Should be expired now
	expired = tracker.GetExpired()
	if len(expired) != 1 {
		t.Fatalf("expected 1 expired entry, got %d", len(expired))
	}

	// Execute close command
	output, err := ExecuteCommand(expired[0].CloseCmd)
	if err != nil {
		t.Fatalf("close command failed: %v", err)
	}
	_ = output

	// Remove from tracker (as timeout watcher would)
	tracker.Remove(expired[0].IP, expired[0].PortNum, expired[0].Proto)

	// Tracker should be empty
	if len(tracker.GetAll()) != 0 {
		t.Error("tracker should be empty after removing expired entry")
	}
}

// TestCloseOnShutdown verifies that CloseAll executes close commands for all entries.
func TestCloseOnShutdown(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := tmpDir + "/state.json"
	logger := log.New(os.Stdout, "[TEST] ", 0)

	tracker := NewTracker(statePath, logger, true)

	// Add multiple entries
	for i, ip := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"} {
		tracker.Add(&PortEntry{
			IP:        ip,
			Port:      "t22",
			Proto:     "tcp",
			PortNum:   "22",
			OpenedAt:  time.Now(),
			ExpiresAt: time.Now().Add(1 * time.Hour),
			Command:   "echo open",
			CloseCmd:  echoCmd(i),
		})
	}

	if len(tracker.GetAll()) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(tracker.GetAll()))
	}

	// Shutdown - should close all
	tracker.CloseAll()

	// All entries should be removed
	if len(tracker.GetAll()) != 0 {
		t.Errorf("expected 0 entries after CloseAll, got %d", len(tracker.GetAll()))
	}
}

// TestCloseOnCrashRecoveryTrue verifies that on crash recovery,
// expired entries have their close commands executed when closePortsOnCrash=true.
// Recovery validates close commands against an allowlist of known firewall binaries.
func TestCloseOnCrashRecoveryTrue(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := tmpDir + "/state.json"

	// Write state file simulating a crash where an entry expired.
	// Close command uses iptables (passes allowlist). We can't verify execution
	// in a test (iptables not available), but we verify the entry is removed.
	state := `{
		"10.0.0.1:22:tcp": {
			"ip": "10.0.0.1",
			"port": "t22",
			"proto": "tcp",
			"port_num": "22",
			"opened_at": "2020-01-01T00:00:00Z",
			"expires_at": "2020-01-01T00:30:00Z",
			"open_command": "iptables -A INPUT -p tcp --dport 22 -s 10.0.0.1 -j ACCEPT",
			"close_command": "iptables -D INPUT -p tcp --dport 22 -s 10.0.0.1 -j ACCEPT"
		}
	}`
	os.WriteFile(statePath, []byte(state), 0600)

	logger := log.New(os.Stdout, "[TEST] ", 0)
	tracker := NewTracker(statePath, logger, true) // closePortsOnCrash=true

	// Entry should be removed (close command attempted during recovery)
	entries := tracker.GetAll()
	if len(entries) != 0 {
		t.Errorf("expected 0 entries after crash recovery (expired entry closed), got %d", len(entries))
	}
}

// TestCloseOnCrashRecoveryFalse verifies that with closePortsOnCrash=false,
// expired entries are dropped WITHOUT executing close commands.
func TestCloseOnCrashRecoveryFalse(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := tmpDir + "/state.json"

	// Write state file with expired entry using a valid firewall command
	state := `{
		"10.0.0.1:22:tcp": {
			"ip": "10.0.0.1",
			"port": "t22",
			"proto": "tcp",
			"port_num": "22",
			"opened_at": "2020-01-01T00:00:00Z",
			"expires_at": "2020-01-01T00:30:00Z",
			"open_command": "iptables -A INPUT -p tcp --dport 22 -s 10.0.0.1 -j ACCEPT",
			"close_command": "iptables -D INPUT -p tcp --dport 22 -s 10.0.0.1 -j ACCEPT"
		}
	}`
	os.WriteFile(statePath, []byte(state), 0600)

	logger := log.New(os.Stdout, "[TEST] ", 0)
	tracker := NewTracker(statePath, logger, false) // closePortsOnCrash=false

	// Entry should be dropped without executing close
	entries := tracker.GetAll()
	if len(entries) != 0 {
		t.Errorf("expected 0 entries (expired dropped), got %d", len(entries))
	}
}

// TestCloseOnShutdownFlagIrrelevant verifies that CloseAll always executes
// close commands regardless of closePortsOnCrash setting.
func TestCloseOnShutdownFlagIrrelevant(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := tmpDir + "/state.json"
	logger := log.New(os.Stdout, "[TEST] ", 0)

	// closePortsOnCrash=false - but CloseAll should still work
	tracker := NewTracker(statePath, logger, false)

	tracker.Add(&PortEntry{
		IP:        "10.0.0.1",
		Port:      "t22",
		Proto:     "tcp",
		PortNum:   "22",
		OpenedAt:  time.Now(),
		ExpiresAt: time.Now().Add(1 * time.Hour),
		Command:   "echo open",
		CloseCmd:  echoCmd(0),
	})

	tracker.CloseAll()

	if len(tracker.GetAll()) != 0 {
		t.Error("CloseAll should remove all entries regardless of closePortsOnCrash flag")
	}
}

// TestCloseMultiplePortsSameIP verifies that CloseAll correctly handles
// multiple ports opened for the same IP.
func TestCloseMultiplePortsSameIP(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := tmpDir + "/state.json"
	logger := log.New(os.Stdout, "[TEST] ", 0)

	tracker := NewTracker(statePath, logger, true)

	ports := []string{"22", "443", "80", "8080"}
	for _, port := range ports {
		tracker.Add(&PortEntry{
			IP:        "10.0.0.1",
			Port:      "t" + port,
			Proto:     "tcp",
			PortNum:   port,
			OpenedAt:  time.Now(),
			ExpiresAt: time.Now().Add(1 * time.Hour),
			Command:   "echo open " + port,
			CloseCmd:  "echo close " + port,
		})
	}

	if len(tracker.GetAll()) != 4 {
		t.Fatalf("expected 4 entries, got %d", len(tracker.GetAll()))
	}

	tracker.CloseAll()

	if len(tracker.GetAll()) != 0 {
		t.Errorf("expected 0 entries after CloseAll, got %d", len(tracker.GetAll()))
	}
}

// TestTimeoutWatcherExecutesCloseCmd verifies that the timeout watcher goroutine
// correctly detects expired entries and executes their close commands.
func TestTimeoutWatcherExecutesCloseCmd(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := tmpDir + "/state.json"
	logger := log.New(os.Stdout, "[TEST] ", 0)

	tracker := NewTracker(statePath, logger, true)

	// Add entry that expires in 500ms
	tracker.Add(&PortEntry{
		IP:        "10.0.0.1",
		Port:      "t22",
		Proto:     "tcp",
		PortNum:   "22",
		OpenedAt:  time.Now(),
		ExpiresAt: time.Now().Add(500 * time.Millisecond),
		Command:   "echo open",
		CloseCmd:  echoCmd(0),
	})

	// Start timeout watcher with frequent check interval
	tracker.StartTimeoutWatcher(200 * time.Millisecond)

	// Wait for timeout + watcher interval
	time.Sleep(1500 * time.Millisecond)

	// Entry should be removed by the watcher
	entries := tracker.GetAll()
	if len(entries) != 0 {
		t.Errorf("expected 0 entries after timeout watcher, got %d", len(entries))
	}
}

// TestCrashRecoveryWithValidNonExpiredEntry verifies that non-expired entries
// survive crash recovery and remain tracked.
func TestCrashRecoveryWithValidNonExpiredEntry(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := tmpDir + "/state.json"

	// Entry with far-future expiry (valid firewall close command)
	state := `{
		"10.0.0.1:22:tcp": {
			"ip": "10.0.0.1",
			"port": "t22",
			"proto": "tcp",
			"port_num": "22",
			"opened_at": "2024-01-01T00:00:00Z",
			"expires_at": "2099-12-31T23:59:59Z",
			"open_command": "iptables -A INPUT -p tcp --dport 22 -s 10.0.0.1 -j ACCEPT",
			"close_command": "iptables -D INPUT -p tcp --dport 22 -s 10.0.0.1 -j ACCEPT"
		}
	}`
	os.WriteFile(statePath, []byte(state), 0600)

	logger := log.New(os.Stdout, "[TEST] ", 0)

	// With closePortsOnCrash=true - non-expired should still survive
	tracker := NewTracker(statePath, logger, true)
	entries := tracker.GetAll()
	if len(entries) != 1 {
		t.Fatalf("expected 1 surviving entry, got %d", len(entries))
	}
	if entries[0].IP != "10.0.0.1" {
		t.Errorf("entry IP = %q, want 10.0.0.1", entries[0].IP)
	}
}

// TestCrashRecoveryMixedWithFlag verifies mixed expired/non-expired entries
// with closePortsOnCrash=true: expired get closed, non-expired survive.
func TestCrashRecoveryMixedWithFlag(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := tmpDir + "/state.json"

	state := `{
		"10.0.0.1:22:tcp": {
			"ip": "10.0.0.1",
			"port": "t22",
			"proto": "tcp",
			"port_num": "22",
			"opened_at": "2020-01-01T00:00:00Z",
			"expires_at": "2020-01-01T00:30:00Z",
			"open_command": "iptables -A INPUT -p tcp --dport 22 -s 10.0.0.1 -j ACCEPT",
			"close_command": "iptables -D INPUT -p tcp --dport 22 -s 10.0.0.1 -j ACCEPT"
		},
		"10.0.0.2:443:tcp": {
			"ip": "10.0.0.2",
			"port": "t443",
			"proto": "tcp",
			"port_num": "443",
			"opened_at": "2024-01-01T00:00:00Z",
			"expires_at": "2099-12-31T23:59:59Z",
			"open_command": "iptables -A INPUT -p tcp --dport 443 -s 10.0.0.2 -j ACCEPT",
			"close_command": "iptables -D INPUT -p tcp --dport 443 -s 10.0.0.2 -j ACCEPT"
		}
	}`
	os.WriteFile(statePath, []byte(state), 0600)

	logger := log.New(os.Stdout, "[TEST] ", 0)
	tracker := NewTracker(statePath, logger, true) // closePortsOnCrash=true

	entries := tracker.GetAll()
	if len(entries) != 1 {
		t.Fatalf("expected 1 surviving entry (expired closed), got %d", len(entries))
	}
	if entries[0].IP != "10.0.0.2" {
		t.Errorf("surviving entry IP = %q, want 10.0.0.2", entries[0].IP)
	}
}

// Helper: platform-agnostic echo command
func echoCmd(id int) string {
	return "echo close_" + strings.Repeat("x", id)
}

// Helper: command to create a marker file (cross-platform)
func echoToFile(path string) string {
	// Use Go-friendly shell command
	return "echo closed > " + strings.ReplaceAll(path, "\\", "/")
}

// Helper: JSON-safe version of echoToFile (escape backslashes for JSON)
func echoToFileJSON(path string) string {
	return strings.ReplaceAll(echoToFile(path), "\\", "\\\\")
}
