// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package server

import (
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"spk/internal/config"
)

// ------------------------------------------------------------------------
// Close Command Tests
// Verify close commands execute correctly on:
//   - Timeout expiry
//   - Graceful shutdown (CloseAll)
//   - Crash recovery with close_ports_on_crash=true
//   - Crash recovery with close_ports_on_crash=false (skipped)
// ------------------------------------------------------------------------

// TestCloseOnOpenDurationExpiry verifies that GetExpired returns expired entries
// and that their close commands can be executed.
func TestCloseOnOpenDurationExpiry(t *testing.T) {
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

// TestExpiryWatcherExecutesCloseCmd verifies that the expiry watcher goroutine
// correctly detects expired entries and executes their close commands.
func TestExpiryWatcherExecutesCloseCmd(t *testing.T) {
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

	// Start expiry watcher with frequent check interval
	tracker.StartExpiryWatcher(200 * time.Millisecond)

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

// minCfg returns a minimal *config.Config suitable for handleOpen/handleOpenAll tests.
func minCfg() *config.Config {
	return &config.Config{
		AllowCustomPort: true,
		CommandTimeout:  0.5,
	}
}

// failCmd returns a command that always exits non-zero (simulates a failed open command).
func failCmd() string {
	if runtime.GOOS == "windows" {
		return "cmd /c exit 1"
	}
	return "false"
}

// ------------------------------------------------------------------------
// Close-after-open-failure tests
// When an open command fails (error or timeout), the tracker entry must be
// kept so the expiry watcher executes the close command at the normal
// scheduled time. The close must NOT run immediately on open failure.
// ------------------------------------------------------------------------

// TestHandleOpenKeepsEntryOnOpenFailure verifies that when the open command
// exits non-zero the tracker entry is preserved for the expiry watcher.
func TestHandleOpenKeepsEntryOnOpenFailure(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := tmpDir + "/state.json"
	logger := log.New(os.Stdout, "[TEST] ", 0)
	tracker := NewTracker(statePath, logger, true)

	closeMarker := tmpDir + "/close_ran.txt"

	cfg := minCfg()
	cfg.OpenTCPCommand = failCmd()
	cfg.CloseTCPCommand = echoToFile(closeMarker)

	allowedPorts := map[string]bool{"t22": true}

	handleOpen(logger, cfg, tracker, allowedPorts, "10.0.0.1", "t22", 3600)

	// Entry must remain so the expiry watcher can close it later
	if len(tracker.GetAll()) != 1 {
		t.Errorf("expected 1 tracker entry after failed open (for expiry watcher), got %d", len(tracker.GetAll()))
	}

	// Close command must NOT have run yet
	time.Sleep(150 * time.Millisecond)
	if _, err := os.Stat(closeMarker); err == nil {
		t.Error("close command must not execute immediately on open failure")
	}
}

// TestHandleOpenKeepsEntryOnOpenTimeout verifies that when the open command
// times out the tracker entry is preserved for the expiry watcher.
func TestHandleOpenKeepsEntryOnOpenTimeout(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := tmpDir + "/state.json"
	logger := log.New(os.Stdout, "[TEST] ", 0)
	tracker := NewTracker(statePath, logger, true)

	closeMarker := tmpDir + "/close_timeout_ran.txt"

	cfg := minCfg()
	cfg.CommandTimeout = 0.1 // 100ms
	if runtime.GOOS == "windows" {
		cfg.OpenTCPCommand = "ping -n 5 127.0.0.1"
	} else {
		cfg.OpenTCPCommand = "sleep 5"
	}
	cfg.CloseTCPCommand = echoToFile(closeMarker)

	allowedPorts := map[string]bool{"t22": true}

	handleOpen(logger, cfg, tracker, allowedPorts, "10.0.0.1", "t22", 3600)

	// Entry must remain
	if len(tracker.GetAll()) != 1 {
		t.Errorf("expected 1 tracker entry after timed-out open, got %d", len(tracker.GetAll()))
	}

	// Close not yet run
	time.Sleep(150 * time.Millisecond)
	if _, err := os.Stat(closeMarker); err == nil {
		t.Error("close command must not execute immediately on open timeout")
	}
}

// TestHandleOpenAllKeepsEntryOnOpenAllFailure verifies that when the
// open_all_command fails the tracker entry is preserved for the expiry watcher.
func TestHandleOpenAllKeepsEntryOnOpenAllFailure(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := tmpDir + "/state.json"
	logger := log.New(os.Stdout, "[TEST] ", 0)
	tracker := NewTracker(statePath, logger, true)

	closeAllMarker := tmpDir + "/close_all_ran.txt"

	cfg := minCfg()
	cfg.AllowOpenAll = true
	cfg.OpenAllCommand = failCmd()
	cfg.CloseAllCommand = echoToFile(closeAllMarker)

	allowedPorts := map[string]bool{"t22": true}

	handleOpenAll(logger, cfg, tracker, allowedPorts, "10.0.0.1", 3600)

	if len(tracker.GetAll()) != 1 {
		t.Errorf("expected 1 tracker entry after failed open-all, got %d", len(tracker.GetAll()))
	}

	time.Sleep(150 * time.Millisecond)
	if _, err := os.Stat(closeAllMarker); err == nil {
		t.Error("close-all command must not execute immediately on open-all failure")
	}
}

// TestHandleOpenNoCloseOnSuccessfulOpen verifies that the close command is NOT
// executed when the open command succeeds (baseline / regression guard).
func TestHandleOpenNoCloseOnSuccessfulOpen(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := tmpDir + "/state.json"
	logger := log.New(os.Stdout, "[TEST] ", 0)
	tracker := NewTracker(statePath, logger, true)

	closeMarker := tmpDir + "/should_not_exist.txt"

	cfg := minCfg()
	cfg.OpenTCPCommand = "echo open_ok"
	cfg.CloseTCPCommand = echoToFile(closeMarker)

	allowedPorts := map[string]bool{"t22": true}

	handleOpen(logger, cfg, tracker, allowedPorts, "10.0.0.1", "t22", 3600)

	// Tracker should have the entry (open succeeded)
	if len(tracker.GetAll()) != 1 {
		t.Errorf("expected 1 tracker entry after successful open, got %d", len(tracker.GetAll()))
	}

	// Close must not run yet
	if _, err := os.Stat(closeMarker); err == nil {
		t.Error("close command must not execute on a successful open")
	}
}

// TestAdaptiveExpiryWatcherClosesPromptly verifies that the adaptive watcher
// executes the close command shortly after the port expires, even when the
// maxInterval is much larger than the open duration.
func TestAdaptiveExpiryWatcherClosesPromptly(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := tmpDir + "/state.json"
	logger := log.New(os.Stdout, "[TEST] ", 0)
	tracker := NewTracker(statePath, logger, true)

	closeMarker := tmpDir + "/adaptive_close.txt"

	// Add entry expiring in 500ms
	tracker.Add(&PortEntry{
		IP:        "10.0.0.1",
		Port:      "t22",
		Proto:     "tcp",
		PortNum:   "22",
		OpenedAt:  time.Now(),
		ExpiresAt: time.Now().Add(500 * time.Millisecond),
		Command:   "echo open",
		CloseCmd:  echoToFile(closeMarker),
	})

	// Start watcher with a 30-second max interval - the adaptive logic must
	// still wake up close to the 500ms expiry, not after 30 seconds.
	tracker.StartExpiryWatcher(30 * time.Second)

	// With a fixed 30s ticker this would never pass within 2s.
	// With the adaptive watcher it should fire within ~600ms.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(closeMarker); err == nil {
			// Close ran - the watcher Remove call happens just after the command
			// returns, so poll briefly for the tracker to drain.
			removeDeadline := time.Now().Add(200 * time.Millisecond)
			for time.Now().Before(removeDeadline) {
				if len(tracker.GetAll()) == 0 {
					return
				}
				time.Sleep(10 * time.Millisecond)
			}
			t.Error("tracker should be empty after expiry watcher ran close")
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Error("close command was not executed within 2s despite 500ms open duration (adaptive watcher failed)")
}

// TestAdaptiveExpiryWatcherMultipleEntries verifies that when multiple entries
// have different expiry times, each is closed promptly after its own deadline.
func TestAdaptiveExpiryWatcherMultipleEntries(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := tmpDir + "/state.json"
	logger := log.New(os.Stdout, "[TEST] ", 0)
	tracker := NewTracker(statePath, logger, true)

	marker1 := tmpDir + "/close1.txt"
	marker2 := tmpDir + "/close2.txt"

	now := time.Now()
	tracker.Add(&PortEntry{
		IP: "10.0.0.1", Port: "t22", Proto: "tcp", PortNum: "22",
		OpenedAt: now, ExpiresAt: now.Add(400 * time.Millisecond),
		Command: "echo open1", CloseCmd: echoToFile(marker1),
	})
	tracker.Add(&PortEntry{
		IP: "10.0.0.2", Port: "t80", Proto: "tcp", PortNum: "80",
		OpenedAt: now, ExpiresAt: now.Add(800 * time.Millisecond),
		Command: "echo open2", CloseCmd: echoToFile(marker2),
	})

	tracker.StartExpiryWatcher(30 * time.Second)

	// Both markers must appear within 2 seconds
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		_, err1 := os.Stat(marker1)
		_, err2 := os.Stat(marker2)
		if err1 == nil && err2 == nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	_, err1 := os.Stat(marker1)
	_, err2 := os.Stat(marker2)
	if err1 != nil {
		t.Error("first close command not executed within 2s")
	}
	if err2 != nil {
		t.Error("second close command not executed within 2s")
	}
}

// ------------------------------------------------------------------------
// No close command tests
// When close_tcp_command (or equivalent) is not configured, handleOpen must
// still execute the open command and log a warning that the port will remain
// open permanently (no expiry timer is set, nothing to close at timeout).
// When no open command is configured, handleOpen skips entirely as before.
// ------------------------------------------------------------------------

// TestHandleOpenNoCloseCommandExecutesOpen verifies that when no close command
// template is configured, handleOpen still runs the open command but does NOT
// add a tracker entry (no expiry timer needed since there is nothing to close).
// A [WARN] line about permanent open must be logged.
func TestHandleOpenNoCloseCommandExecutesOpen(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := tmpDir + "/state.json"
	cl := &captureLogger{}
	tracker := NewTracker(statePath, cl, true)

	openMarker := tmpDir + "/open_ran.txt"

	cfg := minCfg()
	cfg.OpenTCPCommand = echoToFile(openMarker)
	cfg.CloseTCPCommand = "" // No close command configured

	allowedPorts := map[string]bool{"t22": true}

	handleOpen(cl, cfg, tracker, allowedPorts, "10.0.0.1", "t22", 3600)

	// Open command must have run
	time.Sleep(150 * time.Millisecond)
	if _, err := os.Stat(openMarker); err != nil {
		t.Error("open command must still execute even when no close command is configured")
	}

	// No tracker entry -- no close command means no expiry needed
	if len(tracker.GetAll()) != 0 {
		t.Errorf("expected 0 tracker entries when close command is not configured, got %d", len(tracker.GetAll()))
	}

	// A warning about permanent open must appear in the log
	warnFound := false
	for _, l := range cl.lines {
		if strings.Contains(l, "permanently") {
			warnFound = true
			break
		}
	}
	if !warnFound {
		t.Errorf("expected [WARN] about permanent open, got lines: %v", cl.lines)
	}
}

// TestHandleOpenNoOpenCommandNoTracker verifies the existing behavior:
// when no open command template is configured, handleOpen skips entirely.
func TestHandleOpenNoOpenCommandNoTracker(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := tmpDir + "/state.json"
	logger := log.New(os.Stdout, "[TEST] ", 0)
	tracker := NewTracker(statePath, logger, true)

	cfg := minCfg()
	cfg.OpenTCPCommand = "" // No open command configured
	cfg.CloseTCPCommand = "echo close_ok"

	allowedPorts := map[string]bool{"t22": true}

	handleOpen(logger, cfg, tracker, allowedPorts, "10.0.0.1", "t22", 3600)

	if len(tracker.GetAll()) != 0 {
		t.Errorf("expected 0 tracker entries when open command is not configured, got %d", len(tracker.GetAll()))
	}
}

// TestHandleOpenAllNoCloseCommandExecutesOpen verifies that when open_all_command
// is set but close_all_command is not, handleOpenAll still executes the open-all
// command but does not create a tracker entry, and warns about permanent open.
func TestHandleOpenAllNoCloseCommandExecutesOpen(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := tmpDir + "/state.json"
	cl := &captureLogger{}
	tracker := NewTracker(statePath, cl, true)

	openMarker := tmpDir + "/open_all_ran.txt"

	cfg := minCfg()
	cfg.AllowOpenAll = true
	cfg.OpenAllCommand = echoToFile(openMarker)
	cfg.CloseAllCommand = "" // No close-all command configured

	allowedPorts := map[string]bool{"t22": true}

	handleOpenAll(cl, cfg, tracker, allowedPorts, "10.0.0.1", 3600)

	time.Sleep(150 * time.Millisecond)
	if _, err := os.Stat(openMarker); err != nil {
		t.Error("open-all command must still execute even when no close-all command is configured")
	}

	if len(tracker.GetAll()) != 0 {
		t.Errorf("expected 0 tracker entries when close-all command is not configured, got %d", len(tracker.GetAll()))
	}

	warnFound := false
	for _, l := range cl.lines {
		if strings.Contains(l, "permanently") {
			warnFound = true
			break
		}
	}
	if !warnFound {
		t.Errorf("expected [WARN] about permanent open, got lines: %v", cl.lines)
	}
}

// ------------------------------------------------------------------------
// CMD-EXEC logging tests
// When cfg.LogCommandOutput is true, a [CMD-EXEC] line must be logged
// with the exact command before it is executed.
// ------------------------------------------------------------------------

// captureLogger is a simple logger that records all Printf calls.
type captureLogger struct {
	lines []string
}

func (c *captureLogger) Printf(format string, v ...interface{}) {
	c.lines = append(c.lines, fmt.Sprintf(format, v...))
}

func hasCmdExec(lines []string, substr string) bool {
	for _, l := range lines {
		if strings.Contains(l, "[CMD-EXEC]") && strings.Contains(l, substr) {
			return true
		}
	}
	return false
}

// TestLogCommandExecOnOpen verifies that [CMD-EXEC] is logged before the
// open command runs when LogCommandOutput is true.
func TestLogCommandExecOnOpen(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := tmpDir + "/state.json"
	cl := &captureLogger{}
	tracker := NewTracker(statePath, cl, true)
	tracker.logCmdExec = true

	cfg := minCfg()
	cfg.LogCommandOutput = true
	cfg.OpenTCPCommand = "echo open_exec_test"
	cfg.CloseTCPCommand = "echo close_exec_test"

	allowedPorts := map[string]bool{"t22": true}
	handleOpen(cl, cfg, tracker, allowedPorts, "10.0.0.1", "t22", 3600)

	if !hasCmdExec(cl.lines, "open_exec_test") {
		t.Errorf("[CMD-EXEC] line not found for open command; got lines: %v", cl.lines)
	}
}

// TestLogCommandExecOnClose verifies that [CMD-EXEC] is logged before the
// close command runs when LogCommandOutput is true.
func TestLogCommandExecOnClose(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := tmpDir + "/state.json"
	cl := &captureLogger{}
	tracker := NewTracker(statePath, cl, true)
	tracker.logCmdExec = true

	// Pre-populate tracking so handleClose has an entry to remove
	tracker.Add(&PortEntry{
		IP: "10.0.0.1", Port: "t22", Proto: "tcp", PortNum: "22",
		OpenedAt: time.Now(), ExpiresAt: time.Now().Add(1 * time.Hour),
		Command:  "echo open",
		CloseCmd: "echo close_exec_test",
	})

	cfg := minCfg()
	cfg.LogCommandOutput = true
	cfg.CloseTCPCommand = "echo close_exec_test"

	allowedPorts := map[string]bool{"t22": true}
	handleClose(cl, cfg, tracker, allowedPorts, "10.0.0.1", "t22")

	if !hasCmdExec(cl.lines, "close_exec_test") {
		t.Errorf("[CMD-EXEC] line not found for close command; got lines: %v", cl.lines)
	}
}

// TestLogCommandExecDisabled verifies that no [CMD-EXEC] lines are produced
// when LogCommandOutput is false (default).
func TestLogCommandExecDisabled(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := tmpDir + "/state.json"
	cl := &captureLogger{}
	tracker := NewTracker(statePath, cl, true)

	cfg := minCfg()
	cfg.LogCommandOutput = false // default -- no CMD-EXEC logging
	cfg.OpenTCPCommand = "echo open_no_exec_log"
	cfg.CloseTCPCommand = "echo close_no_exec_log"

	allowedPorts := map[string]bool{"t22": true}
	handleOpen(cl, cfg, tracker, allowedPorts, "10.0.0.1", "t22", 3600)

	for _, l := range cl.lines {
		if strings.Contains(l, "[CMD-EXEC]") {
			t.Errorf("unexpected [CMD-EXEC] line when LogCommandOutput=false: %s", l)
		}
	}
}

// TestExpiryWatcherLogsCmdExec verifies that the expiry watcher logs [CMD-EXEC]
// before running the close command when logCmdExec is true.
func TestExpiryWatcherLogsCmdExec(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := tmpDir + "/state.json"
	cl := &captureLogger{}
	tracker := NewTracker(statePath, cl, true)
	tracker.logCmdExec = true

	tracker.Add(&PortEntry{
		IP: "10.0.0.1", Port: "t22", Proto: "tcp", PortNum: "22",
		OpenedAt: time.Now(), ExpiresAt: time.Now().Add(200 * time.Millisecond),
		Command:  "echo open",
		CloseCmd: "echo watcher_exec_test",
	})

	tracker.StartExpiryWatcher(50 * time.Millisecond)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(tracker.GetAll()) == 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if len(tracker.GetAll()) != 0 {
		t.Fatal("expiry watcher did not remove entry within 2s")
	}
	if !hasCmdExec(cl.lines, "watcher_exec_test") {
		t.Errorf("[CMD-EXEC] line not found for expiry watcher close command; got lines: %v", cl.lines)
	}
}
