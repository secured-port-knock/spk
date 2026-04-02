// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package server

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/secured-port-knock/spk/internal/config"
)

// ========================================================================
// Tracker deduplication tests (Has / RefreshExpiry / TryReserve)
// ========================================================================

func TestTrackerHas(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	logger := log.New(os.Stdout, "[test] ", 0)
	tracker := NewTracker(statePath, logger, true)

	tracker.Add(&PortEntry{
		IP: "10.0.0.1", Port: "t22", Proto: "tcp", PortNum: "22",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	})

	if !tracker.Has("10.0.0.1", "22", "tcp") {
		t.Error("Has should return true for existing entry")
	}
	if tracker.Has("10.0.0.2", "22", "tcp") {
		t.Error("Has should return false for different IP")
	}
	if tracker.Has("10.0.0.1", "80", "tcp") {
		t.Error("Has should return false for different port")
	}
	if tracker.Has("10.0.0.1", "22", "udp") {
		t.Error("Has should return false for different proto")
	}
}

func TestTrackerRefreshExpiry(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	logger := log.New(os.Stdout, "[test] ", 0)
	tracker := NewTracker(statePath, logger, true)

	orig := time.Now().Add(1 * time.Hour)
	tracker.Add(&PortEntry{
		IP: "10.0.0.1", Port: "t22", Proto: "tcp", PortNum: "22",
		ExpiresAt: orig, CloseCmd: "echo close",
	})

	// Refresh to a later time
	later := time.Now().Add(2 * time.Hour)
	tracker.RefreshExpiry("10.0.0.1", "22", "tcp", later)

	entries := tracker.GetAll()
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if !entries[0].ExpiresAt.Equal(later) {
		t.Errorf("ExpiresAt should be updated; got %v, want %v", entries[0].ExpiresAt, later)
	}
}

func TestTrackerRefreshExpiryNonExistent(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	logger := log.New(os.Stdout, "[test] ", 0)
	tracker := NewTracker(statePath, logger, true)

	// Refreshing a non-existent entry should be a no-op
	tracker.RefreshExpiry("10.0.0.1", "22", "tcp", time.Now().Add(1*time.Hour))
	if len(tracker.GetAll()) != 0 {
		t.Error("RefreshExpiry on non-existent should not create an entry")
	}
}

func TestTryReserveNewEntry(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	logger := log.New(os.Stdout, "[test] ", 0)
	tracker := NewTracker(statePath, logger, true)

	entry := &PortEntry{
		IP: "10.0.0.1", Port: "t22", Proto: "tcp", PortNum: "22",
		ExpiresAt: time.Now().Add(1 * time.Hour), CloseCmd: "echo close",
	}

	reserved, existing := tracker.TryReserve(entry)
	if !reserved {
		t.Fatal("TryReserve should return true for new entry")
	}
	if existing != nil {
		t.Fatal("existing should be nil for new reservation")
	}
	if !tracker.Has("10.0.0.1", "22", "tcp") {
		t.Error("entry should be tracked after TryReserve")
	}
}

func TestTryReserveDuplicate(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	logger := log.New(os.Stdout, "[test] ", 0)
	tracker := NewTracker(statePath, logger, true)

	entry1 := &PortEntry{
		IP: "10.0.0.1", Port: "t22", Proto: "tcp", PortNum: "22",
		ExpiresAt: time.Now().Add(1 * time.Hour), CloseCmd: "echo close1",
	}
	entry2 := &PortEntry{
		IP: "10.0.0.1", Port: "t22", Proto: "tcp", PortNum: "22",
		ExpiresAt: time.Now().Add(2 * time.Hour), CloseCmd: "echo close2",
	}

	reserved1, _ := tracker.TryReserve(entry1)
	if !reserved1 {
		t.Fatal("first TryReserve should succeed")
	}

	reserved2, existing := tracker.TryReserve(entry2)
	if reserved2 {
		t.Fatal("second TryReserve should return false (duplicate)")
	}
	if existing == nil {
		t.Fatal("existing should be returned for duplicate")
	}
	if existing.CloseCmd != "echo close1" {
		t.Errorf("existing.CloseCmd = %q, want %q", existing.CloseCmd, "echo close1")
	}

	// Only 1 entry in tracker
	if len(tracker.GetAll()) != 1 {
		t.Errorf("expected 1 entry, got %d", len(tracker.GetAll()))
	}
}

// ========================================================================
// Port close balance tests -- the original bug scenario
// ========================================================================

// TestPortCloseBalance reproduces the original bug:
// 5 identical open-t22 knocks should produce exactly 1 tracked entry,
// and removing that entry should leave the tracker empty (1 open = 1 close).
func TestPortCloseBalance(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	logger := log.New(os.Stdout, "[test] ", 0)
	tracker := NewTracker(statePath, logger, true)

	for i := 0; i < 5; i++ {
		entry := &PortEntry{
			IP: "192.168.1.50", Port: "t22", Proto: "tcp", PortNum: "22",
			OpenedAt: time.Now(), ExpiresAt: time.Now().Add(30 * time.Second),
			Command: "iptables -A INPUT ...", CloseCmd: "iptables -D INPUT ...",
		}
		reserved, _ := tracker.TryReserve(entry)
		if i == 0 && !reserved {
			t.Fatal("first TryReserve must succeed")
		}
		if i > 0 && reserved {
			t.Errorf("TryReserve #%d should return false (duplicate)", i+1)
		}
	}

	all := tracker.GetAll()
	if len(all) != 1 {
		t.Fatalf("5 identical knocks should produce exactly 1 entry, got %d", len(all))
	}

	// Simulate the single close
	tracker.Remove("192.168.1.50", "22", "tcp")
	if len(tracker.GetAll()) != 0 {
		t.Error("tracker should be empty after removing the single entry")
	}
}

// TestPortCloseBalanceOpenAll tests dedup for the "open-all" / "close-all" command.
func TestPortCloseBalanceOpenAll(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	logger := log.New(os.Stdout, "[test] ", 0)
	tracker := NewTracker(statePath, logger, true)

	for i := 0; i < 3; i++ {
		entry := &PortEntry{
			IP: "10.0.0.1", Port: "all", Proto: "all", PortNum: "all",
			OpenedAt: time.Now(), ExpiresAt: time.Now().Add(30 * time.Second),
			Command: "iptables -A ...", CloseCmd: "iptables -D ...",
		}
		reserved, _ := tracker.TryReserve(entry)
		if i == 0 && !reserved {
			t.Fatal("first TryReserve must succeed")
		}
		if i > 0 && reserved {
			t.Errorf("TryReserve #%d should return false (duplicate)", i+1)
		}
	}

	if len(tracker.GetAll()) != 1 {
		t.Fatalf("expected exactly 1 entry for repeated open-all, got %d", len(tracker.GetAll()))
	}
}

// TestPortCloseBalanceMixed tests that different port specs create distinct entries.
func TestPortCloseBalanceMixed(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	logger := log.New(os.Stdout, "[test] ", 0)
	tracker := NewTracker(statePath, logger, true)

	specs := []struct {
		port, proto, portNum string
	}{
		{"t22", "tcp", "22"},
		{"t80", "tcp", "80"},
		{"u53", "udp", "53"},
	}
	for _, s := range specs {
		entry := &PortEntry{
			IP: "10.0.0.1", Port: s.port, Proto: s.proto, PortNum: s.portNum,
			ExpiresAt: time.Now().Add(1 * time.Hour),
		}
		reserved, _ := tracker.TryReserve(entry)
		if !reserved {
			t.Errorf("TryReserve for %s should succeed", s.port)
		}
	}

	if len(tracker.GetAll()) != 3 {
		t.Errorf("expected 3 distinct entries, got %d", len(tracker.GetAll()))
	}

	// Duplicate each -- should all be rejected
	for _, s := range specs {
		entry := &PortEntry{
			IP: "10.0.0.1", Port: s.port, Proto: s.proto, PortNum: s.portNum,
			ExpiresAt: time.Now().Add(1 * time.Hour),
		}
		reserved, _ := tracker.TryReserve(entry)
		if reserved {
			t.Errorf("duplicate TryReserve for %s should be rejected", s.port)
		}
	}

	if len(tracker.GetAll()) != 3 {
		t.Errorf("still expected 3 entries after duplicates, got %d", len(tracker.GetAll()))
	}
}

// ========================================================================
// Concurrent TryReserve tests
// ========================================================================

func TestTryReserveConcurrent(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	logger := log.New(os.Stdout, "[test] ", 0)
	tracker := NewTracker(statePath, logger, true)

	const goroutines = 20
	var wg sync.WaitGroup
	reservedCount := make(chan bool, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			entry := &PortEntry{
				IP: "10.0.0.1", Port: "t22", Proto: "tcp", PortNum: "22",
				ExpiresAt: time.Now().Add(1 * time.Hour),
			}
			reserved, _ := tracker.TryReserve(entry)
			reservedCount <- reserved
		}()
	}

	wg.Wait()
	close(reservedCount)

	wins := 0
	for r := range reservedCount {
		if r {
			wins++
		}
	}

	if wins != 1 {
		t.Errorf("exactly 1 goroutine should win TryReserve, got %d", wins)
	}
	if len(tracker.GetAll()) != 1 {
		t.Errorf("expected 1 entry, got %d", len(tracker.GetAll()))
	}
}

// TestTryReserveConcurrentDifferentPorts tests that concurrent reservations
// for different ports all succeed.
func TestTryReserveConcurrentDifferentPorts(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	logger := log.New(os.Stdout, "[test] ", 0)
	tracker := NewTracker(statePath, logger, true)

	const portCount = 10
	var wg sync.WaitGroup
	failures := make(chan string, portCount)

	for i := 1; i <= portCount; i++ {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			entry := &PortEntry{
				IP: "10.0.0.1", Port: fmt.Sprintf("t%d", port),
				Proto: "tcp", PortNum: fmt.Sprintf("%d", port),
				ExpiresAt: time.Now().Add(1 * time.Hour),
			}
			reserved, _ := tracker.TryReserve(entry)
			if !reserved {
				failures <- fmt.Sprintf("port %d", port)
			}
		}(i)
	}

	wg.Wait()
	close(failures)

	for f := range failures {
		t.Errorf("TryReserve should succeed for distinct %s", f)
	}
	if len(tracker.GetAll()) != portCount {
		t.Errorf("expected %d entries, got %d", portCount, len(tracker.GetAll()))
	}
}

func TestTrackerConcurrentRefreshAndReadStability(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	logger := log.New(os.Stdout, "[test] ", 0)
	tracker := NewTracker(statePath, logger, true)

	tracker.Add(&PortEntry{
		IP: "10.0.0.10", Port: "t22", Proto: "tcp", PortNum: "22",
		ExpiresAt: time.Now().Add(1 * time.Minute),
	})

	const goroutines = 40
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			future := time.Now().Add(time.Duration(2+idx%5) * time.Minute)
			tracker.RefreshExpiry("10.0.0.10", "22", "tcp", future)
			_ = tracker.GetExpired()
			_ = tracker.GetAll()
			_ = tracker.Has("10.0.0.10", "22", "tcp")
		}(i)
	}
	wg.Wait()

	if !tracker.Has("10.0.0.10", "22", "tcp") {
		t.Fatal("tracked entry disappeared during concurrent refresh/read operations")
	}
	if len(tracker.GetExpired()) != 0 {
		t.Fatal("entry should not be expired after concurrent refresh operations")
	}
}

// ========================================================================
// ExecuteCommandTimeout tests
// ========================================================================

func TestExecuteCommandTimeoutSuccess(t *testing.T) {
	out, err := ExecuteCommandTimeout("echo hello", 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out != "hello" {
		t.Errorf("output = %q, want %q", out, "hello")
	}
}

func TestExecuteCommandTimeoutEmpty(t *testing.T) {
	out, err := ExecuteCommandTimeout("", 5*time.Second)
	if err != nil {
		t.Errorf("empty command should not error: %v", err)
	}
	if out != "" {
		t.Errorf("output = %q, want empty", out)
	}
}

func TestExecuteCommandTimeoutExceeded(t *testing.T) {
	// Use a command that would hang long enough to exceed the timeout.
	// On Windows, "waitfor /T 30 __never__" blocks for ~30s.
	// On Unix, "sleep 30" blocks.
	var cmd string
	if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		cmd = "sleep 30"
	} else {
		cmd = "waitfor /T 30 __never__"
	}

	start := time.Now()
	_, err := ExecuteCommandTimeout(cmd, 200*time.Millisecond)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if elapsed > 5*time.Second {
		t.Errorf("command took %v; should have been killed near 200ms", elapsed)
	}
}

func TestExecuteCommandTimeoutFailure(t *testing.T) {
	_, err := ExecuteCommandTimeout("exit 1", 5*time.Second)
	if err == nil {
		t.Fatal("expected error for exit 1")
	}
}

func TestExecuteCommandTimeoutZeroDefaultsTo30s(t *testing.T) {
	// With timeout=0, ExecuteCommandTimeout should default to 30s
	// We just verify it doesn't panic and the command succeeds
	out, err := ExecuteCommandTimeout("echo ok", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out != "ok" {
		t.Errorf("output = %q, want %q", out, "ok")
	}
}

// ========================================================================
// Command validation tests (server-side)
// ========================================================================

func TestValidateCommandServerValid(t *testing.T) {
	tests := []struct {
		cmd      string
		wantType string
		wantData string
	}{
		{"open-t22", "open", "t22"},
		{"open-t22,u53", "open", "t22,u53"},
		{"open-all", "open", "all"},
		{"close-t80", "close", "t80"},
		{"close-all", "close", "all"},
		{"cust-mycommand", "cust", "mycommand"},
		{"OPEN-T22", "open", "t22"},     // case-insensitive
		{"Close-T443", "close", "t443"}, // mixed case
	}

	for _, tt := range tests {
		cmdType, data, err := validateCommandServer(tt.cmd)
		if err != nil {
			t.Errorf("validateCommandServer(%q) error: %v", tt.cmd, err)
			continue
		}
		if cmdType != tt.wantType {
			t.Errorf("validateCommandServer(%q) type = %q, want %q", tt.cmd, cmdType, tt.wantType)
		}
		if data != tt.wantData {
			t.Errorf("validateCommandServer(%q) data = %q, want %q", tt.cmd, data, tt.wantData)
		}
	}
}

func TestValidateCommandServerInvalid(t *testing.T) {
	tests := []string{
		"",
		"unknown-t22",
		"openx-t22",
		"open-",       // empty port spec
		"open-t0",     // port 0
		"open-t65536", // port > 65535
		"open-x22",    // invalid protocol prefix
		"open-tabc",   // non-numeric port
		"cust-",       // empty custom command ID
	}

	for _, cmd := range tests {
		_, _, err := validateCommandServer(cmd)
		if err == nil {
			t.Errorf("validateCommandServer(%q) should return error", cmd)
		}
	}
}

func TestValidatePortSpecsServerEdgeCases(t *testing.T) {
	tests := []struct {
		specs   string
		wantErr bool
	}{
		{"t1", false},
		{"t65535", false},
		{"u1", false},
		{"u65535", false},
		{"t22,u53", false},
		{"all", false},
		{"t22,all,u53", false},
		{"t0", true},
		{"t65536", true},
		{"t99999", true},
		{"", true},
		{"t", true},
		{"22", true}, // missing protocol prefix
	}

	for _, tt := range tests {
		err := validatePortSpecsServer(tt.specs)
		if (err != nil) != tt.wantErr {
			t.Errorf("validatePortSpecsServer(%q) err=%v, wantErr=%v", tt.specs, err, tt.wantErr)
		}
	}
}

func TestValidateASCIIServer(t *testing.T) {
	tests := []struct {
		input   string
		wantErr bool
	}{
		{"hello", false},
		{"my-command_1", false},
		{"!@#$%^&*()", false},
		{"", true},                   // empty
		{string([]byte{0x00}), true}, // null byte
		{string([]byte{0x1F}), true}, // control character
		{string([]byte{0x7F}), true}, // DEL
		{"\xe2\x80\x93", true},       // em-dash (multi-byte UTF-8)
	}

	for _, tt := range tests {
		err := validateASCIIServer(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("validateASCIIServer(%q) err=%v, wantErr=%v", tt.input, err, tt.wantErr)
		}
	}
}

// ========================================================================
// commandTimeout helper test
// ========================================================================

func TestCommandTimeoutHelper(t *testing.T) {
	// Zero value should return default 500ms
	cfg := &config.Config{}
	d := commandTimeout(cfg)
	if d != 500*time.Millisecond {
		t.Errorf("commandTimeout(zero) = %v, want 500ms", d)
	}

	// Configured value
	cfg.CommandTimeout = 2.0
	d = commandTimeout(cfg)
	if d != 2*time.Second {
		t.Errorf("commandTimeout(2.0) = %v, want 2s", d)
	}

	// Sub-second value (0.1s)
	cfg.CommandTimeout = 0.1
	d = commandTimeout(cfg)
	if d != 100*time.Millisecond {
		t.Errorf("commandTimeout(0.1) = %v, want 100ms", d)
	}
}

// ========================================================================
// Tracker with custom cmdTimeout
// ========================================================================

func TestNewTrackerCustomTimeout(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	logger := log.New(os.Stdout, "[test] ", 0)

	// Custom timeout of 5 seconds
	tracker := NewTracker(statePath, logger, true, 5*time.Second)
	if tracker.cmdTimeout != 5*time.Second {
		t.Errorf("cmdTimeout = %v, want 5s", tracker.cmdTimeout)
	}
}

func TestNewTrackerDefaultTimeout(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	logger := log.New(os.Stdout, "[test] ", 0)

	tracker := NewTracker(statePath, logger, true)
	if tracker.cmdTimeout != 30*time.Second {
		t.Errorf("cmdTimeout = %v, want 30s", tracker.cmdTimeout)
	}
}

// ========================================================================
// TryReserve + Remove rollback pattern test
// ========================================================================

func TestTryReserveRemoveRollback(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	logger := log.New(os.Stdout, "[test] ", 0)
	tracker := NewTracker(statePath, logger, true)

	entry := &PortEntry{
		IP: "10.0.0.1", Port: "t22", Proto: "tcp", PortNum: "22",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	// Reserve succeeds
	reserved, _ := tracker.TryReserve(entry)
	if !reserved {
		t.Fatal("first TryReserve must succeed")
	}

	// Simulate command failure -> rollback by removing
	tracker.Remove("10.0.0.1", "22", "tcp")

	// Now a second attempt should succeed (entry was rolled back)
	reserved2, _ := tracker.TryReserve(entry)
	if !reserved2 {
		t.Error("TryReserve after rollback should succeed")
	}
}
