// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package server

import (
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestBuildCommand(t *testing.T) {
	tests := []struct {
		template string
		ip       string
		port     string
		proto    string
		want     string
	}{
		{
			"iptables -A INPUT -p tcp --dport {{PORT}} -s {{IP}} -j ACCEPT",
			"192.168.1.100", "22", "tcp",
			"iptables -A INPUT -p tcp --dport 22 -s 192.168.1.100 -j ACCEPT",
		},
		{
			`netsh advfirewall firewall add rule name="SPK_{{IP}}_{{PORT}}" dir=in action=allow protocol={{PROTO}} localport={{PORT}} remoteip={{IP}}`,
			"10.0.0.5", "443", "tcp",
			`netsh advfirewall firewall add rule name="SPK_10.0.0.5_443" dir=in action=allow protocol=tcp localport=443 remoteip=10.0.0.5`,
		},
		{"", "1.2.3.4", "80", "tcp", ""},
	}

	for _, tt := range tests {
		got := BuildCommand(tt.template, tt.ip, tt.port, tt.proto)
		if got != tt.want {
			t.Errorf("BuildCommand(%q, %q, %q, %q) = %q, want %q",
				tt.template, tt.ip, tt.port, tt.proto, got, tt.want)
		}
	}
}

func TestParsePortSpec(t *testing.T) {
	tests := []struct {
		spec      string
		wantProto string
		wantPort  string
		wantErr   bool
	}{
		{"t22", "tcp", "22", false},
		{"T443", "tcp", "443", false},
		{"u53", "udp", "53", false},
		{"U8080", "udp", "8080", false},
		{"x99", "", "", true},  // Invalid prefix
		{"t", "", "", true},    // Too short
		{"", "", "", true},     // Empty
		{"tabc", "", "", true}, // Non-numeric port
	}

	for _, tt := range tests {
		proto, port, err := parsePortSpec(tt.spec)
		if tt.wantErr {
			if err == nil {
				t.Errorf("parsePortSpec(%q) expected error", tt.spec)
			}
			continue
		}
		if err != nil {
			t.Errorf("parsePortSpec(%q) error: %v", tt.spec, err)
			continue
		}
		if proto != tt.wantProto {
			t.Errorf("parsePortSpec(%q) proto = %q, want %q", tt.spec, proto, tt.wantProto)
		}
		if port != tt.wantPort {
			t.Errorf("parsePortSpec(%q) port = %q, want %q", tt.spec, port, tt.wantPort)
		}
	}
}

func TestTracker(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	logger := log.New(os.Stdout, "[test] ", 0)
	tracker := NewTracker(statePath, logger, true)

	// Add entry
	entry := &PortEntry{
		IP:        "192.168.1.100",
		Port:      "t22",
		Proto:     "tcp",
		PortNum:   "22",
		OpenedAt:  time.Now(),
		ExpiresAt: time.Now().Add(1 * time.Hour),
		Command:   "test-open",
		CloseCmd:  "test-close",
	}
	tracker.Add(entry)

	// Get by IP
	entries := tracker.GetByIP("192.168.1.100")
	if len(entries) != 1 {
		t.Errorf("GetByIP found %d entries, want 1", len(entries))
	}

	// Get all
	all := tracker.GetAll()
	if len(all) != 1 {
		t.Errorf("GetAll found %d entries, want 1", len(all))
	}

	// Not expired
	expired := tracker.GetExpired()
	if len(expired) != 0 {
		t.Errorf("GetExpired found %d entries, want 0", len(expired))
	}

	// Remove
	tracker.Remove("192.168.1.100", "22", "tcp")
	all = tracker.GetAll()
	if len(all) != 0 {
		t.Errorf("after remove: GetAll found %d entries, want 0", len(all))
	}
}

func TestTrackerExpiry(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	logger := log.New(os.Stdout, "[test] ", 0)
	tracker := NewTracker(statePath, logger, true)

	// Add entry that's already expired
	entry := &PortEntry{
		IP:        "10.0.0.1",
		Port:      "t80",
		Proto:     "tcp",
		PortNum:   "80",
		OpenedAt:  time.Now().Add(-2 * time.Hour),
		ExpiresAt: time.Now().Add(-1 * time.Hour),
		Command:   "test-open",
		CloseCmd:  "echo closed",
	}
	tracker.Add(entry)

	expired := tracker.GetExpired()
	if len(expired) != 1 {
		t.Errorf("GetExpired found %d entries, want 1", len(expired))
	}
}

func TestTrackerStateRecovery(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	logger := log.New(os.Stdout, "[test] ", 0)

	// Create tracker with an entry
	tracker1 := NewTracker(statePath, logger, true)
	tracker1.Add(&PortEntry{
		IP:        "10.0.0.1",
		Port:      "t22",
		Proto:     "tcp",
		PortNum:   "22",
		OpenedAt:  time.Now(),
		ExpiresAt: time.Now().Add(1 * time.Hour),
		Command:   "iptables -A INPUT -p tcp --dport 22 -s 10.0.0.1 -j ACCEPT",
		CloseCmd:  "iptables -D INPUT -p tcp --dport 22 -s 10.0.0.1 -j ACCEPT",
	})

	// Create new tracker from same state file (simulates restart)
	tracker2 := NewTracker(statePath, logger, true)
	entries := tracker2.GetAll()
	if len(entries) != 1 {
		t.Errorf("recovered %d entries, want 1", len(entries))
	}
	if len(entries) > 0 && entries[0].IP != "10.0.0.1" {
		t.Error("recovered entry has wrong IP")
	}
}

func TestIsIPv6(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"192.168.1.1", false},
		{"10.0.0.1", false},
		{"127.0.0.1", false},
		{"::1", true},
		{"2001:db8::1", true},
		{"fe80::1", true},
		{"::ffff:192.168.1.1", false}, // IPv4-mapped IPv6 -> treated as IPv4
		{"", false},
		{"invalid", false},
	}

	for _, tt := range tests {
		got := isIPv6(tt.ip)
		if got != tt.want {
			t.Errorf("isIPv6(%q) = %v, want %v", tt.ip, got, tt.want)
		}
	}
}

func TestBuildCommandIPv6(t *testing.T) {
	// Test that IPv6 addresses work correctly in commands
	cmd := BuildCommand("ip6tables -A INPUT -p tcp --dport {{PORT}} -s {{IP}} -j ACCEPT",
		"2001:db8::1", "22", "tcp")
	want := "ip6tables -A INPUT -p tcp --dport 22 -s 2001:db8::1 -j ACCEPT"
	if cmd != want {
		t.Errorf("BuildCommand IPv6 = %q, want %q", cmd, want)
	}
}

func TestExecuteCommandOutput(t *testing.T) {
	// Test that ExecuteCommand returns output
	output, err := ExecuteCommand("echo hello")
	if err != nil {
		t.Fatalf("ExecuteCommand: %v", err)
	}
	if output != "hello" {
		t.Errorf("output = %q, want %q", output, "hello")
	}
}

func TestExecuteCommandEmpty(t *testing.T) {
	output, err := ExecuteCommand("")
	if err != nil {
		t.Errorf("ExecuteCommand empty should not error: %v", err)
	}
	if output != "" {
		t.Errorf("output = %q, want empty", output)
	}
}

// --- Tracker CloseAll and concurrent access tests ---

func TestTrackerCloseAll(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	logger := log.New(os.Stdout, "[test] ", 0)
	tracker := NewTracker(statePath, logger, true)

	// Add 3 entries
	for i, spec := range []struct {
		ip, port, portNum string
	}{
		{"10.0.0.1", "t22", "22"},
		{"10.0.0.2", "t80", "80"},
		{"10.0.0.3", "u53", "53"},
	} {
		tracker.Add(&PortEntry{
			IP:        spec.ip,
			Port:      spec.port,
			Proto:     "tcp",
			PortNum:   spec.portNum,
			OpenedAt:  time.Now(),
			ExpiresAt: time.Now().Add(1 * time.Hour),
			Command:   "echo open",
			CloseCmd:  "echo close",
		})
		_ = i
	}

	if len(tracker.GetAll()) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(tracker.GetAll()))
	}

	tracker.CloseAll()

	if len(tracker.GetAll()) != 0 {
		t.Errorf("expected 0 entries after CloseAll, got %d", len(tracker.GetAll()))
	}
}

func TestTrackerConcurrentAddRemove(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	logger := log.New(os.Stdout, "[test] ", 0)
	tracker := NewTracker(statePath, logger, true)

	var wg sync.WaitGroup

	// 10 goroutines adding entries concurrently
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			entry := &PortEntry{
				IP:        "10.0.0.1",
				Port:      "t22",
				Proto:     "tcp",
				PortNum:   "22",
				OpenedAt:  time.Now(),
				ExpiresAt: time.Now().Add(1 * time.Hour),
				Command:   "echo open",
				CloseCmd:  "echo close",
			}
			tracker.Add(entry)
			tracker.GetAll()
			tracker.GetByIP("10.0.0.1")
			tracker.GetExpired()
		}(i)
	}

	// 5 goroutines removing entries concurrently
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tracker.Remove("10.0.0.1", "22", "tcp")
		}()
	}

	wg.Wait()
	// No panic, no data race - test passes if we get here
}

func TestTrackerCorruptedStateFile(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "state.json")

	// Write invalid JSON
	if err := os.WriteFile(statePath, []byte("{{invalid json!!"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	logger := log.New(os.Stdout, "[test] ", 0)
	tracker := NewTracker(statePath, logger, true) // Should not panic

	// Tracker should be empty (fresh start)
	entries := tracker.GetAll()
	if len(entries) != 0 {
		t.Errorf("expected 0 entries on corrupted state, got %d", len(entries))
	}
}

func TestBuildCommandProtoPlaceholder(t *testing.T) {
	cmd := BuildCommand("firewall add rule proto={{PROTO}} port={{PORT}} ip={{IP}}",
		"10.0.0.1", "80", "tcp")
	want := "firewall add rule proto=tcp port=80 ip=10.0.0.1"
	if cmd != want {
		t.Errorf("got %q, want %q", cmd, want)
	}
}

func TestBuildCommandMultipleSamePlaceholder(t *testing.T) {
	cmd := BuildCommand("rule ip1={{IP}} ip2={{IP}}", "10.0.0.1", "80", "tcp")
	want := "rule ip1=10.0.0.1 ip2=10.0.0.1"
	if cmd != want {
		t.Errorf("got %q, want %q", cmd, want)
	}
}

func TestBuildCommandInvalidProto(t *testing.T) {
	cmd := BuildCommand("rule proto={{PROTO}}", "10.0.0.1", "80", "icmp")
	if cmd != "" {
		t.Errorf("expected empty for invalid proto, got %q", cmd)
	}
}

func TestBuildCommandEmptyIP(t *testing.T) {
	// Empty IP is allowed (substitutes empty string into template)
	cmd := BuildCommand("rule ip={{IP}}", "", "80", "tcp")
	want := "rule ip="
	if cmd != want {
		t.Errorf("got %q, want %q", cmd, want)
	}
}

func TestBuildCommandInvalidPort(t *testing.T) {
	cmd := BuildCommand("rule port={{PORT}}", "10.0.0.1", "22;whoami", "tcp")
	if cmd != "" {
		t.Errorf("expected empty for injection in port, got %q", cmd)
	}
}

func TestEntryKeyFormat(t *testing.T) {
	got := entryKey("10.0.0.1", "22", "tcp")
	want := "10.0.0.1:22:tcp"
	if got != want {
		t.Errorf("entryKey = %q, want %q", got, want)
	}
}

func TestTrackerAddDuplicateOverwrites(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "state.json")
	logger := log.New(os.Stdout, "[test] ", 0)
	tracker := NewTracker(statePath, logger, true)

	expires := time.Now().Add(1 * time.Hour)
	tracker.Add(&PortEntry{IP: "10.0.0.1", PortNum: "22", Proto: "tcp", CloseCmd: "cmd1", ExpiresAt: expires})
	tracker.Add(&PortEntry{IP: "10.0.0.1", PortNum: "22", Proto: "tcp", CloseCmd: "cmd2", ExpiresAt: expires})

	all := tracker.GetAll()
	if len(all) != 1 {
		t.Fatalf("expected 1 entry after duplicate add, got %d", len(all))
	}
	if all[0].CloseCmd != "cmd2" {
		t.Errorf("CloseCmd = %q, want %q", all[0].CloseCmd, "cmd2")
	}
}

func TestTrackerGetByIPNoMatch(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "state.json")
	logger := log.New(os.Stdout, "[test] ", 0)
	tracker := NewTracker(statePath, logger, true)

	tracker.Add(&PortEntry{IP: "10.0.0.1", PortNum: "22", Proto: "tcp", CloseCmd: "cmd", ExpiresAt: time.Now().Add(1 * time.Hour)})
	entries := tracker.GetByIP("10.0.0.2")
	if len(entries) != 0 {
		t.Errorf("expected 0 entries for non-matching IP, got %d", len(entries))
	}
}

func TestTrackerGetByIPMultiplePorts(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "state.json")
	logger := log.New(os.Stdout, "[test] ", 0)
	tracker := NewTracker(statePath, logger, true)

	expires := time.Now().Add(1 * time.Hour)
	tracker.Add(&PortEntry{IP: "10.0.0.1", PortNum: "22", Proto: "tcp", CloseCmd: "cmd1", ExpiresAt: expires})
	tracker.Add(&PortEntry{IP: "10.0.0.1", PortNum: "80", Proto: "tcp", CloseCmd: "cmd2", ExpiresAt: expires})
	tracker.Add(&PortEntry{IP: "10.0.0.1", PortNum: "443", Proto: "tcp", CloseCmd: "cmd3", ExpiresAt: expires})

	entries := tracker.GetByIP("10.0.0.1")
	if len(entries) != 3 {
		t.Errorf("expected 3 entries, got %d", len(entries))
	}
}

func TestTrackerRemoveNonExistent(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "state.json")
	logger := log.New(os.Stdout, "[test] ", 0)
	tracker := NewTracker(statePath, logger, true)

	tracker.Add(&PortEntry{IP: "10.0.0.1", PortNum: "22", Proto: "tcp", CloseCmd: "cmd", ExpiresAt: time.Now().Add(1 * time.Hour)})
	tracker.Remove("10.0.0.2", "80", "tcp") // doesn't exist

	all := tracker.GetAll()
	if len(all) != 1 {
		t.Errorf("expected 1 entry after removing non-existent, got %d", len(all))
	}
}

func TestTrackerStatePersistenceRoundTrip(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "state.json")
	logger := log.New(os.Stdout, "[test] ", 0)

	// Create tracker and add entries with allowlisted close commands
	tracker1 := NewTracker(statePath, logger, false)
	expires := time.Now().Add(1 * time.Hour)
	tracker1.Add(&PortEntry{IP: "10.0.0.1", PortNum: "22", Proto: "tcp", CloseCmd: "iptables -D INPUT -p tcp --dport 22 -s 10.0.0.1 -j ACCEPT", ExpiresAt: expires})
	tracker1.Add(&PortEntry{IP: "10.0.0.2", PortNum: "80", Proto: "tcp", CloseCmd: "iptables -D INPUT -p tcp --dport 80 -s 10.0.0.2 -j ACCEPT", ExpiresAt: expires})

	// Create new tracker from same state file
	tracker2 := NewTracker(statePath, logger, false)
	all := tracker2.GetAll()
	if len(all) != 2 {
		t.Fatalf("expected 2 recovered entries, got %d", len(all))
	}
}

func TestTrackerRecoveryNoStateFile(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "nonexistent.json")
	logger := log.New(os.Stdout, "[test] ", 0)
	tracker := NewTracker(statePath, logger, true)

	all := tracker.GetAll()
	if len(all) != 0 {
		t.Errorf("expected 0 entries for missing state file, got %d", len(all))
	}
}

func TestTrackerRecoveryEmptyJSON(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "state.json")
	os.WriteFile(statePath, []byte("{}"), 0600)
	logger := log.New(os.Stdout, "[test] ", 0)
	tracker := NewTracker(statePath, logger, true)

	all := tracker.GetAll()
	if len(all) != 0 {
		t.Errorf("expected 0 entries for empty JSON, got %d", len(all))
	}
}

// ========================================================================
// ExecuteCommandTimeout -- process group kill test
// ========================================================================

// TestExecuteCommandTimeoutKillsChildren verifies that the timeout actually
// terminates long-running child processes (the root cause of the Linux
// "timeout never fires" bug where sh was killed but ping survived, and the
// Windows bug where cmd.exe was killed but ping.exe survived).
// Works cross-platform: uses "sleep 60" on Unix, "ping -n 60 127.0.0.1" on Windows.
func TestExecuteCommandTimeoutKillsChildren(t *testing.T) {
	var cmd string
	if runtime.GOOS == "windows" {
		// ping -n 60 sends 60 ICMP packets (~60s). cmd.exe spawns ping.exe as a child.
		// taskkill /T /F /PID must kill both cmd.exe AND ping.exe.
		cmd = "ping -n 60 127.0.0.1"
	} else {
		cmd = "sleep 60"
	}

	start := time.Now()
	_, err := ExecuteCommandTimeout(cmd, 500*time.Millisecond)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("expected timeout error, got: %v", err)
	}
	// Must complete in well under 60s. Allow generous margin for CI.
	if elapsed > 5*time.Second {
		t.Fatalf("command took %v; should have been killed at ~500ms", elapsed)
	}
}

// TestExecuteCommandTimeoutCompletesBeforeDeadline verifies that a fast command
// returns its output normally without being killed by the timeout.
func TestExecuteCommandTimeoutCompletesBeforeDeadline(t *testing.T) {
	var cmd string
	var want string
	if runtime.GOOS == "windows" {
		cmd = "echo hello"
		want = "hello"
	} else {
		cmd = "echo hello"
		want = "hello"
	}

	output, err := ExecuteCommandTimeout(cmd, 5*time.Second)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if !strings.Contains(output, want) {
		t.Errorf("output %q does not contain %q", output, want)
	}
}

// TestExecuteCommandTimeoutZeroMeansNoTimeout verifies that a zero timeout
// lets the command run to completion (no deadline).
func TestExecuteCommandTimeoutZeroMeansNoTimeout(t *testing.T) {
	var cmd string
	if runtime.GOOS == "windows" {
		cmd = "echo done"
	} else {
		cmd = "echo done"
	}

	output, err := ExecuteCommandTimeout(cmd, 0)
	if err != nil {
		t.Fatalf("expected no error with zero timeout, got: %v", err)
	}
	if !strings.Contains(output, "done") {
		t.Errorf("output %q does not contain 'done'", output)
	}
}

// TestExecuteCommandTimeoutReturnsPartialOutput verifies that when a command
// times out, any output produced before the timeout is still captured and
// returned. This is essential for CMD-OUTPUT logging on timed-out commands.
func TestExecuteCommandTimeoutReturnsPartialOutput(t *testing.T) {
	var cmd string
	if runtime.GOOS == "windows" {
		// echo writes immediately, then ping runs for 60s
		cmd = "echo partial_before_timeout && ping -n 60 127.0.0.1"
	} else {
		// echo writes immediately, then sleep blocks for 60s
		cmd = "echo partial_before_timeout && sleep 60"
	}

	start := time.Now()
	output, err := ExecuteCommandTimeout(cmd, 500*time.Millisecond)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("expected timeout error, got: %v", err)
	}
	// Verify the partial output was captured
	if !strings.Contains(output, "partial_before_timeout") {
		t.Errorf("expected partial output to contain 'partial_before_timeout', got: %q", output)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("command took %v; should have been killed at ~500ms", elapsed)
	}
}

// TestExecuteCommandTimeoutOutputOnNormalFailure verifies that output is
// captured even when the command exits with a non-zero exit code (not timeout).
func TestExecuteCommandTimeoutOutputOnNormalFailure(t *testing.T) {
	var cmd string
	if runtime.GOOS == "windows" {
		cmd = "echo fail_output && exit /b 1"
	} else {
		cmd = "echo fail_output && exit 1"
	}

	output, err := ExecuteCommandTimeout(cmd, 5*time.Second)
	if err == nil {
		t.Fatal("expected error from non-zero exit, got nil")
	}
	if !strings.Contains(output, "fail_output") {
		t.Errorf("expected output to contain 'fail_output', got: %q", output)
	}
}

// TestExecuteCommandTimeoutStartFailure verifies that an invalid command
// returns an error from Start, not a hang.
func TestExecuteCommandTimeoutStartFailure(t *testing.T) {
	// Use a command name that definitely does not exist.
	_, err := ExecuteCommandTimeout("__nonexistent_binary_xyz__", 1*time.Second)
	// On Unix this goes through sh -c so it may return exit-code error, not start error.
	// Either way, it must not hang and must return an error.
	if err == nil {
		t.Fatal("expected error for nonexistent command")
	}
}

// ========================================================================
// Stop() idempotency test
// ========================================================================

// TestStopIdempotent verifies that calling Stop() multiple times does not
// panic. This matters because both the signal handler and the Windows service
// stopFn may race to call Stop().
func TestStopIdempotent(t *testing.T) {
	// We just call Stop() twice and verify no panic.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Stop() panicked on second call: %v", r)
		}
	}()
	Stop()
	Stop() // must not panic
}

// ---------------------------------------------------------------------------
// hexDecodePortSeed / hexByte / hexNibble
// ---------------------------------------------------------------------------

func TestHexNibble(t *testing.T) {
	tests := []struct {
		in   byte
		want byte
		ok   bool
	}{
		{'0', 0, true}, {'9', 9, true},
		{'a', 10, true}, {'f', 15, true},
		{'A', 10, true}, {'F', 15, true},
		{'g', 0, false}, {'z', 0, false}, {'/', 0, false},
	}
	for _, tt := range tests {
		got, err := hexNibble(tt.in)
		if tt.ok {
			if err != nil {
				t.Errorf("hexNibble(%q): unexpected error %v", tt.in, err)
			}
			if got != tt.want {
				t.Errorf("hexNibble(%q) = %d, want %d", tt.in, got, tt.want)
			}
		} else if err == nil {
			t.Errorf("hexNibble(%q) should error", tt.in)
		}
	}
}

func TestHexByte(t *testing.T) {
	got, err := hexByte('a', 'b')
	if err != nil || got != 0xab {
		t.Errorf("hexByte('a','b') = 0x%x, err=%v; want 0xab", got, err)
	}
	_, err = hexByte('g', '0')
	if err == nil {
		t.Error("hexByte('g','0') should error")
	}
}

func TestHexDecodePortSeed(t *testing.T) {
	// Valid 16-char hex = 8 bytes
	seed, err := hexDecodePortSeed("0102030405060708")
	if err != nil {
		t.Fatalf("hexDecodePortSeed: %v", err)
	}
	if len(seed) != 8 {
		t.Fatalf("seed length = %d, want 8", len(seed))
	}
	if seed[0] != 1 || seed[7] != 8 {
		t.Errorf("seed = %x, want 0102030405060708", seed)
	}

	// Too short
	_, err = hexDecodePortSeed("0102")
	if err == nil {
		t.Error("hexDecodePortSeed too-short should error")
	}

	// Invalid hex char
	_, err = hexDecodePortSeed("0102030405060g08")
	if err == nil {
		t.Error("hexDecodePortSeed invalid hex should error")
	}
}

// ---------------------------------------------------------------------------
// maxConcurrentKnocks constant validation
// ---------------------------------------------------------------------------

func TestMaxConcurrentKnocksValue(t *testing.T) {
	if maxConcurrentKnocks < 1 {
		t.Errorf("maxConcurrentKnocks = %d, must be >= 1", maxConcurrentKnocks)
	}
	if maxConcurrentKnocks != 9999 {
		t.Errorf("maxConcurrentKnocks = %d, want 9999", maxConcurrentKnocks)
	}
}

func TestKnockSemaphoreBehavior(t *testing.T) {
	// Verify semaphore pattern works: fill pool, verify overflow is non-blocking
	sem := make(chan struct{}, 3)
	// Fill the semaphore
	for i := 0; i < 3; i++ {
		sem <- struct{}{}
	}
	// Next send should not block (select with default)
	dropped := false
	select {
	case sem <- struct{}{}:
		t.Error("should not be able to send to full semaphore")
	default:
		dropped = true
	}
	if !dropped {
		t.Error("overflow should have been dropped")
	}
	// Drain one slot
	<-sem
	// Now should accept
	select {
	case sem <- struct{}{}:
		// ok
	default:
		t.Error("should accept after draining one slot")
	}
}

// ---------------------------------------------------------------------------
// validateCommandServer tests
// ---------------------------------------------------------------------------

func TestValidateCommandServerOpen(t *testing.T) {
	cmdType, data, err := validateCommandServer("open-t22")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cmdType != "open" || data != "t22" {
		t.Errorf("got type=%q data=%q, want open/t22", cmdType, data)
	}
}

func TestValidateCommandServerClose(t *testing.T) {
	cmdType, data, err := validateCommandServer("close-t22,u53")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cmdType != "close" || data != "t22,u53" {
		t.Errorf("got type=%q data=%q, want close/t22,u53", cmdType, data)
	}
}

func TestValidateCommandServerCustom(t *testing.T) {
	cmdType, data, err := validateCommandServer("cust-reboot")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cmdType != "cust" || data != "reboot" {
		t.Errorf("got type=%q data=%q, want cust/reboot", cmdType, data)
	}
}

func TestValidateCommandServerUnsupportedPrefix(t *testing.T) {
	_, _, err := validateCommandServer("invalid-cmd")
	if err == nil {
		t.Error("expected error for unsupported command type")
	}
}

func TestValidateCommandServerInjection(t *testing.T) {
	// Port spec with injection attempt
	_, _, err := validateCommandServer("open-t22;rm -rf /")
	if err == nil {
		t.Error("expected error for injection in port spec")
	}
}

func TestSanitizeForLogReplacesNonPrintable(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"hello", "hello"},
		{"test\x00inject", "test?inject"},
		{"line\nbreak", "line?break"},
		{"tab\there", "tab?here"},
		{"\x7fDEL", "?DEL"},
		{"normal ASCII 123!", "normal ASCII 123!"},
	}
	for _, tt := range tests {
		got := sanitizeForLog(tt.input)
		if got != tt.want {
			t.Errorf("sanitizeForLog(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
