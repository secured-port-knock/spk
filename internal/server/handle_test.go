// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package server

import (
	"bytes"
	"fmt"
	"log"
	"path/filepath"
	"testing"
	"time"

	"spk/internal/config"
)

// testLogger captures log output for verification.
type testLogger struct {
	buf bytes.Buffer
}

func (l *testLogger) Printf(format string, v ...interface{}) {
	fmt.Fprintf(&l.buf, format+"\n", v...)
}

// --- handleCloseAll tests ---

func TestHandleCloseAllNoPorts(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	stdLogger := log.New(&bytes.Buffer{}, "", 0)
	tracker := NewTracker(statePath, stdLogger, true)

	logger := &testLogger{}
	cfg := &config.Config{CommandTimeout: 0.5}

	handleCloseAll(logger, cfg, tracker, "10.0.0.1")

	if out := logger.buf.String(); out == "" {
		t.Error("expected log output for no open ports")
	}
}

func TestHandleCloseAllMultiplePorts(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	stdLogger := log.New(&bytes.Buffer{}, "", 0)
	tracker := NewTracker(statePath, stdLogger, true)

	expires := time.Now().Add(1 * time.Hour)
	tracker.Add(&PortEntry{
		IP: "10.0.0.1", Port: "t22", Proto: "tcp", PortNum: "22",
		ExpiresAt: expires, CloseCmd: "echo close22",
	})
	tracker.Add(&PortEntry{
		IP: "10.0.0.1", Port: "t443", Proto: "tcp", PortNum: "443",
		ExpiresAt: expires, CloseCmd: "echo close443",
	})
	// Different IP - should not be closed
	tracker.Add(&PortEntry{
		IP: "10.0.0.2", Port: "t80", Proto: "tcp", PortNum: "80",
		ExpiresAt: expires, CloseCmd: "echo close80",
	})

	logger := &testLogger{}
	cfg := &config.Config{CommandTimeout: 1}

	handleCloseAll(logger, cfg, tracker, "10.0.0.1")

	// Only 10.0.0.1 entries should be removed
	remaining := tracker.GetAll()
	if len(remaining) != 1 {
		t.Errorf("expected 1 remaining entry (10.0.0.2), got %d", len(remaining))
	}
	if len(remaining) > 0 && remaining[0].IP != "10.0.0.2" {
		t.Errorf("remaining entry IP = %q, want 10.0.0.2", remaining[0].IP)
	}
}

func TestHandleCloseAllLogsCommandOutput(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	stdLogger := log.New(&bytes.Buffer{}, "", 0)
	tracker := NewTracker(statePath, stdLogger, true)

	tracker.Add(&PortEntry{
		IP: "10.0.0.1", Port: "t22", Proto: "tcp", PortNum: "22",
		ExpiresAt: time.Now().Add(1 * time.Hour), CloseCmd: "echo closed_port_22",
	})

	logger := &testLogger{}
	cfg := &config.Config{
		CommandTimeout:   1,
		LogCommandOutput: true,
	}

	handleCloseAll(logger, cfg, tracker, "10.0.0.1")

	out := logger.buf.String()
	if out == "" {
		t.Error("expected log output")
	}
}

// --- handleCustomCommand tests ---

func TestHandleCustomCommandKnown(t *testing.T) {
	logger := &testLogger{}
	cfg := &config.Config{
		CustomCommands: map[string]string{
			"ping": "echo pong",
		},
		CommandTimeout: 1,
	}

	handleCustomCommand(logger, cfg, "10.0.0.1", "ping")

	out := logger.buf.String()
	if out == "" {
		t.Error("expected log output for known command")
	}
}

func TestHandleCustomCommandUnknown(t *testing.T) {
	logger := &testLogger{}
	cfg := &config.Config{
		CustomCommands: map[string]string{
			"ping": "echo pong",
		},
		CommandTimeout: 1,
	}

	handleCustomCommand(logger, cfg, "10.0.0.1", "nonexistent")

	out := logger.buf.String()
	if out == "" {
		t.Fatal("expected IGNORE log")
	}
}

func TestHandleCustomCommandEmptyCommands(t *testing.T) {
	logger := &testLogger{}
	cfg := &config.Config{
		CustomCommands: map[string]string{},
		CommandTimeout: 1,
	}

	handleCustomCommand(logger, cfg, "10.0.0.1", "anything")
	// Should not panic, should log IGNORE
}

func TestHandleCustomCommandNilCommands(t *testing.T) {
	logger := &testLogger{}
	cfg := &config.Config{
		CustomCommands: nil,
		CommandTimeout: 1,
	}

	handleCustomCommand(logger, cfg, "10.0.0.1", "anything")
	// Should not panic
}

func TestHandleCustomCommandWithIPSubstitution(t *testing.T) {
	logger := &testLogger{}
	cfg := &config.Config{
		CustomCommands: map[string]string{
			"check": "echo checking {{IP}}",
		},
		CommandTimeout:   1,
		LogCommandOutput: true,
	}

	handleCustomCommand(logger, cfg, "10.0.0.1", "check")

	out := logger.buf.String()
	if out == "" {
		t.Error("expected log output")
	}
}

// --- sanitizeForLog tests ---

func TestSanitizeForLog(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"hello", "hello"},
		{"hello\nworld", "hello?world"},
		{"tab\there", "tab?here"},
		{"\x00null", "?null"},
		{"\x7fDEL", "?DEL"},
		{"clean text 123", "clean text 123"},
		{"", ""},
		{"line1\r\nline2", "line1??line2"},
	}

	for _, tt := range tests {
		got := sanitizeForLog(tt.in)
		if got != tt.want {
			t.Errorf("sanitizeForLog(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// --- commandTimeout tests ---

func TestCommandTimeoutCustom(t *testing.T) {
	cfg := &config.Config{CommandTimeout: 2.5}
	got := commandTimeout(cfg)
	want := time.Duration(2.5 * float64(time.Second))
	if got != want {
		t.Errorf("commandTimeout = %v, want %v", got, want)
	}
}

func TestCommandTimeoutDefault(t *testing.T) {
	cfg := &config.Config{CommandTimeout: 0}
	got := commandTimeout(cfg)
	if got != 500*time.Millisecond {
		t.Errorf("commandTimeout default = %v, want 500ms", got)
	}
}
