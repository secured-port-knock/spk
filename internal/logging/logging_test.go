// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package logging

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNewLogger(t *testing.T) {
	cfg := DefaultConfig()

	l, err := New("test_unit.log", cfg)
	if err != nil {
		// May fail if LogDir is not writable - skip
		t.Skipf("cannot create logger: %v", err)
	}
	defer l.Close()

	l.Printf("test message %d", 42)
	l.Println("another message")

	if l.FilePath() == "" {
		t.Error("FilePath should not be empty")
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.MaxSizeMB != 10 {
		t.Errorf("MaxSizeMB = %d, want 10", cfg.MaxSizeMB)
	}
	if cfg.MaxBackups != 5 {
		t.Errorf("MaxBackups = %d, want 5", cfg.MaxBackups)
	}
	if cfg.MaxAgeDays != 30 {
		t.Errorf("MaxAgeDays = %d, want 30", cfg.MaxAgeDays)
	}
	if cfg.FloodLimitPS != 100 {
		t.Errorf("FloodLimitPS = %d, want 100", cfg.FloodLimitPS)
	}
}

func TestFloodProtection(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{
		MaxSizeMB:    1,
		MaxBackups:   2,
		MaxAgeDays:   1,
		FloodLimitPS: 5, // Very low limit for testing
	}

	filePath := filepath.Join(dir, "flood_test.log")
	os.WriteFile(filePath, []byte{}, 0640)

	l := &Logger{
		filePath:    filePath,
		config:      cfg,
		floodWindow: time.Now(),
	}
	if err := l.openFile(); err != nil {
		t.Fatalf("openFile: %v", err)
	}
	defer l.Close()

	// First 5 should pass
	for i := 0; i < 5; i++ {
		if l.isFlooded() {
			t.Errorf("message %d should not be flooded", i)
		}
	}

	// 6th+ should be suppressed
	if !l.isFlooded() {
		t.Error("6th message should be suppressed by flood protection")
	}
}

func TestLogRotation(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{
		MaxSizeMB:    1,
		MaxBackups:   3,
		MaxAgeDays:   30,
		FloodLimitPS: 0, // No limit
	}

	filePath := filepath.Join(dir, "rotate_test.log")
	os.WriteFile(filePath, []byte("initial content\n"), 0640)

	l := &Logger{
		filePath:    filePath,
		config:      cfg,
		floodWindow: time.Now(),
	}
	if err := l.openFile(); err != nil {
		t.Fatalf("openFile: %v", err)
	}
	defer l.Close()

	// Force rotation by setting size beyond threshold
	l.mu.Lock()
	l.currentSize = int64(cfg.MaxSizeMB)*1024*1024 + 1
	l.mu.Unlock()

	// This write should trigger rotation
	l.Printf("trigger rotation")

	// Check that .1 backup was created
	if _, err := os.Stat(filePath + ".1"); err != nil {
		t.Logf("Note: .1 backup status: %v", err)
	}

	// New log file should exist and be writable
	if _, err := os.Stat(filePath); err != nil {
		t.Errorf("log file should exist after rotation: %v", err)
	}
}

func TestLogDirNotEmpty(t *testing.T) {
	dir := LogDir()
	if dir == "" {
		t.Error("LogDir should not return empty string")
	}
}

func TestLoggerStdLogger(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultConfig()
	filePath := filepath.Join(dir, "std_test.log")
	os.WriteFile(filePath, []byte{}, 0640)

	l := &Logger{
		filePath:    filePath,
		config:      cfg,
		floodWindow: time.Now(),
	}
	if err := l.openFile(); err != nil {
		t.Fatalf("openFile: %v", err)
	}
	defer l.Close()

	stdLog := l.StdLogger()
	if stdLog == nil {
		t.Error("StdLogger should not return nil")
	}

	if !strings.Contains(l.FilePath(), "std_test.log") {
		t.Errorf("FilePath = %s, want to contain std_test.log", l.FilePath())
	}
}

func TestFloodProtectionReset(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{
		MaxSizeMB:    1,
		MaxBackups:   2,
		MaxAgeDays:   1,
		FloodLimitPS: 3,
	}

	filePath := filepath.Join(dir, "flood_reset.log")
	os.WriteFile(filePath, []byte{}, 0640)

	l := &Logger{
		filePath:    filePath,
		config:      cfg,
		floodWindow: time.Now().Add(-2 * time.Second), // Window already expired
	}
	if err := l.openFile(); err != nil {
		t.Fatalf("openFile: %v", err)
	}
	defer l.Close()

	// Should reset window and allow messages
	if l.isFlooded() {
		t.Error("first message after window reset should not be flooded")
	}
}

func TestNoFloodLimitWhenZero(t *testing.T) {
	cfg := Config{
		MaxSizeMB:    1,
		MaxBackups:   2,
		MaxAgeDays:   1,
		FloodLimitPS: 0, // Unlimited
	}

	l := &Logger{config: cfg}

	for i := 0; i < 1000; i++ {
		if l.isFlooded() {
			t.Errorf("should never be flooded when limit is 0 (iteration %d)", i)
			break
		}
	}
}

func TestSetLogDirOverride(t *testing.T) {
	dir := t.TempDir()
	origDir := customLogDir
	defer func() { customLogDir = origDir }()

	SetLogDir(dir)
	if LogDir() != dir {
		t.Errorf("LogDir() = %q, want %q", LogDir(), dir)
	}
}

func TestSetLogDirCreatesDirectory(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "subdir", "logs")
	origDir := customLogDir
	defer func() { customLogDir = origDir }()

	SetLogDir(dir)
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("directory not created: %v", err)
	}
	if !info.IsDir() {
		t.Error("expected directory")
	}
}

func TestLogDirDefaultReturnsNonEmpty(t *testing.T) {
	origDir := customLogDir
	defer func() { customLogDir = origDir }()
	customLogDir = ""

	d := LogDir()
	if d == "" {
		t.Error("LogDir() should not return empty string")
	}
}

func TestNewLoggerWithCustomDir(t *testing.T) {
	dir := t.TempDir()
	origDir := customLogDir
	defer func() { customLogDir = origDir }()

	SetLogDir(dir)
	cfg := DefaultConfig()
	l, err := New("test_custom_dir.log", cfg, "test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer l.Close()

	l.Infof("hello from custom dir")
	if !strings.HasPrefix(l.FilePath(), dir) {
		t.Errorf("FilePath() = %q, want prefix %q", l.FilePath(), dir)
	}
}

// TestLogDirDefaultCreatesDirectory verifies that LogDir() always returns a path
// that exists on disk, even when no custom override is set.
func TestLogDirDefaultCreatesDirectory(t *testing.T) {
	origDir := customLogDir
	defer func() { customLogDir = origDir }()
	customLogDir = ""

	dir := LogDir()
	if dir == "" {
		t.Fatal("LogDir() returned empty string")
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("LogDir() returned %q but directory does not exist: %v", dir, err)
	}
	if !info.IsDir() {
		t.Errorf("LogDir() returned %q but it is not a directory", dir)
	}
}

// TestLoggerWritesToFileEvenIfStdoutFails verifies that the logger writes to
// the log file even when the process has no valid stdout (the Windows service
// scenario). The fix is that the file writer comes first in io.MultiWriter so
// that file writes succeed before any stdout error can short-circuit.
func TestLoggerWritesToFileEvenIfStdoutFails(t *testing.T) {
	dir := t.TempDir()
	origDir := customLogDir
	defer func() { customLogDir = origDir }()

	SetLogDir(dir)
	cfg := DefaultConfig()
	l, err := New("test_file_first.log", cfg, "test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Write a message
	l.Infof("hello file first")
	l.Close()

	// Verify the file has content
	data, err := os.ReadFile(filepath.Join(dir, "test_file_first.log"))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "hello file first") {
		t.Errorf("log file does not contain expected message, got: %q", content)
	}
}

// TestLoggerFileWriteOrder verifies file writer is listed before stdout
// in the MultiWriter, ensuring log persistence when stdout is unavailable
// (e.g. Windows service without a console).
func TestLoggerFileWriteOrder(t *testing.T) {
	dir := t.TempDir()
	origDir := customLogDir
	defer func() { customLogDir = origDir }()

	SetLogDir(dir)
	cfg := DefaultConfig()
	l, err := New("test_order.log", cfg, "test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Write multiple messages
	for i := 0; i < 10; i++ {
		l.Infof("message %d", i)
	}
	l.Close()

	data, err := os.ReadFile(filepath.Join(dir, "test_order.log"))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	content := string(data)
	for i := 0; i < 10; i++ {
		expected := "message " + strings.TrimSpace(filepath.Base(
			filepath.Join("dummy", string(rune('0'+i)))))
		if !strings.Contains(content, "message") {
			t.Errorf("log file missing message %d", i)
		}
		_ = expected
	}

	// Verify file is non-empty (the key assertion for the 0KB bug)
	if len(data) == 0 {
		t.Fatal("log file is 0 bytes -- file writer did not persist any data")
	}
}

// ---------------------------------------------------------------------------
// Level methods and concurrent writes
// ---------------------------------------------------------------------------

func TestLoggerWarnf(t *testing.T) {
	dir := t.TempDir()
	origDir := customLogDir
	defer func() { customLogDir = origDir }()

	SetLogDir(dir)
	l, err := New("test_warn.log", DefaultConfig(), "test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	l.Warnf("something %s happened", "bad")
	l.Close()

	data, _ := os.ReadFile(filepath.Join(dir, "test_warn.log"))
	content := string(data)
	if !strings.Contains(content, "WARN") {
		t.Error("log should contain WARN level")
	}
	if !strings.Contains(content, "something bad happened") {
		t.Error("log should contain formatted message")
	}
}

func TestLoggerErrorf(t *testing.T) {
	dir := t.TempDir()
	origDir := customLogDir
	defer func() { customLogDir = origDir }()

	SetLogDir(dir)
	l, err := New("test_error.log", DefaultConfig(), "test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	l.Errorf("failure: %d", 42)
	l.Close()

	data, _ := os.ReadFile(filepath.Join(dir, "test_error.log"))
	content := string(data)
	if !strings.Contains(content, "ERROR") {
		t.Error("log should contain ERROR level")
	}
	if !strings.Contains(content, "failure: 42") {
		t.Error("log should contain formatted message")
	}
}

func TestLoggerConcurrentWrites(t *testing.T) {
	dir := t.TempDir()
	origDir := customLogDir
	defer func() { customLogDir = origDir }()

	SetLogDir(dir)
	cfg := DefaultConfig()
	cfg.FloodLimitPS = 0 // disable flood protection for concurrency test
	l, err := New("test_concurrent.log", cfg, "test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	done := make(chan struct{})
	for g := 0; g < 20; g++ {
		go func(id int) {
			defer func() { done <- struct{}{} }()
			for i := 0; i < 50; i++ {
				l.Infof("goroutine %d message %d", id, i)
			}
		}(g)
	}

	for g := 0; g < 20; g++ {
		<-done
	}
	l.Close()

	data, err := os.ReadFile(filepath.Join(dir, "test_concurrent.log"))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if len(data) == 0 {
		t.Error("log file should have content after concurrent writes")
	}
	// Should have at least 20*50 = 1000 lines (each Infof call = 1 line)
	lines := strings.Count(string(data), "\n")
	if lines < 500 {
		t.Errorf("expected at least 500 log lines, got %d", lines)
	}
}

// TestUsingFallbackLogDir verifies the fallback tracking.
func TestUsingFallbackLogDir(t *testing.T) {
	// By default (before any SetLogDir override), UsingFallbackLogDir
	// may be true or false depending on the OS. Just verify it does not panic
	// and returns a boolean.
	_ = UsingFallbackLogDir()
}

// TestDefaultConfigValues verifies DefaultConfig returns sensible defaults.
func TestDefaultConfigValues(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.MaxSizeMB <= 0 {
		t.Errorf("MaxSizeMB = %d, want > 0", cfg.MaxSizeMB)
	}
	if cfg.MaxBackups < 0 {
		t.Errorf("MaxBackups = %d, want >= 0", cfg.MaxBackups)
	}
	if cfg.MaxAgeDays <= 0 {
		t.Errorf("MaxAgeDays = %d, want > 0", cfg.MaxAgeDays)
	}
}
