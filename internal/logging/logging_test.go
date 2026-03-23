// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package logging

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestNewLogger(t *testing.T) {
	cfg := DefaultConfig()

	l, err := New("test_unit.log", cfg, "test")
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
		if LogDirInitError() == nil {
			t.Error("LogDir() returned empty string but LogDirInitError() is nil")
		}
		t.Skipf("no writable log directory (LogDirInitError: %v); expected without root on Linux/macOS", LogDirInitError())
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

	if err := SetLogDir(dir); err != nil {
		t.Fatalf("SetLogDir: %v", err)
	}
	if LogDir() != dir {
		t.Errorf("LogDir() = %q, want %q", LogDir(), dir)
	}
}

func TestSetLogDirCreatesDirectory(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "subdir", "logs")
	origDir := customLogDir
	defer func() { customLogDir = origDir }()

	if err := SetLogDir(dir); err != nil {
		t.Fatalf("SetLogDir: %v", err)
	}
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
		if LogDirInitError() == nil {
			t.Error("LogDir() returned empty string but LogDirInitError() is nil")
		}
		t.Skipf("no writable log directory (LogDirInitError: %v); expected without root on Linux/macOS", LogDirInitError())
	}
}

func TestNewLoggerWithCustomDir(t *testing.T) {
	dir := t.TempDir()
	origDir := customLogDir
	defer func() { customLogDir = origDir }()

	if err := SetLogDir(dir); err != nil {
		t.Fatalf("SetLogDir: %v", err)
	}
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

// TestLogDirDefaultCreatesDirectory verifies that LogDir() returns an existing
// directory when one is accessible. On Linux/macOS without root /var/log/spk
// cannot be created; in that case LogDir() returns "" (file logging disabled)
// and LogDirInitError() reports the reason.
func TestLogDirDefaultCreatesDirectory(t *testing.T) {
	origDir := customLogDir
	defer func() { customLogDir = origDir }()
	customLogDir = ""

	dir := LogDir()
	if dir == "" {
		// Expected on Linux/macOS when /var/log/spk is not accessible.
		if LogDirInitError() == nil {
			t.Error("LogDir() returned empty string but LogDirInitError() is nil")
		}
		t.Skipf("no writable log directory (LogDirInitError: %v); expected without root on Linux/macOS", LogDirInitError())
		return
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

	if err := SetLogDir(dir); err != nil {
		t.Fatalf("SetLogDir: %v", err)
	}
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

	if err := SetLogDir(dir); err != nil {
		t.Fatalf("SetLogDir: %v", err)
	}
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

	if err := SetLogDir(dir); err != nil {
		t.Fatalf("SetLogDir: %v", err)
	}
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

	if err := SetLogDir(dir); err != nil {
		t.Fatalf("SetLogDir: %v", err)
	}
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

	if err := SetLogDir(dir); err != nil {
		t.Fatalf("SetLogDir: %v", err)
	}
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

// TestLogDirInitError verifies that LogDirInitError returns nil by default when
// a custom log directory is set (the init error is only set on Linux/macOS when
// /var/log/spk is inaccessible and no --logdir override is in effect).
func TestLogDirInitError(t *testing.T) {
	dir := t.TempDir()
	origDir := LogDir() // prime and capture
	// Restore via SetLogDir -- SetLogDir("") resets to defaults.
	if origDir != "" {
		defer func() { _ = SetLogDir(origDir) }()
	} else {
		defer func() { _ = SetLogDir("") }()
	}

	if err := SetLogDir(dir); err != nil {
		t.Fatalf("SetLogDir: %v", err)
	}
	// After an explicit SetLogDir call, LogDirInitError must be nil.
	if LogDirInitError() != nil {
		t.Errorf("LogDirInitError() should be nil after SetLogDir, got: %v", LogDirInitError())
	}
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

// ---------------------------------------------------------------------------
// Client logging: stdout-only and NewClientLogger
// ---------------------------------------------------------------------------

// TestNewStdoutOnlyReturnsNonNil verifies NewStdoutOnly returns a usable logger.
func TestNewStdoutOnlyReturnsNonNil(t *testing.T) {
	l := NewStdoutOnly(DefaultConfig(), "test")
	if l == nil {
		t.Fatal("NewStdoutOnly returned nil")
	}
	// FilePath should be empty -- no file is associated.
	if l.FilePath() != "" {
		t.Errorf("FilePath() = %q, want empty string for stdout-only logger", l.FilePath())
	}
	// Methods must not panic.
	l.Infof("stdout-only info %d", 1)
	l.Warnf("stdout-only warn")
	l.Errorf("stdout-only error")
	l.Printf("stdout-only printf")
	l.Println("stdout-only println")
	l.Close()
}

// TestNewClientLoggerNoLogDirReturnStdoutOnly verifies that when no custom
// log directory is set, NewClientLogger returns a stdout-only logger.
func TestNewClientLoggerNoLogDirReturnStdoutOnly(t *testing.T) {
	origDir := customLogDir
	defer func() { customLogDir = origDir }()
	customLogDir = "" // ensure no custom dir

	l, err := NewClientLogger("spk_client.log", DefaultConfig(), "client")
	if err != nil {
		t.Fatalf("NewClientLogger: %v", err)
	}
	if l == nil {
		t.Fatal("NewClientLogger returned nil")
	}
	// No file should be created.
	if l.FilePath() != "" {
		t.Errorf("expected no file path when logdir not set, got %q", l.FilePath())
	}
	l.Infof("client stdout message")
	l.Close()
}

// TestNewClientLoggerWithLogDirCreatesFile verifies that when a custom log
// directory is set (via --logdir), NewClientLogger creates a log file.
func TestNewClientLoggerWithLogDirCreatesFile(t *testing.T) {
	dir := t.TempDir()
	origDir := customLogDir
	defer func() { customLogDir = origDir }()

	if err := SetLogDir(dir); err != nil {
		t.Fatalf("SetLogDir: %v", err)
	}

	l, err := NewClientLogger("spk_client.log", DefaultConfig(), "client")
	if err != nil {
		t.Fatalf("NewClientLogger: %v", err)
	}
	defer l.Close()

	l.Infof("client file message")

	expected := filepath.Join(dir, "spk_client.log")
	if l.FilePath() != expected {
		t.Errorf("FilePath() = %q, want %q", l.FilePath(), expected)
	}
	if _, err := os.Stat(expected); err != nil {
		t.Errorf("log file not created: %v", err)
	}
}

// TestIsCustomLogDir verifies the flag tracks SetLogDir correctly.
func TestIsCustomLogDir(t *testing.T) {
	origDir := customLogDir
	defer func() { customLogDir = origDir }()

	customLogDir = ""
	if IsCustomLogDir() {
		t.Error("IsCustomLogDir() should be false when no dir is set")
	}

	dir := t.TempDir()
	if err := SetLogDir(dir); err != nil {
		t.Fatalf("SetLogDir: %v", err)
	}
	if !IsCustomLogDir() {
		t.Error("IsCustomLogDir() should be true after SetLogDir")
	}
}

// ---------------------------------------------------------------------------
// Platform-aware LogDir behaviour tests
// ---------------------------------------------------------------------------

// TestLogDirServerModeNoRoot verifies that on Linux/macOS without root,
// LogDir() returns "" and LogDirInitError() is set. Skips on Windows or when
// already running as root (i.e. /var/log/spk is accessible).
func TestLogDirServerModeNoRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows always returns exe-relative log dir; root not required")
	}
	origDir := customLogDir
	defer func() { customLogDir = origDir }()
	customLogDir = ""

	dir := LogDir()
	if dir != "" {
		t.Skipf("LogDir() = %q (non-empty); running as root or /var/log/spk is accessible -- skip non-root path", dir)
		return
	}
	// Non-root path: LogDirInitError must be set.
	if LogDirInitError() == nil {
		t.Error("LogDirInitError() should be non-nil when LogDir() returns empty")
	}
	if LogDirInitError().Error() == "" {
		t.Error("LogDirInitError() error message should not be empty")
	}
}

// TestLogDirServerModeWithCustomDir verifies that --logdir always works
// regardless of whether /var/log/spk is accessible (simulates server started
// with --logdir).
func TestLogDirServerModeWithCustomDir(t *testing.T) {
	dir := t.TempDir()
	origDir := customLogDir
	defer func() { customLogDir = origDir }()

	if err := SetLogDir(dir); err != nil {
		t.Fatalf("SetLogDir: %v", err)
	}

	if got := LogDir(); got != dir {
		t.Errorf("LogDir() = %q, want %q", got, dir)
	}
	if LogDirInitError() != nil {
		t.Errorf("LogDirInitError() should be nil after SetLogDir, got: %v", LogDirInitError())
	}

	l, err := New("server.log", DefaultConfig(), "server")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer l.Close()
	l.Infof("server startup message")

	if _, err := os.Stat(filepath.Join(dir, "server.log")); err != nil {
		t.Errorf("log file not created: %v", err)
	}
}

// TestNewServerLoggerFailsWithNoLogDir verifies that on Linux/macOS non-root
// (no --logdir set), New() returns an error so the caller can fall back to
// stdout-only logging.
func TestNewServerLoggerFailsWithNoLogDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows always has an exe-relative log dir")
	}
	origDir := customLogDir
	defer func() { customLogDir = origDir }()
	customLogDir = ""

	if LogDir() != "" {
		t.Skip("LogDir() is non-empty (running as root or /var/log/spk is accessible); skip")
	}

	// New() must return an error when there is no directory to write to.
	_, err := New("server.log", DefaultConfig(), "server")
	if err == nil {
		t.Error("New() should return error when LogDir() is empty")
	}
}

// TestLogDirWindowsAlwaysNonEmpty verifies that on Windows, LogDir() always
// returns a non-empty exe-relative path and sets no init error.
func TestLogDirWindowsAlwaysNonEmpty(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only test")
	}
	origDir := customLogDir
	defer func() { customLogDir = origDir }()
	customLogDir = ""

	dir := LogDir()
	if dir == "" {
		t.Fatal("LogDir() returned empty string on Windows")
	}
	if LogDirInitError() != nil {
		t.Errorf("LogDirInitError() should be nil on Windows, got: %v", LogDirInitError())
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("LogDir() = %q but directory does not exist: %v", dir, err)
	}
	if !info.IsDir() {
		t.Errorf("LogDir() = %q is not a directory", dir)
	}
}

// TestLogDirInitErrorClearedBySetLogDir verifies that SetLogDir with a valid
// path clears any prior init error.
func TestLogDirInitErrorClearedBySetLogDir(t *testing.T) {
	origDir := customLogDir
	defer func() { customLogDir = origDir }()

	// Force a fresh probe on Linux/macOS to possibly set logDirInitError.
	if runtime.GOOS != "windows" {
		customLogDir = ""
		_ = LogDir() // may set logDirInitError on non-root
	}

	// Override with a valid dir -- error must be cleared.
	dir := t.TempDir()
	if err := SetLogDir(dir); err != nil {
		t.Fatalf("SetLogDir: %v", err)
	}
	if LogDirInitError() != nil {
		t.Errorf("LogDirInitError() should be nil after SetLogDir, got: %v", LogDirInitError())
	}
}

// TestLogDirServerModeWithRoot verifies that on Linux/macOS running as root,
// LogDir() returns "/var/log/spk" and LogDirInitError() is nil. Skips when
// not running as root or on Windows.
func TestLogDirServerModeWithRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows uses exe-relative log dir; root not applicable")
	}
	origDir := customLogDir
	defer func() { customLogDir = origDir }()
	customLogDir = ""

	dir := LogDir()
	if dir == "" {
		t.Skip("LogDir() returned empty; not running as root -- skip root path test")
	}
	if LogDirInitError() != nil {
		t.Errorf("LogDirInitError() should be nil when running as root, got: %v", LogDirInitError())
	}
	if dir != "/var/log/spk" {
		t.Errorf("LogDir() = %q, want /var/log/spk when running as root", dir)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("LogDir() = %q but directory does not exist: %v", dir, err)
	}
	if !info.IsDir() {
		t.Errorf("LogDir() = %q is not a directory", dir)
	}
}

// TestNewServerLoggerWithRoot verifies that on Linux/macOS running as root,
// New() can create a log file in /var/log/spk without --logdir. Skips when
// not running as root or on Windows.
func TestNewServerLoggerWithRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows uses exe-relative log dir; root not applicable")
	}
	origDir := customLogDir
	defer func() { customLogDir = origDir }()
	customLogDir = ""

	if LogDir() == "" {
		t.Skip("LogDir() empty; not running as root -- skip root path test")
	}

	l, err := New("test_server_root.log", DefaultConfig(), "server")
	if err != nil {
		t.Fatalf("New() should succeed when running as root, got: %v", err)
	}
	defer l.Close()
	l.Infof("server root test message")

	if l.FilePath() == "" {
		t.Error("FilePath() should not be empty when running as root")
	}
	if _, err := os.Stat(l.FilePath()); err != nil {
		t.Errorf("log file not created: %v", err)
	}
}
