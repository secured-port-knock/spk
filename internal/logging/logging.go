// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
// Package logging provides structured logging with file rotation,
// flood protection, and platform-aware log paths for SPK.
package logging

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Config holds logging configuration (mapped from TOML config).
type Config struct {
	MaxSizeMB    int // Max log file size before rotation (default: 10)
	MaxBackups   int // Max rotated log files to keep (default: 5)
	MaxAgeDays   int // Max age of rotated logs in days (default: 30)
	FloodLimitPS int // Max log lines per second (0 = unlimited, default: 100)
}

// DefaultConfig returns sensible logging defaults.
func DefaultConfig() Config {
	return Config{
		MaxSizeMB:    10,
		MaxBackups:   5,
		MaxAgeDays:   30,
		FloodLimitPS: 100,
	}
}

// Logger wraps Go's standard logger with rotation and flood protection.
type Logger struct {
	mu          sync.Mutex
	logger      *log.Logger
	file        *os.File
	filePath    string
	config      Config
	currentSize int64
	module      string // module name for log prefix (e.g. "main", "handler")
	writer      io.Writer

	// Flood protection
	floodMu     sync.Mutex
	lineCount   int
	floodWindow time.Time
	dropped     int
}

// customLogDir is set via --logdir to override the platform default.
var customLogDir string

// logDirFallback is set when /var/log/spk is not writable and the
// exe-relative log/ directory is used instead.
var logDirFallback bool

// SetLogDir overrides the default log directory.
// Creates the directory if it does not exist.
func SetLogDir(dir string) {
	os.MkdirAll(dir, 0750)
	customLogDir = dir
}

// UsingFallbackLogDir returns true when LogDir fell back to an
// exe-relative log/ directory because /var/log/spk was not writable.
func UsingFallbackLogDir() bool {
	return logDirFallback
}

// LogDir returns the platform-appropriate log directory.
// If SetLogDir was called, returns that override.
// Linux/macOS: /var/log/spk (falls back to <exe_dir>/log if no permission)
// Windows: <exe_dir>/log
func LogDir() string {
	if customLogDir != "" {
		return customLogDir
	}
	if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		dir := "/var/log/spk"
		// Try to create; fall back to exe-relative log/ if no permission
		if err := os.MkdirAll(dir, 0750); err == nil {
			return dir
		}
		logDirFallback = true
		// Fall through to exe-relative log/ (same pattern as Windows)
	}
	// Windows / fallback (same pattern for all platforms)
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	dir := filepath.Join(filepath.Dir(exe), "log")
	os.MkdirAll(dir, 0750) //nolint:errcheck
	return dir
}

// New creates a new Logger that writes to the specified log file with rotation.
// It also writes to stdout so console output is preserved.
// The module parameter identifies the component (e.g. "main", "handler").
func New(filename string, cfg Config, module ...string) (*Logger, error) {
	if cfg.MaxSizeMB <= 0 {
		cfg.MaxSizeMB = 10
	}
	if cfg.MaxBackups <= 0 {
		cfg.MaxBackups = 5
	}
	if cfg.MaxAgeDays <= 0 {
		cfg.MaxAgeDays = 30
	}

	logDir := LogDir()
	if err := os.MkdirAll(logDir, 0750); err != nil {
		return nil, fmt.Errorf("create log directory %s: %w", logDir, err)
	}

	filePath := filepath.Join(logDir, filename)

	mod := "main"
	if len(module) > 0 && module[0] != "" {
		mod = module[0]
	}

	l := &Logger{
		filePath:    filePath,
		config:      cfg,
		module:      mod,
		floodWindow: time.Now(),
	}

	if err := l.openFile(); err != nil {
		return nil, err
	}

	return l, nil
}

// openFile opens (or creates) the log file and sets up the multi-writer.
func (l *Logger) openFile() error {
	f, err := os.OpenFile(l.filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
	if err != nil {
		return fmt.Errorf("open log file %s: %w", l.filePath, err)
	}

	info, err := f.Stat()
	if err != nil {
		if cerr := f.Close(); cerr != nil {
			fmt.Fprintf(os.Stderr, "ERROR | [logging] failed to close log file after stat error: %v\n", cerr)
		}
		return fmt.Errorf("stat log file: %w", err)
	}

	l.file = f
	l.currentSize = info.Size()

	// Write to file first, then stdout. Order matters: when running as a
	// Windows service, stdout is invalid. MultiWriter stops on the first
	// write error, so the file must come first to guarantee log persistence.
	l.writer = io.MultiWriter(f, os.Stdout)
	l.logger = log.New(l.writer, "", 0) // no prefix/flags -- we format manually

	return nil
}

// formatLine builds a log line: "LEVEL | 2006/01/02 15:04:05 [module] message"
func (l *Logger) formatLine(level, msg string) string {
	ts := time.Now().Format("2006/01/02 15:04:05")
	return fmt.Sprintf("%-5s | %s [%s] %s", level, ts, l.module, msg)
}

// logMsg writes a formatted message at the given level with rotation and flood checks.
func (l *Logger) logMsg(level, msg string) {
	line := l.formatLine(level, msg)
	l.logger.Println(line)
	l.currentSize += int64(len(line) + 2)

	if l.currentSize >= int64(l.config.MaxSizeMB)*1024*1024 {
		l.rotate()
	}
}

// Infof logs an INFO-level formatted message.
func (l *Logger) Infof(format string, v ...interface{}) {
	if l.isFlooded() {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.logMsg("INFO", fmt.Sprintf(format, v...))
}

// Warnf logs a WARN-level formatted message.
func (l *Logger) Warnf(format string, v ...interface{}) {
	if l.isFlooded() {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.logMsg("WARN", fmt.Sprintf(format, v...))
}

// Errorf logs an ERROR-level formatted message.
func (l *Logger) Errorf(format string, v ...interface{}) {
	if l.isFlooded() {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.logMsg("ERROR", fmt.Sprintf(format, v...))
}

// Printf logs a formatted message at INFO level (backward compat).
func (l *Logger) Printf(format string, v ...interface{}) {
	if l.isFlooded() {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	msg := fmt.Sprintf(format, v...)
	l.logMsg("INFO", msg)
}

// Println logs a message at INFO level (backward compat).
func (l *Logger) Println(v ...interface{}) {
	if l.isFlooded() {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	msg := fmt.Sprint(v...)
	l.logMsg("INFO", msg)
}

// Fatalf logs a FATAL message and exits.
func (l *Logger) Fatalf(format string, v ...interface{}) {
	l.mu.Lock()
	msg := fmt.Sprintf(format, v...)
	l.logMsg("FATAL", msg)
	l.mu.Unlock()
	os.Exit(1)
}

// StdLogger returns the underlying *log.Logger for compatibility.
func (l *Logger) StdLogger() *log.Logger {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.logger
}

// Close flushes and closes the log file.
func (l *Logger) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file != nil {
		if err := l.file.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR | [%s] failed to close log file: %v\n", l.module, err)
		}
	}
}

// isFlooded checks flood protection limits.
// Returns true if the message should be suppressed.
func (l *Logger) isFlooded() bool {
	if l.config.FloodLimitPS <= 0 {
		return false
	}

	l.floodMu.Lock()
	defer l.floodMu.Unlock()

	now := time.Now()
	if now.Sub(l.floodWindow) >= time.Second {
		// New window
		if l.dropped > 0 {
			// Log how many were dropped (bypass flood check)
			l.mu.Lock()
			l.logMsg("WARN", fmt.Sprintf("Suppressed %d log messages in the last second", l.dropped))
			l.mu.Unlock()
		}
		l.floodWindow = now
		l.lineCount = 0
		l.dropped = 0
	}

	l.lineCount++
	if l.lineCount > l.config.FloodLimitPS {
		l.dropped++
		return true
	}
	return false
}

// rotate performs log file rotation.
func (l *Logger) rotate() {
	if l.file != nil {
		if err := l.file.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR | [%s] failed to close log file during rotation: %v\n", l.module, err)
		}
	}

	// Rotate existing backups
	for i := l.config.MaxBackups - 1; i >= 1; i-- {
		src := fmt.Sprintf("%s.%d", l.filePath, i)
		dst := fmt.Sprintf("%s.%d", l.filePath, i+1)
		os.Rename(src, dst)
	}

	// Rename current log to .1
	os.Rename(l.filePath, l.filePath+".1")

	// Remove backups exceeding max
	for i := l.config.MaxBackups + 1; i <= l.config.MaxBackups+5; i++ {
		path := fmt.Sprintf("%s.%d", l.filePath, i)
		os.Remove(path)
	}

	// Clean old backups by age
	l.cleanOldBackups()

	// Open new file
	if err := l.openFile(); err != nil {
		// Fallback to stdout only
		l.writer = os.Stdout
		l.logger = log.New(os.Stdout, "", 0)
		l.logMsg("ERROR", fmt.Sprintf("Failed to open new log file after rotation: %v", err))
	}
}

// cleanOldBackups removes rotated logs older than MaxAgeDays.
func (l *Logger) cleanOldBackups() {
	cutoff := time.Now().Add(-time.Duration(l.config.MaxAgeDays) * 24 * time.Hour)
	base := filepath.Base(l.filePath)
	dir := filepath.Dir(l.filePath)

	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if !strings.HasPrefix(entry.Name(), base+".") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			os.Remove(filepath.Join(dir, entry.Name()))
		}
	}
}

// FilePath returns the current log file path.
func (l *Logger) FilePath() string {
	return l.filePath
}
