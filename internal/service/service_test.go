// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package service

import (
	"bufio"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestServiceNameDefault(t *testing.T) {
	sc := ServiceConfig{}
	if got := sc.ServiceName(); got != "spk" {
		t.Errorf("ServiceName() = %q, want %q", got, "spk")
	}
}

func TestServiceNameWithLabel(t *testing.T) {
	tests := []struct {
		label string
		want  string
	}{
		{"", "spk"},
		{"Production", "spk_production"},
		{"My Instance", "spk_my_instance"},
		{"prod-1", "spk_prod-1"},
		{"UPPER", "spk_upper"},
		{"hello world!", "spk_hello_world_"},
		{"  spaces  ", "spk_spaces"},
	}
	for _, tt := range tests {
		sc := ServiceConfig{DisplayLabel: tt.label}
		if got := sc.ServiceName(); got != tt.want {
			t.Errorf("ServiceName(%q) = %q, want %q", tt.label, got, tt.want)
		}
	}
}

func TestDisplayNameDefault(t *testing.T) {
	sc := ServiceConfig{}
	want := "Secured Port Knock"
	if got := sc.DisplayName(); got != want {
		t.Errorf("DisplayName() = %q, want %q", got, want)
	}
}

func TestDisplayNameWithLabel(t *testing.T) {
	sc := ServiceConfig{DisplayLabel: "Production"}
	want := "Secured Port Knock (Production)"
	if got := sc.DisplayName(); got != want {
		t.Errorf("DisplayName() = %q, want %q", got, want)
	}
}

func TestDisplayNameEmptyLabel(t *testing.T) {
	sc := ServiceConfig{DisplayLabel: ""}
	want := "Secured Port Knock"
	if got := sc.DisplayName(); got != want {
		t.Errorf("DisplayName() = %q, want %q", got, want)
	}
}

func TestFillDefaultsPopulatesExePath(t *testing.T) {
	cfg := ServiceConfig{}
	if err := fillDefaults(&cfg); err != nil {
		t.Fatalf("fillDefaults: %v", err)
	}
	if cfg.ExePath == "" {
		t.Error("ExePath should be auto-detected, got empty")
	}
}

func TestServerArgsDefaultDirs(t *testing.T) {
	sc := ServiceConfig{}
	args := sc.ServerArgs()
	if len(args) != 1 || args[0] != "--server" {
		t.Errorf("ServerArgs() = %v, want [--server]", args)
	}
}

func TestServerArgsCustomDirs(t *testing.T) {
	sc := ServiceConfig{CfgDir: "/etc/test", LogDir: "/var/log/test"}
	args := sc.ServerArgs()
	want := []string{"--server", "--cfgdir", "/etc/test", "--logdir", "/var/log/test"}
	if len(args) != len(want) {
		t.Fatalf("ServerArgs() = %v, want %v", args, want)
	}
	for i := range want {
		if args[i] != want[i] {
			t.Errorf("ServerArgs()[%d] = %q, want %q", i, args[i], want[i])
		}
	}
}

func TestServerArgsCfgDirOnly(t *testing.T) {
	sc := ServiceConfig{CfgDir: "/etc/myspk"}
	args := sc.ServerArgs()
	want := []string{"--server", "--cfgdir", "/etc/myspk"}
	if len(args) != len(want) {
		t.Fatalf("ServerArgs() = %v, want %v", args, want)
	}
	for i := range want {
		if args[i] != want[i] {
			t.Errorf("ServerArgs()[%d] = %q, want %q", i, args[i], want[i])
		}
	}
}

func TestServerArgsLogDirOnly(t *testing.T) {
	sc := ServiceConfig{LogDir: "/tmp/logs"}
	args := sc.ServerArgs()
	want := []string{"--server", "--logdir", "/tmp/logs"}
	if len(args) != len(want) {
		t.Fatalf("ServerArgs() = %v, want %v", args, want)
	}
	for i := range want {
		if args[i] != want[i] {
			t.Errorf("ServerArgs()[%d] = %q, want %q", i, args[i], want[i])
		}
	}
}

func TestValidateServerFilesMissing(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := ServiceConfig{
		CfgDir:  tmpDir,
		ExePath: "/usr/bin/spk",
	}
	err := validateServerFiles(cfg)
	if err == nil {
		t.Fatal("expected error for missing files")
	}
	// Should mention all three required files
	for _, f := range []string{"spk_server.toml", "server.key", "server.crt"} {
		if !strings.Contains(err.Error(), f) {
			t.Errorf("error should mention %q: %v", f, err)
		}
	}
}

func TestValidateServerFilesPresent(t *testing.T) {
	tmpDir := t.TempDir()
	// Create dummy files
	for _, f := range []string{"spk_server.toml", "server.key", "server.crt"} {
		path := tmpDir + "/" + f
		if err := os.WriteFile(path, []byte("test"), 0600); err != nil {
			t.Fatalf("write %s: %v", f, err)
		}
	}
	cfg := ServiceConfig{
		CfgDir:  tmpDir,
		ExePath: "/usr/bin/spk",
	}
	if err := validateServerFiles(cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestIsWindows(t *testing.T) {
	got := isWindows()
	if runtime.GOOS == "windows" && !got {
		t.Error("isWindows should return true on windows")
	}
	if runtime.GOOS != "windows" && got {
		t.Error("isWindows should return false on non-windows")
	}
}

func TestDetectDefaultCfgDir(t *testing.T) {
	exePath := filepath.Join("root", "bin", "spk")
	dir := detectDefaultCfgDir(exePath)
	if runtime.GOOS == "windows" {
		want := filepath.Join(filepath.Dir(exePath), "config")
		if dir != want {
			t.Errorf("detectDefaultCfgDir() = %q, want %q", dir, want)
		}
		return
	}
	if dir == "" {
		t.Fatal("detectDefaultCfgDir should return non-empty dir")
	}
	if dir != "/etc/spk" && dir != filepath.Dir(exePath) {
		t.Errorf("detectDefaultCfgDir() = %q, want /etc/spk or %q", dir, filepath.Dir(exePath))
	}
}

func TestReadLineTrimsWhitespace(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("  hello world  \n"))
	if got := readLine(r); got != "hello world" {
		t.Errorf("readLine() = %q, want %q", got, "hello world")
	}
}
