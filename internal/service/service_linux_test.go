//go:build linux

// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package service

import (
	"strings"
	"testing"
)

// TestBuildSystemdUnitProtectHome verifies that the generated unit file uses
// ProtectHome=read-only (not =true) so that binaries located under /root or
// /home can still be executed by the service manager.
func TestBuildSystemdUnitProtectHome(t *testing.T) {
	cfg := ServiceConfig{
		ExePath: "/root/bin/spk",
		CfgDir:  "/etc/spk",
		LogDir:  "/var/log/spk",
	}
	unit := buildSystemdUnit(cfg)

	if strings.Contains(unit, "ProtectHome=true") {
		t.Error("unit file must not use ProtectHome=true (breaks binaries in /root); use ProtectHome=read-only")
	}
	if !strings.Contains(unit, "ProtectHome=read-only") {
		t.Error("unit file should use ProtectHome=read-only")
	}
}

// TestBuildSystemdUnitExecStart verifies the ExecStart line is correct.
func TestBuildSystemdUnitExecStart(t *testing.T) {
	cfg := ServiceConfig{
		ExePath: "/usr/local/bin/spk",
	}
	unit := buildSystemdUnit(cfg)

	if !strings.Contains(unit, "ExecStart=/usr/local/bin/spk --server") {
		t.Errorf("unit file should contain ExecStart with binary and --server:\n%s", unit)
	}
}

// TestBuildSystemdUnitCustomDirs verifies custom cfgdir/logdir end up in ReadWritePaths.
func TestBuildSystemdUnitCustomDirs(t *testing.T) {
	cfg := ServiceConfig{
		ExePath: "/usr/local/bin/spk",
		CfgDir:  "/opt/spk/config",
		LogDir:  "/opt/spk/logs",
	}
	unit := buildSystemdUnit(cfg)

	if !strings.Contains(unit, "/opt/spk/config") {
		t.Error("ReadWritePaths should include custom CfgDir")
	}
	if !strings.Contains(unit, "/opt/spk/logs") {
		t.Error("ReadWritePaths should include custom LogDir")
	}
	if !strings.Contains(unit, "--cfgdir /opt/spk/config") {
		t.Error("ExecStart should include --cfgdir")
	}
	if !strings.Contains(unit, "--logdir /opt/spk/logs") {
		t.Error("ExecStart should include --logdir")
	}
}

// TestBuildSystemdUnitServiceName verifies the service name changes with a label.
func TestBuildSystemdUnitServiceName(t *testing.T) {
	cfg := ServiceConfig{
		ExePath:      "/usr/local/bin/spk",
		DisplayLabel: "production",
	}
	if cfg.ServiceName() != "spk_production" {
		t.Errorf("ServiceName() = %q, want %q", cfg.ServiceName(), "spk_production")
	}

	unit := buildSystemdUnit(cfg)
	if !strings.Contains(unit, "Secured Port Knock (production)") {
		t.Errorf("unit Description should reflect label:\n%s", unit)
	}
}

// TestBuildSystemdUnitExecStartPreDefault verifies that, with no custom dirs, the
// generated unit creates both /etc/spk and /var/log/spk via ExecStartPre so that
// ProtectSystem=strict does not fail on first install when those dirs are absent.
func TestBuildSystemdUnitExecStartPreDefault(t *testing.T) {
	cfg := ServiceConfig{
		ExePath: "/usr/local/bin/spk",
	}
	unit := buildSystemdUnit(cfg)

	if !strings.Contains(unit, "ExecStartPre=+/bin/mkdir -p /etc/spk /var/log/spk") {
		t.Errorf("default unit must create both /etc/spk and /var/log/spk:\n%s", unit)
	}
}

// TestBuildSystemdUnitExecStartPreCfgDirOnly verifies that a custom --cfgdir
// replaces /etc/spk while /var/log/spk is still created as the log dir.
func TestBuildSystemdUnitExecStartPreCfgDirOnly(t *testing.T) {
	cfg := ServiceConfig{
		ExePath: "/usr/local/bin/spk",
		CfgDir:  "/opt/spk/config",
	}
	unit := buildSystemdUnit(cfg)

	// Custom cfgdir must be created.
	if !strings.Contains(unit, "/opt/spk/config") {
		t.Error("ExecStartPre should reference custom CfgDir")
	}
	// Default logdir must still be created (no --logdir was given).
	if !strings.Contains(unit, "/var/log/spk") {
		t.Error("ExecStartPre should still create default /var/log/spk when --logdir is not set")
	}
	// Default cfgdir must NOT appear -- the custom one replaced it.
	if strings.Contains(unit, "ExecStartPre=+/bin/mkdir -p /etc/spk") {
		t.Error("ExecStartPre must not reference /etc/spk when a custom --cfgdir is set")
	}
	// ReadWritePaths must not carry the redundant default either.
	if strings.Contains(unit, "ReadWritePaths=/etc/spk") {
		t.Error("ReadWritePaths must not include /etc/spk when a custom --cfgdir is set")
	}
}

// TestBuildSystemdUnitExecStartPreLogDirOnly verifies that a custom --logdir
// replaces /var/log/spk while /etc/spk is still created as the config dir.
// This was the original bug: specifying only --logdir left the redundant default
// /var/log/spk in both ExecStartPre and ReadWritePaths.
func TestBuildSystemdUnitExecStartPreLogDirOnly(t *testing.T) {
	cfg := ServiceConfig{
		ExePath: "/usr/local/bin/spk",
		LogDir:  "/opt/spk/logs",
	}
	unit := buildSystemdUnit(cfg)

	// Custom logdir must be created.
	if !strings.Contains(unit, "/opt/spk/logs") {
		t.Error("ExecStartPre should reference custom LogDir")
	}
	// Default cfgdir must still be created.
	if !strings.Contains(unit, "/etc/spk") {
		t.Error("ExecStartPre should still create default /etc/spk when --cfgdir is not set")
	}
	// Default logdir must NOT appear -- the custom one replaced it.
	if strings.Contains(unit, "ExecStartPre=+/bin/mkdir -p /etc/spk /var/log/spk") {
		t.Errorf("ExecStartPre must not retain default /var/log/spk when a custom --logdir is set:\n%s", unit)
	}
	// ReadWritePaths must not carry the redundant default logdir.
	if strings.Contains(unit, "/var/log/spk") {
		t.Errorf("ReadWritePaths and ExecStartPre must not include /var/log/spk when --logdir is set:\n%s", unit)
	}
}

// TestBuildSystemdUnitExecStartPreBothCustom verifies that when both --cfgdir
// and --logdir are set, only the custom paths appear (no defaults).
func TestBuildSystemdUnitExecStartPreBothCustom(t *testing.T) {
	cfg := ServiceConfig{
		ExePath: "/usr/local/bin/spk",
		CfgDir:  "/opt/spk/config",
		LogDir:  "/opt/spk/logs",
	}
	unit := buildSystemdUnit(cfg)

	if !strings.Contains(unit, "ExecStartPre=+/bin/mkdir -p /opt/spk/config /opt/spk/logs") {
		t.Errorf("ExecStartPre should reference both custom dirs:\n%s", unit)
	}
	// Neither default path should appear.
	if strings.Contains(unit, "/etc/spk") {
		t.Error("unit must not reference /etc/spk when both custom dirs are set")
	}
	if strings.Contains(unit, "/var/log/spk") {
		t.Error("unit must not reference /var/log/spk when both custom dirs are set")
	}
}

// TestBuildSystemdUnitExecStartPreBeforeExecStart ensures ExecStartPre appears
// before ExecStart in the generated unit so directories exist before the server starts.
func TestBuildSystemdUnitExecStartPreBeforeExecStart(t *testing.T) {
	cfg := ServiceConfig{
		ExePath: "/usr/local/bin/spk",
	}
	unit := buildSystemdUnit(cfg)

	preIdx := strings.Index(unit, "ExecStartPre=")
	startIdx := strings.Index(unit, "ExecStart=")
	if preIdx < 0 {
		t.Fatal("ExecStartPre not found in unit")
	}
	if startIdx < 0 {
		t.Fatal("ExecStart not found in unit")
	}
	if preIdx >= startIdx {
		t.Error("ExecStartPre must appear before ExecStart")
	}
}

// TestBuildSystemdUnitReadWritePathsMatchExecStartPre verifies that
// ReadWritePaths and ExecStartPre always reference the same set of directories,
// so the directories that are created are exactly those that ProtectSystem=strict
// grants write access to.
func TestBuildSystemdUnitReadWritePathsMatchExecStartPre(t *testing.T) {
	cases := []ServiceConfig{
		{ExePath: "/usr/local/bin/spk"},
		{ExePath: "/usr/local/bin/spk", CfgDir: "/opt/spk/config"},
		{ExePath: "/usr/local/bin/spk", LogDir: "/opt/spk/logs"},
		{ExePath: "/usr/local/bin/spk", CfgDir: "/opt/spk/config", LogDir: "/opt/spk/logs"},
	}
	for _, cfg := range cases {
		unit := buildSystemdUnit(cfg)

		// Extract the dirs from ExecStartPre and ReadWritePaths.
		prePrefix := "ExecStartPre=+/bin/mkdir -p "
		rwPrefix := "ReadWritePaths="
		var preDirs, rwDirs string
		for _, line := range strings.Split(unit, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, prePrefix) {
				preDirs = strings.TrimPrefix(line, prePrefix)
			}
			if strings.HasPrefix(line, rwPrefix) {
				rwDirs = strings.TrimPrefix(line, rwPrefix)
			}
		}
		if preDirs == "" {
			t.Errorf("cfg=%+v: ExecStartPre dirs not found", cfg)
			continue
		}
		if rwDirs == "" {
			t.Errorf("cfg=%+v: ReadWritePaths not found", cfg)
			continue
		}
		if preDirs != rwDirs {
			t.Errorf("cfg=%+v: ExecStartPre dirs %q != ReadWritePaths %q", cfg, preDirs, rwDirs)
		}
	}
}
