// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package service

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func init() {
	platformInstall = installLinux
	platformUninstall = uninstallLinux
}

// installLinux handles systemd, OpenWRT procd, and generic init.d.
func installLinux(cfg ServiceConfig) error {
	// Detect init system
	if isSystemd() {
		return installSystemd(cfg)
	}
	if isOpenWRT() {
		return installOpenWRT(cfg)
	}
	return fmt.Errorf("unsupported init system (requires systemd or OpenWRT procd)")
}

func uninstallLinux(cfg ServiceConfig) error {
	if isSystemd() {
		return uninstallSystemd(cfg)
	}
	if isOpenWRT() {
		return uninstallOpenWRT(cfg)
	}
	return fmt.Errorf("unsupported init system")
}

func isSystemd() bool {
	_, err := os.Stat("/run/systemd/system")
	return err == nil
}

func isOpenWRT() bool {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return false
	}
	return strings.Contains(string(data), "OpenWrt")
}

// -- systemd --

// buildSystemdUnit returns the content of the systemd service unit file for cfg.
// Exposed as a package-level function so it can be tested without root privileges.
func buildSystemdUnit(cfg ServiceConfig) string {
	args := strings.Join(cfg.ServerArgs(), " ")

	// Resolve the actual config and log directories that the server will use.
	// If --cfgdir / --logdir are not specified, fall back to the platform defaults.
	// Each directory is treated independently so that specifying only one custom
	// path does not accidentally retain the other default in ReadWritePaths.
	cfgDir := "/etc/spk"
	if cfg.CfgDir != "" {
		cfgDir = cfg.CfgDir
	}
	logDir := "/var/log/spk"
	if cfg.LogDir != "" {
		logDir = cfg.LogDir
	}

	// ReadWritePaths lists exactly the two writable trees the server needs.
	// ProtectSystem=strict makes everything else read-only, so every directory
	// that the server writes to must appear here AND must already exist when the
	// service starts (ProtectSystem=strict prevents runtime creation).
	rwPaths := cfgDir + " " + logDir

	return fmt.Sprintf(`[Unit]
Description=%s
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
# Create read-write directories before security restrictions apply.
# The + prefix runs the command with full root privileges.
ExecStartPre=+/bin/mkdir -p %s
ExecStart=%s %s
Restart=on-failure
RestartSec=5
LimitNOFILE=65536
# Security hardening (ProtectHome=read-only allows binaries in /root or /home)
NoNewPrivileges=yes
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=%s
PrivateTmp=true

[Install]
WantedBy=multi-user.target
`, cfg.DisplayName(), rwPaths, cfg.ExePath, args, rwPaths)
}

func installSystemd(cfg ServiceConfig) error {
	name := cfg.ServiceName()
	unitPath := "/etc/systemd/system/" + name + ".service"

	// Check for service name conflict.
	if _, err := os.Stat(unitPath); err == nil {
		return fmt.Errorf("service %q already exists at %s\n"+
			"Use 'spk --uninstall' to remove it first, or choose a different label.",
			name, unitPath)
	}

	unit := buildSystemdUnit(cfg)

	if err := os.WriteFile(unitPath, []byte(unit), 0644); err != nil {
		return fmt.Errorf("write unit file: %w", err)
	}

	// Reload and enable
	cmds := [][]string{
		{"systemctl", "daemon-reload"},
		{"systemctl", "enable", name},
		{"systemctl", "start", name},
	}
	for _, c := range cmds {
		cmd := exec.Command(c[0], c[1:]...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("%s: %w", strings.Join(c, " "), err)
		}
	}

	fmt.Printf("Service %q (%s) installed and started.\n", cfg.DisplayName(), name)
	fmt.Printf("  Status:  systemctl status %s\n", name)
	fmt.Printf("  Logs:    journalctl -u %s -f\n", name)
	fmt.Printf("  Stop:    systemctl stop %s\n", name)
	fmt.Printf("  Remove:  spk --uninstall\n")
	return nil
}

func uninstallSystemd(cfg ServiceConfig) error {
	// Find all SPK-related systemd services
	services := findSPKServicesSystemd()
	if len(services) == 0 {
		fmt.Println("No SPK services found.")
		return nil
	}

	fmt.Println("Found SPK services:")
	fmt.Println()
	for i, svc := range services {
		fmt.Printf("  %d. %s\n", i+1, svc.name)
		fmt.Printf("     Command: %s\n", svc.execStart)
		fmt.Println()
	}

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter the number to uninstall (or press Enter to cancel): ")
	choice := strings.TrimSpace(readLineLinux(reader))
	if choice == "" {
		fmt.Println("Cancelled.")
		return nil
	}

	idx := 0
	for _, c := range choice {
		if c < '0' || c > '9' {
			fmt.Println("Invalid choice.")
			return nil
		}
		idx = idx*10 + int(c-'0')
	}
	idx-- // 1-based to 0-based
	if idx < 0 || idx >= len(services) {
		fmt.Println("Invalid choice.")
		return nil
	}

	svc := services[idx]

	cmds := [][]string{
		{"systemctl", "stop", svc.unitName},
		{"systemctl", "disable", svc.unitName},
	}
	for _, c := range cmds {
		cmd := exec.Command(c[0], c[1:]...)
		cmd.Run() // Ignore errors (service might not be running)
	}

	if err := os.Remove(svc.unitPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove unit file: %w", err)
	}

	exec.Command("systemctl", "daemon-reload").Run()
	fmt.Printf("Service %q uninstalled.\n", svc.name)
	return nil
}

type linuxService struct {
	name      string
	unitName  string
	unitPath  string
	execStart string
}

// findSPKServicesSystemd scans /etc/systemd/system for SPK-related unit files.
func findSPKServicesSystemd() []linuxService {
	dir := "/etc/systemd/system"
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}

	var services []linuxService
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasPrefix(name, "spk") || !strings.HasSuffix(name, ".service") {
			continue
		}
		unitPath := filepath.Join(dir, name)
		data, err := os.ReadFile(unitPath)
		if err != nil {
			continue
		}
		// Extract ExecStart and Description
		var execStart, description string
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "ExecStart=") {
				execStart = strings.TrimPrefix(line, "ExecStart=")
			}
			if strings.HasPrefix(line, "Description=") {
				description = strings.TrimPrefix(line, "Description=")
			}
		}
		displayName := description
		if displayName == "" {
			displayName = strings.TrimSuffix(name, ".service")
		}
		services = append(services, linuxService{
			name:      displayName,
			unitName:  strings.TrimSuffix(name, ".service"),
			unitPath:  unitPath,
			execStart: execStart,
		})
	}
	return services
}

func readLineLinux(reader *bufio.Reader) string {
	line, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		fmt.Fprintf(os.Stderr, "  Warning: failed to read input: %v\n", err)
	}
	return strings.TrimSpace(line)
}

// -- OpenWRT procd --

func installOpenWRT(cfg ServiceConfig) error {
	name := cfg.ServiceName()
	initPath := "/etc/init.d/" + name

	// Check for service name conflict.
	if _, err := os.Stat(initPath); err == nil {
		return fmt.Errorf("service %q already exists at %s\n"+
			"Use 'spk --uninstall' to remove it first, or choose a different label.",
			name, initPath)
	}

	args := strings.Join(cfg.ServerArgs(), " ")

	script := fmt.Sprintf(`#!/bin/sh /etc/rc.common
# %s

START=99
STOP=10
USE_PROCD=1

start_service() {
    procd_open_instance
    procd_set_param command %s %s
    procd_set_param respawn
    procd_set_param stderr 1
    procd_set_param stdout 1
    procd_close_instance
}
`, cfg.DisplayName(), cfg.ExePath, args)

	if err := os.WriteFile(initPath, []byte(script), 0755); err != nil {
		return fmt.Errorf("write init script: %w", err)
	}

	cmds := [][]string{
		{initPath, "enable"},
		{initPath, "start"},
	}
	for _, c := range cmds {
		cmd := exec.Command(c[0], c[1:]...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("%s: %w", strings.Join(c, " "), err)
		}
	}

	fmt.Printf("Service %q installed and started.\n", cfg.DisplayName())
	fmt.Printf("  Status:  %s status\n", initPath)
	fmt.Printf("  Stop:    %s stop\n", initPath)
	fmt.Printf("  Remove:  spk --uninstall\n")
	return nil
}

func uninstallOpenWRT(cfg ServiceConfig) error {
	name := cfg.ServiceName()
	initPath := "/etc/init.d/" + name

	exec.Command(initPath, "stop").Run()
	exec.Command(initPath, "disable").Run()

	if err := os.Remove(initPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove init script: %w", err)
	}

	fmt.Printf("Service %q uninstalled.\n", cfg.DisplayName())
	return nil
}
