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
	platformInstall = installDarwin
	platformUninstall = uninstallDarwin
}

// installDarwin registers SPK as a launchd daemon.
func installDarwin(cfg ServiceConfig) error {
	name := cfg.ServiceName()
	label := "com.spk." + name
	plistPath := "/Library/LaunchDaemons/" + label + ".plist"

	// Check for service name conflict.
	if _, err := os.Stat(plistPath); err == nil {
		return fmt.Errorf("service %q already exists at %s\n"+
			"Use 'spk --uninstall' to remove it first, or choose a different label.",
			label, plistPath)
	}

	args := cfg.ServerArgs()

	// Build ProgramArguments array
	var argElements string
	for _, a := range args {
		argElements += fmt.Sprintf("        <string>%s</string>\n", a)
	}

	// Determine log directory
	logDir := "/var/log/spk"
	if cfg.LogDir != "" {
		logDir = cfg.LogDir
	}

	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>%s</string>
    <key>ProgramArguments</key>
    <array>
        <string>%s</string>
%s    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>%s/%s.stdout.log</string>
    <key>StandardErrorPath</key>
    <string>%s/%s.stderr.log</string>
</dict>
</plist>
`, label, cfg.ExePath, argElements, logDir, name, logDir, name)

	// Create log directory
	os.MkdirAll(logDir, 0750)

	if err := os.WriteFile(plistPath, []byte(plist), 0644); err != nil {
		return fmt.Errorf("write plist: %w", err)
	}

	cmd := exec.Command("launchctl", "load", plistPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("launchctl load: %w", err)
	}

	fmt.Printf("Service %q (%s) installed and loaded.\n", cfg.DisplayName(), label)
	fmt.Printf("  Status:  launchctl list | grep %s\n", label)
	fmt.Printf("  Stop:    launchctl unload %s\n", plistPath)
	fmt.Printf("  Remove:  spk --uninstall\n")
	return nil
}

func uninstallDarwin(cfg ServiceConfig) error {
	// Find all SPK-related launchd plists
	services := findSPKServicesDarwin()
	if len(services) == 0 {
		fmt.Println("No SPK services found.")
		return nil
	}

	fmt.Println("Found SPK services:")
	fmt.Println()
	for i, svc := range services {
		fmt.Printf("  %d. %s\n", i+1, svc.label)
		fmt.Printf("     Path: %s\n", svc.plistPath)
		fmt.Println()
	}

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter the number to uninstall (or press Enter to cancel): ")
	choice := strings.TrimSpace(readLineDarwin(reader))
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

	exec.Command("launchctl", "unload", svc.plistPath).Run()

	if err := os.Remove(svc.plistPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove plist: %w", err)
	}

	fmt.Printf("Service %q uninstalled.\n", svc.label)
	return nil
}

type darwinService struct {
	label     string
	plistPath string
}

// findSPKServicesDarwin scans LaunchDaemons for SPK-related plists.
func findSPKServicesDarwin() []darwinService {
	dir := "/Library/LaunchDaemons"
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}

	var services []darwinService
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.Contains(strings.ToLower(name), "spk") || !strings.HasSuffix(name, ".plist") {
			continue
		}
		services = append(services, darwinService{
			label:     strings.TrimSuffix(name, ".plist"),
			plistPath: filepath.Join(dir, name),
		})
	}
	return services
}

func readLineDarwin(reader *bufio.Reader) string {
	line, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		fmt.Fprintf(os.Stderr, "  Warning: failed to read input: %v\n", err)
	}
	return strings.TrimSpace(line)
}
