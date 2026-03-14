// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package service

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func init() {
	platformInstall = installWindows
	platformUninstall = uninstallWindows
}

// installWindows registers SPK as a Windows service using sc.exe.
func installWindows(cfg ServiceConfig) error {
	name := cfg.ServiceName()

	// Check for service name conflict.
	if out, err := exec.Command("sc.exe", "query", name).Output(); err == nil {
		if strings.Contains(string(out), "SERVICE_NAME") {
			return fmt.Errorf("service %q already exists\n"+
				"Use 'spk --uninstall' to remove it first, or choose a different label.", name)
		}
	}

	// Build binPath: include --service-name so the binary can register the
	// correct service name dispatcher with the Windows SCM.
	args := cfg.ServerArgs()
	args = append(args, "--service-name", name)
	binPath := `"` + cfg.ExePath + `" ` + strings.Join(args, " ")

	// Create the service
	cmd := exec.Command("sc.exe", "create", name,
		"binPath=", binPath,
		"start=", "auto",
		"DisplayName=", cfg.DisplayName(),
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("sc create: %w", err)
	}

	// Set description
	exec.Command("sc.exe", "description", name,
		"Secured port knocking server").Run()

	// Set failure recovery (restart after 5s, 10s, 30s)
	exec.Command("sc.exe", "failure", name,
		"reset=", "86400",
		"actions=", "restart/5000/restart/10000/restart/30000").Run()

	// Start the service
	startCmd := exec.Command("sc.exe", "start", name)
	startCmd.Stdout = os.Stdout
	startCmd.Stderr = os.Stderr
	if err := startCmd.Run(); err != nil {
		fmt.Printf("Warning: service created but failed to start: %v\n", err)
		fmt.Println("You may need to run --setup first if no config exists.")
	}

	fmt.Printf("Service %q (%s) installed.\n", cfg.DisplayName(), name)
	fmt.Printf("  Status:  sc query %s\n", name)
	fmt.Printf("  Stop:    sc stop %s\n", name)
	fmt.Printf("  Remove:  spk --uninstall\n")
	return nil
}

func uninstallWindows(cfg ServiceConfig) error {
	// Find all SPK-related services
	services := findSPKServicesWindows()
	if len(services) == 0 {
		fmt.Println("No SPK services found.")
		return nil
	}

	fmt.Println("Found SPK services:")
	fmt.Println()
	for i, svc := range services {
		fmt.Printf("  %d. %s\n", i+1, svc.displayName)
		fmt.Printf("     Command: %s\n", svc.binPath)
		fmt.Println()
	}

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter the number to uninstall (or press Enter to cancel): ")
	choice := strings.TrimSpace(readLineStdio(reader))
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

	// Stop the service first
	exec.Command("sc.exe", "stop", svc.name).Run()

	// Delete
	cmd := exec.Command("sc.exe", "delete", svc.name)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("sc delete: %w", err)
	}

	fmt.Printf("Service %q uninstalled.\n", svc.displayName)
	return nil
}

type winService struct {
	name        string
	displayName string
	binPath     string
}

// findSPKServicesWindows queries Windows SCM for services with "spk" in the binary path.
func findSPKServicesWindows() []winService {
	// Use sc.exe query to list services, then filter
	// Use PowerShell for reliable parsing
	psCmd := `Get-WmiObject Win32_Service | Where-Object { $_.PathName -like '*spk*' } | ForEach-Object { $_.Name + '|' + $_.DisplayName + '|' + $_.PathName }`
	cmd := exec.Command("powershell", "-NoProfile", "-Command", psCmd)
	out, err := cmd.Output()
	if err != nil {
		return nil
	}

	var services []winService
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "|", 3)
		if len(parts) != 3 {
			continue
		}
		services = append(services, winService{
			name:        parts[0],
			displayName: parts[1],
			binPath:     parts[2],
		})
	}
	return services
}

func readLineStdio(reader *bufio.Reader) string {
	line, _ := reader.ReadString('\n')
	return strings.TrimSpace(line)
}
