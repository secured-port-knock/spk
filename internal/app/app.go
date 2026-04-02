// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

// Package app implements the SPK command-line application: flag parsing,
// mode detection, version resolution, and dispatch to the server, client,
// and service sub-systems.
//
// SPK - PQC Port Knocking with ML-KEM-768/1024
//
// A post-quantum secure port knocking application that uses ML-KEM-768 or
// ML-KEM-1024 (FIPS 203) for key encapsulation and AES-256-GCM for payload
// encryption. ML-KEM-768 is the default and fits within a standard 1500-byte
// Ethernet MTU; ML-KEM-1024 provides a higher security level but requires IP
// fragmentation and is recommended for LAN use only.
//
// Usage:
//
//	spk --server --setup              # First-time server setup
//	spk --server                      # Run server
//	spk --server --export             # Re-export activation bundle
//	spk --client --setup              # First-time client setup
//	spk --client --cmd open-t22       # Open TCP port 22
//	spk --client --cmd open-t22,t443,u53  # Batch open in one packet
//	spk --client --cmd close-t22      # Close TCP port 22
//	spk --client --cmd close-t22,t443 # Batch close in one packet
//	spk --client --cmd open-all       # Open all allowed ports
//	spk --client --cmd open-t22 --duration 7200  # Open with custom open duration
//	spk --client --cmd open-t22 --ip 2001:db8::1  # With explicit IPv6
//	spk --client --cmd cust-1         # Run custom command "1"
//
// Shorthand (auto-detects client mode from config):
//
//	spk open-t22                      # Send command (auto-detect)
//	spk open-t22,t443,u53             # Batch open (auto-detect)
//	spk open-t22 --duration 3600 --ip 1.2.3.4
package app

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"github.com/secured-port-knock/spk/internal/client"
	"github.com/secured-port-knock/spk/internal/config"
	"github.com/secured-port-knock/spk/internal/logging"
	"github.com/secured-port-knock/spk/internal/server"
	"github.com/secured-port-knock/spk/internal/service"
	"github.com/secured-port-knock/spk/internal/sniffer"
)

// version variables are overridden at build time via -ldflags:
//
//	-X github.com/secured-port-knock/spk/internal/app.version=1.0.3
//	-X github.com/secured-port-knock/spk/internal/app.commit=abc1234
//	-X github.com/secured-port-knock/spk/internal/app.buildNumber=1008
//
// When not injected (plain 'go install' / 'go build'), the sentinel value
// "Dev" for commit triggers version resolution from runtime/debug.BuildInfo.
var (
	version     = "1.0.0"
	commit      = "Dev"
	buildNumber = "0"
)

func fullVersion() string {
	return fmt.Sprintf("%s.%s", version, buildNumber)
}

// versionTag returns the version string used in binary filenames.
// Pcap-capable builds append "p" (e.g. "1.0.3.1004p").
func versionTag() string {
	v := fullVersion()
	if sniffer.PcapImplemented() {
		v += "p"
	}
	return v
}

// pcapLabel returns a human-readable PCAP capability label.
// Uses sniffer.PcapImplemented() which reflects the actual compile-time state
// regardless of whether -ldflags were passed (correct for 'go install' builds).
func pcapLabel() string {
	if sniffer.PcapImplemented() {
		return "[With PCAP]"
	}
	return "[No PCAP]"
}

// resolveVersionFromBuildInfo returns the display version and commit label to
// show in --version output. It is a pure function that accepts all inputs
// explicitly so it can be tested without modifying globals.
//
// Rules:
//  1. If currentCommit != "Dev", ldflags were injected by the build scripts;
//     use currentVersion+"."+currentBuildNumber and currentCommit unchanged.
//  2. Otherwise this is a plain 'go install' or 'go build' without ldflags.
//     If debug.ReadBuildInfo returned a real module version tag (non-empty,
//     not "(devel)"), strip the leading "v" and label it "Go".
//  3. Fall back to the hardcoded placeholder and "Dev" label.
func resolveVersionFromBuildInfo(currentVersion, currentBuildNumber, currentCommit string, info *debug.BuildInfo, ok bool) (ver, commitLabel string) {
	if currentCommit != "Dev" {
		return fmt.Sprintf("%s.%s", currentVersion, currentBuildNumber), currentCommit
	}
	if ok && info != nil && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return strings.TrimPrefix(info.Main.Version, "v"), "Go"
	}
	return fmt.Sprintf("%s.%s", currentVersion, currentBuildNumber), currentCommit
}

// versionString returns the full application version string shown to users.
func versionString() string {
	info, ok := debug.ReadBuildInfo()
	ver, commitLabel := resolveVersionFromBuildInfo(version, buildNumber, commit, info, ok)
	return fmt.Sprintf("SPK - Secured Port Knock - %s (%s) %s\nCopyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)\nGithub Repository: https://github.com/secured-port-knock/spk", ver, commitLabel, pcapLabel())
}

// isPrivileged checks whether the process is running with elevated privileges
// (root on Linux/macOS, Administrator on Windows).
func isPrivileged() bool {
	if runtime.GOOS == "windows" {
		// Attempt to open the \\.\PHYSICALDRIVE0 handle - only Administrators can.
		f, err := os.Open("\\\\.\\PHYSICALDRIVE0")
		if err != nil {
			return false
		}
		f.Close()
		return true
	}
	// Unix: running as root (UID 0)
	return os.Getuid() == 0
}

// promptModeSelection asks the user to pick server or client mode with a 30s timeout.
// Returns "server" or "client".
func promptModeSelection() string {
	fmt.Println("No configuration found (or both server and client configs exist).")
	fmt.Println("Which mode would you like to run?")
	fmt.Println("  1. Server (default)")
	fmt.Println("  2. Client")
	fmt.Fprintln(os.Stderr, "  (no input received in 30s -> server mode will be selected automatically)")
	fmt.Print("Select [1]: ")

	choiceCh := make(chan string, 1)
	go func() {
		var input string
		fmt.Scanln(&input)
		choiceCh <- strings.TrimSpace(input)
	}()

	timer := time.NewTimer(30 * time.Second)
	select {
	case choice := <-choiceCh:
		timer.Stop()
		switch choice {
		case "2", "client", "c":
			return "client"
		}
		return "server"
	case <-timer.C:
		fmt.Println()
		fmt.Fprintln(os.Stderr, "[auto-detect] No input after 30s -> defaulting to server mode")
		return "server"
	}
}

// applyAutoDetect sets *serverMode or *clientMode based on existing config files
// or user prompt, and enables setup if no config file is present for the chosen mode.
func applyAutoDetect(serverMode, clientMode *bool, cmd *string, setup *bool) {
	if *cmd != "" {
		*clientMode = true
		fmt.Fprintln(os.Stderr, "[auto-detect] Command specified -> client mode")
		return
	}

	_, detectedMode := config.DetectConfigPath()
	switch detectedMode {
	case "server":
		*serverMode = true
		fmt.Fprintln(os.Stderr, "[auto-detect] Found server config -> server mode")
	case "client":
		*clientMode = true
		fmt.Fprintln(os.Stderr, "[auto-detect] Found client config -> client mode")
	default:
		chosenMode := promptModeSelection()
		if chosenMode == "client" {
			*clientMode = true
			if _, err := os.Stat(config.ClientConfigPath()); os.IsNotExist(err) {
				*setup = true
			}
		} else {
			*serverMode = true
			if _, err := os.Stat(config.ServerConfigPath()); os.IsNotExist(err) {
				*setup = true
			}
		}
	}
}

// runServerMode dispatches the server sub-command (setup, export, or run).
func runServerMode(setup, export *bool, cfgDir, svcName *string) {
	_ = config.ConfigDir()
	if *cfgDir == "" {
		if cfgDirErr := config.ConfigDirInitError(); cfgDirErr != nil {
			fmt.Fprintf(os.Stderr,
				"Error: %v.\nTry running as root, fixing the directory permissions, or use --cfgdir <path>.\n",
				cfgDirErr)
			os.Exit(1)
		}
	}
	switch {
	case *setup:
		server.RunSetup()
	case *export:
		server.RunExport()
	default:
		if _, err := os.Stat(config.ServerConfigPath()); os.IsNotExist(err) {
			fmt.Fprintln(os.Stderr, "No server config found. Starting first-time setup...")
			server.RunSetup()
			return
		}
		fmt.Fprintf(os.Stderr, "%s\n", versionString())
		warnIfUnprivileged()
		if ran, err := runAsWindowsService(*svcName, server.Run, server.Stop); ran {
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			return
		}
		server.Run()
	}
}

// warnIfUnprivileged prints a warning when the process is not running as root/Administrator.
func warnIfUnprivileged() {
	if isPrivileged() {
		return
	}
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "===========================================================")
	fmt.Fprintln(os.Stderr, "  WARNING: Not running as root / Administrator!")
	fmt.Fprintln(os.Stderr, "  Many features will fail (firewall rules, raw sockets,")
	fmt.Fprintln(os.Stderr, "  packet capture, WinDivert, AF_PACKET, etc.).")
	if runtime.GOOS == "windows" {
		fmt.Fprintln(os.Stderr, "  Restart with: Run as Administrator")
	} else {
		fmt.Fprintln(os.Stderr, "  Restart with: sudo spk --server")
	}
	fmt.Fprintln(os.Stderr, "===========================================================")
	fmt.Fprintln(os.Stderr, "")
}

// runClientMode dispatches the client sub-command (setup, delete-key, or send command).
func runClientMode(setup, deleteKey *bool, cmd, host, clientIP, totpCode *string, duration *int) {
	switch {
	case *setup:
		client.RunSetup()
	case *deleteKey:
		client.RunDeleteKey()
	case *cmd != "":
		client.RunCommand(*host, *cmd, *duration, *clientIP, *totpCode)
	default:
		if _, err := os.Stat(config.ClientConfigPath()); os.IsNotExist(err) {
			fmt.Fprintln(os.Stderr, "No client config found. Starting first-time setup...")
			client.RunSetup()
			return
		}
		fmt.Fprintln(os.Stderr, "Error: --cmd is required in client mode")
		fmt.Fprintln(os.Stderr, "Usage: spk --client --cmd open-t22")
		os.Exit(1)
	}
}

// Run is the application entry point, called from package main.
func Run() {
	// Define flags
	serverMode := flag.Bool("server", false, "Run in server mode")
	clientMode := flag.Bool("client", false, "Run in client mode")
	setup := flag.Bool("setup", false, "Run interactive first-time setup")
	deleteKey := flag.Bool("delete-key", false, "Delete server public key from secure storage (client only)")
	export := flag.Bool("export", false, "Export activation bundle (server only)")
	cmd := flag.String("cmd", "", "Command to send (see command formats below)")
	duration := flag.Int("duration", 0, "Custom open duration in seconds (client only, if allowed)")
	host := flag.String("host", "", "Server host override (client only)")
	clientIP := flag.String("ip", "", "Client IP override (IPv4/IPv6, auto-detected if empty)")
	totpCode := flag.String("totp", "", "TOTP code for two-factor authentication (client only)")
	showVersion := flag.Bool("version", false, "Show version")
	installSvc := flag.Bool("install", false, "Install as system service (server only)")
	uninstallSvc := flag.Bool("uninstall", false, "Uninstall system service (server only)")
	cfgDir := flag.String("cfgdir", "", "Custom config directory (overrides platform default)")
	logDir := flag.String("logdir", "", "Custom log directory (overrides platform default)")
	svcName := flag.String("service-name", "", "Windows service name (set automatically by --install, do not use manually)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "%s\n\n", versionString())
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  Server:\n")
		fmt.Fprintf(os.Stderr, "    spk --server --setup     First-time setup (generates keys & config)\n")
		fmt.Fprintf(os.Stderr, "    spk --server             Start listening for knocks\n")
		fmt.Fprintf(os.Stderr, "    spk --server --export    Re-export activation bundle\n")
		fmt.Fprintf(os.Stderr, "    spk --install            Install as system service\n")
		fmt.Fprintf(os.Stderr, "    spk --uninstall          Uninstall system service\n")
		fmt.Fprintf(os.Stderr, "    spk --server --cfgdir /etc/test --logdir /var/log/test\n")
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "  Client:\n")
		fmt.Fprintf(os.Stderr, "    spk --client --setup         First-time setup (import server key)\n")
		fmt.Fprintf(os.Stderr, "    spk --client --cmd CMD       Send command (see formats below)\n")
		fmt.Fprintf(os.Stderr, "    spk --client --cmd CMD --totp 123456  Send with TOTP\n")
		fmt.Fprintf(os.Stderr, "    spk --client --delete-key    Delete stored server public key\n")
		fmt.Fprintf(os.Stderr, "    spk --cfgdir DIR --client --delete-key  Delete key for specific config\n")
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "  Shorthand (auto-detects client mode from config):\n")
		fmt.Fprintf(os.Stderr, "    spk open-t22             Open TCP 22 (auto-detect client)\n")
		fmt.Fprintf(os.Stderr, "    spk open-t22 --duration 3600 --ip 1.2.3.4\n")
		fmt.Fprintf(os.Stderr, "    spk open-t22,t443,u53    Batch open in one packet\n")
		fmt.Fprintf(os.Stderr, "    spk close-t22,t443       Batch close in one packet\n")
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "  Command formats:\n")
		fmt.Fprintf(os.Stderr, "    open-t<port>          Open TCP port       (e.g., open-t22, open-t443)\n")
		fmt.Fprintf(os.Stderr, "    open-u<port>          Open UDP port       (e.g., open-u53)\n")
		fmt.Fprintf(os.Stderr, "    close-t<port>         Close TCP port\n")
		fmt.Fprintf(os.Stderr, "    close-u<port>         Close UDP port\n")
		fmt.Fprintf(os.Stderr, "    open-all              Open all allowed ports\n")
		fmt.Fprintf(os.Stderr, "    close-all             Close all your open ports\n")
		fmt.Fprintf(os.Stderr, "    open-t22,t443,u53     Batch open (comma-separated port specs)\n")
		fmt.Fprintf(os.Stderr, "    close-t22,t443        Batch close (comma-separated port specs)\n")
		fmt.Fprintf(os.Stderr, "    cust-<id>             Run custom command (e.g., cust-1, cust-ping)\n")
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "  Options:\n")
		fmt.Fprintf(os.Stderr, "    --server        Run in server mode\n")
		fmt.Fprintf(os.Stderr, "    --client        Run in client mode\n")
		fmt.Fprintf(os.Stderr, "    --setup         Run interactive first-time setup\n")
		fmt.Fprintf(os.Stderr, "    --export        Export activation bundle (server only)\n")
		fmt.Fprintf(os.Stderr, "    --cmd CMD       Command to send (see command formats above)\n")
		fmt.Fprintf(os.Stderr, "    --duration N    Custom open duration in seconds (client only, open- commands)\n")
		fmt.Fprintf(os.Stderr, "    --host ADDR     Server host override (client only)\n")
		fmt.Fprintf(os.Stderr, "    --ip ADDR       Client IP override, IPv4 or IPv6 (auto-detected if empty)\n")
		fmt.Fprintf(os.Stderr, "    --totp CODE     6-digit TOTP code for two-factor auth (client only)\n")
		fmt.Fprintf(os.Stderr, "    --delete-key    Delete server public key from secure storage (client only)\n")
		fmt.Fprintf(os.Stderr, "    --install       Install as system service (server only)\n")
		fmt.Fprintf(os.Stderr, "    --uninstall     Uninstall system service (server only)\n")
		fmt.Fprintf(os.Stderr, "    --cfgdir DIR    Custom config directory (overrides default)\n")
		fmt.Fprintf(os.Stderr, "    --logdir DIR    Custom log directory (overrides default)\n")
		fmt.Fprintf(os.Stderr, "    --version       Show version\n")
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "  Auto-detect: if neither --server nor --client is specified,\n")
		fmt.Fprintf(os.Stderr, "  mode is detected from config files, or you will be prompted.\n")
		fmt.Fprintf(os.Stderr, "\n")
	}

	flag.Parse()

	// Support positional command: spk open-t22 [--duration ...]
	if *cmd == "" && len(flag.Args()) > 0 {
		arg := flag.Args()[0]
		if strings.HasPrefix(arg, "open-") || strings.HasPrefix(arg, "close-") ||
			arg == "open-all" || arg == "close-all" || strings.HasPrefix(arg, "cust-") {
			*cmd = arg
		}
	}

	if *showVersion {
		fmt.Println(versionString())
		os.Exit(0)
	}

	if *cfgDir != "" {
		config.SetConfigDir(*cfgDir)
	}
	if *logDir != "" {
		if err := logging.SetLogDir(*logDir); err != nil {
			fmt.Fprintf(os.Stderr, "Error: failed to set log directory: %v\n", err)
			os.Exit(1)
		}
	}

	if *installSvc || *uninstallSvc {
		if *clientMode {
			fmt.Fprintln(os.Stderr, "Error: --install/--uninstall is server only")
			os.Exit(1)
		}
		svcCfg := service.ServiceConfig{CfgDir: *cfgDir, LogDir: *logDir}
		var err error
		if *installSvc {
			err = service.Install(svcCfg)
		} else {
			err = service.Uninstall(svcCfg)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	if *serverMode && *clientMode {
		fmt.Fprintln(os.Stderr, "Error: Cannot run as both --server and --client")
		os.Exit(1)
	}

	if !*serverMode && !*clientMode {
		applyAutoDetect(serverMode, clientMode, cmd, setup)
	}

	if *serverMode {
		runServerMode(setup, export, cfgDir, svcName)
		return
	}

	if *clientMode {
		runClientMode(setup, deleteKey, cmd, host, clientIP, totpCode, duration)
	}
}
