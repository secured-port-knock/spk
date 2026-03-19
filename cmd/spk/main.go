// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
// SPK - PQC Port Knocking with ML-KEM-1024
//
// A post-quantum secure port knocking application that uses ML-KEM-1024
// (FIPS 203) for key encapsulation and AES-256-GCM for payload encryption.
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
package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"spk/internal/client"
	"spk/internal/config"
	"spk/internal/logging"
	"spk/internal/server"
	"spk/internal/service"
)

var (
	version     = "1.0.0"
	commit      = "dev"
	buildNumber = "0"
	pcapBuild   = "0" // set to "1" by linker for pcap builds
)

func fullVersion() string {
	return fmt.Sprintf("%s.%s", version, buildNumber)
}

// versionTag returns the version string used in binary filenames.
// Pcap-capable builds append "p" (e.g. "1.0.3.1004p").
func versionTag() string {
	v := fullVersion()
	if pcapBuild == "1" {
		v += "p"
	}
	return v
}

// pcapLabel returns a human-readable PCAP capability label.
func pcapLabel() string {
	if pcapBuild == "1" {
		return "[With PCAP]"
	}
	return "[No PCAP]"
}

// versionString returns the full application version string shown to users.
func versionString() string {
	return fmt.Sprintf("SPK - Secured Port Knock - %s (%s) %s\nCopyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)\nGithub Repository: https://github.com/Secured-Port-Knock/Secured-Port-Knock", fullVersion(), commit, pcapLabel())
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

func main() {
	// Define flags
	serverMode := flag.Bool("server", false, "Run in server mode")
	clientMode := flag.Bool("client", false, "Run in client mode")
	setup := flag.Bool("setup", false, "Run interactive first-time setup")
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
		fmt.Fprintf(os.Stderr, "    spk --client --setup     First-time setup (import server key)\n")
		fmt.Fprintf(os.Stderr, "    spk --client --cmd CMD   Send command (see formats below)\n")
		fmt.Fprintf(os.Stderr, "    spk --client --cmd CMD --totp 123456   Send with TOTP\n")
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

	// Apply custom directory overrides before anything else
	if *cfgDir != "" {
		config.SetConfigDir(*cfgDir)
	}
	if *logDir != "" {
		if err := logging.SetLogDir(*logDir); err != nil {
			fmt.Fprintf(os.Stderr, "Error: failed to set log directory: %v\n", err)
			os.Exit(1)
		}
	}

	// Handle service install/uninstall (independent of mode flags)
	if *installSvc || *uninstallSvc {
		if *clientMode {
			fmt.Fprintln(os.Stderr, "Error: --install/--uninstall is server only")
			os.Exit(1)
		}
		svcCfg := service.ServiceConfig{
			CfgDir: *cfgDir,
			LogDir: *logDir,
		}
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

	// Auto-detect mode from config files if neither flag specified
	if !*serverMode && !*clientMode {
		// If a command is specified, it must be client mode
		if *cmd != "" {
			*clientMode = true
			fmt.Fprintln(os.Stderr, "[auto-detect] Command specified -> client mode")
		} else {
			_, detectedMode := config.DetectConfigPath()
			switch detectedMode {
			case "server":
				*serverMode = true
				fmt.Fprintln(os.Stderr, "[auto-detect] Found server config -> server mode")
			case "client":
				*clientMode = true
				fmt.Fprintln(os.Stderr, "[auto-detect] Found client config -> client mode")
			default:
				// No config or both configs exist - ask user with 30s timeout
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

				var choice string
				timer := time.NewTimer(30 * time.Second)
				select {
				case choice = <-choiceCh:
					timer.Stop()
				case <-timer.C:
					fmt.Println()
					fmt.Fprintln(os.Stderr, "[auto-detect] No input after 30s -> defaulting to server mode")
				}

				switch choice {
				case "2", "client", "c":
					*clientMode = true
					if _, err := os.Stat(config.ClientConfigPath()); os.IsNotExist(err) {
						*setup = true
					}
				default:
					// "1", "server", "s", "", or timeout
					*serverMode = true
					if _, err := os.Stat(config.ServerConfigPath()); os.IsNotExist(err) {
						*setup = true
					}
				}
			}
		}
	}

	if *serverMode {
		switch {
		case *setup:
			server.RunSetup()
		case *export:
			server.RunExport()
		default:
			// Auto-detect: if no server config exists, run setup first
			if _, err := os.Stat(config.ServerConfigPath()); os.IsNotExist(err) {
				fmt.Fprintln(os.Stderr, "No server config found. Starting first-time setup...")
				server.RunSetup()
				return
			}
			fmt.Fprintf(os.Stderr, "%s\n", versionString())
			if !isPrivileged() {
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
			// On Windows, check if the SCM launched us as a service and dispatch
			// accordingly.  This must happen before server.Run() so the SCM timer
			// (ERROR 1053) does not expire.
			if ran, err := runAsWindowsService(*svcName, server.Run, server.Stop); ran {
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error: %v\n", err)
					os.Exit(1)
				}
				return
			}
			server.Run()
		}
		return
	}

	if *clientMode {
		switch {
		case *setup:
			client.RunSetup()
		case *cmd != "":
			client.RunCommand(*host, *cmd, *duration, *clientIP, *totpCode)
		default:
			// Auto-detect: if no client config exists, run setup first
			if _, err := os.Stat(config.ClientConfigPath()); os.IsNotExist(err) {
				fmt.Fprintln(os.Stderr, "No client config found. Starting first-time setup...")
				client.RunSetup()
				return
			}
			fmt.Fprintln(os.Stderr, "Error: --cmd is required in client mode")
			fmt.Fprintln(os.Stderr, "Usage: spk --client --cmd open-t22")
			os.Exit(1)
		}
		return
	}
}
