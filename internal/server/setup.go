// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package server

import (
	"bufio"
	cryptorand "crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"spk/internal/config"
	"spk/internal/crypto"
	"spk/internal/sniffer"
)

// RunSetup runs the interactive server setup wizard.
func RunSetup() {
	fmt.Println("========================================")
	fmt.Println("  SPK - Server Setup")
	fmt.Println("  PQC Port Knocking with ML-KEM")
	fmt.Println("========================================")
	fmt.Println()

	reader := bufio.NewReader(os.Stdin)

	cfg := config.DefaultServerConfig()

	// 1. KEM Size selection
	fmt.Println("[1/8] ML-KEM Key Size")
	fmt.Println("  Select the post-quantum key encapsulation size:")
	fmt.Println()
	fmt.Println("  1. ML-KEM-768  (default, recommended)")
	fmt.Println("     NIST security level 3 (AES-192 equivalent)")
	fmt.Println("     Packet size: ~1300 bytes  -- fits within 1500 MTU")
	fmt.Println("     Works reliably over LAN and WAN/Internet")
	fmt.Println()
	fmt.Println("  2. ML-KEM-1024")
	fmt.Println("     NIST security level 5 (AES-256 equivalent)")
	fmt.Println("     Packet size: ~1800 bytes  -- EXCEEDS 1500 MTU")
	fmt.Println("     WARNING: Requires UDP fragmentation. May fail over WAN,")
	fmt.Println("     firewalls, NAT, or ISPs that drop fragmented UDP packets.")
	fmt.Println("     Only use if jumbo frames are supported end-to-end.")
	fmt.Println()
	fmt.Printf("  Select [1]: ")
	kemChoice := readLine(reader)
	switch kemChoice {
	case "2":
		cfg.KEMSize = 1024
		fmt.Println("  -> Key size: ML-KEM-1024 (NIST level 5)")
		fmt.Println("  !! WARNING: Packets will exceed 1500 MTU. Verify UDP fragmentation works on your network. !!")
	default:
		cfg.KEMSize = 768
		fmt.Println("  -> Key size: ML-KEM-768 (NIST level 3, MTU-safe)")
	}
	fmt.Println()

	// 2. Port selection - empty means dynamic port
	fmt.Println("[2/8] Listen Port")
	fmt.Println("  Enter a fixed port, or press Enter for automatic dynamic port rotation.")
	fmt.Println("  Dynamic port: changes every N seconds based on a shared seed (stealthier).")
	fmt.Printf("  Port (Enter = dynamic): ")
	portStr := readLine(reader)
	if portStr != "" {
		p, err := strconv.Atoi(portStr)
		if err != nil || p < 1 || p > 65535 {
			fmt.Println("  Invalid port, using dynamic port instead.")
			portStr = ""
		} else {
			cfg.ListenPort = p
			cfg.DynamicPort = false
			fmt.Printf("  -> Static listen port: %d\n", cfg.ListenPort)
		}
	}
	if portStr == "" {
		// Dynamic port - generate seed
		cfg.DynamicPort = true
		cfg.ListenPort = 0
		seedBytes := make([]byte, 8)
		if _, err := cryptorand.Read(seedBytes); err != nil {
			fmt.Println("  Error generating seed, using fallback")
		}
		cfg.PortSeed = fmt.Sprintf("%x", seedBytes)

		// Ask for rotation interval
		fmt.Printf("  Rotation interval in seconds [600]: ")
		wStr := readLine(reader)
		if wStr != "" {
			w, err := strconv.Atoi(wStr)
			if err == nil && w >= 60 && w <= 86400 {
				cfg.DynPortWindow = w
			} else {
				fmt.Println("  Invalid (must be 60-86400), using default 600s")
				cfg.DynPortWindow = 600
			}
		} else {
			cfg.DynPortWindow = 600
		}

		fmt.Printf("  -> Dynamic port: ENABLED (seed: %s, interval: %ds)\n", cfg.PortSeed, cfg.DynPortWindow)
		fmt.Printf("  -> Port range: %d-%d\n", cfg.DynPortMin, cfg.DynPortMax)
	}
	fmt.Println()

	// 3. Export encryption
	fmt.Println("[3/8] Export Encryption")
	fmt.Println("  Encrypt exported public key and QR code with a password?")
	fmt.Println("  Uses Argon2id (PQC-safe) key derivation + AES-256-GCM encryption.")
	fmt.Println("  The password is NOT stored in the config  -- you must remember it.")
	fmt.Print("  Enter password (leave empty for no encryption): ")
	password := readLine(reader)
	if password != "" {
		cfg.ExportEncrypted = true
		cfg.ExportPassword = password
		fmt.Println("  -> Export encryption: ENABLED (password not saved to config)")
	} else {
		fmt.Println("  -> Export encryption: disabled")
	}
	fmt.Println()

	// 4. Port policies
	fmt.Println("[4/8] Port Policies")
	fmt.Print("  Allow clients to open custom ports? (y/N): ")
	if strings.ToLower(readLine(reader)) == "y" {
		cfg.AllowCustomPort = true
		fmt.Println("  -> Custom port: ENABLED (clients can request any port)")
	} else {
		fmt.Println("  -> Custom port: disabled (only whitelisted ports in allowed_ports)")
	}

	fmt.Print("  Allow clients to set custom open duration? (y/N): ")
	if strings.ToLower(readLine(reader)) == "y" {
		cfg.AllowCustomOpenDuration = true
		fmt.Println("  -> Custom open duration: ENABLED")
	} else {
		fmt.Println("  -> Custom open duration: disabled (uses default_open_duration)")
	}

	fmt.Print("  Allow 'open-all' command? (y/N): ")
	if strings.ToLower(readLine(reader)) == "y" {
		cfg.AllowOpenAll = true
		if cfg.AllowCustomPort {
			fmt.Println("  -> Open all: ENABLED (opens ALL system ports, tcp+udp)")
		} else {
			fmt.Println("  -> Open all: ENABLED (opens all ports in allowed_ports list)")
		}
	} else {
		fmt.Println("  -> Open all: disabled")
	}

	fmt.Printf("  Default port open duration in seconds [%d]: ", cfg.DefaultOpenDuration)
	dtStr := readLine(reader)
	if dtStr != "" {
		dt, err := strconv.Atoi(dtStr)
		if err == nil && dt >= 1 && dt <= 604800 {
			cfg.DefaultOpenDuration = dt
		} else {
			fmt.Printf("  Invalid (must be 1-604800), using default %ds\n", cfg.DefaultOpenDuration)
		}
	}
	fmt.Printf("  -> Default open duration: %ds\n", cfg.DefaultOpenDuration)
	fmt.Println()

	// 5. Packet capture
	fmt.Println("[5/8] Packet Capture Method")
	options := sniffer.DetectSniffers()
	options = sniffer.RecommendSniffers(options)

	// Find the recommended option index for the default prompt
	defaultIdx := 0
	for i, opt := range options {
		if opt.Recommended {
			defaultIdx = i
			break
		}
	}

	// Display all options
	for i, opt := range options {
		status := "NOT INSTALLED"
		if opt.Installed {
			status = "INSTALLED"
		}
		rec := ""
		if opt.Recommended {
			rec = " [RECOMMENDED]"
		}
		maturity := ""
		if opt.Maturity != "" && opt.Maturity != "stable" {
			maturity = fmt.Sprintf(" (%s)", opt.Maturity)
		}
		implTag := ""
		if !opt.Implemented {
			implTag = " [NOT AVAILABLE IN THIS BUILD]"
		}
		fmt.Printf("  %d. %s [%s]%s%s%s\n", i+1, opt.Name, status, rec, maturity, implTag)
		fmt.Printf("     %s\n", opt.Description)
		if opt.InstallCmd != "" && !opt.Installed {
			fmt.Printf("     Install: %s\n", opt.InstallCmd)
			if opt.InstallCmd2 != "" {
				fmt.Printf("              %s\n", opt.InstallCmd2)
			}
		}
	}

	// Selection loop - keep asking until user picks a valid, implemented option
	var selected sniffer.SnifferOption
	for {
		fmt.Printf("  Select capture method [%d]: ", defaultIdx+1)
		snifferChoice := readLine(reader)
		selectedIdx := defaultIdx
		if snifferChoice != "" {
			idx, err := strconv.Atoi(snifferChoice)
			if err != nil || idx < 1 || idx > len(options) {
				fmt.Printf("  Invalid choice '%s'. Please enter a number between 1 and %d.\n", snifferChoice, len(options))
				continue
			}
			selectedIdx = idx - 1
		}
		candidate := options[selectedIdx]

		if !candidate.Implemented {
			fmt.Printf("  '%s' is not available in this build.\n", candidate.Name)
			if candidate.ID == "pcap" {
				fmt.Println("  Rebuild with: go build -tags pcap (CGO_ENABLED=1 + libpcap/Npcap)")
			}
			fmt.Println("  Please choose a different option.")
			continue
		}
		if !candidate.Installed {
			fmt.Printf("  '%s' is not installed on this system.\n", candidate.Name)
			if candidate.InstallCmd != "" {
				fmt.Printf("  Install: %s\n", candidate.InstallCmd)
			}
			fmt.Print("  Use it anyway? (y/N): ")
			if strings.ToLower(readLine(reader)) != "y" {
				continue
			}
		}
		selected = candidate
		break
	}

	cfg.SnifferMode = selected.ID

	// Test selected sniffer
	if selected.Installed {
		fmt.Printf("  Testing %s... ", selected.Name)
		if err := sniffer.TestSniffer(selected.ID); err != nil {
			fmt.Printf("FAILED: %v\n", err)
			fmt.Println("  Will use this setting anyway. Please verify installation.")
		} else {
			fmt.Println("OK")
		}
	}
	fmt.Printf("  -> Capture method: %s\n", selected.Name)
	fmt.Println()

	// 6. Generate keypair
	kemSizeLabel := "ML-KEM-768"
	if cfg.KEMSize == 1024 {
		kemSizeLabel = "ML-KEM-1024"
	}
	fmt.Printf("[6/8] Generating %s Keypair...\n", kemSizeLabel)
	dk, err := crypto.GenerateKeyPair(crypto.KEMSize(cfg.KEMSize))
	if err != nil {
		fmt.Printf("ERROR: Failed to generate keypair: %v\n", err)
		os.Exit(1)
	}

	cfgDir := config.ConfigDir()

	keyPath := filepath.Join(cfgDir, "server.key")
	if err := crypto.SavePrivateKey(keyPath, dk); err != nil {
		fmt.Printf("ERROR: Failed to save private key: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("  -> Private key saved: %s\n", keyPath)

	certPath := filepath.Join(cfgDir, "server.crt")
	if err := crypto.SavePublicKey(certPath, dk); err != nil {
		fmt.Printf("ERROR: Failed to save public key: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("  -> Public key saved: %s\n", certPath)

	// Save config
	configPath := config.ServerConfigPath()
	if err := config.WriteServerConfigWithComments(configPath, cfg); err != nil {
		fmt.Printf("ERROR: Failed to save config: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("  -> Config saved: %s\n", configPath)

	// 7. Export activation bundle
	fmt.Println()
	fmt.Println("[7/8] Exporting Activation Bundle...")

	ek := dk.EncapsulationKey()

	var portSeed []byte
	if cfg.PortSeed != "" {
		portSeed, _ = hexDecodeSetupSeed(cfg.PortSeed)
	}

	var b64Data string
	if cfg.ExportEncrypted && cfg.ExportPassword != "" {
		b64Data, err = crypto.CreateEncryptedExportBundleWithWindow(ek, cfg.ListenPort,
			cfg.AllowCustomOpenDuration, cfg.AllowCustomPort, cfg.AllowOpenAll,
			cfg.ExportPassword, portSeed, cfg.DynamicPort, cfg.DefaultOpenDuration, cfg.DynPortWindow)
	} else {
		b64Data, err = crypto.CreateExportBundleWithWindow(ek, cfg.ListenPort,
			cfg.AllowCustomOpenDuration, cfg.AllowCustomPort, cfg.AllowOpenAll,
			portSeed, cfg.DynamicPort, cfg.DefaultOpenDuration, cfg.DynPortWindow)
	}
	if err != nil {
		fmt.Printf("ERROR: Failed to create export bundle: %v\n", err)
		os.Exit(1)
	}

	activationPath := filepath.Join(cfgDir, "activation.b64")
	if err := crypto.ExportToFile(activationPath, b64Data); err != nil {
		fmt.Printf("ERROR: Failed to save activation.b64: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("  -> Activation bundle: %s\n", activationPath)

	// Generate raw binary for QR code (more compact than base64)
	rawData, rawErr := crypto.CreateExportBundleRawWithWindow(ek, cfg.ListenPort,
		cfg.AllowCustomOpenDuration, cfg.AllowCustomPort, cfg.AllowOpenAll,
		portSeed, cfg.DynamicPort, cfg.DefaultOpenDuration, cfg.DynPortWindow)
	if rawErr == nil {
		qrPath := filepath.Join(cfgDir, "activation_qr.png")
		qrErr := crypto.GenerateQRCode(rawData, qrPath)
		if qrErr != nil {
			fmt.Printf("  -> QR code image: skipped (%v)\n", qrErr)
		} else {
			fmt.Printf("  -> QR code image: %s\n", qrPath)
		}
	}

	// Print bundle and QR to console
	fmt.Printf("  -> Bundle size: %d chars (b64)\n", len(b64Data))
	fmt.Println("\n--- Activation Bundle (base64) ---")
	fmt.Println(b64Data)
	fmt.Println("--- End ---")

	if rawErr == nil {
		qrConsoleErr := crypto.PrintQRCodeToConsole(rawData)
		if qrConsoleErr != nil {
			fmt.Printf("(QR code generation failed: %v)\n", qrConsoleErr)
		}
	}

	// 8. TOTP two-factor authentication
	fmt.Println()
	fmt.Println("[8/8] Two-Factor Authentication (TOTP)")
	fmt.Println("  Enable TOTP verification for additional security?")
	fmt.Println("  When enabled, clients must provide a 6-digit code with each knock.")
	fmt.Println("  Requires an authenticator app (Google Authenticator, Authy, etc.).")
	fmt.Print("  Enable TOTP? (y/N): ")
	if strings.ToLower(readLine(reader)) == "y" {
		secret, err := crypto.GenerateTOTPSecret()
		if err != nil {
			fmt.Printf("  ERROR: Failed to generate TOTP secret: %v\n", err)
		} else {
			cfg.TOTPEnabled = true
			cfg.TOTPSecret = secret

			// Re-save config with TOTP settings
			if err := config.WriteServerConfigWithComments(configPath, cfg); err != nil {
				fmt.Printf("  Warning: could not update config with TOTP: %v\n", err)
			}

			// Generate TOTP QR code image
			totpQRPath := filepath.Join(cfgDir, "totp_qr.png")
			if err := crypto.GenerateTOTPQRCode(secret, totpQRPath); err != nil {
				fmt.Printf("  -> TOTP QR image: skipped (%v)\n", err)
			} else {
				fmt.Printf("  -> TOTP QR image: %s\n", totpQRPath)
			}

			fmt.Println("  -> TOTP: ENABLED")
			fmt.Printf("  -> Secret: %s\n", secret)

			// Print TOTP QR to console
			if err := crypto.PrintTOTPQRToConsole(secret); err != nil {
				fmt.Printf("  (TOTP QR display failed: %v)\n", err)
			}

			fmt.Println()
			fmt.Println("  Or manually enter this secret in your authenticator app:")
			fmt.Printf("  %s\n", crypto.FormatTOTPSecret(secret))
			fmt.Println()
			fmt.Printf("  Current TOTP code: %s (for verification)\n", currentTOTPCode(secret))
			fmt.Println()
			fmt.Println("  IMPORTANT: The TOTP secret is stored in the server config only.")
			fmt.Println("  It is NOT included in the activation bundle.")
			fmt.Println("  Clients must use --totp <code> flag when sending knocks.")
		}
	} else {
		fmt.Println("  -> TOTP: disabled")
	}

	fmt.Println()
	fmt.Println("========================================")
	fmt.Println("  Setup complete!")
	fmt.Println()
	fmt.Println("  NEXT STEPS:")
	fmt.Println("  1. Edit spk_server.toml - set firewall commands")
	fmt.Println("  2. Add allowed_ports entries (e.g., t22, t443, u53)")
	fmt.Println("  3. Add custom_commands if needed (client sends cust-<id>)")
	fmt.Println("  4. Share activation.b64 or QR code with authorized clients")
	fmt.Println("  5. Run: spk --server")
	fmt.Println("========================================")

	config.WaitForUserOrTimeout(30)
}

// RunExport regenerates the activation bundle with interactive options.
// Prompts for encryption settings and regenerates TOTP QR if enabled.
// The TOTP QR code is never encrypted -- it is always a plain PNG for
// scanning into an authenticator app.
func RunExport() {
	reader := bufio.NewReader(os.Stdin)

	cfg, err := config.Load(config.ServerConfigPath())
	if err != nil {
		fmt.Printf("Error loading config: %v\nRun --server --setup first.\n", err)
		os.Exit(1)
	}

	dk, err := crypto.LoadPrivateKey(filepath.Join(config.ConfigDir(), "server.key"))
	if err != nil {
		fmt.Printf("Error loading private key: %v\nRun --server --setup first.\n", err)
		os.Exit(1)
	}

	// Ask about encryption
	fmt.Println("Export Activation Bundle")
	fmt.Println("========================")
	fmt.Println()
	fmt.Println("Encrypt the activation bundle with a password?")
	fmt.Println("Uses Argon2id (PQC-safe) key derivation + AES-256-GCM encryption.")
	fmt.Println("The password is NOT stored -- you must remember it for the client.")
	fmt.Print("Enter password (leave empty for no encryption): ")
	password := readLine(reader)
	if password != "" {
		cfg.ExportEncrypted = true
		cfg.ExportPassword = password
		fmt.Println("-> Export encryption: ENABLED (password not saved to config)")
	} else {
		cfg.ExportEncrypted = false
		cfg.ExportPassword = ""
		fmt.Println("-> Export encryption: disabled")
	}

	// Password is NOT persisted to config for security.
	// Export settings are transient -- used only for this bundle generation.

	exportBundle(cfg, dk)

	// Regenerate TOTP QR if enabled (always unencrypted)
	if cfg.TOTPEnabled && cfg.TOTPSecret != "" {
		cfgDir := config.ConfigDir()
		totpQRPath := filepath.Join(cfgDir, "totp_qr.png")
		if err := crypto.GenerateTOTPQRCode(cfg.TOTPSecret, totpQRPath); err != nil {
			fmt.Printf("TOTP QR image: %v\n", err)
		} else {
			fmt.Printf("Exported: %s\n", totpQRPath)
		}

		if err := crypto.PrintTOTPQRToConsole(cfg.TOTPSecret); err != nil {
			fmt.Printf("(TOTP QR display failed: %v)\n", err)
		}

		fmt.Println()
		fmt.Println("TOTP secret (for manual entry):")
		fmt.Printf("  %s\n", crypto.FormatTOTPSecret(cfg.TOTPSecret))
	}
}

// exportBundle creates and outputs the activation bundle.
func exportBundle(cfg *config.Config, dk crypto.DecapsulationKey) {
	ek := dk.EncapsulationKey()

	var portSeed []byte
	if cfg.PortSeed != "" {
		portSeed, _ = hexDecodeSetupSeed(cfg.PortSeed)
	}

	var b64Data string
	var err error
	if cfg.ExportEncrypted && cfg.ExportPassword != "" {
		b64Data, err = crypto.CreateEncryptedExportBundleWithWindow(ek, cfg.ListenPort,
			cfg.AllowCustomOpenDuration, cfg.AllowCustomPort, cfg.AllowOpenAll,
			cfg.ExportPassword, portSeed, cfg.DynamicPort, cfg.DefaultOpenDuration, cfg.DynPortWindow)
	} else {
		b64Data, err = crypto.CreateExportBundleWithWindow(ek, cfg.ListenPort,
			cfg.AllowCustomOpenDuration, cfg.AllowCustomPort, cfg.AllowOpenAll,
			portSeed, cfg.DynamicPort, cfg.DefaultOpenDuration, cfg.DynPortWindow)
	}
	if err != nil {
		fmt.Printf("Error creating export bundle: %v\n", err)
		os.Exit(1)
	}

	cfgDir := config.ConfigDir()
	activationPath := filepath.Join(cfgDir, "activation.b64")
	if err := crypto.ExportToFile(activationPath, b64Data); err != nil {
		fmt.Printf("Error saving activation.b64: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Exported: %s\n", activationPath)

	// Generate raw binary for QR code
	rawData, rawErr := crypto.CreateExportBundleRawWithWindow(ek, cfg.ListenPort,
		cfg.AllowCustomOpenDuration, cfg.AllowCustomPort, cfg.AllowOpenAll,
		portSeed, cfg.DynamicPort, cfg.DefaultOpenDuration, cfg.DynPortWindow)
	if rawErr == nil {
		qrPath := filepath.Join(cfgDir, "activation_qr.png")
		qrErr := crypto.GenerateQRCode(rawData, qrPath)
		if qrErr == nil {
			fmt.Printf("Exported: %s\n", qrPath)
		} else {
			fmt.Printf("QR image: %v\n", qrErr)
		}
	}

	fmt.Printf("Bundle size: %d chars (b64)\n", len(b64Data))
	fmt.Println("\n--- Activation Bundle (base64) ---")
	fmt.Println(b64Data)
	fmt.Println("--- End ---")

	if rawErr == nil {
		_ = crypto.PrintQRCodeToConsole(rawData)
	}
}

// hexDecodeSetupSeed decodes a hex port seed in setup context.
func hexDecodeSetupSeed(hexSeed string) ([]byte, error) {
	seed := make([]byte, 0, 8)
	for i := 0; i+1 < len(hexSeed); i += 2 {
		h := hexVal(hexSeed[i])
		l := hexVal(hexSeed[i+1])
		if h == 255 || l == 255 {
			return nil, fmt.Errorf("invalid hex")
		}
		seed = append(seed, h<<4|l)
	}
	if len(seed) < 8 {
		return nil, fmt.Errorf("port seed too short: need 8 bytes, got %d", len(seed))
	}
	return seed[:8], nil
}

func hexVal(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	}
	return 255
}

func readLine(reader *bufio.Reader) string {
	line, _ := reader.ReadString('\n')
	return strings.TrimSpace(line)
}

// currentTOTPCode generates the current TOTP code for display/verification.
func currentTOTPCode(secret string) string {
	code, err := crypto.GenerateTOTP(secret, time.Now())
	if err != nil {
		return "(error)"
	}
	return code
}
