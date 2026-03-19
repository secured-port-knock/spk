// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package client

import (
	"bufio"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"spk/internal/config"
	"spk/internal/crypto"
)

// RunSetup runs the interactive client setup wizard.
func RunSetup() {
	fmt.Println("========================================")
	fmt.Println("  SPK - Client Setup")
	fmt.Println("  PQC Port Knocking with ML-KEM")
	fmt.Println("========================================")
	fmt.Println()

	reader := bufio.NewReader(os.Stdin)
	cfg := config.DefaultClientConfig()

	// 1. Key storage
	fmt.Println("[1/3] Key Storage")
	fmt.Println("  Where to store the server's public key?")

	storageOptions := getKeyStorageOptions()
	for i, opt := range storageOptions {
		fmt.Printf("  %d. %s\n", i+1, opt)
	}
	fmt.Print("  Select [1]: ")
	choice := readLine(reader)
	idx := 0
	if choice != "" {
		if i := parseChoice(choice, len(storageOptions)); i >= 0 {
			idx = i
		}
	}

	switch idx {
	case 0:
		cfg.KeyStorageMode = "file"
		fmt.Println("  -> Key storage: plaintext file (server.crt)")
	case 1:
		// Test secure storage before committing
		fmt.Print("  Testing secure storage... ")
		if err := TestSecureStorage(); err != nil {
			fmt.Printf("FAILED: %v\n", err)
			fmt.Println("  Secure storage is not available. Choose an alternative:")
			fmt.Println("  1. Plaintext file (server.crt)")
			fmt.Println("  2. Retry secure storage")
			fmt.Print("  Select [1]: ")
			retry := readLine(reader)
			if retry == "2" {
				fmt.Print("  Retesting... ")
				if err := TestSecureStorage(); err != nil {
					fmt.Printf("FAILED again: %v\n", err)
					fmt.Println("  -> Falling back to plaintext file")
					cfg.KeyStorageMode = "file"
				} else {
					fmt.Println("OK")
					cfg.KeyStorageMode = "credential_manager"
					fmt.Println("  -> Key storage: system credential manager")
				}
			} else {
				cfg.KeyStorageMode = "file"
				fmt.Println("  -> Key storage: plaintext file (server.crt)")
			}
		} else {
			fmt.Println("OK")
			cfg.KeyStorageMode = "credential_manager"
			fmt.Println("  -> Key storage: system credential manager")
		}
	default:
		cfg.KeyStorageMode = "file"
	}
	fmt.Println()

	// 2. Import server public key
	fmt.Println("[2/3] Import Server Public Key")

	var bundle *crypto.ExportBundle

	// Check if activation.b64 exists in the exe directory or client config directory.
	// Never search the server config directory (e.g. /etc/spk on Linux).
	var bundleFile string
	for _, candidate := range ActivationBundleCandidates() {
		if _, err := os.Stat(candidate); err == nil {
			bundleFile = candidate
			break
		}
	}
	if bundleFile != "" {
		b64Data, err := crypto.ImportFromFile(bundleFile)
		if err == nil {
			fmt.Printf("  Found %s file.\n", filepath.Base(bundleFile))
			fmt.Print("  Use this file? (Y/n): ")
			if strings.ToLower(readLine(reader)) != "n" {
				// Check if encrypted
				bundle = tryParseBundle(reader, b64Data)
			}
		}
	}

	if bundle == nil {
		fmt.Println("  Paste the base64 key bundle from the server (single line):")
		fmt.Print("  > ")
		b64Data := readLine(reader)
		if b64Data == "" {
			fmt.Println("  Error: No key data provided. Exiting.")
			os.Exit(1)
		}
		bundle = tryParseBundle(reader, b64Data)
	}

	if bundle == nil {
		fmt.Println("  Error: Failed to import key. Exiting.")
		os.Exit(1)
	}

	// Store the key
	ekBytes, err := base64.StdEncoding.DecodeString(bundle.EncapsulationKey)
	if err != nil {
		fmt.Printf("  Error decoding key: %v\n", err)
		os.Exit(1)
	}

	// Validate the key
	_, err = crypto.LoadPublicKeyBytes(ekBytes)
	if err != nil {
		kemLabel := "ML-KEM-1024"
		if bundle.KEMSize == 768 {
			kemLabel = "ML-KEM-768"
		}
		fmt.Printf("  Error: Invalid %s key: %v\n", kemLabel, err)
		os.Exit(1)
	}

	// Save key to file in PEM format (so LoadPublicKey can parse it)
	pemType := crypto.PublicKeyPEMType1024
	if bundle.KEMSize == 768 {
		pemType = crypto.PublicKeyPEMType768
	}
	pemBlock := &pem.Block{
		Type:  pemType,
		Bytes: ekBytes,
	}
	certPath := filepath.Join(config.ClientConfigDir(), "server.crt")
	pemData := pem.EncodeToMemory(pemBlock)

	// Ensure the config directory exists before writing any file into it.
	if err := os.MkdirAll(filepath.Dir(certPath), 0750); err != nil {
		fmt.Printf("  Error creating config directory: %v\n", err)
		os.Exit(1)
	}

	if cfg.KeyStorageMode == "credential_manager" {
		// Write temporarily so SaveKeySecure can read it, then remove
		if err := os.WriteFile(certPath, pemData, 0600); err != nil {
			fmt.Printf("  Error saving key: %v\n", err)
			os.Exit(1)
		}
		if err := SaveKeySecure(certPath); err != nil {
			fmt.Printf("  -> Warning: secure storage save failed: %v\n", err)
			fmt.Println("  -> Key is still stored as server.crt (plaintext file)")
			cfg.KeyStorageMode = "file"
		} else {
			os.Remove(certPath)
			fmt.Println("  -> Server public key stored in system credential manager")
			fmt.Println("  -> No server.crt file written (key is in secure storage only)")
		}
	} else {
		if err := os.WriteFile(certPath, pemData, 0600); err != nil {
			fmt.Printf("  Error saving key: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("  -> Server public key saved: %s\n", certPath)
	}

	// Extract server info from bundle
	if bundle.Port > 0 {
		cfg.ServerPort = bundle.Port
	}
	cfg.AllowCustomOpenDuration = bundle.AllowCustomOpenDuration
	cfg.AllowCustomPort = bundle.AllowCustomPort
	cfg.AllowOpenAll = bundle.AllowOpenAll
	if bundle.DynamicPort && len(bundle.PortSeed) > 0 {
		cfg.DynamicPort = true
		cfg.PortSeed = fmt.Sprintf("%x", bundle.PortSeed)
	}
	if bundle.DefaultOpenDuration > 0 {
		cfg.DefaultOpenDuration = bundle.DefaultOpenDuration
	}
	if bundle.DynPortWindow > 0 {
		cfg.DynPortWindow = bundle.DynPortWindow
	}
	// Set KEM size from bundle (transient, not persisted to config)
	if bundle.KEMSize > 0 {
		cfg.KEMSize = bundle.KEMSize
	} else {
		cfg.KEMSize = 1024
	}

	// 3. Server host
	fmt.Println()
	fmt.Println("[3/3] Server Connection")
	fmt.Print("  Server host/IP address: ")
	host := readLine(reader)
	if host == "" {
		fmt.Println("  Error: Server host is required. Exiting.")
		os.Exit(1)
	}
	cfg.ServerHost = host
	if cfg.DynamicPort {
		window := cfg.DynPortWindow
		if window == 0 {
			window = 600
		}
		fmt.Printf("  -> Server: %s (dynamic port)\n", cfg.ServerHost)
		fmt.Printf("  -> Dynamic port: enabled (port rotates every %d seconds)\n", window)
	} else {
		fmt.Printf("  -> Server: %s:%d\n", cfg.ServerHost, cfg.ServerPort)
	}

	// Save client config with comments
	configPath := config.ClientConfigPath()
	if err := config.WriteClientConfigWithComments(configPath, cfg); err != nil {
		fmt.Printf("Error saving config: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("  -> Config saved: %s\n", configPath)

	fmt.Println()
	fmt.Println("========================================")
	fmt.Println("  Client setup complete!")
	fmt.Println()
	fmt.Println("  Usage:")
	fmt.Println("    spk --client --cmd open-t22")
	fmt.Println("    spk --client --cmd open-t22 --duration 7200")
	fmt.Println("    spk --client --cmd open-t22,t443,u53        # Batch open in one packet")
	fmt.Println("    spk --client --cmd close-t22")
	fmt.Println("    spk --client --cmd close-t22,t443           # Batch close in one packet")
	fmt.Println("    spk --client --cmd cust-1")
	fmt.Println("    spk open-t22                                # Shorthand (auto-detect)")
	fmt.Println("    spk open-t22,t443,u53                       # Batch shorthand")
	fmt.Println("========================================")

	// Offer to delete the activation bundle if it was used from a file
	if bundleFile != "" {
		fmt.Printf("\n  Delete %s? It is no longer needed. (y/N): ", filepath.Base(bundleFile))
		if strings.ToLower(readLine(reader)) == "y" {
			if err := os.Remove(bundleFile); err != nil {
				fmt.Printf("  Warning: could not delete %s: %v\n", bundleFile, err)
			} else {
				fmt.Printf("  -> Deleted %s\n", bundleFile)
			}
		}
	}

	config.WaitForUserOrTimeout(30)
}

func tryParseBundle(reader *bufio.Reader, b64Data string) *crypto.ExportBundle {
	// First try without password
	bundle, err := crypto.ParseExportBundle(b64Data, "")
	if err != nil {
		if strings.Contains(err.Error(), "password required") {
			fmt.Print("  Bundle is encrypted. Enter password: ")
			password := readLine(reader)
			bundle, err = crypto.ParseExportBundle(b64Data, password)
			if err != nil {
				fmt.Printf("  Error: %v\n", err)
				return nil
			}
		} else {
			fmt.Printf("  Error parsing bundle: %v\n", err)
			return nil
		}
	}

	fmt.Printf("  -> Server port: %d\n", bundle.Port)
	fmt.Printf("  -> Custom open duration: %v\n", bundle.AllowCustomOpenDuration)
	fmt.Printf("  -> Custom port: %v\n", bundle.AllowCustomPort)
	fmt.Printf("  -> Open all: %v\n", bundle.AllowOpenAll)
	if bundle.DynamicPort {
		fmt.Println("  -> Dynamic port: enabled")
	}
	kemLabel := "ML-KEM-1024"
	if bundle.KEMSize == 768 {
		kemLabel = "ML-KEM-768"
	}
	fmt.Printf("  -> Key size: %s\n", kemLabel)
	return bundle
}

// ActivationBundleCandidates returns the ordered list of paths where the
// client setup wizard will look for an activation bundle file.
//
// Search order:
//  1. <exe_dir>/activation.b64
//  2. <client_config_dir>/activation.b64  (respects --cfgdir)
//
// The server config directory (e.g. /etc/spk on Linux) is never searched.
// Duplicate paths (e.g. when exe_dir == client_config_dir) are omitted.
func ActivationBundleCandidates() []string {
	var candidates []string
	seen := make(map[string]bool)

	exeDir := ""
	if exe, err := os.Executable(); err == nil {
		exeDir = filepath.Dir(exe)
	}

	cfgDir := config.ClientConfigDir()

	add := func(path string) {
		// Normalise to an absolute path so duplicate detection is reliable.
		if abs, err := filepath.Abs(path); err == nil {
			path = abs
		}
		if !seen[path] {
			seen[path] = true
			candidates = append(candidates, path)
		}
	}

	if exeDir != "" {
		add(filepath.Join(exeDir, "activation.b64"))
	}
	add(filepath.Join(cfgDir, "activation.b64"))

	return candidates
}

func getKeyStorageOptions() []string {
	opts := []string{"Plaintext file (server.crt) - simple, portable"}
	switch runtime.GOOS {
	case "windows":
		opts = append(opts, "Windows Credential Manager")
	case "darwin":
		opts = append(opts, "macOS Keychain")
	case "linux":
		opts = append(opts, "Linux Secret Service (GNOME Keyring / KDE Wallet)")
	}
	return opts
}

func parseChoice(s string, max int) int {
	if len(s) == 1 && s[0] >= '1' && s[0] <= '9' {
		idx := int(s[0]-'0') - 1
		if idx < max {
			return idx
		}
	}
	return -1
}

func readLine(reader *bufio.Reader) string {
	line, _ := reader.ReadString('\n')
	return strings.TrimSpace(line)
}
