// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package client

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"spk/internal/config"
	"spk/internal/crypto"
	"spk/internal/protocol"
)

// RunCommand sends a knock command to the server (CLI mode).
func RunCommand(host, command string, openDuration int, clientIP string, totp string) {
	cfg, ek, err := loadClientState(host)
	if err != nil {
		fmt.Printf("Error: %v\nRun: spk --client --setup\n", err)
		os.Exit(1)
	}

	// Determine port (dynamic or static)
	dynWindow := cfg.DynPortWindow
	if dynWindow == 0 {
		dynWindow = crypto.DynPortWindowSeconds
	}
	port := resolvePortWithWindow(cfg, dynWindow)

	// Determine client IP (auto-detect LAN vs WAN, or use manual override)
	localIP, err := resolveClientIP(cfg.ServerHost, port, clientIP, cfg.StunServers)
	if err != nil {
		fmt.Printf("Error determining client IP: %v\n", err)
		os.Exit(1)
	}

	// Build knock options
	var opts protocol.KnockOptions

	// Padding config
	if cfg.PaddingEnabled {
		opts.Padding = protocol.PaddingConfig{
			Enabled:  true,
			MinBytes: cfg.PaddingMinBytes,
			MaxBytes: cfg.PaddingMaxBytes,
		}
		if opts.Padding.MinBytes == 0 {
			opts.Padding.MinBytes = 64
		}
		if opts.Padding.MaxBytes == 0 {
			opts.Padding.MaxBytes = 512
		}
		// Cap max padding to prevent excessive memory use / packet overflow
		if opts.Padding.MaxBytes > config.MaxPaddingBytes {
			fmt.Printf("Warning: padding_max_bytes capped at %d (was %d)\n", config.MaxPaddingBytes, opts.Padding.MaxBytes)
			opts.Padding.MaxBytes = config.MaxPaddingBytes
		}
	}

	// TOTP code
	if totp != "" {
		opts.TOTP = totp
	}

	// --duration is only meaningful for open- commands; reject it early for close/cust
	if err := validateDurationForCommand(command, openDuration); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	// Early validation: command length (binary protocol CmdLen is 1 byte = max 255)
	if len(command) > 255 {
		fmt.Printf("Error: command too long (%d bytes, max 255).\n", len(command))
		fmt.Println("Tip: batch commands use comma-separated port specs, e.g., open-t22,t443,u53")
		os.Exit(1)
	}

	// Validate command format before sending
	if err := protocol.ValidateCommand(command); err != nil {
		fmt.Printf("Error: %v\n", err)
		fmt.Println("Valid formats: open-t<port>, open-u<port>, open-all, close-t<port>, close-u<port>, close-all, cust-<id>")
		fmt.Println("Examples: open-t22, open-u53, close-t443, open-t22,t443,u53, cust-ping")
		os.Exit(1)
	}

	// Build and send knock packet
	packet, err := protocol.BuildKnockPacket(ek, localIP, command, openDuration, opts)
	if err != nil {
		fmt.Printf("Error building knock packet: %v\n", err)
		os.Exit(1)
	}

	serverAddr := net.JoinHostPort(cfg.ServerHost, fmt.Sprintf("%d", port))
	if err := sendUDPPacket(serverAddr, packet); err != nil {
		fmt.Printf("Error sending knock: %v\n", err)
		os.Exit(1)
	}

	// Resolve hostname to IP for display
	resolvedIP := cfg.ServerHost
	if ips, err := net.LookupHost(cfg.ServerHost); err == nil && len(ips) > 0 {
		resolvedIP = ips[0]
	}
	resolvedAddr := net.JoinHostPort(resolvedIP, fmt.Sprintf("%d", port))

	if resolvedIP != cfg.ServerHost {
		fmt.Printf("Knock sent to %s (%s) : %s", serverAddr, resolvedAddr, command)
	} else {
		fmt.Printf("Knock sent to %s : %s", serverAddr, command)
	}
	if openDuration > 0 {
		fmt.Printf(" (open duration: %ds)", openDuration)
	}
	fmt.Println()
	if cfg.DynamicPort {
		fmt.Printf("(Dynamic port: %d, next change in %ds)\n", port, crypto.DynPortSecondsUntilChangeWithWindow(dynWindow))
	}
	fmt.Printf("(Client IP: %s)\n", localIP)
	fmt.Println("(Server does not send a response. Check server logs for status.)")
}

// validateDurationForCommand returns an error when a non-zero openDuration is
// paired with a command that is not an open- command.  close- and cust-
// commands do not use a custom open duration.
func validateDurationForCommand(command string, openDuration int) error {
	if openDuration > 0 && !strings.HasPrefix(strings.ToLower(command), "open-") {
		return fmt.Errorf("--duration is only valid with open- commands (e.g., open-t22, open-all); " +
			"commands like close- and cust- do not use a custom open duration")
	}
	return nil
}

// loadClientState loads config and encryption key for the client.
func loadClientState(hostOverride string) (*config.Config, crypto.EncapsulationKey, error) {
	cfg, err := config.Load(config.ClientConfigPath())
	if err != nil {
		return nil, nil, fmt.Errorf("load config: %w", err)
	}

	// Enforce config validation - reject invalid values
	if errs := cfg.Validate(); len(errs) > 0 {
		return nil, nil, fmt.Errorf("config validation failed: %s", strings.Join(errs, "; "))
	}

	if hostOverride != "" {
		cfg.ServerHost = hostOverride
	}

	if cfg.ServerHost == "" {
		return nil, nil, fmt.Errorf("no server host configured")
	}
	if cfg.ServerPort == 0 && !cfg.DynamicPort {
		return nil, nil, fmt.Errorf("no server port configured (set server_port or use dynamic port)")
	}

	// Load public key
	certPath := filepath.Join(config.ClientConfigDir(), "server.crt")

	// If using credential manager and file doesn't exist, restore from secure storage
	if cfg.KeyStorageMode == "credential_manager" {
		if _, statErr := os.Stat(certPath); os.IsNotExist(statErr) {
			if restoreErr := LoadKeySecure(certPath); restoreErr != nil {
				return nil, nil, fmt.Errorf("restore key from credential manager: %w", restoreErr)
			}
		}
	}

	ek, err := crypto.LoadPublicKey(certPath)
	if err != nil {
		return nil, nil, fmt.Errorf("load public key: %w", err)
	}

	return cfg, ek, nil
}

// sendUDPPacket sends a UDP packet to the specified address.
func sendUDPPacket(address string, data []byte) error {
	conn, err := net.Dial("udp", address)
	if err != nil {
		return fmt.Errorf("connect to %s: %w", address, err)
	}
	defer conn.Close()

	_, err = conn.Write(data)
	if err != nil {
		return fmt.Errorf("send to %s: %w", address, err)
	}

	return nil
}

// getLocalIPForHost determines the local IP that would be used to reach the given host.
func getLocalIPForHost(host string, port int) (string, error) {
	conn, err := net.Dial("udp", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
	if err != nil {
		return "", fmt.Errorf("determine local IP: %w", err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String(), nil
}

// resolvePortWithWindow returns the current port using a custom rotation window.
func resolvePortWithWindow(cfg *config.Config, windowSeconds int) int {
	if cfg.DynamicPort && cfg.PortSeed != "" {
		seed, err := hex.DecodeString(cfg.PortSeed)
		if err == nil && len(seed) >= 8 {
			return crypto.ComputeDynamicPortWithWindow(seed[:8], windowSeconds)
		}
	}
	return cfg.ServerPort
}
