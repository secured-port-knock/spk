// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package server

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"spk/internal/config"
	"spk/internal/crypto"
	"spk/internal/logging"
	"spk/internal/protocol"
	"spk/internal/sniffer"
)

// serverLogger is a minimal interface satisfied by both *log.Logger and *logging.Logger.
type serverLogger interface {
	Printf(format string, v ...interface{})
}

var (
	shutdownOnce sync.Once
	shutdownCh   = make(chan struct{})
)

// Stop signals the server to shut down gracefully.
// Safe to call multiple times; only the first call has any effect.
func Stop() {
	shutdownOnce.Do(func() { close(shutdownCh) })
}

// Run starts the server in listening mode.
func Run() {
	// Bootstrap logger (stdout only until file logger is ready)
	logger := log.New(os.Stdout, "", 0)
	logLine := func(level, msg string) {
		ts := time.Now().Format("2006/01/02 15:04:05")
		logger.Printf("%-5s | %s [server] %s", level, ts, msg)
	}

	// Load config from platform-appropriate path
	configPath := config.ServerConfigPath()
	cfg, err := config.Load(configPath)
	if err != nil {
		logLine("FATAL", fmt.Sprintf("Failed to load config: %v\nExpected: %s\nRun: spk --server --setup", err, configPath))
		os.Exit(1)
	}

	// Enforce config validation - reject insecure or invalid values at startup
	if errs := cfg.Validate(); len(errs) > 0 {
		logLine("FATAL", "Config validation failed:")
		for _, e := range errs {
			logLine("FATAL", fmt.Sprintf("  - %s", e))
		}
		logLine("FATAL", fmt.Sprintf("Fix %s and restart.", configPath))
		os.Exit(1)
	}

	// Initialize structured logger with rotation
	logCfg := logging.Config{
		MaxSizeMB:    cfg.LogMaxSizeMB,
		MaxBackups:   cfg.LogMaxBackups,
		MaxAgeDays:   cfg.LogMaxAgeDays,
		FloodLimitPS: cfg.LogFloodLimit,
	}
	if logCfg.MaxSizeMB == 0 {
		logCfg = logging.DefaultConfig()
	}
	srvLogger, logErr := logging.New("spk_server.log", logCfg, "server")
	if logErr != nil {
		logLine("WARN", fmt.Sprintf("could not initialize file logging: %v", logErr))
		// Continue with stdout-only logging
	} else {
		defer srvLogger.Close()
		logLine("INFO", fmt.Sprintf("Logging to: %s", srvLogger.FilePath()))
	}

	// Use the structured logger if available, otherwise fall back to basic
	var srvLog serverLogger = logger
	logf := logger.Printf
	if srvLogger != nil {
		srvLog = srvLogger
		logf = srvLogger.Printf
	}

	// Inform user when running with exe-relative directories instead of system paths
	if config.UsingFallbackConfigDir() {
		logLine("INFO", fmt.Sprintf("/etc/spk is not available, using %s instead", config.ConfigDir()))
	}
	if logging.UsingFallbackLogDir() {
		logLine("INFO", fmt.Sprintf("/var/log/spk is not available, using %s instead", logging.LogDir()))
	}

	// Load private key
	keyPath := filepath.Join(config.ConfigDir(), "server.key")
	dk, err := crypto.LoadPrivateKey(keyPath)
	if err != nil {
		logLine("FATAL", fmt.Sprintf("Failed to load private key: %v\nRun: spk --server --setup", err))
		os.Exit(1)
	}

	// Initialize nonce tracker
	nonceExpiry := time.Duration(cfg.NonceExpiry) * time.Second
	if nonceExpiry == 0 {
		nonceExpiry = 120 * time.Second
	}
	maxNonceCache := cfg.MaxNonceCache
	if maxNonceCache == 0 {
		maxNonceCache = 10000
	}
	nonceTracker := protocol.NewNonceTrackerWithLimit(nonceExpiry, maxNonceCache)

	// Dynamic port window
	dynPortWindow := cfg.DynPortWindow
	if dynPortWindow == 0 {
		dynPortWindow = crypto.DynPortWindowSeconds
	}

	// Initialize port tracker with state recovery
	tracker := NewTracker(config.StatePath(), srvLog, cfg.ClosePortsOnCrash, commandTimeout(cfg))
	tracker.logCmdExec = cfg.LogCommandOutput
	tracker.StartExpiryWatcher(10 * time.Second)

	// Build allowed ports map for quick lookup
	allowedPorts := make(map[string]bool)
	for _, p := range cfg.AllowedPorts {
		allowedPorts[strings.ToLower(p)] = true
	}

	timestampTolerance := int64(cfg.TimestampTolerance)
	if timestampTolerance == 0 {
		timestampTolerance = 30
	}

	// Validate: nonce_expiry must be >= timestamp_tolerance to prevent replay gap
	if timestampTolerance > 0 && int64(nonceExpiry.Seconds()) < timestampTolerance {
		logf("[WARN] nonce_expiry (%ds) < timestamp_tolerance (%ds) - replay window exists! Increasing nonce_expiry to match.",
			int(nonceExpiry.Seconds()), timestampTolerance)
		nonceExpiry = time.Duration(timestampTolerance+30) * time.Second
		nonceTracker = protocol.NewNonceTrackerWithLimit(nonceExpiry, maxNonceCache)
	}

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// snifferRef holds the current sniffer for graceful shutdown.
	// Updated atomically when dynamic port rotation creates a new sniffer.
	var snifferMu sync.Mutex
	var currentSniffer sniffer.Sniffer

	go func() {
		sig := <-sigChan
		logf("Received signal %v, shutting down...", sig)
		Stop() // signal the main loop to exit
	}()

	// Auto-regenerate bundle on load (re-exports if config changes)
	autoRegenerateBundle(dk, cfg, logf)

	// Determine listen port (dynamic or static)
	listenPort := cfg.ListenPort
	var portSeed []byte
	if cfg.DynamicPort && cfg.PortSeed != "" {
		var decErr error
		portSeed, decErr = hexDecodePortSeed(cfg.PortSeed)
		if decErr == nil {
			listenPort = crypto.ComputeDynamicPortWithWindow(portSeed, dynPortWindow)
			logf("  Dynamic port enabled (seed: %s...)", cfg.PortSeed[:8])
			logf("  Current dynamic port: %d (changes every %ds)", listenPort, dynPortWindow)
		} else {
			logf("  Warning: invalid port_seed, using static port %d", cfg.ListenPort)
			portSeed = nil
		}
	}

	// Warn about dynamic port + UDP sniffer combination
	if cfg.DynamicPort && portSeed != nil && strings.EqualFold(cfg.SnifferMode, "udp") {
		logf("")
		logf("  !! WARNING: dynamic_port + sniffer_mode=\"udp\" !!")
		logf("  The UDP sniffer binds to the listen port. When the port rotates,")
		logf("  the new port may already be in use by another process, causing")
		logf("  the sniffer to fail. Consider using a stealth sniffer mode")
		logf("  (afpacket, pcap, windivert) which captures at the network layer")
		logf("  without binding a port.")
		logf("")
	}

	// Create sniffer
	sniff, err := sniffer.NewSniffer(cfg.SnifferMode, cfg.ListenAddresses, listenPort)
	if err != nil {
		logLine("FATAL", fmt.Sprintf("Failed to create sniffer: %v", err))
		os.Exit(1)
	}

	// Validate sniffer backend works before starting the server.
	if err := sniffer.TestSniffer(cfg.SnifferMode); err != nil {
		logLine("FATAL", fmt.Sprintf("Sniffer startup check failed (%s): %v", cfg.SnifferMode, err))
		logf("  Hint: verify the capture backend is installed and the service/driver is running.")
		os.Exit(1)
	}

	snifferMu.Lock()
	currentSniffer = sniff
	snifferMu.Unlock()

	logf("SPK server starting")
	logf("  Mode:    %s", cfg.SnifferMode)
	logf("  Listen:  %v port %d/udp", cfg.ListenAddresses, listenPort)
	logf("  Ports:   %v", cfg.AllowedPorts)
	logf("  Custom port: %v, Custom open duration: %v, Open-all: %v",
		cfg.AllowCustomPort, cfg.AllowCustomOpenDuration, cfg.AllowOpenAll)
	logf("  Default open duration: %ds, Max open duration: %ds", cfg.DefaultOpenDuration, cfg.MaxOpenDuration)
	if cfg.TOTPEnabled {
		logf("  TOTP: ENABLED (two-factor authentication)")
	}
	logf("  Listening for knock packets...")

	// Packet handler -- each knock is dispatched in its own goroutine so
	// that a slow or stuck command never blocks the sniffer receive loop.
	knockHandler := func(data []byte, sourceIP string) {
		go handleKnock(srvLog, dk, cfg, nonceTracker, tracker, allowedPorts, timestampTolerance, data, sourceIP)
	}

	// Dynamic port rotation: wake up precisely at each window boundary, then re-check
	if portSeed != nil {
		// Run initial sniffer in a goroutine (not blocking main)
		go sniff.Start(knockHandler)

		currentPort := listenPort
	rotationLoop:
		for {
			// Sleep until exactly 1 second past the next window boundary.
			// DynPortSecondsUntilChangeWithWindow returns the integer seconds remaining
			// in the current window; adding 1 guarantees we land in the new window
			// regardless of sub-second timing, so the port check always sees the
			// rotated value. No polling interval needed.
			secsUntil := crypto.DynPortSecondsUntilChangeWithWindow(dynPortWindow)

			select {
			case <-shutdownCh:
				break rotationLoop
			case <-time.After(time.Duration(secsUntil+1) * time.Second):
			}

			newPort := crypto.ComputeDynamicPortWithWindow(portSeed, dynPortWindow)
			if newPort != currentPort {
				logf("  Dynamic port rotating: %d -> %d", currentPort, newPort)
				sniff.Stop()
				time.Sleep(100 * time.Millisecond) // Brief pause for socket cleanup
				newSniff, sErr := sniffer.NewSniffer(cfg.SnifferMode, cfg.ListenAddresses, newPort)
				if sErr != nil {
					logf("[ERROR] Failed to create sniffer on port %d: %v", newPort, sErr)
					// Try to re-listen on old port
					fallback, fErr := sniffer.NewSniffer(cfg.SnifferMode, cfg.ListenAddresses, currentPort)
					if fErr != nil {
						logf("[FATAL] Cannot re-bind to old port %d either: %v -- server is deaf!", currentPort, fErr)
						continue
					}
					sniff = fallback
					snifferMu.Lock()
					currentSniffer = sniff
					snifferMu.Unlock()
					go sniff.Start(knockHandler)
					continue
				}
				currentPort = newPort
				sniff = newSniff
				snifferMu.Lock()
				currentSniffer = sniff
				snifferMu.Unlock()
				go sniff.Start(knockHandler)
			}
		}
	} else {
		// Static port mode: run sniffer in a goroutine and wait for shutdown.
		snifferDone := make(chan error, 1)
		go func() {
			snifferDone <- sniff.Start(knockHandler)
		}()

		select {
		case <-shutdownCh:
			// Graceful shutdown requested
		case err := <-snifferDone:
			if err != nil {
				logLine("FATAL", fmt.Sprintf("Sniffer error: %v", err))
				os.Exit(1)
			}
		}
	}

	// Graceful cleanup: stop sniffer, close ports, let deferred logger.Close() flush.
	logf("Cleaning up...")
	snifferMu.Lock()
	if currentSniffer != nil {
		if err := currentSniffer.Stop(); err != nil {
			logf("  Sniffer stop warning: %v", err)
		}
	}
	snifferMu.Unlock()
	// Brief pause for driver/socket cleanup (WinDivert, AF_PACKET, etc.)
	time.Sleep(200 * time.Millisecond)
	tracker.CloseAll()
	logf("Shutdown complete.")
	// Run() returns; deferred srvLogger.Close() flushes and closes the log file.
}

// commandTimeout returns the configured command execution timeout as a Duration.
// Defaults to 500ms if not configured.
func commandTimeout(cfg *config.Config) time.Duration {
	if cfg.CommandTimeout > 0 {
		return time.Duration(cfg.CommandTimeout * float64(time.Second))
	}
	return 500 * time.Millisecond
}

// validateCommandServer performs server-side command sanitization.
// Returns the command type ("open", "close", "cust") and the data portion,
// or an error if the command is malformed.
func validateCommandServer(cmd string) (string, string, error) {
	cmd = strings.ToLower(cmd)
	switch {
	case strings.HasPrefix(cmd, "open-"):
		data := cmd[5:]
		if err := validatePortSpecsServer(data); err != nil {
			return "", "", fmt.Errorf("invalid open command: %w", err)
		}
		return "open", data, nil
	case strings.HasPrefix(cmd, "close-"):
		data := cmd[6:]
		if err := validatePortSpecsServer(data); err != nil {
			return "", "", fmt.Errorf("invalid close command: %w", err)
		}
		return "close", data, nil
	case strings.HasPrefix(cmd, "cust-"):
		data := cmd[5:]
		if err := validateASCIIServer(data); err != nil {
			return "", "", fmt.Errorf("invalid custom command: %w", err)
		}
		return "cust", data, nil
	default:
		return "", "", fmt.Errorf("unsupported command type (must be open-/close-/cust-)")
	}
}

// validatePortSpecsServer validates comma-separated port specs on the server side.
func validatePortSpecsServer(specs string) error {
	if specs == "" {
		return fmt.Errorf("empty port specification")
	}
	parts := strings.Split(specs, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if part == "all" {
			continue
		}
		if len(part) < 2 || len(part) > 6 {
			return fmt.Errorf("invalid port spec length: %q", part)
		}
		prefix := strings.ToLower(part[:1])
		if prefix != "t" && prefix != "u" {
			return fmt.Errorf("unknown protocol %q in %q (use t for TCP, u for UDP)", prefix, part)
		}
		portStr := part[1:]
		port := 0
		for _, c := range portStr {
			if c < '0' || c > '9' {
				return fmt.Errorf("non-numeric port in %q", part)
			}
			port = port*10 + int(c-'0')
			if port > 65535 {
				return fmt.Errorf("port exceeds 65535 in %q", part)
			}
		}
		if port < 1 {
			return fmt.Errorf("port must be >= 1 in %q", part)
		}
	}
	return nil
}

// validateASCIIServer checks that a custom command ID contains only printable ASCII.
func validateASCIIServer(s string) error {
	if len(s) == 0 {
		return fmt.Errorf("empty command ID")
	}
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b < 0x20 || b > 0x7E {
			return fmt.Errorf("non-printable ASCII byte 0x%02x at position %d", b, i)
		}
	}
	return nil
}

func handleKnock(
	logger serverLogger,
	dk crypto.DecapsulationKey,
	cfg *config.Config,
	nonceTracker *protocol.NonceTracker,
	tracker *Tracker,
	allowedPorts map[string]bool,
	timestampTolerance int64,
	data []byte,
	sourceIP string,
) {
	// Panic recovery - never crash server from malformed input
	defer func() {
		if r := recover(); r != nil {
			logger.Printf("[PANIC] recovered from panic handling packet from %s: %v", sourceIP, r)
		}
	}()

	// Parse and validate knock packet
	payload, err := protocol.ParseKnockPacket(dk, data, sourceIP, timestampTolerance, !cfg.MatchIncomingIP)
	if err != nil {
		logger.Printf("[REJECT] from %s: %v", sourceIP, err)
		return
	}

	// Validate client IP is present in payload
	if payload.ClientIP == "" {
		logger.Printf("[REJECT] from %s: missing client IP in payload", sourceIP)
		return
	}

	// Determine the IP to use for firewall commands
	// When match_incoming_ip=true: sourceIP == payload.ClientIP (verified above)
	// When match_incoming_ip=false: use payload.ClientIP (what client specified)
	clientIP := sourceIP
	if !cfg.MatchIncomingIP {
		clientIP = payload.ClientIP
	}

	// Check nonce (anti-replay)
	if !nonceTracker.Check(payload.Nonce) {
		logger.Printf("[REJECT] from %s: possible replay attack (duplicate nonce %s...)", sourceIP, payload.Nonce[:16])
		return
	}

	// Verify TOTP if enabled
	if cfg.TOTPEnabled && cfg.TOTPSecret != "" {
		if payload.TOTP == "" {
			logger.Printf("[REJECT] from %s: TOTP required but not provided (client must use --totp flag)", sourceIP)
			return
		}
		if !crypto.ValidateTOTP(cfg.TOTPSecret, payload.TOTP) {
			logger.Printf("[REJECT] from %s: TOTP verification failed (possible clock skew or wrong secret)", sourceIP)
			return
		}
	}

	// open_duration is the client-requested port-open duration in seconds (0 = use server default).
	// This is NOT the cmd_timeout setting for command execution.
	logger.Printf("[KNOCK] from %s (client=%s): cmd=%s open_duration=%d", sourceIP, clientIP, payload.Command, payload.OpenDuration)

	// Determine open duration
	openDuration := cfg.DefaultOpenDuration
	if cfg.AllowCustomOpenDuration && payload.OpenDuration > 0 {
		openDuration = payload.OpenDuration
		if cfg.MaxOpenDuration > 0 && openDuration > cfg.MaxOpenDuration {
			openDuration = cfg.MaxOpenDuration
		}
	}

	// Process command
	cmd := strings.ToLower(payload.Command)

	// Server-side command validation/sanitization
	cmdType, _, valErr := validateCommandServer(cmd)
	if valErr != nil {
		logger.Printf("[REJECT] from %s: %v (raw: %q)", sourceIP, valErr, sanitizeForLog(cmd))
		return
	}

	switch cmdType {
	case "open":
		if cmd == "open-all" {
			handleOpenAll(logger, cfg, tracker, allowedPorts, clientIP, openDuration)
		} else {
			portSpecs := cmd[5:]
			// Support batch: "open-t22,t443,u53"
			specs := strings.Split(portSpecs, ",")
			for _, spec := range specs {
				spec = strings.TrimSpace(spec)
				if spec != "" {
					handleOpen(logger, cfg, tracker, allowedPorts, clientIP, spec, openDuration)
				}
			}
		}

	case "close":
		if cmd == "close-all" {
			handleCloseAll(logger, cfg, tracker, clientIP)
		} else {
			portSpecs := cmd[6:]
			// Support batch: "close-t22,t443,u53"
			specs := strings.Split(portSpecs, ",")
			for _, spec := range specs {
				spec = strings.TrimSpace(spec)
				if spec != "" {
					handleClose(logger, cfg, tracker, allowedPorts, clientIP, spec)
				}
			}
		}

	case "cust":
		cmdID := cmd[5:]
		handleCustomCommand(logger, cfg, clientIP, cmdID)
	}
}

func handleOpen(
	logger serverLogger,
	cfg *config.Config,
	tracker *Tracker,
	allowedPorts map[string]bool,
	ip, portSpec string,
	openDuration int,
) {
	proto, portNum, err := parsePortSpec(portSpec)
	if err != nil {
		logger.Printf("[IGNORE] from %s: invalid port spec: %s", ip, portSpec)
		return
	}

	portKey := strings.ToLower(portSpec) // e.g., "t22"

	// Check if allowed
	if !cfg.AllowCustomPort {
		if !allowedPorts[portKey] {
			logger.Printf("[DENY] from %s: port %s not in allowed list", ip, portSpec)
			return
		}
	}

	// Build commands (select IPv4 or IPv6 template based on client IP)
	var openCmd, closeCmd string
	ipv6 := isIPv6(ip)
	switch proto {
	case "tcp":
		if ipv6 && cfg.OpenTCP6Command != "" {
			openCmd = BuildCommand(cfg.OpenTCP6Command, ip, portNum, proto)
			closeCmd = BuildCommand(cfg.CloseTCP6Command, ip, portNum, proto)
		} else {
			openCmd = BuildCommand(cfg.OpenTCPCommand, ip, portNum, proto)
			closeCmd = BuildCommand(cfg.CloseTCPCommand, ip, portNum, proto)
		}
	case "udp":
		if ipv6 && cfg.OpenUDP6Command != "" {
			openCmd = BuildCommand(cfg.OpenUDP6Command, ip, portNum, proto)
			closeCmd = BuildCommand(cfg.CloseUDP6Command, ip, portNum, proto)
		} else {
			openCmd = BuildCommand(cfg.OpenUDPCommand, ip, portNum, proto)
			closeCmd = BuildCommand(cfg.CloseUDPCommand, ip, portNum, proto)
		}
	}

	if openCmd == "" {
		logger.Printf("[WARN] No open command template configured for %s", proto)
		return
	}

	// When no close command is configured, execute the open command but skip
	// the tracker -- there is nothing to close at expiry so no timer is needed.
	// The port will remain open until manually closed.
	if closeCmd == "" {
		logger.Printf("[OPEN] %s/%s for %s (permanent - no close command configured)", portNum, proto, ip)
		if cfg.LogCommandOutput {
			logger.Printf("[CMD-EXEC] %s", openCmd)
		}
		output, err := ExecuteCommandTimeout(openCmd, commandTimeout(cfg))
		if err != nil {
			logger.Printf("[ERROR] Open command failed for %s/%s %s: %v", portNum, proto, ip, err)
			if cfg.LogCommandOutput && output != "" {
				logger.Printf("[CMD-OUTPUT] %s", output)
			}
			return
		}
		if cfg.LogCommandOutput && output != "" {
			logger.Printf("[CMD-OUTPUT] %s", output)
		}
		logger.Printf("[WARN] No close command configured for %s/%s - port will remain open permanently", portNum, proto)
		return
	}

	// Build entry and attempt atomic reservation
	expiry := time.Now().Add(time.Duration(openDuration) * time.Second)
	entry := &PortEntry{
		IP:        ip,
		Port:      portSpec,
		Proto:     proto,
		PortNum:   portNum,
		OpenedAt:  time.Now(),
		ExpiresAt: expiry,
		Command:   openCmd,
		CloseCmd:  closeCmd,
	}

	reserved, _ := tracker.TryReserve(entry)
	if !reserved {
		// Port already open for this IP -- just refresh the timeout
		tracker.RefreshExpiry(ip, portNum, proto, expiry)
		logger.Printf("[REFRESH] %s/%s for %s (open duration extended to %ds)", portNum, proto, ip, openDuration)
		return
	}

	// Execute open command
	logger.Printf("[OPEN] %s/%s for %s (open duration: %ds)", portNum, proto, ip, openDuration)
	if cfg.LogCommandOutput {
		logger.Printf("[CMD-EXEC] %s", openCmd)
	}
	output, err := ExecuteCommandTimeout(openCmd, commandTimeout(cfg))
	if err != nil {
		logger.Printf("[ERROR] Open command failed for %s/%s %s: %v", portNum, proto, ip, err)
		if cfg.LogCommandOutput && output != "" {
			logger.Printf("[CMD-OUTPUT] %s", output)
		}
		// Keep the tracker entry so the expiry watcher executes the close command
		// at the normal open-duration timeout. The open command may have partially
		// succeeded, so we must still close at the scheduled time.
		logger.Printf("[WARN] Open failed for %s/%s %s - close command will run at expiry (%s)",
			portNum, proto, ip, entry.ExpiresAt.Format("15:04:05"))
		return
	}
	if cfg.LogCommandOutput && output != "" {
		logger.Printf("[CMD-OUTPUT] %s", output)
	}
}

func handleClose(
	logger serverLogger,
	cfg *config.Config,
	tracker *Tracker,
	allowedPorts map[string]bool,
	ip, portSpec string,
) {
	proto, portNum, err := parsePortSpec(portSpec)
	if err != nil {
		logger.Printf("[IGNORE] from %s: invalid port spec: %s", ip, portSpec)
		return
	}

	portKey := strings.ToLower(portSpec)

	if !cfg.AllowCustomPort {
		if !allowedPorts[portKey] {
			logger.Printf("[DENY] from %s: port %s not in allowed list", ip, portSpec)
			return
		}
	}

	var closeCmd string
	ipv6 := isIPv6(ip)
	switch proto {
	case "tcp":
		if ipv6 && cfg.CloseTCP6Command != "" {
			closeCmd = BuildCommand(cfg.CloseTCP6Command, ip, portNum, proto)
		} else {
			closeCmd = BuildCommand(cfg.CloseTCPCommand, ip, portNum, proto)
		}
	case "udp":
		if ipv6 && cfg.CloseUDP6Command != "" {
			closeCmd = BuildCommand(cfg.CloseUDP6Command, ip, portNum, proto)
		} else {
			closeCmd = BuildCommand(cfg.CloseUDPCommand, ip, portNum, proto)
		}
	}

	if closeCmd == "" {
		logger.Printf("[WARN] No close command template configured for %s", proto)
		return
	}

	logger.Printf("[CLOSE] %s/%s for %s", portNum, proto, ip)
	if cfg.LogCommandOutput {
		logger.Printf("[CMD-EXEC] %s", closeCmd)
	}
	output, err := ExecuteCommandTimeout(closeCmd, commandTimeout(cfg))
	if err != nil {
		logger.Printf("[ERROR] Close command failed for %s/%s %s: %v", portNum, proto, ip, err)
	}
	if cfg.LogCommandOutput && output != "" {
		logger.Printf("[CMD-OUTPUT] %s", output)
	}
	tracker.Remove(ip, portNum, proto)
}

func handleOpenAll(
	logger serverLogger,
	cfg *config.Config,
	tracker *Tracker,
	allowedPorts map[string]bool,
	ip string,
	openDuration int,
) {
	if !cfg.AllowOpenAll {
		logger.Printf("[DENY] from %s: open-all not allowed", ip)
		return
	}

	// If open_all_command is set, use it directly
	if cfg.OpenAllCommand != "" {
		var cmd, closeCmd string
		if isIPv6(ip) && cfg.OpenAll6Command != "" {
			cmd = BuildCommand(cfg.OpenAll6Command, ip, "", "")
			closeCmd = BuildCommand(cfg.CloseAll6Command, ip, "", "")
		} else {
			cmd = BuildCommand(cfg.OpenAllCommand, ip, "", "")
			closeCmd = BuildCommand(cfg.CloseAllCommand, ip, "", "")
		}

		// When no close-all command is configured, execute the open-all command but
		// skip the tracker -- no expiry timer is needed since nothing can be closed.
		if closeCmd == "" {
			logger.Printf("[OPEN-ALL] for %s (permanent - no close-all command configured)", ip)
			if cfg.LogCommandOutput {
				logger.Printf("[CMD-EXEC] %s", cmd)
			}
			output, err := ExecuteCommandTimeout(cmd, commandTimeout(cfg))
			if err != nil {
				logger.Printf("[ERROR] Open-all command failed for %s: %v", ip, err)
				if cfg.LogCommandOutput && output != "" {
					logger.Printf("[CMD-OUTPUT] %s", output)
				}
				return
			}
			if cfg.LogCommandOutput && output != "" {
				logger.Printf("[CMD-OUTPUT] %s", output)
			}
			logger.Printf("[WARN] No close-all command configured - all ports will remain open permanently")
			return
		}

		// Atomic reservation -- avoid duplicate open-all rules
		expiry := time.Now().Add(time.Duration(openDuration) * time.Second)
		entry := &PortEntry{
			IP:        ip,
			Port:      "all",
			Proto:     "all",
			PortNum:   "all",
			OpenedAt:  time.Now(),
			ExpiresAt: expiry,
			Command:   cmd,
			CloseCmd:  closeCmd,
		}

		reserved, _ := tracker.TryReserve(entry)
		if !reserved {
			tracker.RefreshExpiry(ip, "all", "all", expiry)
			logger.Printf("[REFRESH] open-all for %s (open duration extended to %ds)", ip, openDuration)
			return
		}

		logger.Printf("[OPEN-ALL] for %s (open duration: %ds)", ip, openDuration)
		if cfg.LogCommandOutput {
			logger.Printf("[CMD-EXEC] %s", cmd)
		}
		output, err := ExecuteCommandTimeout(cmd, commandTimeout(cfg))
		if err != nil {
			logger.Printf("[ERROR] Open-all command failed for %s: %v", ip, err)
			if cfg.LogCommandOutput && output != "" {
				logger.Printf("[CMD-OUTPUT] %s", output)
			}
			// Keep the tracker entry so the expiry watcher executes the close-all
			// command at the normal open-duration timeout.
			logger.Printf("[WARN] Open-all failed for %s - close-all command will run at expiry (%s)",
				ip, entry.ExpiresAt.Format("15:04:05"))
			return
		}
		if cfg.LogCommandOutput && output != "" {
			logger.Printf("[CMD-OUTPUT] %s", output)
		}
		return
	}

	// Otherwise open each allowed port individually
	for portKey := range allowedPorts {
		handleOpen(logger, cfg, tracker, allowedPorts, ip, portKey, openDuration)
	}
}

func handleCloseAll(
	logger serverLogger,
	cfg *config.Config,
	tracker *Tracker,
	ip string,
) {
	// Close all ports opened by this IP
	entries := tracker.GetByIP(ip)
	if len(entries) == 0 {
		logger.Printf("[INFO] No open ports found for %s", ip)
		return
	}

	for _, entry := range entries {
		logger.Printf("[CLOSE] %s/%s for %s", entry.PortNum, entry.Proto, ip)
		if cfg.LogCommandOutput && entry.CloseCmd != "" {
			logger.Printf("[CMD-EXEC] %s", entry.CloseCmd)
		}
		output, err := ExecuteCommandTimeout(entry.CloseCmd, commandTimeout(cfg))
		if err != nil {
			logger.Printf("[ERROR] Close command failed for %s/%s %s: %v", entry.PortNum, entry.Proto, ip, err)
		}
		if cfg.LogCommandOutput && output != "" {
			logger.Printf("[CMD-OUTPUT] %s", output)
		}
		tracker.Remove(entry.IP, entry.PortNum, entry.Proto)
	}
}

// sanitizeForLog replaces control characters with '?' to prevent log injection.
func sanitizeForLog(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			b.WriteByte('?')
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func handleCustomCommand(
	logger serverLogger,
	cfg *config.Config,
	ip, commandKey string,
) {
	safeKey := sanitizeForLog(commandKey)
	command, exists := cfg.CustomCommands[commandKey]
	if !exists {
		logger.Printf("[IGNORE] from %s: unknown command '%s'", ip, safeKey)
		return
	}

	logger.Printf("[CUSTOM] from %s: executing '%s'", ip, safeKey)
	cmd := BuildCommand(command, ip, "", "")
	if cfg.LogCommandOutput && cmd != "" {
		logger.Printf("[CMD-EXEC] %s", cmd)
	}
	output, err := ExecuteCommandTimeout(cmd, commandTimeout(cfg))
	if err != nil {
		logger.Printf("[ERROR] Custom command '%s' failed for %s: %v", safeKey, ip, err)
	}
	if cfg.LogCommandOutput && output != "" {
		logger.Printf("[CMD-OUTPUT] %s -> %s", commandKey, output)
	}
}

// isIPv6 checks if the given IP string is an IPv6 address.
func isIPv6(ip string) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && parsed.To4() == nil
}

// parsePortSpec parses a port specification like "t22", "u53", "T443".
// Returns (proto, portNum, error).
func parsePortSpec(spec string) (string, string, error) {
	if len(spec) < 2 || len(spec) > 6 {
		return "", "", fmt.Errorf("port spec invalid length: %s", spec)
	}

	prefix := strings.ToLower(spec[:1])
	portNum := spec[1:]

	var proto string
	switch prefix {
	case "t":
		proto = "tcp"
	case "u":
		proto = "udp"
	default:
		return "", "", fmt.Errorf("unknown protocol prefix: %s (use t for TCP, u for UDP)", prefix)
	}

	// Validate port number - must be all digits
	for _, c := range portNum {
		if c < '0' || c > '9' {
			return "", "", fmt.Errorf("invalid port number: %s", portNum)
		}
	}

	// Validate port range (1-65535)
	port := 0
	for _, c := range portNum {
		port = port*10 + int(c-'0')
		if port > 65535 {
			return "", "", fmt.Errorf("port number out of range: %s", portNum)
		}
	}
	if port < 1 {
		return "", "", fmt.Errorf("port number must be >= 1: %s", portNum)
	}

	return proto, portNum, nil
}

// autoRegenerateBundle re-exports activation.b64 and QR code on server load
// if the config has potentially changed since last export.
func autoRegenerateBundle(dk crypto.DecapsulationKey, cfg *config.Config, logf func(string, ...interface{})) {
	ek := dk.EncapsulationKey()

	var portSeed []byte
	if cfg.PortSeed != "" {
		portSeed, _ = hexDecodePortSeed(cfg.PortSeed)
	}

	dynWindow := cfg.DynPortWindow

	var b64Data string
	var err error
	// Export settings (password) are not persisted in config for security.
	// Auto-regenerated bundles are always unencrypted.
	// Use --export for encrypted bundles with an interactive password prompt.
	b64Data, err = crypto.CreateExportBundleWithWindow(ek, cfg.ListenPort,
		cfg.AllowCustomOpenDuration, cfg.AllowCustomPort, cfg.AllowOpenAll,
		portSeed, cfg.DynamicPort, cfg.DefaultOpenDuration, dynWindow)
	if err != nil {
		logf("[WARN] Failed to regenerate bundle: %v", err)
		return
	}

	cfgDir := config.ConfigDir()
	activationPath := filepath.Join(cfgDir, "activation.b64")

	// Check if bundle changed
	existing, _ := crypto.ImportFromFile(activationPath)
	if existing == b64Data {
		return // no change
	}

	if writeErr := crypto.ExportToFile(activationPath, b64Data); writeErr != nil {
		logf("[WARN] Failed to write activation.b64: %v", writeErr)
	} else {
		logf("Auto-regenerated activation.b64 (config changed)")
	}

	// Generate raw binary for QR code
	rawData, rawErr := crypto.CreateExportBundleRawWithWindow(ek, cfg.ListenPort,
		cfg.AllowCustomOpenDuration, cfg.AllowCustomPort, cfg.AllowOpenAll,
		portSeed, cfg.DynamicPort, cfg.DefaultOpenDuration, dynWindow)
	if rawErr == nil {
		qrPath := filepath.Join(cfgDir, "activation_qr.png")
		qrErr := crypto.GenerateQRCode(rawData, qrPath)
		if qrErr != nil {
			logf("[WARN] QR code: %v", qrErr)
		} else {
			logf("Auto-regenerated activation_qr.png")
		}
	}
}

// hexDecodePortSeed decodes a hex-encoded port seed string.
func hexDecodePortSeed(hexSeed string) ([]byte, error) {
	seed := make([]byte, 0, 8)
	for i := 0; i+1 < len(hexSeed); i += 2 {
		b, err := hexByte(hexSeed[i], hexSeed[i+1])
		if err != nil {
			return nil, err
		}
		seed = append(seed, b)
	}
	if len(seed) < 8 {
		return nil, fmt.Errorf("port seed too short: need 8 bytes, got %d", len(seed))
	}
	return seed[:8], nil
}

func hexByte(hi, lo byte) (byte, error) {
	h, err := hexNibble(hi)
	if err != nil {
		return 0, err
	}
	l, err := hexNibble(lo)
	if err != nil {
		return 0, err
	}
	return h<<4 | l, nil
}

func hexNibble(c byte) (byte, error) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', nil
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, nil
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, nil
	}
	return 0, fmt.Errorf("invalid hex char: %c", c)
}
