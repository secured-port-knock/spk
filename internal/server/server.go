// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
// Package server implements the SPK knock server: packet handling, port open/close
// lifecycle, command execution, and graceful shutdown.
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

	"github.com/secured-port-knock/spk/internal/config"
	"github.com/secured-port-knock/spk/internal/crypto"
	"github.com/secured-port-knock/spk/internal/logging"
	"github.com/secured-port-knock/spk/internal/protocol"
	"github.com/secured-port-knock/spk/internal/sniffer"
)

// serverLogger is a minimal interface satisfied by both *log.Logger and *logging.Logger.
type serverLogger interface {
	Printf(format string, v ...interface{})
}

var (
	shutdownOnce sync.Once
	shutdownCh   = make(chan struct{})
)

// maxConcurrentKnocks limits the number of knock packets being processed
// simultaneously. This prevents resource exhaustion if an attacker floods
// the server with packets. When the pool is fully utilized, excess packets
// are dropped with a warning log.
const maxConcurrentKnocks = 9999

// Stop signals the server to shut down gracefully.
// Safe to call multiple times; only the first call has any effect.
func Stop() {
	shutdownOnce.Do(func() { close(shutdownCh) })
}

// Run starts the server in listening mode.
// initFileLogger sets up the rotating file logger for the server.
// Returns the structured logger (or nil when file logging is unavailable) and the
// formatted logLine function used for startup/fatal messages.
func initFileLogger(cfg *config.Config, logger *log.Logger, logLine func(string, string)) (*logging.Logger, func(string, ...interface{})) {
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
		if logging.LogDirInitError() != nil {
			logLine("WARN", fmt.Sprintf("File logging disabled: %v", logging.LogDirInitError()))
		} else {
			logLine("WARN", fmt.Sprintf("could not initialize file logging: %v", logErr))
			logLine("WARN", "Fix log directory permissions or specify --logdir to enable file logging")
		}
		logf := func(format string, v ...interface{}) {
			logLine("INFO", fmt.Sprintf(format, v...))
		}
		return nil, logf
	}
	logf := func(format string, v ...interface{}) {
		srvLogger.Printf(format, v...)
	}
	return srvLogger, logf
}

// resolveListenPort decodes the port seed (if dynamic) and returns the current
// listen port plus the decoded seed bytes. When decoding fails portSeed is nil
// and the static listen port from cfg is used.
func resolveListenPort(cfg *config.Config, dynPortWindow int, logf func(string, ...interface{})) (listenPort int, portSeed []byte) {
	listenPort = cfg.ListenPort
	if !cfg.DynamicPort || cfg.PortSeed == "" {
		return listenPort, nil
	}
	var decErr error
	portSeed, decErr = hexDecodePortSeed(cfg.PortSeed)
	if decErr != nil {
		logf("  Warning: invalid port_seed, using static port %d", cfg.ListenPort)
		return listenPort, nil
	}
	listenPort = crypto.ComputeDynamicPortWithWindow(portSeed, dynPortWindow)
	logf("  Dynamic port enabled (seed: %s...)", cfg.PortSeed[:8])
	logf("  Current dynamic port: %d (changes every %ds)", listenPort, dynPortWindow)
	return listenPort, portSeed
}

// runStaticMode runs the sniffer in static port mode and blocks until the server
// shuts down or the sniffer reports a fatal error.
func runStaticMode(sniff sniffer.Sniffer, knockHandler func([]byte, string), logLine func(string, string)) {
	snifferDone := make(chan error, 1)
	go func() {
		snifferDone <- sniff.Start(knockHandler)
	}()

	select {
	case <-shutdownCh:
		// Graceful shutdown requested.
	case err := <-snifferDone:
		if err != nil {
			logLine("FATAL", fmt.Sprintf("Sniffer error: %v", err))
			os.Exit(1)
		}
	}
}

// attemptRebind tries to create a new sniffer on newPort; on failure it falls
// back to currentPort. Returns the active sniffer and port after the attempt.
func attemptRebind(
	cfg *config.Config,
	portSeed []byte,
	sniff sniffer.Sniffer,
	currentPort, newPort int,
	snifferMu *sync.Mutex,
	currentSnifferRef *sniffer.Sniffer,
	knockHandler func([]byte, string),
	logf func(string, ...interface{}),
) (activeSniffer sniffer.Sniffer, activePort int) {
	logf("  Dynamic port rotating: %d -> %d", currentPort, newPort)
	sniff.Stop()
	time.Sleep(100 * time.Millisecond)

	newSniff, sErr := sniffer.NewSniffer(cfg.SnifferMode, cfg.ListenAddresses, newPort)
	if sErr == nil {
		snifferMu.Lock()
		*currentSnifferRef = newSniff
		snifferMu.Unlock()
		go newSniff.Start(knockHandler)
		return newSniff, newPort
	}

	logf("[ERROR] Failed to create sniffer on port %d: %v", newPort, sErr)
	// Try falling back to the old port.
	fallback, fErr := sniffer.NewSniffer(cfg.SnifferMode, cfg.ListenAddresses, currentPort)
	if fErr != nil {
		logf("[ERROR] Cannot re-bind to old port %d either: %v", currentPort, fErr)
		return sniff, currentPort
	}
	snifferMu.Lock()
	*currentSnifferRef = fallback
	snifferMu.Unlock()
	go fallback.Start(knockHandler)
	return fallback, currentPort
}

// retryBindLoop keeps retrying sniffer creation every 60 s when both the new
// and old ports are unavailable. It exits when a bind succeeds or shutdown is
// requested. Returns the sniffer and port that eventually became active, plus
// a bool that is false when shutdown was requested.
func retryBindLoop(
	cfg *config.Config,
	portSeed []byte,
	dynPortWindow int,
	targetPort int,
	snifferMu *sync.Mutex,
	currentSnifferRef *sniffer.Sniffer,
	knockHandler func([]byte, string),
	logf func(string, ...interface{}),
) (activeSniffer sniffer.Sniffer, activePort int, ok bool) {
	logf("[ERROR] Cannot bind to any port -- will retry every 60s")
	newPort := targetPort
	for {
		select {
		case <-shutdownCh:
			return nil, newPort, false
		case <-time.After(60 * time.Second):
		}
		retryPort := crypto.ComputeDynamicPortWithWindow(portSeed, dynPortWindow)
		if retryPort != newPort {
			logf("[INFO] Dynamic port changed during retry: %d -> %d, attempting new port", newPort, retryPort)
			newPort = retryPort
		}
		retrySniff, rErr := sniffer.NewSniffer(cfg.SnifferMode, cfg.ListenAddresses, newPort)
		if rErr != nil {
			logf("[ERROR] Retry: still cannot bind to port %d: %v -- will retry in 60s", newPort, rErr)
			continue
		}
		logf("[INFO] Successfully bound to port %d after retry", newPort)
		snifferMu.Lock()
		*currentSnifferRef = retrySniff
		snifferMu.Unlock()
		go retrySniff.Start(knockHandler)
		return retrySniff, newPort, true
	}
}

// runDynamicPortMode runs the dynamic port rotation loop.
// It starts the initial sniffer and then sleeps until each window boundary,
// rotating to a new port when needed.
func runDynamicPortMode(
	cfg *config.Config,
	initialSniff sniffer.Sniffer,
	portSeed []byte,
	dynPortWindow int,
	listenPort int,
	snifferMu *sync.Mutex,
	currentSnifferRef *sniffer.Sniffer,
	knockHandler func([]byte, string),
	logf func(string, ...interface{}),
) {
	go initialSniff.Start(knockHandler)

	sniff := initialSniff
	currentPort := listenPort

	for {
		secsUntil := crypto.DynPortSecondsUntilChangeWithWindow(dynPortWindow)
		select {
		case <-shutdownCh:
			return
		case <-time.After(time.Duration(secsUntil+1) * time.Second):
		}

		newPort := crypto.ComputeDynamicPortWithWindow(portSeed, dynPortWindow)
		if newPort == currentPort {
			continue
		}

		// Stop existing sniffer and try to rebind.
		sniff.Stop()
		time.Sleep(100 * time.Millisecond)

		newSniff, sErr := sniffer.NewSniffer(cfg.SnifferMode, cfg.ListenAddresses, newPort)
		if sErr == nil {
			logf("  Dynamic port rotating: %d -> %d", currentPort, newPort)
			snifferMu.Lock()
			*currentSnifferRef = newSniff
			snifferMu.Unlock()
			go newSniff.Start(knockHandler)
			sniff = newSniff
			currentPort = newPort
			continue
		}

		logf("[ERROR] Failed to create sniffer on port %d: %v", newPort, sErr)
		// Try the old port as a fallback.
		fallback, fErr := sniffer.NewSniffer(cfg.SnifferMode, cfg.ListenAddresses, currentPort)
		if fErr == nil {
			snifferMu.Lock()
			*currentSnifferRef = fallback
			snifferMu.Unlock()
			go fallback.Start(knockHandler)
			sniff = fallback
			// currentPort stays the same
			continue
		}

		logf("[ERROR] Cannot re-bind to old port %d either: %v -- entering retry loop", currentPort, fErr)
		// Enter retry loop (blocks until bind succeeds or shutdown).
		retrySniff, retryPort, ok := retryBindLoop(
			cfg, portSeed, dynPortWindow, newPort,
			snifferMu, currentSnifferRef, knockHandler, logf,
		)
		if !ok {
			return // shutdown requested
		}
		sniff = retrySniff
		currentPort = retryPort
	}
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

	srvLogger, logf := initFileLogger(cfg, logger, logLine)
	if srvLogger != nil {
		defer srvLogger.Close()
		logLine("INFO", fmt.Sprintf("Logging to: %s", srvLogger.FilePath()))
	}

	var srvLog serverLogger = logger
	if srvLogger != nil {
		srvLog = srvLogger
	}

	// Load private key
	keyPath := filepath.Join(config.ConfigDir(), "server.key")
	dk, err := crypto.LoadPrivateKey(keyPath)
	if err != nil {
		logLine("FATAL", fmt.Sprintf("Failed to load private key: %v\nRun: spk --server --setup", err))
		os.Exit(1)
	}

	// Initialize nonce tracker with configurable expiry and cache size.
	nonceExpiry := time.Duration(cfg.NonceExpiry) * time.Second
	if nonceExpiry == 0 {
		nonceExpiry = 120 * time.Second
	}
	maxNonceCache := cfg.MaxNonceCache
	if maxNonceCache == 0 {
		maxNonceCache = 10000
	}
	nonceTracker := protocol.NewNonceTrackerWithLimit(nonceExpiry, maxNonceCache)

	dynPortWindow := cfg.DynPortWindow
	if dynPortWindow == 0 {
		dynPortWindow = crypto.DynPortWindowSeconds
	}

	tracker := NewTracker(config.StatePath(), srvLog, cfg.ClosePortsOnCrash, commandTimeout(cfg))
	tracker.logCmdExec = cfg.LogCommandOutput
	tracker.StartExpiryWatcher(10 * time.Second)

	allowedPorts := make(map[string]bool)
	for _, p := range cfg.AllowedPorts {
		allowedPorts[strings.ToLower(p)] = true
	}

	timestampTolerance := int64(cfg.TimestampTolerance)
	if timestampTolerance == 0 {
		timestampTolerance = 30
	}

	// Warn and auto-correct when nonce_expiry < timestamp_tolerance (replay gap).
	if timestampTolerance > 0 && int64(nonceExpiry.Seconds()) < timestampTolerance {
		logf("[WARN] nonce_expiry (%ds) < timestamp_tolerance (%ds) - replay window exists! Increasing nonce_expiry to match.",
			int(nonceExpiry.Seconds()), timestampTolerance)
		nonceExpiry = time.Duration(timestampTolerance+30) * time.Second
		nonceTracker = protocol.NewNonceTrackerWithLimit(nonceExpiry, maxNonceCache)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigChan
		logf("Received signal %v, shutting down...", sig)
		Stop()
	}()

	listenPort, portSeed := resolveListenPort(cfg, dynPortWindow, logf)

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

	sniff, err := sniffer.NewSniffer(cfg.SnifferMode, cfg.ListenAddresses, listenPort)
	if err != nil {
		logLine("FATAL", fmt.Sprintf("Failed to create sniffer: %v", err))
		os.Exit(1)
	}
	if err := sniffer.TestSniffer(cfg.SnifferMode); err != nil {
		logLine("FATAL", fmt.Sprintf("Sniffer startup check failed (%s): %v", cfg.SnifferMode, err))
		logf("  Hint: verify the capture backend is installed and the service/driver is running.")
		os.Exit(1)
	}

	var snifferMu sync.Mutex
	var currentSniffer sniffer.Sniffer = sniff

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

	knockHandler := makeKnockHandler(srvLog, dk, cfg, nonceTracker, tracker, allowedPorts, timestampTolerance, logf)

	if portSeed != nil {
		runDynamicPortMode(cfg, sniff, portSeed, dynPortWindow, listenPort,
			&snifferMu, &currentSniffer, knockHandler, logf)
	} else {
		runStaticMode(sniff, knockHandler, logLine)
	}

	logf("Cleaning up...")
	snifferMu.Lock()
	if currentSniffer != nil {
		if err := currentSniffer.Stop(); err != nil {
			logf("  Sniffer stop warning: %v", err)
		}
	}
	snifferMu.Unlock()
	time.Sleep(200 * time.Millisecond)
	tracker.CloseAll()
	logf("Shutdown complete.")
}

// commandTimeout returns the configured command execution timeout as a Duration.
// Defaults to 500ms if not configured.
func commandTimeout(cfg *config.Config) time.Duration {
	if cfg.CommandTimeout > 0 {
		return time.Duration(cfg.CommandTimeout * float64(time.Second))
	}
	return 500 * time.Millisecond
}

// makeKnockHandler returns a PacketHandler that dispatches knock packets via a
// bounded semaphore (maxConcurrentKnocks). Excess packets are dropped with a
// warning rather than blocking the sniffer goroutine.
func makeKnockHandler(
	srvLog serverLogger,
	dk crypto.DecapsulationKey,
	cfg *config.Config,
	nonceTracker *protocol.NonceTracker,
	tracker *Tracker,
	allowedPorts map[string]bool,
	timestampTolerance int64,
	logf func(string, ...interface{}),
) sniffer.PacketHandler {
	knockSem := make(chan struct{}, maxConcurrentKnocks)
	return func(data []byte, sourceIP string) {
		select {
		case knockSem <- struct{}{}:
			go func() {
				defer func() { <-knockSem }()
				handleKnock(srvLog, dk, cfg, nonceTracker, tracker, allowedPorts, timestampTolerance, data, sourceIP)
			}()
		default:
			logf("[WARN] knock processing pool exhausted (%d concurrent) -- dropping packet from %s", maxConcurrentKnocks, sourceIP)
		}
	}
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

// verifyTOTP checks the TOTP code from the payload against the server config.
// Returns false and logs the rejection if TOTP is required but invalid.
func verifyTOTP(logger serverLogger, cfg *config.Config, payload *protocol.KnockPayload, sourceIP string) bool {
	if !cfg.TOTPEnabled || cfg.TOTPSecret == "" {
		return true
	}
	if payload.TOTP == "" {
		logger.Printf("[REJECT] from %s: TOTP required but not provided (client must use --totp flag)", sourceIP)
		return false
	}
	if !crypto.ValidateTOTP(cfg.TOTPSecret, payload.TOTP) {
		logger.Printf("[REJECT] from %s: TOTP verification failed (possible clock skew or wrong secret)", sourceIP)
		return false
	}
	return true
}

// resolveOpenDuration determines the effective port-open duration from the
// client request and server policy.
func resolveOpenDuration(cfg *config.Config, requested int) int {
	if !cfg.AllowCustomOpenDuration || requested <= 0 {
		return cfg.DefaultOpenDuration
	}
	if cfg.MaxOpenDuration > 0 && requested > cfg.MaxOpenDuration {
		return cfg.MaxOpenDuration
	}
	return requested
}

// dispatchKnockCommand routes a validated knock command to the appropriate handler.
func dispatchKnockCommand(
	logger serverLogger,
	cfg *config.Config,
	tracker *Tracker,
	allowedPorts map[string]bool,
	clientIP, cmd string,
	openDuration int,
) {
	cmdType, _, _ := validateCommandServer(cmd) // already validated; error impossible here

	switch cmdType {
	case "open":
		if cmd == "open-all" {
			handleOpenAll(logger, cfg, tracker, allowedPorts, clientIP, openDuration)
		} else {
			for _, spec := range strings.Split(cmd[5:], ",") {
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
			for _, spec := range strings.Split(cmd[6:], ",") {
				spec = strings.TrimSpace(spec)
				if spec != "" {
					handleClose(logger, cfg, tracker, allowedPorts, clientIP, spec)
				}
			}
		}

	case "cust":
		handleCustomCommand(logger, cfg, clientIP, cmd[5:])
	}
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

	if payload.ClientIP == "" {
		logger.Printf("[REJECT] from %s: missing client IP in payload", sourceIP)
		return
	}

	// Determine the IP to use for firewall commands.
	// When match_incoming_ip=true: sourceIP == payload.ClientIP (verified above).
	// When match_incoming_ip=false: use payload.ClientIP (what client specified).
	clientIP := sourceIP
	if !cfg.MatchIncomingIP {
		clientIP = payload.ClientIP
	}

	// Anti-replay: reject duplicate nonces
	if !nonceTracker.Check(payload.Nonce) {
		logger.Printf("[REJECT] from %s: possible replay attack (duplicate nonce %s...)", sourceIP, payload.Nonce[:16])
		return
	}

	if !verifyTOTP(logger, cfg, payload, sourceIP) {
		return
	}

	// open_duration is the client-requested port-open duration in seconds (0 = use server default).
	logger.Printf("[KNOCK] from %s (client=%s): cmd=%s open_duration=%d", sourceIP, clientIP, payload.Command, payload.OpenDuration)

	openDuration := resolveOpenDuration(cfg, payload.OpenDuration)

	cmd := strings.ToLower(payload.Command)
	if _, _, valErr := validateCommandServer(cmd); valErr != nil {
		logger.Printf("[REJECT] from %s: %v (raw: %q)", sourceIP, valErr, sanitizeForLog(cmd))
		return
	}

	dispatchKnockCommand(logger, cfg, tracker, allowedPorts, clientIP, cmd, openDuration)
}

// buildPortOpenCloseCommands returns the open and close command strings for a
// given protocol and IP (selecting IPv6 templates when the IP is IPv6).
func buildPortOpenCloseCommands(cfg *config.Config, proto, portNum, ip string) (openCmd, closeCmd string) {
	ipv6 := isIPv6(ip)
	switch proto {
	case "tcp":
		if ipv6 && cfg.OpenTCP6Command != "" {
			return BuildCommand(cfg.OpenTCP6Command, ip, portNum, proto),
				BuildCommand(cfg.CloseTCP6Command, ip, portNum, proto)
		}
		return BuildCommand(cfg.OpenTCPCommand, ip, portNum, proto),
			BuildCommand(cfg.CloseTCPCommand, ip, portNum, proto)
	case "udp":
		if ipv6 && cfg.OpenUDP6Command != "" {
			return BuildCommand(cfg.OpenUDP6Command, ip, portNum, proto),
				BuildCommand(cfg.CloseUDP6Command, ip, portNum, proto)
		}
		return BuildCommand(cfg.OpenUDPCommand, ip, portNum, proto),
			BuildCommand(cfg.CloseUDPCommand, ip, portNum, proto)
	}
	return "", ""
}

// execPermanentOpen runs the open command immediately without tracking expiry.
// Used when no close command is configured; the port stays open permanently.
func execPermanentOpen(logger serverLogger, cfg *config.Config, ip, portNum, proto, openCmd string) {
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
	if !cfg.AllowCustomPort && !allowedPorts[portKey] {
		logger.Printf("[DENY] from %s: port %s not in allowed list", ip, portSpec)
		return
	}

	openCmd, closeCmd := buildPortOpenCloseCommands(cfg, proto, portNum, ip)
	if openCmd == "" {
		logger.Printf("[WARN] No open command template configured for %s", proto)
		return
	}

	// When no close command is configured, execute the open command but skip
	// the tracker -- there is nothing to close at expiry so no timer is needed.
	if closeCmd == "" {
		execPermanentOpen(logger, cfg, ip, portNum, proto, openCmd)
		return
	}

	// Attempt atomic reservation; if already open, just refresh the timeout.
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
		tracker.RefreshExpiry(ip, portNum, proto, expiry)
		logger.Printf("[REFRESH] %s/%s for %s (open duration extended to %ds)", portNum, proto, ip, openDuration)
		return
	}

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
		// Keep the tracker entry so expiry watcher still runs the close command.
		logger.Printf("[WARN] Open failed for %s/%s %s - close command will run at expiry (%s)",
			portNum, proto, ip, entry.ExpiresAt.Format("15:04:05"))
		return
	}
	if cfg.LogCommandOutput && output != "" {
		logger.Printf("[CMD-OUTPUT] %s", output)
	}
}

// buildCloseCmd returns the close command string for a given protocol and IP.
func buildCloseCmd(cfg *config.Config, proto, portNum, ip string) string {
	ipv6 := isIPv6(ip)
	switch proto {
	case "tcp":
		if ipv6 && cfg.CloseTCP6Command != "" {
			return BuildCommand(cfg.CloseTCP6Command, ip, portNum, proto)
		}
		return BuildCommand(cfg.CloseTCPCommand, ip, portNum, proto)
	case "udp":
		if ipv6 && cfg.CloseUDP6Command != "" {
			return BuildCommand(cfg.CloseUDP6Command, ip, portNum, proto)
		}
		return BuildCommand(cfg.CloseUDPCommand, ip, portNum, proto)
	}
	return ""
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
	if !cfg.AllowCustomPort && !allowedPorts[portKey] {
		logger.Printf("[DENY] from %s: port %s not in allowed list", ip, portSpec)
		return
	}

	closeCmd := buildCloseCmd(cfg, proto, portNum, ip)
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

// buildOpenAllCommands selects the open-all and close-all command templates for the IP.
func buildOpenAllCommands(cfg *config.Config, ip string) (cmd, closeCmd string) {
	if isIPv6(ip) && cfg.OpenAll6Command != "" {
		return BuildCommand(cfg.OpenAll6Command, ip, "", ""),
			BuildCommand(cfg.CloseAll6Command, ip, "", "")
	}
	return BuildCommand(cfg.OpenAllCommand, ip, "", ""),
		BuildCommand(cfg.CloseAllCommand, ip, "", "")
}

// execOpenAllCmd executes an open-all-command, managing tracker reservation and expiry.
// Returns after the command completes (or fails).
func execOpenAllCmd(
	logger serverLogger,
	cfg *config.Config,
	tracker *Tracker,
	ip string,
	openDuration int,
	cmd, closeCmd string,
) {
	// No close-all: run the command but skip the tracker (permanent open).
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
		// Keep the tracker entry so the expiry watcher executes the close-all command.
		logger.Printf("[WARN] Open-all failed for %s - close-all command will run at expiry (%s)",
			ip, entry.ExpiresAt.Format("15:04:05"))
		return
	}
	if cfg.LogCommandOutput && output != "" {
		logger.Printf("[CMD-OUTPUT] %s", output)
	}
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

	if cfg.OpenAllCommand != "" {
		cmd, closeCmd := buildOpenAllCommands(cfg, ip)
		execOpenAllCmd(logger, cfg, tracker, ip, openDuration, cmd, closeCmd)
		return
	}

	// No open_all_command: open each allowed port individually.
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
