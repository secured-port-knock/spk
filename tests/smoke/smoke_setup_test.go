// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

//go:build testsmoke

package smoke_test

import (
	"bufio"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/secured-port-knock/spk/internal/config"
	"github.com/secured-port-knock/spk/internal/crypto"
)

// serverSetup holds parameters for a smoke-test server instance.
type serverSetup struct {
	snifferMode         string
	listenPort          int
	allowedPorts        []string
	allowCustomPort     bool
	allowOpenAll        bool
	matchIncomingIP     bool
	totpEnabled         bool
	totpSecret          string
	defaultOpenDuration int
	dynamicPort         bool
	portSeed            string
	dynPortWindow       int
}

// defaultSetup returns conservative defaults suitable for most smoke tests.
func defaultSetup() serverSetup {
	return serverSetup{
		snifferMode:         "udp",
		allowedPorts:        []string{"t22"},
		allowCustomPort:     false,
		defaultOpenDuration: 60,
		matchIncomingIP:     true,
	}
}

// testServer holds a running SPK server subprocess and test metadata.
type testServer struct {
	port      int
	ek        crypto.EncapsulationKey
	markerDir string
	stop      func()
}

// setupTestServer creates a temporary server config, starts the SPK binary
// in server mode, and waits until the server reports it is listening.
//
// The returned testServer.stop must be called to terminate the subprocess;
// it is also registered as a t.Cleanup handler automatically.
func setupTestServer(t *testing.T, setup serverSetup) *testServer {
	t.Helper()

	cfgDir := t.TempDir()
	markerDir := t.TempDir()

	_, ek := generateServerKeys(t, cfgDir)

	cfg, port := buildServerConfig(t, setup, cfgDir, markerDir)

	if errs := cfg.Validate(); len(errs) > 0 {
		t.Fatalf("config validation: %v", strings.Join(errs, "; "))
	}
	if err := cfg.Save(filepath.Join(cfgDir, "spk_server.toml")); err != nil {
		t.Fatalf("save config: %v", err)
	}

	stopFn := startServerProcess(t, cfgDir)
	t.Cleanup(stopFn)

	return &testServer{
		port:      port,
		ek:        ek,
		markerDir: markerDir,
		stop:      stopFn,
	}
}

// generateServerKeys generates a KEM-768 keypair, saves the private key to
// cfgDir, and returns the decapsulation key and encapsulation key.
func generateServerKeys(t *testing.T, cfgDir string) (crypto.DecapsulationKey, crypto.EncapsulationKey) {
	t.Helper()
	dk, err := crypto.GenerateKeyPair(crypto.KEM768)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	if err := crypto.SavePrivateKey(filepath.Join(cfgDir, "server.key"), dk); err != nil {
		t.Fatalf("SavePrivateKey: %v", err)
	}
	return dk, dk.EncapsulationKey()
}

// buildServerConfig constructs a *config.Config from a serverSetup and returns
// both the config and the resolved listen port (static or dynamic).
func buildServerConfig(t *testing.T, setup serverSetup, cfgDir, markerDir string) (*config.Config, int) {
	t.Helper()

	listenPort := setup.listenPort
	if listenPort == 0 && !setup.dynamicPort {
		listenPort = freeUDPPort(t)
	}

	cfg := &config.Config{
		Mode:                "server",
		SnifferMode:         setup.snifferMode,
		ListenPort:          listenPort,
		ListenAddresses:     []string{"127.0.0.1"},
		AllowedPorts:        setup.allowedPorts,
		AllowCustomPort:     setup.allowCustomPort,
		AllowOpenAll:        setup.allowOpenAll,
		MatchIncomingIP:     setup.matchIncomingIP,
		TOTPEnabled:         setup.totpEnabled,
		TOTPSecret:          setup.totpSecret,
		DefaultOpenDuration: setup.defaultOpenDuration,
		TimestampTolerance:  30,
		NonceExpiry:         120,
		CommandTimeout:      2.0,
		LogCommandOutput:    true,
		ClosePortsOnCrash:   true,
		OpenTCPCommand:      stubCmd("open_tcp", markerDir),
		CloseTCPCommand:     stubCmd("close_tcp", markerDir),
		OpenAllCommand:      stubCmd("open_all", markerDir),
		CloseAllCommand:     stubCmd("close_all", markerDir),
		KEMSize:             768,
		CustomCommands:      map[string]string{},
	}

	port := listenPort
	if setup.dynamicPort && setup.portSeed != "" {
		port = applyDynamicPortConfig(t, cfg, setup)
	}
	return cfg, port
}

// applyDynamicPortConfig sets dynamic port fields on cfg and returns the
// current listen port computed from the seed and window.
func applyDynamicPortConfig(t *testing.T, cfg *config.Config, setup serverSetup) int {
	t.Helper()
	window := setup.dynPortWindow
	if window == 0 {
		window = 60
	}
	cfg.PortSeed = setup.portSeed
	cfg.DynPortWindow = window
	cfg.ListenPort = 0

	seedBytes, err := hex.DecodeString(setup.portSeed)
	if err != nil {
		t.Fatalf("decode portSeed: %v", err)
	}
	return crypto.ComputeDynamicPortWithWindow(seedBytes, window)
}

// startServerProcess launches the SPK binary in server mode and waits for it
// to report that it is listening. Returns a stop function for graceful
// shutdown.
//
// The stop function waits for the server output scanner goroutine to finish
// before returning, ensuring no t.Logf calls occur after the test has ended.
func startServerProcess(t *testing.T, cfgDir string) func() {
	t.Helper()

	serverCmd := exec.Command(spkBinary, "--server", "--cfgdir", cfgDir, "--logdir", cfgDir)
	pr, pw := io.Pipe()
	serverCmd.Stdout = pw
	serverCmd.Stderr = pw
	if err := serverCmd.Start(); err != nil {
		t.Fatalf("start server: %v", err)
	}

	readyCh := make(chan struct{}, 1)
	scanDone := make(chan struct{})
	go func() {
		defer close(scanDone)
		defer pr.Close()
		scanner := bufio.NewScanner(pr)
		for scanner.Scan() {
			line := scanner.Text()
			t.Logf("[srv] %s", line)
			if strings.Contains(line, "Listening for knock") {
				select {
				case readyCh <- struct{}{}:
				default:
				}
			}
		}
	}()

	select {
	case <-readyCh:
	case <-time.After(20 * time.Second):
		_ = serverCmd.Process.Kill()
		pw.Close()
		<-scanDone
		t.Fatal("timeout waiting for server startup")
	}

	var stopped bool
	return func() {
		if stopped {
			return
		}
		stopped = true
		_ = serverCmd.Process.Signal(os.Interrupt)
		done := make(chan struct{})
		go func() {
			_ = serverCmd.Wait()
			pw.Close()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			_ = serverCmd.Process.Kill()
			pw.Close()
		}
		// Wait for the scanner goroutine to finish so no t.Logf calls
		// occur after the test has been marked as done.
		<-scanDone
	}
}
