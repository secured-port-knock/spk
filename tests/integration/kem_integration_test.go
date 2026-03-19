// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package integration

import (
	"encoding/base64"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"spk/internal/config"
	"spk/internal/crypto"
	"spk/internal/protocol"
)

// =============================================================================
// Multi-KEM Full Integration Tests
// =============================================================================

func TestFullKnockCycleKEM768(t *testing.T) {
	dk, err := crypto.GenerateKeyPair(crypto.KEM768)
	if err != nil {
		t.Fatalf("GenerateKeyPair(KEM768): %v", err)
	}
	ek := dk.EncapsulationKey()

	// Start a UDP listener
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer conn.Close()
	serverAddr := conn.LocalAddr().String()

	type knockResult struct {
		payload *protocol.KnockPayload
		err     error
	}
	resultCh := make(chan knockResult, 1)

	// Server goroutine
	go func() {
		buf := make([]byte, 4096)
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			resultCh <- knockResult{nil, err}
			return
		}
		payload, err := protocol.ParseKnockPacket(dk, buf[:n], "127.0.0.1", 30)
		resultCh <- knockResult{payload, err}
	}()

	// Client sends knock
	packet, err := protocol.BuildKnockPacket(ek, "127.0.0.1", "open-t22", 3600)
	if err != nil {
		t.Fatalf("BuildKnockPacket: %v", err)
	}

	// Verify packet fits MTU
	if len(packet) > 1472 { // 1500 - IP(20) - UDP(8)
		t.Errorf("KEM-768 knock packet %d bytes exceeds 1472 max UDP payload", len(packet))
	}
	t.Logf("KEM-768 knock packet: %d bytes", len(packet))

	clientConn, err := net.Dial("udp", serverAddr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer clientConn.Close()

	if _, err := clientConn.Write(packet); err != nil {
		t.Fatalf("Write: %v", err)
	}

	result := <-resultCh
	if result.err != nil {
		t.Fatalf("server parse: %v", result.err)
	}

	if result.payload.Version != protocol.ProtocolVersion {
		t.Errorf("version = %d, want %d", result.payload.Version, protocol.ProtocolVersion)
	}
	if result.payload.Command != "open-t22" {
		t.Errorf("command = %s, want open-t22", result.payload.Command)
	}
}

func TestFullKnockCycleKEM1024(t *testing.T) {
	dk, err := crypto.GenerateKeyPair(crypto.KEM1024)
	if err != nil {
		t.Fatalf("GenerateKeyPair(KEM1024): %v", err)
	}
	ek := dk.EncapsulationKey()

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer conn.Close()
	serverAddr := conn.LocalAddr().String()

	type knockResult struct {
		payload *protocol.KnockPayload
		err     error
	}
	resultCh := make(chan knockResult, 1)

	go func() {
		buf := make([]byte, 8192)
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			resultCh <- knockResult{nil, err}
			return
		}
		payload, err := protocol.ParseKnockPacket(dk, buf[:n], "127.0.0.1", 30)
		resultCh <- knockResult{payload, err}
	}()

	packet, err := protocol.BuildKnockPacket(ek, "127.0.0.1", "open-t443", 7200)
	if err != nil {
		t.Fatalf("BuildKnockPacket: %v", err)
	}

	// KEM-1024 is expected to exceed MTU
	if len(packet) <= 1472 {
		t.Logf("Warning: KEM-1024 packet %d bytes fits in MTU - unexpected", len(packet))
	}
	t.Logf("KEM-1024 knock packet: %d bytes", len(packet))

	clientConn, _ := net.Dial("udp", serverAddr)
	defer clientConn.Close()
	clientConn.Write(packet)

	result := <-resultCh
	if result.err != nil {
		t.Fatalf("server parse: %v", result.err)
	}
	if result.payload.Command != "open-t443" {
		t.Errorf("command = %s, want open-t443", result.payload.Command)
	}
}

func TestExportBundleKeyExchangeKEM768(t *testing.T) {
	// Simulate full workflow: server generates bundle, client imports it, sends knock
	dk, _ := crypto.GenerateKeyPair(crypto.KEM768)
	ek := dk.EncapsulationKey()

	// Server exports bundle
	b64, err := crypto.CreateExportBundle(ek, 33333, true, false, true)
	if err != nil {
		t.Fatalf("CreateExportBundle: %v", err)
	}

	// Client imports bundle
	bundle, err := crypto.ParseExportBundle(b64, "")
	if err != nil {
		t.Fatalf("ParseExportBundle: %v", err)
	}

	if bundle.KEMSize != 768 {
		t.Errorf("bundle KEMSize = %d, want 768", bundle.KEMSize)
	}

	// Client extracts key
	clientEK, err := crypto.GetEncapsulationKeyFromBundle(bundle)
	if err != nil {
		t.Fatalf("GetEncapsulationKeyFromBundle: %v", err)
	}

	// Client builds knock
	packet, err := protocol.BuildKnockPacket(clientEK, "10.0.0.50", "open-t22", 3600)
	if err != nil {
		t.Fatalf("BuildKnockPacket: %v", err)
	}

	// Server decrypts
	payload, err := protocol.ParseKnockPacket(dk, packet, "10.0.0.50", 30)
	if err != nil {
		t.Fatalf("ParseKnockPacket: %v", err)
	}

	if payload.Command != "open-t22" {
		t.Errorf("command = %s, want open-t22", payload.Command)
	}
}

func TestExportBundleEncryptedWorkflowKEM768(t *testing.T) {
	dk, _ := crypto.GenerateKeyPair(crypto.KEM768)
	ek := dk.EncapsulationKey()
	password := "integration-test-pwd"

	b64, err := crypto.CreateEncryptedExportBundle(ek, 44444, true, true, false, password)
	if err != nil {
		t.Fatalf("CreateEncryptedExportBundle: %v", err)
	}

	// Client imports with password
	bundle, err := crypto.ParseExportBundle(b64, password)
	if err != nil {
		t.Fatalf("ParseExportBundle: %v", err)
	}

	if bundle.KEMSize != 768 {
		t.Errorf("bundle KEMSize = %d, want 768", bundle.KEMSize)
	}

	clientEK, _ := crypto.GetEncapsulationKeyFromBundle(bundle)
	packet, _ := protocol.BuildKnockPacket(clientEK, "172.16.0.1", "open-t8080", 1800)
	payload, err := protocol.ParseKnockPacket(dk, packet, "172.16.0.1", 30)
	if err != nil {
		t.Fatalf("ParseKnockPacket: %v", err)
	}
	if payload.Command != "open-t8080" {
		t.Errorf("command = %s, want open-t8080", payload.Command)
	}
}

// =============================================================================
// Config-Driven Tests
// =============================================================================

func TestDefaultConfigProducesMTUSafePackets(t *testing.T) {
	// Default config uses KEM-768, which should produce MTU-safe packets
	cfg := config.DefaultServerConfig()
	if cfg.KEMSize != 768 {
		t.Fatalf("default KEMSize = %d, want 768", cfg.KEMSize)
	}

	dk, _ := crypto.GenerateKeyPair(crypto.KEMSize(cfg.KEMSize))
	ek := dk.EncapsulationKey()

	packet, _ := protocol.BuildKnockPacket(ek, "1.2.3.4", "open-t22", cfg.DefaultOpenDuration)

	maxPayload := 1500 - 28 // IP + UDP
	if len(packet) > maxPayload {
		t.Errorf("default config packet %d bytes exceeds 1500 MTU", len(packet))
	}
}

func TestKEM768WithMaxSafePadding(t *testing.T) {
	// Verify MaxPaddingMTUSafe768 actually produces packets within MTU
	dk, _ := crypto.GenerateKeyPair(crypto.KEM768)
	ek := dk.EncapsulationKey()

	opts := protocol.KnockOptions{
		Padding: protocol.PaddingConfig{
			Enabled:  true,
			MinBytes: config.MaxPaddingMTUSafe768,
			MaxBytes: config.MaxPaddingMTUSafe768,
		},
	}

	packet, err := protocol.BuildKnockPacket(ek, "203.0.113.1", "open-t22", 3600, opts)
	if err != nil {
		t.Fatalf("BuildKnockPacket with max safe padding: %v", err)
	}

	maxPayload := 1500 - 28
	if len(packet) > maxPayload {
		t.Errorf("KEM-768 + MaxPaddingMTUSafe768(%d) = %d bytes, exceeds MTU (max %d)",
			config.MaxPaddingMTUSafe768, len(packet), maxPayload)
	}
	t.Logf("KEM-768 + %d-byte padding: %d bytes (max %d)", config.MaxPaddingMTUSafe768, len(packet), maxPayload)
}

// =============================================================================
// Key Save/Load Integration
// =============================================================================

func TestClientSetupPEMRoundTrip768(t *testing.T) {
	// Regression test for KEM-768 client bug:
	// Server creates a KEM-768 bundle -> client imports -> saves public key as PEM -> loads -> uses.
	// Previously, the PEM header was always "MLKEM1024 PUBLIC KEY" regardless of KEM size,
	// causing LoadPublicKey to fail for 768 keys.
	dir := t.TempDir()

	// Server side: generate KEM-768 keypair and create bundle
	dk, err := crypto.GenerateKeyPair(crypto.KEM768)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	ek := dk.EncapsulationKey()

	b64, err := crypto.CreateExportBundle(ek, 12345, true, false, true)
	if err != nil {
		t.Fatalf("CreateExportBundle: %v", err)
	}

	// Client side: parse bundle and extract key
	bundle, err := crypto.ParseExportBundle(b64, "")
	if err != nil {
		t.Fatalf("ParseExportBundle: %v", err)
	}
	if bundle.KEMSize != 768 {
		t.Fatalf("bundle KEMSize = %d, want 768", bundle.KEMSize)
	}

	// Client saves PEM with correct KEM-768 type (this was the bug)
	ekBytes, _ := base64.StdEncoding.DecodeString(bundle.EncapsulationKey)
	pemType := crypto.PublicKeyPEMType1024
	if bundle.KEMSize == 768 {
		pemType = crypto.PublicKeyPEMType768
	}
	pemBlock := &pem.Block{Type: pemType, Bytes: ekBytes}
	certPath := filepath.Join(dir, "server.crt")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(pemBlock), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Client loads PEM back - this would fail before the fix
	loadedEK, err := crypto.LoadPublicKey(certPath)
	if err != nil {
		t.Fatalf("LoadPublicKey after PEM save: %v", err)
	}
	if loadedEK.KEMSize() != crypto.KEM768 {
		t.Errorf("loaded EK KEMSize = %d, want 768", loadedEK.KEMSize())
	}

	// Full knock cycle with the loaded key
	packet, err := protocol.BuildKnockPacket(loadedEK, "10.0.0.1", "open-t22", 3600)
	if err != nil {
		t.Fatalf("BuildKnockPacket: %v", err)
	}
	if len(packet) > 1472 {
		t.Errorf("KEM-768 packet %d bytes exceeds MTU", len(packet))
	}

	payload, err := protocol.ParseKnockPacket(dk, packet, "10.0.0.1", 30)
	if err != nil {
		t.Fatalf("ParseKnockPacket: %v", err)
	}
	if payload.Command != "open-t22" {
		t.Errorf("command = %s, want open-t22", payload.Command)
	}
}

func TestClientSetupPEMRoundTrip1024(t *testing.T) {
	// Same test for KEM-1024 to ensure it still works
	dir := t.TempDir()

	dk, err := crypto.GenerateKeyPair(crypto.KEM1024)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	ek := dk.EncapsulationKey()

	b64, err := crypto.CreateExportBundle(ek, 54321, false, true, false)
	if err != nil {
		t.Fatalf("CreateExportBundle: %v", err)
	}

	bundle, err := crypto.ParseExportBundle(b64, "")
	if err != nil {
		t.Fatalf("ParseExportBundle: %v", err)
	}

	ekBytes, _ := base64.StdEncoding.DecodeString(bundle.EncapsulationKey)
	pemType := crypto.PublicKeyPEMType1024
	if bundle.KEMSize == 768 {
		pemType = crypto.PublicKeyPEMType768
	}
	pemBlock := &pem.Block{Type: pemType, Bytes: ekBytes}
	certPath := filepath.Join(dir, "server.crt")
	os.WriteFile(certPath, pem.EncodeToMemory(pemBlock), 0600)

	loadedEK, err := crypto.LoadPublicKey(certPath)
	if err != nil {
		t.Fatalf("LoadPublicKey: %v", err)
	}
	if loadedEK.KEMSize() != crypto.KEM1024 {
		t.Errorf("loaded EK KEMSize = %d, want 1024", loadedEK.KEMSize())
	}

	packet, _ := protocol.BuildKnockPacket(loadedEK, "10.0.0.2", "close-t80", 0)
	payload, err := protocol.ParseKnockPacket(dk, packet, "10.0.0.2", 30)
	if err != nil {
		t.Fatalf("ParseKnockPacket: %v", err)
	}
	if payload.Command != "close-t80" {
		t.Errorf("command = %s, want close-t80", payload.Command)
	}
}

func TestEncryptedBundlePEMRoundTrip768(t *testing.T) {
	// Encrypted bundle -> decrypt -> PEM save -> load -> knock
	dir := t.TempDir()
	password := "test-secure-pass"

	dk, _ := crypto.GenerateKeyPair(crypto.KEM768)
	ek := dk.EncapsulationKey()

	b64, err := crypto.CreateEncryptedExportBundle(ek, 33333, true, true, true, password)
	if err != nil {
		t.Fatalf("CreateEncryptedExportBundle: %v", err)
	}

	bundle, err := crypto.ParseExportBundle(b64, password)
	if err != nil {
		t.Fatalf("ParseExportBundle with password: %v", err)
	}
	if bundle.KEMSize != 768 {
		t.Fatalf("encrypted bundle KEMSize = %d, want 768", bundle.KEMSize)
	}

	ekBytes, _ := base64.StdEncoding.DecodeString(bundle.EncapsulationKey)
	pemBlock := &pem.Block{Type: crypto.PublicKeyPEMType768, Bytes: ekBytes}
	certPath := filepath.Join(dir, "server.crt")
	os.WriteFile(certPath, pem.EncodeToMemory(pemBlock), 0600)

	loadedEK, err := crypto.LoadPublicKey(certPath)
	if err != nil {
		t.Fatalf("LoadPublicKey from encrypted bundle: %v", err)
	}

	packet, _ := protocol.BuildKnockPacket(loadedEK, "10.0.0.3", "open-all", 7200)
	payload, err := protocol.ParseKnockPacket(dk, packet, "10.0.0.3", 30)
	if err != nil {
		t.Fatalf("ParseKnockPacket: %v", err)
	}
	if payload.Command != "open-all" {
		t.Errorf("command = %s, want open-all", payload.Command)
	}
}

func TestKeySaveLoadCrossProcess768(t *testing.T) {
	// Simulate server and client using different loaded keys
	dir := t.TempDir()

	// Server generates and saves
	dk, _ := crypto.GenerateKeyPair(crypto.KEM768)
	crypto.SavePrivateKey(dir+"/server_priv.pem", dk)
	crypto.SavePublicKey(dir+"/server_pub.pem", dk)

	// "Client" loads public key from file
	loadedEK, err := crypto.LoadPublicKey(dir + "/server_pub.pem")
	if err != nil {
		t.Fatalf("LoadPublicKey: %v", err)
	}

	if loadedEK.KEMSize() != crypto.KEM768 {
		t.Errorf("loaded EK KEMSize = %d, want 768", loadedEK.KEMSize())
	}

	// "Server" loads private key
	loadedDK, err := crypto.LoadPrivateKey(dir + "/server_priv.pem")
	if err != nil {
		t.Fatalf("LoadPrivateKey: %v", err)
	}

	// Client builds knock with loaded public key
	packet, _ := protocol.BuildKnockPacket(loadedEK, "192.168.1.50", "open-t22", 1800)

	// Server parses with loaded private key
	payload, err := protocol.ParseKnockPacket(loadedDK, packet, "192.168.1.50", 30)
	if err != nil {
		t.Fatalf("ParseKnockPacket with loaded keys: %v", err)
	}
	if payload.Command != "open-t22" {
		t.Errorf("command = %s, want open-t22", payload.Command)
	}
}

// =============================================================================
// Dynamic Port with Multi-KEM
// =============================================================================

func TestDynamicPortDeterminismMultiKEM(t *testing.T) {
	// Dynamic port should be independent of KEM size
	seed := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04}

	port1 := crypto.ComputeDynamicPort(seed)
	port2 := crypto.ComputeDynamicPort(seed)
	if port1 != port2 {
		t.Errorf("dynamic port not deterministic: %d != %d", port1, port2)
	}

	if port1 < 10000 || port1 >= 65000 {
		t.Errorf("dynamic port %d out of range [10000, 65000)", port1)
	}
}

// =============================================================================
// Server Static Port E2E Tests
// =============================================================================

func TestServerStaticPortE2E(t *testing.T) {
	// Full cycle: generate keys, write server config with static port + seed,
	// load config, verify static port wins, then send/receive knock on that port.
	dir := t.TempDir()

	// Generate keys
	dk, err := crypto.GenerateKeyPair(crypto.KEM768)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	ek := dk.EncapsulationKey()

	// Write server config with static port AND port_seed (seed should be ignored)
	cfgContent := `
listen_port = 21116
port_seed = "bdbacb8047d87d67"
dynamic_port_window = 60
dynamic_port_min = 10000
dynamic_port_max = 65000
sniffer_mode = "udp"
listen_addresses = ["127.0.0.1"]
default_open_duration = 3600
max_open_duration = 86400
timestamp_tolerance = 30
nonce_expiry = 120
`
	cfgPath := filepath.Join(dir, "server.toml")
	os.WriteFile(cfgPath, []byte(cfgContent), 0600)

	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Verify static port wins
	if cfg.DynamicPort {
		t.Fatal("DynamicPort should be false with static listen_port=21116")
	}
	if cfg.ListenPort != 21116 {
		t.Fatalf("ListenPort = %d, want 21116", cfg.ListenPort)
	}

	// Start a listener on an ephemeral port to simulate the server
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer conn.Close()

	// Send knock
	packet, err := protocol.BuildKnockPacket(ek, "127.0.0.1", "open-t22", 3600)
	if err != nil {
		t.Fatalf("BuildKnockPacket: %v", err)
	}

	type knockResult struct {
		payload *protocol.KnockPayload
		err     error
	}
	resultCh := make(chan knockResult, 1)
	go func() {
		buf := make([]byte, 4096)
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			resultCh <- knockResult{nil, err}
			return
		}
		payload, err := protocol.ParseKnockPacket(dk, buf[:n], "127.0.0.1", 30)
		resultCh <- knockResult{payload, err}
	}()

	clientConn, err := net.Dial("udp", conn.LocalAddr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer clientConn.Close()
	clientConn.Write(packet)

	result := <-resultCh
	if result.err != nil {
		t.Fatalf("Parse: %v", result.err)
	}
	if result.payload.Command != "open-t22" {
		t.Errorf("command = %s, want open-t22", result.payload.Command)
	}
}

func TestClientStaticPortMatchesServerE2E(t *testing.T) {
	// Verify client and server agree on static port behavior
	dir := t.TempDir()

	// Server config: static port 21116 with seed present
	serverCfg := `
listen_port = 21116
port_seed = "bdbacb8047d87d67"
dynamic_port_window = 60
sniffer_mode = "udp"
`
	serverPath := filepath.Join(dir, "server.toml")
	os.WriteFile(serverPath, []byte(serverCfg), 0600)

	// Client config: static port 21116 with seed present
	clientCfg := `
server_host = "127.0.0.1"
server_port = 21116
port_seed = "bdbacb8047d87d67"
dynamic_port_window = 60
`
	clientPath := filepath.Join(dir, "client.toml")
	os.WriteFile(clientPath, []byte(clientCfg), 0600)

	srv, err := config.Load(serverPath)
	if err != nil {
		t.Fatalf("Load server: %v", err)
	}
	cli, err := config.Load(clientPath)
	if err != nil {
		t.Fatalf("Load client: %v", err)
	}

	// Both should agree: static port, no dynamic
	if srv.DynamicPort {
		t.Error("server DynamicPort should be false")
	}
	if cli.DynamicPort {
		t.Error("client DynamicPort should be false")
	}
	if srv.ListenPort != 21116 {
		t.Errorf("server ListenPort = %d, want 21116", srv.ListenPort)
	}
	if cli.ServerPort != 21116 {
		t.Errorf("client ServerPort = %d, want 21116", cli.ServerPort)
	}
}

func TestDynamicPortClientServerAgreement(t *testing.T) {
	// When both use dynamic, they should compute the same port from the same seed
	dir := t.TempDir()

	serverCfg := `
listen_port = "dynamic"
port_seed = "deadbeef01020304"
dynamic_port_window = 600
sniffer_mode = "udp"
`
	clientCfg := `
server_host = "127.0.0.1"
server_port = "dynamic"
port_seed = "deadbeef01020304"
dynamic_port_window = 600
`
	serverPath := filepath.Join(dir, "server.toml")
	clientPath := filepath.Join(dir, "client.toml")
	os.WriteFile(serverPath, []byte(serverCfg), 0600)
	os.WriteFile(clientPath, []byte(clientCfg), 0600)

	srv, _ := config.Load(serverPath)
	cli, _ := config.Load(clientPath)

	if !srv.DynamicPort {
		t.Error("server should be dynamic")
	}
	if !cli.DynamicPort {
		t.Error("client should be dynamic")
	}

	// Both should compute the same port from the seed
	seed := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04}
	srvPort := crypto.ComputeDynamicPortWithWindow(seed, srv.DynPortWindow)
	cliPort := crypto.ComputeDynamicPortWithWindow(seed, cli.DynPortWindow)
	if srvPort != cliPort {
		t.Errorf("server port %d != client port %d", srvPort, cliPort)
	}
}

func TestPaddingWithinMTUE2E(t *testing.T) {
	// E2E test: build knock with maximum safe padding (96 bytes), send over UDP, verify parsing
	dk, _ := crypto.GenerateKeyPair(crypto.KEM768)
	ek := dk.EncapsulationKey()

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer conn.Close()

	opts := protocol.KnockOptions{
		Padding: protocol.PaddingConfig{
			Enabled:  true,
			MinBytes: config.MaxPaddingMTUSafe768,
			MaxBytes: config.MaxPaddingMTUSafe768,
		},
	}

	packet, err := protocol.BuildKnockPacket(ek, "127.0.0.1", "open-t443", 7200, opts)
	if err != nil {
		t.Fatalf("BuildKnockPacket: %v", err)
	}

	maxUDP := 1500 - 28
	if len(packet) > maxUDP {
		t.Errorf("padded packet %d bytes exceeds MTU %d", len(packet), maxUDP)
	}

	type result struct {
		payload *protocol.KnockPayload
		err     error
	}
	ch := make(chan result, 1)
	go func() {
		buf := make([]byte, 4096)
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			ch <- result{nil, err}
			return
		}
		p, err := protocol.ParseKnockPacket(dk, buf[:n], "127.0.0.1", 30)
		ch <- result{p, err}
	}()

	c, _ := net.Dial("udp", conn.LocalAddr().String())
	defer c.Close()
	c.Write(packet)

	r := <-ch
	if r.err != nil {
		t.Fatalf("Parse: %v", r.err)
	}
	if r.payload.Command != "open-t443" {
		t.Errorf("command = %s, want open-t443", r.payload.Command)
	}
	t.Logf("Padded packet: %d bytes (max %d)", len(packet), maxUDP)
}

func TestBatchCommandMultiPortE2E(t *testing.T) {
	// Verify batch commands (open-t22,t443) work through full cycle
	dk, _ := crypto.GenerateKeyPair(crypto.KEM768)
	ek := dk.EncapsulationKey()

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer conn.Close()

	packet, err := protocol.BuildKnockPacket(ek, "127.0.0.1", "open-t22,t443,u53", 1800)
	if err != nil {
		t.Fatalf("BuildKnockPacket: %v", err)
	}

	type result struct {
		payload *protocol.KnockPayload
		err     error
	}
	ch := make(chan result, 1)
	go func() {
		buf := make([]byte, 4096)
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			ch <- result{nil, err}
			return
		}
		p, err := protocol.ParseKnockPacket(dk, buf[:n], "127.0.0.1", 30)
		ch <- result{p, err}
	}()

	c, _ := net.Dial("udp", conn.LocalAddr().String())
	defer c.Close()
	c.Write(packet)

	r := <-ch
	if r.err != nil {
		t.Fatalf("Parse: %v", r.err)
	}
	if r.payload.Command != "open-t22,t443,u53" {
		t.Errorf("command = %s, want open-t22,t443,u53", r.payload.Command)
	}
}

func TestNonceReplayPreventionE2E(t *testing.T) {
	// Send the same packet twice, second should be rejected by nonce tracker
	dk, _ := crypto.GenerateKeyPair(crypto.KEM768)
	ek := dk.EncapsulationKey()

	packet, err := protocol.BuildKnockPacket(ek, "192.168.1.1", "open-t22", 3600)
	if err != nil {
		t.Fatalf("BuildKnockPacket: %v", err)
	}

	nonceTracker := protocol.NewNonceTrackerWithLimit(120*time.Second, 1000)

	// First parse should succeed
	payload1, err := protocol.ParseKnockPacket(dk, packet, "192.168.1.1", 30)
	if err != nil {
		t.Fatalf("First parse: %v", err)
	}

	// Record the nonce
	if !nonceTracker.Check(payload1.Nonce) {
		t.Fatal("First nonce should be accepted")
	}

	// Second check of the same nonce should be rejected
	if nonceTracker.Check(payload1.Nonce) {
		t.Fatal("Duplicate nonce should be rejected (replay)")
	}
}
