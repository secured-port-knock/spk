// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package integration

import (
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"spk/internal/crypto"
	"spk/internal/protocol"
)

// TestFullKnockCycle tests a complete client->server knock round trip.
func TestFullKnockCycle(t *testing.T) {
	// Generate server keypair
	dk, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	ek := dk.EncapsulationKey()

	// Start a UDP listener (simulated server)
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer conn.Close()

	serverAddr := conn.LocalAddr().String()
	t.Logf("Test server listening on %s", serverAddr)

	// Channel to receive parsed knock
	type knockResult struct {
		payload *protocol.KnockPayload
		err     error
	}
	resultCh := make(chan knockResult, 1)

	// Server goroutine
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 8192)
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			resultCh <- knockResult{nil, fmt.Errorf("ReadFrom: %w", err)}
			return
		}

		sourceIP := addr.(*net.UDPAddr).IP.String()
		payload, err := protocol.ParseKnockPacket(dk, buf[:n], sourceIP, 30)
		resultCh <- knockResult{payload, err}
	}()

	// Client sends knock
	clientConn, err := net.Dial("udp", serverAddr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer clientConn.Close()

	localIP := clientConn.LocalAddr().(*net.UDPAddr).IP.String()
	packet, err := protocol.BuildKnockPacket(ek, localIP, "open-t22", 3600)
	if err != nil {
		t.Fatalf("BuildKnockPacket: %v", err)
	}

	_, err = clientConn.Write(packet)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	// Wait for result
	result := <-resultCh
	if result.err != nil {
		t.Fatalf("Server parse error: %v", result.err)
	}

	p := result.payload
	if p.Command != "open-t22" {
		t.Errorf("command = %s, want open-t22", p.Command)
	}
	if p.OpenDuration != 3600 {
		t.Errorf("open duration = %d, want 3600", p.OpenDuration)
	}
	if p.ClientIP != localIP {
		t.Errorf("clientIP = %s, want %s", p.ClientIP, localIP)
	}

	wg.Wait()
}

// TestMITMRelayPrevention tests that forwarded packets from a different IP are rejected.
func TestMITMRelayPrevention(t *testing.T) {
	dk, _ := crypto.GenerateKeyPair()
	ek := dk.EncapsulationKey()

	// Client builds packet claiming IP 192.168.1.100
	packet, _ := protocol.BuildKnockPacket(ek, "192.168.1.100", "open-t22", 0)

	// Attacker captures and forwards from their IP 10.0.0.99
	_, err := protocol.ParseKnockPacket(dk, packet, "10.0.0.99", 30)
	if err == nil {
		t.Error("MITM relay should be rejected (IP mismatch)")
	}
}

// TestExportImportCycle tests full key export -> import -> use cycle.
func TestExportImportCycle(t *testing.T) {
	// Server generates key
	dk, _ := crypto.GenerateKeyPair()
	ek := dk.EncapsulationKey()

	// Export
	b64, err := crypto.CreateExportBundle(ek, 12345, true, false, false)
	if err != nil {
		t.Fatalf("CreateExportBundle: %v", err)
	}

	// Client imports
	bundle, err := crypto.ParseExportBundle(b64, "")
	if err != nil {
		t.Fatalf("ParseExportBundle: %v", err)
	}

	clientEK, err := crypto.GetEncapsulationKeyFromBundle(bundle)
	if err != nil {
		t.Fatalf("GetEncapsulationKeyFromBundle: %v", err)
	}

	// Client uses imported key to build knock
	packet, err := protocol.BuildKnockPacket(clientEK, "10.0.0.1", "open-t443", 7200)
	if err != nil {
		t.Fatalf("BuildKnockPacket with imported key: %v", err)
	}

	// Server decrypts
	payload, err := protocol.ParseKnockPacket(dk, packet, "10.0.0.1", 30)
	if err != nil {
		t.Fatalf("ParseKnockPacket: %v", err)
	}

	if payload.Command != "open-t443" {
		t.Errorf("command = %s, want open-t443", payload.Command)
	}
	if payload.OpenDuration != 7200 {
		t.Errorf("open duration = %d, want 7200", payload.OpenDuration)
	}
}

// TestEncryptedExportImportCycle tests password-protected export.
func TestEncryptedExportImportCycle(t *testing.T) {
	dk, _ := crypto.GenerateKeyPair()
	ek := dk.EncapsulationKey()

	password := "super-secret-password"

	b64, err := crypto.CreateEncryptedExportBundle(ek, 54321, false, true, true, password)
	if err != nil {
		t.Fatalf("CreateEncryptedExportBundle: %v", err)
	}

	// Import with correct password
	bundle, err := crypto.ParseExportBundle(b64, password)
	if err != nil {
		t.Fatalf("ParseExportBundle: %v", err)
	}

	if bundle.Port != 54321 {
		t.Errorf("port = %d, want 54321", bundle.Port)
	}

	// Use key
	clientEK, _ := crypto.GetEncapsulationKeyFromBundle(bundle)
	packet, _ := protocol.BuildKnockPacket(clientEK, "1.2.3.4", "open-all", 0)
	payload, err := protocol.ParseKnockPacket(dk, packet, "1.2.3.4", 30)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if payload.Command != "open-all" {
		t.Errorf("command = %s, want open-all", payload.Command)
	}
}

// TestMultipleClientsIndependent tests that knocks from different IPs are independent.
func TestMultipleClientsIndependent(t *testing.T) {
	dk, _ := crypto.GenerateKeyPair()
	ek := dk.EncapsulationKey()
	tracker := protocol.NewNonceTracker(120 * time.Second)

	// Client 1
	p1, _ := protocol.BuildKnockPacket(ek, "10.0.0.1", "open-t22", 0)
	payload1, _ := protocol.ParseKnockPacket(dk, p1, "10.0.0.1", 30)
	if !tracker.Check(payload1.Nonce) {
		t.Error("client 1 nonce should pass")
	}

	// Client 2
	p2, _ := protocol.BuildKnockPacket(ek, "10.0.0.2", "open-t443", 0)
	payload2, _ := protocol.ParseKnockPacket(dk, p2, "10.0.0.2", 30)
	if !tracker.Check(payload2.Nonce) {
		t.Error("client 2 nonce should pass")
	}

	// Each has different nonce
	if payload1.Nonce == payload2.Nonce {
		t.Error("different clients should have different nonces")
	}
}

// TestBatchCommandE2E tests batch open commands through the full knock cycle.
func TestBatchCommandE2E(t *testing.T) {
	dk, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	ek := dk.EncapsulationKey()

	// Start UDP listener
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
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			resultCh <- knockResult{nil, fmt.Errorf("ReadFrom: %w", err)}
			return
		}
		sourceIP := addr.(*net.UDPAddr).IP.String()
		payload, err := protocol.ParseKnockPacket(dk, buf[:n], sourceIP, 30)
		resultCh <- knockResult{payload, err}
	}()

	// Client sends batch command
	clientConn, err := net.Dial("udp", serverAddr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer clientConn.Close()

	localIP := clientConn.LocalAddr().(*net.UDPAddr).IP.String()
	packet, err := protocol.BuildKnockPacket(ek, localIP, "open-t22,t443,u53", 1800)
	if err != nil {
		t.Fatalf("BuildKnockPacket: %v", err)
	}

	_, err = clientConn.Write(packet)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	result := <-resultCh
	if result.err != nil {
		t.Fatalf("Server parse error: %v", result.err)
	}

	if result.payload.Command != "open-t22,t443,u53" {
		t.Errorf("command = %s, want open-t22,t443,u53", result.payload.Command)
	}
	if result.payload.OpenDuration != 1800 {
		t.Errorf("open duration = %d, want 1800", result.payload.OpenDuration)
	}
}

// TestE2EMultipleKnocks tests sending multiple sequential knocks.
func TestE2EMultipleKnocks(t *testing.T) {
	dk, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	ek := dk.EncapsulationKey()

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer conn.Close()

	serverAddr := conn.LocalAddr().String()
	nonceTracker := protocol.NewNonceTracker(120 * time.Second)

	// Send 5 knocks and verify each is unique and valid
	for i := 0; i < 5; i++ {
		resultCh := make(chan *protocol.KnockPayload, 1)
		errCh := make(chan error, 1)

		go func() {
			buf := make([]byte, 8192)
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				errCh <- err
				return
			}
			sourceIP := addr.(*net.UDPAddr).IP.String()
			payload, err := protocol.ParseKnockPacket(dk, buf[:n], sourceIP, 30)
			if err != nil {
				errCh <- err
				return
			}
			resultCh <- payload
		}()

		clientConn, err := net.Dial("udp", serverAddr)
		if err != nil {
			t.Fatalf("Dial %d: %v", i, err)
		}
		localIP := clientConn.LocalAddr().(*net.UDPAddr).IP.String()
		cmd := fmt.Sprintf("open-t%d", 22+i)
		packet, _ := protocol.BuildKnockPacket(ek, localIP, cmd, 0)
		clientConn.Write(packet)
		clientConn.Close()

		select {
		case payload := <-resultCh:
			if payload.Command != cmd {
				t.Errorf("knock %d: command = %s, want %s", i, payload.Command, cmd)
			}
			if !nonceTracker.Check(payload.Nonce) {
				t.Errorf("knock %d: nonce already seen (replay)", i)
			}
		case err := <-errCh:
			t.Fatalf("knock %d: error: %v", i, err)
		case <-time.After(5 * time.Second):
			t.Fatalf("knock %d: timeout waiting for packet", i)
		}
	}
}

// TestMalformedPacketHandling tests that the server gracefully handles garbage.
func TestMalformedPacketHandling(t *testing.T) {
	dk, _ := crypto.GenerateKeyPair()

	malformed := [][]byte{
		make([]byte, 100),  // Too small
		make([]byte, 5000), // Too large
		{0x00},             // Tiny
		make([]byte, 2000), // Right size but garbage
	}

	for i, data := range malformed {
		_, err := protocol.ParseKnockPacket(dk, data, "1.2.3.4", 30)
		if err == nil {
			t.Errorf("malformed packet %d should be rejected", i)
		}
	}
}

// TestExportImportWithBatchCapability tests key exchange + batch commands.
func TestExportImportWithBatchCapability(t *testing.T) {
	dk, _ := crypto.GenerateKeyPair()
	ek := dk.EncapsulationKey()

	// Export and import
	b64, err := crypto.CreateExportBundle(ek, 12345, true, true, true)
	if err != nil {
		t.Fatalf("CreateExportBundle: %v", err)
	}
	bundle, err := crypto.ParseExportBundle(b64, "")
	if err != nil {
		t.Fatalf("ParseExportBundle: %v", err)
	}
	clientEK, err := crypto.GetEncapsulationKeyFromBundle(bundle)
	if err != nil {
		t.Fatalf("GetEncapsulationKeyFromBundle: %v", err)
	}

	// Use imported key for batch command
	packet, err := protocol.BuildKnockPacket(clientEK, "10.0.0.1", "open-t22,t443,t8080,u53", 7200)
	if err != nil {
		t.Fatalf("BuildKnockPacket: %v", err)
	}

	payload, err := protocol.ParseKnockPacket(dk, packet, "10.0.0.1", 30)
	if err != nil {
		t.Fatalf("ParseKnockPacket: %v", err)
	}

	if payload.Command != "open-t22,t443,t8080,u53" {
		t.Errorf("command = %s, want open-t22,t443,t8080,u53", payload.Command)
	}
	if payload.OpenDuration != 7200 {
		t.Errorf("open duration = %d, want 7200", payload.OpenDuration)
	}
}

// TestIPv6KnockCycle tests a knock with an IPv6 client address.
func TestIPv6KnockCycle(t *testing.T) {
	dk, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	ek := dk.EncapsulationKey()

	// Use IPv6 loopback for testing
	conn, err := net.ListenPacket("udp6", "[::1]:0")
	if err != nil {
		t.Skip("IPv6 not available on this system")
	}
	defer conn.Close()

	serverAddr := conn.LocalAddr().String()
	t.Logf("IPv6 test server listening on %s", serverAddr)

	type knockResult struct {
		payload *protocol.KnockPayload
		err     error
	}
	resultCh := make(chan knockResult, 1)

	go func() {
		buf := make([]byte, 8192)
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			resultCh <- knockResult{nil, fmt.Errorf("ReadFrom: %w", err)}
			return
		}
		sourceIP := addr.(*net.UDPAddr).IP.String()
		payload, err := protocol.ParseKnockPacket(dk, buf[:n], sourceIP, 30)
		resultCh <- knockResult{payload, err}
	}()

	clientConn, err := net.Dial("udp6", serverAddr)
	if err != nil {
		t.Fatalf("Dial IPv6: %v", err)
	}
	defer clientConn.Close()

	clientIP := "::1"
	packet, err := protocol.BuildKnockPacket(ek, clientIP, "open-t22", 3600)
	if err != nil {
		t.Fatalf("BuildKnockPacket: %v", err)
	}

	_, err = clientConn.Write(packet)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	result := <-resultCh
	if result.err != nil {
		t.Fatalf("Server parse IPv6 error: %v", result.err)
	}

	p := result.payload
	if p.Command != "open-t22" {
		t.Errorf("command = %s, want open-t22", p.Command)
	}
	if p.ClientIP != clientIP {
		t.Errorf("clientIP = %s, want %s", p.ClientIP, clientIP)
	}
}

// TestIPv6AddressInPayload verifies that full IPv6 addresses survive the encrypt/decrypt cycle.
func TestIPv6AddressInPayload(t *testing.T) {
	dk, _ := crypto.GenerateKeyPair()
	ek := dk.EncapsulationKey()

	ipv6Addrs := []string{
		"2001:db8::1",
		"fe80::1",
		"::1",
		"2001:db8:85a3::8a2e:370:7334",
	}

	for _, addr := range ipv6Addrs {
		packet, err := protocol.BuildKnockPacket(ek, addr, "open-t22", 0)
		if err != nil {
			t.Fatalf("BuildKnockPacket(%s): %v", addr, err)
		}

		// Parse with matching IP (IP check not skipped)
		payload, err := protocol.ParseKnockPacket(dk, packet, addr, 30)
		if err != nil {
			t.Fatalf("ParseKnockPacket(%s): %v", addr, err)
		}

		if payload.ClientIP != addr {
			t.Errorf("clientIP = %q, want %q", payload.ClientIP, addr)
		}
	}
}
