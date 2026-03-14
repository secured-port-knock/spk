// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package sniffer

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"spk/internal/crypto"
)

// ------------------------------------------------------------------------
// Dynamic Port + Sniffer Tests
// Verify that dynamic port computation produces valid ports and that
// sniffers can be created at dynamically computed ports for all modes.
// ------------------------------------------------------------------------

// TestDynamicPortValidRange verifies dynamic ports always fall in the expected range.
func TestDynamicPortValidRange(t *testing.T) {
	for i := 0; i < 100; i++ {
		seed := make([]byte, 8)
		rand.Read(seed)

		for _, window := range []int{60, 120, 300, 600, 3600, 86400} {
			port := crypto.ComputeDynamicPortWithWindow(seed, window)
			if port < 10000 || port > 64999 {
				t.Errorf("seed=%s window=%d: port %d out of range [10000, 64999]",
					hex.EncodeToString(seed), window, port)
			}
		}
	}
}

// TestDynamicPortDeterministic verifies same seed+time gives same port.
func TestDynamicPortDeterministic(t *testing.T) {
	seed := make([]byte, 8)
	rand.Read(seed)

	port1 := crypto.ComputeDynamicPortWithWindow(seed, 600)
	port2 := crypto.ComputeDynamicPortWithWindow(seed, 600)

	if port1 != port2 {
		t.Errorf("same seed+time should give same port: %d vs %d", port1, port2)
	}
}

// TestDynamicPortDifferentSeeds verifies different seeds give different ports (usually).
func TestDynamicPortDifferentSeeds(t *testing.T) {
	seeds := make([][]byte, 20)
	for i := range seeds {
		seeds[i] = make([]byte, 8)
		rand.Read(seeds[i])
	}

	ports := make(map[int]bool)
	for _, seed := range seeds {
		port := crypto.ComputeDynamicPortWithWindow(seed, 600)
		ports[port] = true
	}

	// With 20 random seeds, we should get at least 10 distinct ports
	// (55000 port range, probability of collision is very low)
	if len(ports) < 10 {
		t.Errorf("expected at least 10 distinct ports from 20 seeds, got %d", len(ports))
	}
}

// TestNewSnifferAllModesAtDynamicPort verifies that each sniffer mode can be
// instantiated at a dynamically computed port.
func TestNewSnifferAllModesAtDynamicPort(t *testing.T) {
	seed := make([]byte, 8)
	rand.Read(seed)
	port := crypto.ComputeDynamicPortWithWindow(seed, 600)

	modes := []string{"udp", "afpacket", "pcap", "windivert"}
	for _, mode := range modes {
		s, err := NewSniffer(mode, []string{"127.0.0.1"}, port)
		if err != nil {
			t.Errorf("NewSniffer(%s, port=%d): %v", mode, port, err)
			continue
		}
		if s == nil {
			t.Errorf("NewSniffer(%s, port=%d) returned nil", mode, port)
		}
	}
}

// TestSnifferCreationAtMultipleDynamicPorts simulates port rotation:
// create a sniffer, stop it, create a new one at a different port.
func TestSnifferCreationAtMultipleDynamicPorts(t *testing.T) {
	ports := []int{10000, 20000, 30000, 45678, 64999}

	for _, port := range ports {
		s, err := NewSniffer("udp", []string{"127.0.0.1"}, port)
		if err != nil {
			t.Fatalf("NewSniffer(udp, port=%d): %v", port, err)
		}
		// Verify it was created at the right port
		if udp, ok := s.(*UDPSniffer); ok {
			expectedAddr := "127.0.0.1:" + itoa(port)
			if udp.Address != expectedAddr {
				t.Errorf("sniffer address = %q, want %q", udp.Address, expectedAddr)
			}
		}
	}
}

// TestPortRotationUDPSniffer simulates a full port rotation cycle:
// start sniffer on port A, stop it, start on port B.
func TestPortRotationUDPSniffer(t *testing.T) {
	seed := make([]byte, 8)
	rand.Read(seed)

	portA := 10000 + int(seed[0])%100 + 1
	portB := portA + 1000

	// Create and start sniffer A
	snifferA := NewUDPSniffer("127.0.0.1", portA)
	errCh := make(chan error, 1)
	go func() {
		errCh <- snifferA.Start(func(data []byte, srcIP string) {
			// handler - not relevant for this test
		})
	}()

	// Give it time to start
	time.Sleep(100 * time.Millisecond)

	// Stop sniffer A
	snifferA.Stop()

	// Wait for Start to return
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("snifferA.Start returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("snifferA.Start did not return after Stop")
	}

	// Create and start sniffer B on different port
	snifferB := NewUDPSniffer("127.0.0.1", portB)
	errCh2 := make(chan error, 1)
	go func() {
		errCh2 <- snifferB.Start(func(data []byte, srcIP string) {})
	}()

	time.Sleep(100 * time.Millisecond)
	snifferB.Stop()

	select {
	case err := <-errCh2:
		if err != nil {
			t.Fatalf("snifferB.Start returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("snifferB.Start did not return after Stop")
	}
}

// TestDynPortWindowBoundary tests edge cases for window values.
func TestDynPortWindowBoundary(t *testing.T) {
	seed := make([]byte, 8)
	rand.Read(seed)

	// Minimum window (60s)
	port60 := crypto.ComputeDynamicPortWithWindow(seed, 60)
	if port60 < 10000 || port60 > 64999 {
		t.Errorf("window=60: port %d out of range", port60)
	}

	// Maximum window (86400s = 1 day)
	port86400 := crypto.ComputeDynamicPortWithWindow(seed, 86400)
	if port86400 < 10000 || port86400 > 64999 {
		t.Errorf("window=86400: port %d out of range", port86400)
	}

	// Window=1 (edge case - very fast rotation)
	port1 := crypto.ComputeDynamicPortWithWindow(seed, 1)
	if port1 < 10000 || port1 > 64999 {
		t.Errorf("window=1: port %d out of range", port1)
	}
}

// Helpers

func itoa(n int) string {
	return fmt.Sprintf("%d", n)
}
