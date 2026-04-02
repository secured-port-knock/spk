// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package server

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/secured-port-knock/spk/internal/config"
	"github.com/secured-port-knock/spk/internal/crypto"
	"github.com/secured-port-knock/spk/internal/sniffer"
)

type noOpSniffer struct {
	stopCalls atomic.Int32
}

func (s *noOpSniffer) Start(handler sniffer.PacketHandler) error {
	return nil
}

func (s *noOpSniffer) Stop() error {
	s.stopCalls.Add(1)
	return nil
}

func TestResolveListenPortStaticMode(t *testing.T) {
	cfg := &config.Config{
		ListenPort:  5454,
		DynamicPort: false,
	}

	listenPort, seed := resolveListenPort(cfg, 600, func(string, ...interface{}) {})
	if listenPort != 5454 {
		t.Fatalf("listen port mismatch: got %d want %d", listenPort, 5454)
	}
	if seed != nil {
		t.Fatalf("seed should be nil for static mode, got %x", seed)
	}
}

func TestResolveListenPortInvalidSeedFallsBackToStatic(t *testing.T) {
	cfg := &config.Config{
		ListenPort:  20222,
		DynamicPort: true,
		PortSeed:    "not-hex",
	}

	listenPort, seed := resolveListenPort(cfg, 600, func(string, ...interface{}) {})
	if listenPort != cfg.ListenPort {
		t.Fatalf("expected fallback to static port %d, got %d", cfg.ListenPort, listenPort)
	}
	if seed != nil {
		t.Fatalf("seed should be nil when decode fails, got %x", seed)
	}
}

func TestResolveListenPortDynamicSeedComputesPort(t *testing.T) {
	cfg := &config.Config{
		ListenPort:  9999,
		DynamicPort: true,
		PortSeed:    "0102030405060708",
	}

	window := 600
	listenPort, seed := resolveListenPort(cfg, window, func(string, ...interface{}) {})
	if len(seed) != 8 {
		t.Fatalf("decoded seed length = %d, want 8", len(seed))
	}

	wantPort := crypto.ComputeDynamicPortWithWindow(seed, window)
	if listenPort != wantPort {
		t.Fatalf("dynamic port mismatch: got %d want %d", listenPort, wantPort)
	}
}

func TestAttemptRebindInvalidModeKeepsCurrentSniffer(t *testing.T) {
	cfg := &config.Config{
		SnifferMode:     "invalid-mode",
		ListenAddresses: []string{"127.0.0.1"},
	}

	current := &noOpSniffer{}
	var currentRef sniffer.Sniffer = current
	var snifferMu sync.Mutex

	active, activePort := attemptRebind(
		cfg,
		nil,
		current,
		4000,
		5000,
		&snifferMu,
		&currentRef,
		func([]byte, string) {},
		func(string, ...interface{}) {},
	)

	if active != current {
		t.Fatal("attemptRebind should keep current sniffer when new and fallback creation fail")
	}
	if activePort != 4000 {
		t.Fatalf("attemptRebind port = %d, want 4000", activePort)
	}
	if currentRef != current {
		t.Fatal("current sniffer reference should remain unchanged")
	}
	if current.stopCalls.Load() != 1 {
		t.Fatalf("expected Stop to be called once, got %d", current.stopCalls.Load())
	}
}

func FuzzResolveListenPortNoPanic(f *testing.F) {
	f.Add(false, "", 12345, 600)
	f.Add(true, "0102030405060708", 12345, 600)
	f.Add(true, "not-hex", 54321, 300)

	f.Fuzz(func(t *testing.T, dynamic bool, seed string, listenPort int, window int) {
		if listenPort < 0 || listenPort > 65535 {
			return
		}
		if window <= 0 || window > 86400 {
			window = 600
		}

		cfg := &config.Config{
			ListenPort:  listenPort,
			DynamicPort: dynamic,
			PortSeed:    seed,
		}

		_, _ = resolveListenPort(cfg, window, func(string, ...interface{}) {})
	})
}
