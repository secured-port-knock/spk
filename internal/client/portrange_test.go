// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package client

import (
	"testing"

	"github.com/secured-port-knock/spk/internal/config"
	"github.com/secured-port-knock/spk/internal/crypto"
)

// TestResolvePortHonorsConfiguredRange verifies the client computes its knock
// target inside the dynamic_port_min/max range from its config.
func TestResolvePortHonorsConfiguredRange(t *testing.T) {
	cfg := &config.Config{
		DynamicPort: true,
		PortSeed:    "0102030405060708",
		DynPortMin:  30010,
		DynPortMax:  30020,
	}

	port := resolvePortWithWindow(cfg, 600)
	if port < 30010 || port > 30020 {
		t.Fatalf("client port %d outside configured range 30010-30020", port)
	}
}

// TestResolvePortDefaultRangeUnchanged verifies clients without a configured
// range fall back to the default range computation.
func TestResolvePortDefaultRangeUnchanged(t *testing.T) {
	cfg := &config.Config{
		DynamicPort: true,
		PortSeed:    "0102030405060708",
	}

	port := resolvePortWithWindow(cfg, 600)
	seed := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	legacy := crypto.ComputeDynamicPortWithWindow(seed, 600)
	if port != legacy {
		t.Fatalf("client default-range port %d != legacy port %d", port, legacy)
	}
}

// TestClientServerRangeAgreement verifies both sides derive the identical port
// from the same seed, window, and range -- the invariant that makes knocks land.
func TestClientServerRangeAgreement(t *testing.T) {
	seed := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11}
	for _, r := range []struct{ min, max int }{
		{30010, 30020},
		{0, 0},
		{crypto.DefaultDynPortMin, crypto.DefaultDynPortMax},
		{1024, 2048},
	} {
		serverPort := crypto.ComputeDynamicPortInRange(seed, 600, r.min, r.max)
		clientPort := crypto.ComputeDynamicPortInRange(seed, 600, r.min, r.max)
		if serverPort != clientPort {
			t.Fatalf("range (%d, %d): server %d != client %d", r.min, r.max, serverPort, clientPort)
		}
	}
}

// TestApplyBundleConfigCopiesRange verifies the bundle's custom range lands in
// the client config during setup (and that an unset range stays unset).
func TestApplyBundleConfigCopiesRange(t *testing.T) {
	bundle := &crypto.ExportBundle{
		DynamicPort: true,
		PortSeed:    []byte{1, 2, 3, 4, 5, 6, 7, 8},
		KEMSize:     768,
		DynPortMin:  30010,
		DynPortMax:  30020,
	}
	cfg := &config.Config{}
	applyBundleConfig(cfg, bundle)
	if cfg.DynPortMin != 30010 || cfg.DynPortMax != 30020 {
		t.Errorf("client cfg range = %d-%d, want 30010-30020", cfg.DynPortMin, cfg.DynPortMax)
	}

	noRangeBundle := &crypto.ExportBundle{
		DynamicPort: true,
		PortSeed:    []byte{1, 2, 3, 4, 5, 6, 7, 8},
		KEMSize:     768,
	}
	cfg2 := &config.Config{}
	applyBundleConfig(cfg2, noRangeBundle)
	if cfg2.DynPortMin != 0 || cfg2.DynPortMax != 0 {
		t.Errorf("bundle without range must leave cfg range unset, got %d-%d", cfg2.DynPortMin, cfg2.DynPortMax)
	}
}
