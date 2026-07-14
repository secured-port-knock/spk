// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package server

import (
	"testing"

	"github.com/secured-port-knock/spk/internal/config"
	"github.com/secured-port-knock/spk/internal/crypto"
)

// TestResolveListenPortHonorsConfiguredRange is the config-to-computation
// contract test: a server config with dynamic_port_min/max set MUST produce a
// listen port inside that range. This is the seam that was previously unwired
// (config values were validated and printed but ignored by the port math).
func TestResolveListenPortHonorsConfiguredRange(t *testing.T) {
	cfg := &config.Config{
		DynamicPort: true,
		PortSeed:    "0102030405060708",
		DynPortMin:  30010,
		DynPortMax:  30020,
	}

	listenPort, seed := resolveListenPort(cfg, 600, func(string, ...interface{}) {})
	if len(seed) != 8 {
		t.Fatalf("decoded seed length = %d, want 8", len(seed))
	}
	if listenPort < 30010 || listenPort > 30020 {
		t.Fatalf("listen port %d outside configured range 30010-30020", listenPort)
	}

	wantPort := crypto.ComputeDynamicPortInRange(seed, 600, 30010, 30020)
	if listenPort != wantPort {
		t.Fatalf("listen port %d != range computation %d", listenPort, wantPort)
	}
}

// TestResolveListenPortDefaultRangeUnchanged verifies configs without a range
// (or with the default range) keep computing the exact same port as before the
// range feature existed -- old clients depend on this.
func TestResolveListenPortDefaultRangeUnchanged(t *testing.T) {
	base := &config.Config{
		DynamicPort: true,
		PortSeed:    "0102030405060708",
	}
	withDefaults := &config.Config{
		DynamicPort: true,
		PortSeed:    "0102030405060708",
		DynPortMin:  crypto.DefaultDynPortMin,
		DynPortMax:  crypto.DefaultDynPortMax,
	}

	logf := func(string, ...interface{}) {}
	portUnset, seed := resolveListenPort(base, 600, logf)
	portDefault, _ := resolveListenPort(withDefaults, 600, logf)
	legacy := crypto.ComputeDynamicPortWithWindow(seed, 600)

	if portUnset != legacy || portDefault != legacy {
		t.Fatalf("default-range ports diverged: unset=%d explicit=%d legacy=%d",
			portUnset, portDefault, legacy)
	}
}
