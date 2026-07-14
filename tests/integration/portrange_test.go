// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package integration

import (
	"encoding/base64"
	"hash/crc32"
	"strings"
	"testing"

	"github.com/secured-port-knock/spk/internal/config"
	"github.com/secured-port-knock/spk/internal/crypto"
)

// TestPortRangeBundleProvisioningFlow exercises the full provisioning chain
// for a custom dynamic port range: server config -> exported bundle -> parsed
// bundle -> client config -> identical port on both sides, inside the
// inclusive range.
func TestPortRangeBundleProvisioningFlow(t *testing.T) {
	dk, err := crypto.GenerateKeyPair(crypto.KEM768)
	if err != nil {
		t.Fatal(err)
	}
	seed := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}

	serverCfg := &config.Config{
		DynamicPort:   true,
		PortSeed:      "1122334455667788",
		DynPortWindow: 600,
		DynPortMin:    30010,
		DynPortMax:    30020,
	}
	if errs := serverCfg.Validate(); len(errs) > 0 {
		t.Fatalf("server config validation: %v", errs)
	}

	// Server exports the bundle with its configured range.
	b64, err := crypto.CreateExportBundleWithRange(dk.EncapsulationKey(), 0,
		false, false, false, seed, true,
		3600, serverCfg.DynPortWindow, serverCfg.DynPortMin, serverCfg.DynPortMax)
	if err != nil {
		t.Fatal(err)
	}

	// Client imports the bundle.
	bundle, err := crypto.ParseExportBundle(b64, "")
	if err != nil {
		t.Fatal(err)
	}
	if bundle.DynPortMin != 30010 || bundle.DynPortMax != 30020 {
		t.Fatalf("bundle range = %d-%d, want 30010-30020", bundle.DynPortMin, bundle.DynPortMax)
	}

	// Both sides compute the port with their respective config values.
	serverPort := crypto.ComputeDynamicPortInRange(seed, serverCfg.DynPortWindow,
		serverCfg.DynPortMin, serverCfg.DynPortMax)
	clientPort := crypto.ComputeDynamicPortInRange(bundle.PortSeed, bundle.DynPortWindow,
		bundle.DynPortMin, bundle.DynPortMax)

	if serverPort != clientPort {
		t.Fatalf("port mismatch: server %d, client %d", serverPort, clientPort)
	}
	if serverPort < 30010 || serverPort > 30020 {
		t.Fatalf("port %d outside configured range 30010-30020", serverPort)
	}
}

// TestPortRangeDefaultFlow verifies a server without an explicit range
// provisions clients onto the default range, and both sides agree.
func TestPortRangeDefaultFlow(t *testing.T) {
	dk, err := crypto.GenerateKeyPair(crypto.KEM768)
	if err != nil {
		t.Fatal(err)
	}
	seed := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}

	b64, err := crypto.CreateExportBundleWithRange(dk.EncapsulationKey(), 0,
		false, false, false, seed, true, 3600, 600, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := crypto.ParseExportBundle(b64, "")
	if err != nil {
		t.Fatal(err)
	}
	if bundle.DynPortMin != crypto.DefaultDynPortMin || bundle.DynPortMax != crypto.DefaultDynPortMax {
		t.Fatalf("bundle range = %d-%d, want defaults %d-%d",
			bundle.DynPortMin, bundle.DynPortMax, crypto.DefaultDynPortMin, crypto.DefaultDynPortMax)
	}

	serverPort := crypto.ComputeDynamicPortInRange(seed, 600, 0, 0)
	clientPort := crypto.ComputeDynamicPortInRange(bundle.PortSeed, bundle.DynPortWindow,
		bundle.DynPortMin, bundle.DynPortMax)
	if serverPort != clientPort {
		t.Fatalf("port mismatch: server %d, client %d", serverPort, clientPort)
	}
}

// TestPortRangeV1BundleRejectedWithHint verifies importing a version-1 bundle
// fails with a message telling the user to re-export, not a generic parse error.
func TestPortRangeV1BundleRejectedWithHint(t *testing.T) {
	dk, err := crypto.GenerateKeyPair(crypto.KEM768)
	if err != nil {
		t.Fatal(err)
	}
	// Build a v2 static bundle, then rewrite the version byte to 1 and fix the
	// CRC so only the version check can reject it.
	raw, err := crypto.CreateExportBundleRawWithRange(dk.EncapsulationKey(), 12345,
		false, false, false, nil, false, 3600, 0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	raw[3] = 1
	c := crc32.ChecksumIEEE(raw[:len(raw)-4])
	raw[len(raw)-4] = byte(c >> 24)
	raw[len(raw)-3] = byte(c >> 16)
	raw[len(raw)-2] = byte(c >> 8)
	raw[len(raw)-1] = byte(c)

	_, err = crypto.ParseExportBundle(base64.StdEncoding.EncodeToString(raw), "")
	if err == nil {
		t.Fatal("v1 bundle must be rejected")
	}
	if !strings.Contains(err.Error(), "no longer supported") ||
		!strings.Contains(err.Error(), "--export") {
		t.Errorf("v1 rejection must tell the user to re-export, got: %v", err)
	}
}
