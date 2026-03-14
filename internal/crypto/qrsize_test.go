// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package crypto

import (
	"fmt"
	"testing"

	qrcode "github.com/skip2/go-qrcode"
)

func TestQRCapacityForBundleSizes(t *testing.T) {
	// Generate a real keypair to get actual bundle sizes
	dk, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	ek := dk.EncapsulationKey()

	// Test without dynamic port (static port = smaller bundle)
	rawStatic, err := CreateExportBundleRawWithWindow(ek, 12345, true, false, true, nil, false, 3600, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Static port raw bundle: %d bytes", len(rawStatic))

	// Test with dynamic port (seed = 8 bytes more, but no port = 6 bytes less net... depends on compression)
	seed := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	rawDynamic, err := CreateExportBundleRawWithWindow(ek, 0, true, false, true, seed, true, 3600, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Dynamic port raw bundle: %d bytes", len(rawDynamic))

	// Also get b64 size for comparison
	b64Static, _ := CreateExportBundleWithWindow(ek, 12345, true, false, true, nil, false, 3600, 0)
	b64Dynamic, _ := CreateExportBundleWithWindow(ek, 0, true, false, true, seed, true, 3600, 0)
	t.Logf("Static port b64 bundle: %d chars", len(b64Static))
	t.Logf("Dynamic port b64 bundle: %d chars", len(b64Dynamic))

	// QR code capacity reference (binary mode):
	// Version 40: L=2953, M=2331, Q=1663, H=1273
	// Test each error correction level with both bundle sizes
	levels := []struct {
		name string
		ec   qrcode.RecoveryLevel
	}{
		{"Low", qrcode.Low},
		{"Medium", qrcode.Medium},
		{"Quartile", qrcode.High},
		{"High", qrcode.Highest},
	}

	for _, lvl := range levels {
		// Test raw binary (what QR would use)
		qr1, err1 := qrcode.New(string(rawStatic), lvl.ec)
		status1 := "OK"
		ver1 := 0
		if err1 != nil {
			status1 = fmt.Sprintf("FAIL: %v", err1)
		} else {
			ver1 = qr1.VersionNumber
		}

		qr2, err2 := qrcode.New(string(rawDynamic), lvl.ec)
		status2 := "OK"
		ver2 := 0
		if err2 != nil {
			status2 = fmt.Sprintf("FAIL: %v", err2)
		} else {
			ver2 = qr2.VersionNumber
		}

		t.Logf("EC=%s: static=%s (v%d, %d bytes), dynamic=%s (v%d, %d bytes)",
			lvl.name, status1, ver1, len(rawStatic), status2, ver2, len(rawDynamic))
	}
}
