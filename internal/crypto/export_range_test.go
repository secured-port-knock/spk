// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package crypto

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"math"
	"testing"
)

var rangeTestSeed = []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

// TestBundleRangeRoundTrip verifies the inclusive dynamic port range survives
// encode -> parse for both KEM sizes.
func TestBundleRangeRoundTrip(t *testing.T) {
	for _, kem := range []KEMSize{KEM768, KEM1024} {
		dk, err := GenerateKeyPair(kem)
		if err != nil {
			t.Fatalf("KEM-%d keypair: %v", kem, err)
		}
		b64, err := CreateExportBundleWithRange(dk.EncapsulationKey(), 0, false, false, false,
			rangeTestSeed, true, 3600, 600, 30010, 30020)
		if err != nil {
			t.Fatalf("KEM-%d create: %v", kem, err)
		}
		bundle, err := ParseExportBundle(b64, "")
		if err != nil {
			t.Fatalf("KEM-%d parse: %v", kem, err)
		}
		if bundle.DynPortMin != 30010 || bundle.DynPortMax != 30020 {
			t.Errorf("KEM-%d: range = %d-%d, want 30010-30020", kem, bundle.DynPortMin, bundle.DynPortMax)
		}
		if !bundle.DynamicPort || !bytes.Equal(bundle.PortSeed, rangeTestSeed) {
			t.Errorf("KEM-%d: dynamic port fields lost in round trip", kem)
		}
	}
}

// TestBundleDynamicAlwaysCarriesRange verifies every v2 dynamic-port bundle
// contains the range field, with unset input encoded as the defaults.
func TestBundleDynamicAlwaysCarriesRange(t *testing.T) {
	dk, err := GenerateKeyPair(KEM768)
	if err != nil {
		t.Fatal(err)
	}
	ek := dk.EncapsulationKey()

	unset, err := CreateExportBundleRawWithRange(ek, 0, false, false, false, rangeTestSeed, true, 3600, 600, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	explicit, err := CreateExportBundleRawWithRange(ek, 0, false, false, false, rangeTestSeed, true, 3600, 600,
		DefaultDynPortMin, DefaultDynPortMax)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(unset, explicit) {
		t.Error("unset range must encode identically to the explicit defaults")
	}

	bundle, err := ParseExportBundleRaw(unset, "")
	if err != nil {
		t.Fatal(err)
	}
	if bundle.DynPortMin != DefaultDynPortMin || bundle.DynPortMax != DefaultDynPortMax {
		t.Errorf("parsed range = %d-%d, want defaults %d-%d",
			bundle.DynPortMin, bundle.DynPortMax, DefaultDynPortMin, DefaultDynPortMax)
	}
}

// TestBundleV2WireLayout verifies the range bytes sit directly after the flags,
// ahead of the seed: magic(3) + ver(1) + flags(1) = offset 5.
func TestBundleV2WireLayout(t *testing.T) {
	dk, err := GenerateKeyPair(KEM768)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := CreateExportBundleRawWithRange(dk.EncapsulationKey(), 0, false, false, false,
		rangeTestSeed, true, 3600, 600, 30010, 30020)
	if err != nil {
		t.Fatal(err)
	}
	if raw[3] != 2 {
		t.Fatalf("version byte = %d, want 2", raw[3])
	}
	if raw[4] != 0x08 {
		t.Fatalf("flags = 0x%02x, want 0x08 (dynamic only)", raw[4])
	}
	gotMin := int(binary.BigEndian.Uint16(raw[5:7]))
	gotMax := int(binary.BigEndian.Uint16(raw[7:9]))
	if gotMin != 30010 || gotMax != 30020 {
		t.Errorf("wire range = %d-%d, want 30010-30020", gotMin, gotMax)
	}
}

// TestBundleV1Rejected verifies a version-1 bundle is rejected with the
// re-export hint even when its CRC is valid.
func TestBundleV1Rejected(t *testing.T) {
	dk, err := GenerateKeyPair(KEM768)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := CreateExportBundleRawWithRange(dk.EncapsulationKey(), 12345, false, false, false,
		nil, false, 3600, 0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	raw[3] = 1 // rewrite version to 1
	fixupCRC(raw)
	_, err = ParseExportBundleRaw(raw, "")
	if err == nil {
		t.Fatal("version 1 bundle must be rejected")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("no longer supported")) {
		t.Errorf("v1 rejection should hint at re-export, got: %v", err)
	}
}

// TestBundleUnknownVersionRejected verifies future/garbage versions error out.
func TestBundleUnknownVersionRejected(t *testing.T) {
	dk, err := GenerateKeyPair(KEM768)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := CreateExportBundleRawWithRange(dk.EncapsulationKey(), 12345, false, false, false,
		nil, false, 3600, 0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []byte{0, 3, 99} {
		bad := append([]byte(nil), raw...)
		bad[3] = v
		fixupCRC(bad)
		if _, err := ParseExportBundleRaw(bad, ""); err == nil {
			t.Errorf("version %d bundle must be rejected", v)
		}
	}
}

// TestBundleUnknownFlagBitsRejected verifies reserved flag bits (4-7) cause
// rejection.
func TestBundleUnknownFlagBitsRejected(t *testing.T) {
	dk, err := GenerateKeyPair(KEM768)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := CreateExportBundleRawWithRange(dk.EncapsulationKey(), 12345, false, false, false,
		nil, false, 3600, 0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, bit := range []byte{0x10, 0x20, 0x40, 0x80} {
		bad := append([]byte(nil), raw...)
		bad[4] |= bit
		fixupCRC(bad)
		if _, err := ParseExportBundleRaw(bad, ""); err == nil {
			t.Errorf("flag bit 0x%02x must be rejected", bit)
		}
	}
}

// TestBundleEncryptedRangeRoundTrip verifies the range survives the encrypted
// (SPKE) wrapper in both base64 and raw forms.
func TestBundleEncryptedRangeRoundTrip(t *testing.T) {
	dk, err := GenerateKeyPair(KEM768)
	if err != nil {
		t.Fatal(err)
	}
	ek := dk.EncapsulationKey()
	const pw = "correct horse battery staple"

	b64, err := CreateEncryptedExportBundleWithRange(ek, 0, false, false, false, pw,
		rangeTestSeed, true, 3600, 600, 20000, 20100)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := ParseExportBundle(b64, pw)
	if err != nil {
		t.Fatalf("parse encrypted: %v", err)
	}
	if bundle.DynPortMin != 20000 || bundle.DynPortMax != 20100 {
		t.Errorf("encrypted b64 range = %d-%d, want 20000-20100", bundle.DynPortMin, bundle.DynPortMax)
	}

	raw, err := CreateEncryptedExportBundleRawWithRange(ek, 0, false, false, false, pw,
		rangeTestSeed, true, 3600, 600, 20000, 20100)
	if err != nil {
		t.Fatal(err)
	}
	bundle2, err := ParseExportBundleRaw(raw, pw)
	if err != nil {
		t.Fatalf("parse encrypted raw: %v", err)
	}
	if bundle2.DynPortMin != 20000 || bundle2.DynPortMax != 20100 {
		t.Errorf("encrypted raw range = %d-%d, want 20000-20100", bundle2.DynPortMin, bundle2.DynPortMax)
	}
}

// TestBundleRangeCRCStillEnforced verifies corruption of the range bytes is
// caught by the CRC32 trailer.
func TestBundleRangeCRCStillEnforced(t *testing.T) {
	dk, err := GenerateKeyPair(KEM768)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := CreateExportBundleRawWithRange(dk.EncapsulationKey(), 0, false, false, false,
		rangeTestSeed, true, 3600, 600, 30010, 30020)
	if err != nil {
		t.Fatal(err)
	}
	raw[6] ^= 0xFF // corrupt a range byte
	if _, err := ParseExportBundleRaw(raw, ""); err == nil {
		t.Error("corrupted range bytes must fail CRC verification")
	}
}

// TestBundleMalformedRangeRejected verifies a bundle whose range field is
// internally inconsistent (min >= max) is rejected even with a valid CRC.
func TestBundleMalformedRangeRejected(t *testing.T) {
	dk, err := GenerateKeyPair(KEM768)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := CreateExportBundleRawWithRange(dk.EncapsulationKey(), 0, false, false, false,
		rangeTestSeed, true, 3600, 600, 30010, 30020)
	if err != nil {
		t.Fatal(err)
	}
	// min = 40000, max = 30000 (inverted)
	binary.BigEndian.PutUint16(raw[5:7], 40000)
	binary.BigEndian.PutUint16(raw[7:9], 30000)
	fixupCRC(raw)
	if _, err := ParseExportBundleRaw(raw, ""); err == nil {
		t.Error("bundle with min >= max must be rejected")
	}
}

// TestBundleTruncatedAtRangeRejected verifies a dynamic bundle truncated inside
// the range field fails to parse.
func TestBundleTruncatedAtRangeRejected(t *testing.T) {
	dk, err := GenerateKeyPair(KEM768)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := CreateExportBundleRawWithRange(dk.EncapsulationKey(), 0, false, false, false,
		rangeTestSeed, true, 3600, 600, 30010, 30020)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseExportBundleRaw(raw[:7], ""); err == nil {
		t.Error("bundle truncated inside range field must be rejected")
	}
}

// TestBundleRangeStaticPortOmitted verifies static-port bundles carry no range
// field (range is meaningless without rotation).
func TestBundleRangeStaticPortOmitted(t *testing.T) {
	dk, err := GenerateKeyPair(KEM768)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := CreateExportBundleRawWithRange(dk.EncapsulationKey(), 12345, false, false, false,
		nil, false, 3600, 0, 30010, 30020)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := ParseExportBundleRaw(raw, "")
	if err != nil {
		t.Fatal(err)
	}
	if bundle.DynPortMin != 0 || bundle.DynPortMax != 0 {
		t.Errorf("static-port bundle range = %d-%d, want unset", bundle.DynPortMin, bundle.DynPortMax)
	}
	// Layout check: magic(3)+ver(1)+flags(1)+port(2)+duration(4)+window(4)+kem(2)+ek(1184)+crc(4)
	wantLen := 3 + 1 + 1 + 2 + 4 + 4 + 2 + 1184 + 4
	if len(raw) != wantLen {
		t.Errorf("static bundle length = %d, want %d (no range field)", len(raw), wantLen)
	}
}

// TestBundleFieldExceedingWireBoundsRejected verifies the checked narrowings
// reject values that do not fit their wire field instead of silently
// truncating them.
func TestBundleFieldExceedingWireBoundsRejected(t *testing.T) {
	dk, err := GenerateKeyPair(KEM768)
	if err != nil {
		t.Fatal(err)
	}
	ek := dk.EncapsulationKey()

	cases := []struct {
		name                   string
		port, duration, window int
	}{
		{"static port over uint16", 70000, 3600, 0},
		{"open duration over uint32", 1234, math.MaxUint32 + 1, 0},
		{"port window over uint32", 0, 3600, math.MaxUint32 + 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CreateExportBundleRawWithRange(ek, tc.port, false, false, false,
				nil, false, tc.duration, tc.window, 0, 0)
			if err == nil {
				t.Errorf("%s must be rejected, not truncated on the wire", tc.name)
			}
		})
	}
}

// fixupCRC recomputes and rewrites the CRC32 trailer after test mutations.
func fixupCRC(raw []byte) {
	c := crc32.ChecksumIEEE(raw[:len(raw)-4])
	raw[len(raw)-4] = byte(c >> 24)
	raw[len(raw)-3] = byte(c >> 16)
	raw[len(raw)-2] = byte(c >> 8)
	raw[len(raw)-1] = byte(c)
}
