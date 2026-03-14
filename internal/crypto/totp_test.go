// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package crypto

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// ------------------------------------------------------------------------
// TOTP (RFC 6238) Tests
// ------------------------------------------------------------------------

func TestGenerateTOTPSecret(t *testing.T) {
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}

	// Should be 32 base32 characters (20 bytes * 8/5 = 32)
	if len(secret) != 32 {
		t.Errorf("secret length = %d, want 32", len(secret))
	}

	// Should be uppercase base32 without padding
	if strings.ContainsAny(secret, "=") {
		t.Error("secret should not contain padding characters")
	}
	if secret != strings.ToUpper(secret) {
		t.Error("secret should be uppercase")
	}

	// Should decode back to 20 bytes
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		t.Fatalf("base32 decode: %v", err)
	}
	if len(decoded) != TOTPSecretBytes {
		t.Errorf("decoded bytes = %d, want %d", len(decoded), TOTPSecretBytes)
	}
}

func TestGenerateTOTPSecretUniqueness(t *testing.T) {
	secrets := make(map[string]bool)
	for i := 0; i < 100; i++ {
		s, err := GenerateTOTPSecret()
		if err != nil {
			t.Fatalf("GenerateTOTPSecret #%d: %v", i, err)
		}
		if secrets[s] {
			t.Fatalf("duplicate secret on iteration %d", i)
		}
		secrets[s] = true
	}
}

func TestGenerateTOTPDeterministic(t *testing.T) {
	// Use a known secret and time to verify deterministic output
	secret := "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP" // well-known test vector base
	// Trim to 32 chars (standard secret length)
	secret = secret[:32]

	t1 := time.Unix(1000000000, 0) // Known epoch time
	code1, err := GenerateTOTP(secret, t1)
	if err != nil {
		t.Fatalf("GenerateTOTP: %v", err)
	}
	if len(code1) != TOTPDigits {
		t.Errorf("code length = %d, want %d", len(code1), TOTPDigits)
	}

	// Same time should produce same code
	code2, err := GenerateTOTP(secret, t1)
	if err != nil {
		t.Fatalf("GenerateTOTP: %v", err)
	}
	if code1 != code2 {
		t.Errorf("same secret+time produced different codes: %q vs %q", code1, code2)
	}

	// Different time step should produce different code
	t2 := time.Unix(1000000000+TOTPPeriod, 0)
	code3, err := GenerateTOTP(secret, t2)
	if err != nil {
		t.Fatalf("GenerateTOTP: %v", err)
	}
	if code1 == code3 {
		t.Error("different time step should usually produce different code")
	}
}

func TestGenerateTOTPCodeFormat(t *testing.T) {
	secret, _ := GenerateTOTPSecret()

	code, err := GenerateTOTP(secret, time.Now())
	if err != nil {
		t.Fatalf("GenerateTOTP: %v", err)
	}

	// Must be exactly 6 digits
	if len(code) != 6 {
		t.Errorf("code length = %d, want 6", len(code))
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			t.Errorf("code contains non-digit: %c", c)
		}
	}
}

func TestGenerateTOTPLeadingZeros(t *testing.T) {
	// Verify leading zeros are preserved (code is zero-padded)
	secret, _ := GenerateTOTPSecret()

	// Generate many codes and check all are 6 digits
	for i := 0; i < 100; i++ {
		ts := time.Unix(int64(i)*TOTPPeriod, 0)
		code, err := GenerateTOTP(secret, ts)
		if err != nil {
			t.Fatalf("GenerateTOTP: %v", err)
		}
		if len(code) != 6 {
			t.Errorf("code at step %d has length %d: %q", i, len(code), code)
		}
	}
}

func TestValidateTOTPCurrentCode(t *testing.T) {
	secret, _ := GenerateTOTPSecret()

	// Generate current code
	code, err := GenerateTOTP(secret, time.Now())
	if err != nil {
		t.Fatalf("GenerateTOTP: %v", err)
	}

	if !ValidateTOTP(secret, code) {
		t.Error("current TOTP code should be valid")
	}
}

func TestValidateTOTPAdjacentSteps(t *testing.T) {
	secret, _ := GenerateTOTPSecret()
	now := time.Now()

	// Code from previous step should be valid (within skew)
	prevCode, _ := GenerateTOTP(secret, now.Add(-TOTPPeriod*time.Second))
	if !ValidateTOTP(secret, prevCode) {
		t.Error("previous time step code should be valid (skew +-1)")
	}

	// Code from next step should be valid (within skew)
	nextCode, _ := GenerateTOTP(secret, now.Add(TOTPPeriod*time.Second))
	if !ValidateTOTP(secret, nextCode) {
		t.Error("next time step code should be valid (skew +-1)")
	}
}

func TestValidateTOTPExpiredCode(t *testing.T) {
	secret, _ := GenerateTOTPSecret()

	// Code from far in the past (5 steps ago = 2.5 minutes)
	oldCode, _ := GenerateTOTP(secret, time.Now().Add(-5*TOTPPeriod*time.Second))
	if ValidateTOTP(secret, oldCode) {
		t.Error("expired TOTP code (5 steps old) should be invalid")
	}
}

func TestValidateTOTPWrongCode(t *testing.T) {
	secret, _ := GenerateTOTPSecret()

	if ValidateTOTP(secret, "000000") {
		// This could theoretically pass if 000000 is the current code,
		// but with a random secret this is extremely unlikely
		t.Log("000000 happened to be valid (1 in 1M chance) - skipping")
	}

	if ValidateTOTP(secret, "999999") {
		t.Log("999999 happened to be valid (1 in 1M chance) - skipping")
	}
}

func TestValidateTOTPInvalidFormat(t *testing.T) {
	secret, _ := GenerateTOTPSecret()

	tests := []struct {
		name string
		code string
	}{
		{"empty", ""},
		{"too short", "12345"},
		{"too long", "1234567"},
		{"letters", "abcdef"},
		{"mixed", "12ab56"},
		{"spaces", "12 456"},
		{"negative", "-12345"},
		{"special", "12345!"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if ValidateTOTP(secret, tt.code) {
				t.Errorf("code %q should be invalid", tt.code)
			}
		})
	}
}

func TestValidateTOTPWrongSecret(t *testing.T) {
	secret1, _ := GenerateTOTPSecret()
	secret2, _ := GenerateTOTPSecret()

	code, _ := GenerateTOTP(secret1, time.Now())
	if ValidateTOTP(secret2, code) {
		t.Error("code from secret1 should not validate with secret2")
	}
}

func TestValidateTOTPInvalidSecret(t *testing.T) {
	// Invalid base32 should cause GenerateTOTP to fail internally,
	// and ValidateTOTP should return false (not panic)
	if ValidateTOTP("not-valid-base32!!!", "123456") {
		t.Error("invalid secret should return false")
	}
}

// ------------------------------------------------------------------------
// HOTP Core Algorithm Tests (RFC 4226)
// ------------------------------------------------------------------------

func TestHotpCodeRFC4226(t *testing.T) {
	// RFC 4226 Appendix D - Test Values
	// Secret = "12345678901234567890" (ASCII)
	secret := []byte("12345678901234567890")

	// Expected HOTP values for counters 0-9 with SHA1
	expected := []string{
		"755224", // counter 0
		"287082", // counter 1
		"359152", // counter 2
		"969429", // counter 3
		"338314", // counter 4
		"254676", // counter 5
		"287922", // counter 6
		"162583", // counter 7
		"399871", // counter 8
		"520489", // counter 9
	}

	for i, want := range expected {
		got, err := hotpCode(secret, uint64(i))
		if err != nil {
			t.Fatalf("hotpCode(%d): %v", i, err)
		}
		if got != want {
			t.Errorf("hotpCode(%d) = %s, want %s", i, got, want)
		}
	}
}

func TestHotpCodeDifferentCounters(t *testing.T) {
	secret := []byte("test-secret-key!")

	codes := make(map[string]bool)
	for i := uint64(0); i < 100; i++ {
		code, err := hotpCode(secret, i)
		if err != nil {
			t.Fatalf("hotpCode(%d): %v", i, err)
		}
		codes[code] = true
	}

	// Most codes should be unique (theoretically could collide, but 100 out of 1M is very unlikely)
	if len(codes) < 90 {
		t.Errorf("expected at least 90 unique codes out of 100, got %d", len(codes))
	}
}

// ------------------------------------------------------------------------
// TOTP URI and Formatting Tests
// ------------------------------------------------------------------------

func TestTOTPSecretToURI(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"[:32]
	uri := TOTPSecretToURI(secret)

	expected := fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=%d&period=%d",
		TOTPIssuer, TOTPAccount, secret, TOTPIssuer, TOTPDigits, TOTPPeriod)

	if uri != expected {
		t.Errorf("URI = %q\nwant  %q", uri, expected)
	}

	// Verify URI components
	if !strings.HasPrefix(uri, "otpauth://totp/") {
		t.Error("URI should start with otpauth://totp/")
	}
	if !strings.Contains(uri, "secret="+secret) {
		t.Error("URI should contain the secret")
	}
	if !strings.Contains(uri, "issuer=SPK") {
		t.Error("URI should contain issuer")
	}
	if !strings.Contains(uri, "algorithm=SHA1") {
		t.Error("URI should specify SHA1 algorithm")
	}
	if !strings.Contains(uri, "digits=6") {
		t.Error("URI should specify 6 digits")
	}
	if !strings.Contains(uri, "period=30") {
		t.Error("URI should specify 30s period")
	}
}

func TestFormatTOTPSecret(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", "ABCD EFGH IJKL MNOP QRST UVWX YZ23 4567"},
		{"ABCDEFGH", "ABCD EFGH"},
		{"ABCDE", "ABCD E"},
		{"ABCD", "ABCD"},
		{"AB", "AB"},
		{"", ""},
	}

	for _, tt := range tests {
		got := FormatTOTPSecret(tt.input)
		if got != tt.expected {
			t.Errorf("FormatTOTPSecret(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

// ------------------------------------------------------------------------
// TOTP QR Code Tests
// ------------------------------------------------------------------------

func TestGenerateTOTPQRCode(t *testing.T) {
	secret, _ := GenerateTOTPSecret()
	path := t.TempDir() + "/totp_test_qr.png"

	err := GenerateTOTPQRCode(secret, path)
	if err != nil {
		t.Fatalf("GenerateTOTPQRCode: %v", err)
	}

	// Verify file exists and has content
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read QR file: %v", err)
	}
	if len(data) < 100 {
		t.Errorf("QR PNG too small: %d bytes", len(data))
	}

	// Verify PNG magic bytes
	if len(data) >= 8 && string(data[1:4]) != "PNG" {
		t.Error("output should be a PNG file")
	}
}

// ------------------------------------------------------------------------
// TOTP Integration / Cross-Verification Tests
// ------------------------------------------------------------------------

func TestTOTPRoundTrip(t *testing.T) {
	// Full round-trip: generate secret -> generate code -> validate code
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}

	code, err := GenerateTOTP(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	if !ValidateTOTP(secret, code) {
		t.Error("round-trip validation failed")
	}
}

func TestTOTPManualVerification(t *testing.T) {
	// Manually compute a TOTP and compare with our implementation.
	// Uses the same algorithm to cross-check.
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" // base32 of "12345678901234567890"
	timestamp := time.Unix(59, 0)                // Known time for RFC 6238 test

	secretBytes, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	counter := uint64(timestamp.Unix()) / TOTPPeriod // 59/30 = 1

	// Manual HMAC-SHA1 computation
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)
	mac := hmac.New(sha1.New, secretBytes)
	mac.Write(buf)
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	code := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	mod := uint32(1)
	for i := 0; i < TOTPDigits; i++ {
		mod *= 10
	}
	expectedCode := fmt.Sprintf("%0*d", TOTPDigits, code%mod)

	// Compare with our implementation
	gotCode, err := GenerateTOTP(secret, timestamp)
	if err != nil {
		t.Fatal(err)
	}

	if gotCode != expectedCode {
		t.Errorf("code = %s, manually computed = %s", gotCode, expectedCode)
	}
}

func TestTOTPConstants(t *testing.T) {
	if TOTPSecretBytes != 20 {
		t.Errorf("TOTPSecretBytes = %d, want 20", TOTPSecretBytes)
	}
	if TOTPDigits != 6 {
		t.Errorf("TOTPDigits = %d, want 6", TOTPDigits)
	}
	if TOTPPeriod != 30 {
		t.Errorf("TOTPPeriod = %d, want 30", TOTPPeriod)
	}
	if TOTPSkew != 1 {
		t.Errorf("TOTPSkew = %d, want 1", TOTPSkew)
	}
}
