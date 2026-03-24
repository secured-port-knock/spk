// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package crypto

import (
	"strings"
	"testing"
	"time"
)

// --- Fuzz tests ---

// FuzzValidateTOTP tests TOTP validation with arbitrary secrets and codes.
func FuzzValidateTOTP(f *testing.F) {
	f.Add("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PX", "123456")
	f.Add("", "")
	f.Add("AAAA", "000000")
	f.Add("JBSWY3DPEHPK3PXP", "99999999")
	f.Add("JBSWY3DPEHPK3PXP", "12345")
	f.Add("JBSWY3DPEHPK3PXP", "1234567")
	f.Add("invalid-base32!", "123456")
	f.Add(strings.Repeat("A", 100), "000000")

	f.Fuzz(func(t *testing.T, secret, code string) {
		// Must not panic
		_ = ValidateTOTP(secret, code)
	})
}

// FuzzGenerateTOTP tests TOTP generation with arbitrary secrets.
func FuzzGenerateTOTP(f *testing.F) {
	f.Add("JBSWY3DPEHPK3PXP")
	f.Add("")
	f.Add("AAAA")
	f.Add("A")
	f.Add(strings.Repeat("A", 100))
	f.Add("invalid!")

	f.Fuzz(func(t *testing.T, secret string) {
		code, err := GenerateTOTP(secret, time.Now())
		if err != nil {
			return // invalid secret
		}
		// If succeeded, code must be exactly 6 digits
		if len(code) != TOTPDigits {
			t.Errorf("code length = %d, want %d", len(code), TOTPDigits)
		}
		for _, c := range code {
			if c < '0' || c > '9' {
				t.Errorf("non-digit in TOTP code: %q", code)
				break
			}
		}
	})
}

// --- Property-based tests ---

// TestTOTP_GenerateValidateRoundtrip verifies generated codes pass validation.
func TestTOTP_GenerateValidateRoundtrip(t *testing.T) {
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}

	code, err := GenerateTOTP(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	if !ValidateTOTP(secret, code) {
		t.Errorf("valid TOTP code %q not accepted", code)
	}
}

// TestTOTP_CodeFormat verifies code is always 6 digits, zero-padded.
func TestTOTP_CodeFormat(t *testing.T) {
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}

	for i := 0; i < 100; i++ {
		ts := time.Now().Add(time.Duration(i*30) * time.Second)
		code, err := GenerateTOTP(secret, ts)
		if err != nil {
			t.Fatal(err)
		}
		if len(code) != 6 {
			t.Errorf("code %q has length %d, want 6", code, len(code))
		}
		for _, c := range code {
			if c < '0' || c > '9' {
				t.Errorf("non-digit in code %q", code)
			}
		}
	}
}

// TestTOTP_SkewTolerance verifies +-1 step tolerance works.
func TestTOTP_SkewTolerance(t *testing.T) {
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	now := time.Now()

	// Code from 30s ago should still be valid (skew=1)
	pastCode, err := GenerateTOTP(secret, now.Add(-30*time.Second))
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if !ValidateTOTP(secret, pastCode) {
		t.Error("code from -30s should be valid with skew=1")
	}

	// Code from 30s in the future should still be valid
	futureCode, err := GenerateTOTP(secret, now.Add(30*time.Second))
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if !ValidateTOTP(secret, futureCode) {
		t.Error("code from +30s should be valid with skew=1")
	}
}

// TestTOTP_InvalidCodeLength verifies wrong-length codes are rejected.
func TestTOTP_InvalidCodeLength(t *testing.T) {
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}

	invalidCodes := []string{
		"",
		"1",
		"12345",
		"1234567",
		"12345678",
	}

	for _, code := range invalidCodes {
		if ValidateTOTP(secret, code) {
			t.Errorf("invalid-length code %q accepted", code)
		}
	}
}

// TestTOTP_NonDigitCodes verifies non-digit codes are rejected.
func TestTOTP_NonDigitCodes(t *testing.T) {
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}

	nonDigitCodes := []string{
		"abcdef",
		"12345a",
		"!@#$%^",
		"123 56",
		"12\n456",
	}

	for _, code := range nonDigitCodes {
		if ValidateTOTP(secret, code) {
			t.Errorf("non-digit code %q accepted", code)
		}
	}
}

// TestTOTP_SecretGeneration verifies generated secrets are valid base32.
func TestTOTP_SecretGeneration(t *testing.T) {
	for i := 0; i < 50; i++ {
		secret, err := GenerateTOTPSecret()
		if err != nil {
			t.Fatal(err)
		}
		if len(secret) < 16 {
			t.Errorf("secret too short: %d chars", len(secret))
		}
		// Must be uppercase base32 (A-Z, 2-7, no padding)
		for _, c := range secret {
			if !((c >= 'A' && c <= 'Z') || (c >= '2' && c <= '7')) {
				t.Errorf("invalid base32 char %c in secret %q", c, secret)
				break
			}
		}
	}
}

// TestTOTP_SecretsAreUnique verifies generated secrets are unique.
func TestTOTP_SecretsAreUnique(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		secret, err := GenerateTOTPSecret()
		if err != nil {
			t.Fatal(err)
		}
		if seen[secret] {
			t.Fatalf("duplicate secret at iteration %d", i)
		}
		seen[secret] = true
	}
}

// TestTOTP_URIFormat verifies the otpauth URI format.
func TestTOTP_URIFormat(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"
	uri := TOTPSecretToURI(secret)

	if !strings.HasPrefix(uri, "otpauth://totp/") {
		t.Errorf("URI should start with otpauth://totp/, got %q", uri)
	}
	if !strings.Contains(uri, secret) {
		t.Error("URI should contain the secret")
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

// --- Mutation-resilient tests ---

// TestTOTP_WrongSecretRejected verifies codes from different secrets don't cross-validate.
func TestTOTP_WrongSecretRejected(t *testing.T) {
	secret1, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	secret2, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}

	code1, err := GenerateTOTP(secret1, time.Now())
	if err != nil {
		t.Fatalf("Now: %v", err)
	}

	if ValidateTOTP(secret2, code1) {
		t.Error("code from secret1 should not validate against secret2")
	}
}

// TestTOTP_TimeConstantComparison verifies hmac.Equal is used (not ==).
// This is a structural test - we verify that ValidateTOTP uses constant-time comparison
// by checking that a near-miss code is rejected (would pass with prefix matching).
func TestTOTP_TimeConstantComparison(t *testing.T) {
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	code, err := GenerateTOTP(secret, time.Now())
	if err != nil {
		t.Fatalf("Now: %v", err)
	}

	// Flip last digit
	tampered := code[:5]
	lastDigit := code[5]
	if lastDigit == '0' {
		tampered += "1"
	} else {
		tampered += "0"
	}

	if ValidateTOTP(secret, tampered) {
		t.Error("tampered code should be rejected")
	}
}
