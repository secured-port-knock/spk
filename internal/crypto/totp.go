// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

// TOTP (RFC 6238) support for the crypto package.
//
// The secret is generated during server setup, shown as a QR code for
// authenticator apps (Google Authenticator, Authy, etc.), and verified
// on each incoming knock when TOTP is enabled.
package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"
)

const (
	// TOTPSecretBytes is the raw secret size (20 bytes = 160 bits).
	// When base32-encoded, this produces a 32-character secret.
	TOTPSecretBytes = 20

	// TOTPDigits is the number of digits in a TOTP code.
	TOTPDigits = 6

	// TOTPPeriod is the time step in seconds (standard: 30).
	TOTPPeriod = 30

	// TOTPSkew is the number of time steps to check in each direction
	// for clock drift tolerance (+-1 step = +-30 seconds).
	TOTPSkew = 1

	// TOTPIssuer is the issuer name shown in authenticator apps.
	TOTPIssuer = "SPK"

	// TOTPAccount is the account name shown in authenticator apps.
	TOTPAccount = "Server"
)

// GenerateTOTPSecret generates a random 32-character base32-encoded TOTP secret.
// Returns the base32 string (no padding) suitable for authenticator apps.
func GenerateTOTPSecret() (string, error) {
	secretBytes := make([]byte, TOTPSecretBytes)
	if _, err := io.ReadFull(rand.Reader, secretBytes); err != nil {
		return "", fmt.Errorf("generate TOTP secret: %w", err)
	}
	// Base32 encode without padding (standard for TOTP secrets)
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secretBytes)
	return strings.ToUpper(secret), nil
}

// GenerateTOTP produces a 6-digit TOTP code for the given secret at time t.
// Implements RFC 6238 with HMAC-SHA1.
func GenerateTOTP(secret string, t time.Time) (string, error) {
	secretBytes, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		return "", fmt.Errorf("decode TOTP secret: %w", err)
	}

	counter := uint64(t.Unix()) / TOTPPeriod
	return hotpCode(secretBytes, counter)
}

// ValidateTOTP checks whether the given 6-digit code is valid for the secret.
// Allows +-1 time step (+-30s) to account for clock drift.
func ValidateTOTP(secret, code string) bool {
	if len(code) != TOTPDigits {
		return false
	}
	// Verify code contains only digits
	for _, c := range code {
		if c < '0' || c > '9' {
			return false
		}
	}

	now := time.Now()
	for offset := -TOTPSkew; offset <= TOTPSkew; offset++ {
		t := now.Add(time.Duration(offset*TOTPPeriod) * time.Second)
		expected, err := GenerateTOTP(secret, t)
		if err != nil {
			continue
		}
		if hmac.Equal([]byte(expected), []byte(code)) {
			return true
		}
	}
	return false
}

// hotpCode implements HOTP (RFC 4226) - the core algorithm used by TOTP.
func hotpCode(secret []byte, counter uint64) (string, error) {
	// Encode counter as big-endian 8 bytes
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)

	// HMAC-SHA1
	mac := hmac.New(sha1.New, secret)
	mac.Write(buf)
	sum := mac.Sum(nil)

	// Dynamic truncation (RFC 4226 Section 5.3)
	offset := sum[len(sum)-1] & 0x0f
	code := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff

	// Modulo to get the desired number of digits
	mod := uint32(1)
	for i := 0; i < TOTPDigits; i++ {
		mod *= 10
	}
	code = code % mod

	return fmt.Sprintf("%0*d", TOTPDigits, code), nil
}

// TOTPSecretToURI generates an otpauth:// URI for QR code generation.
// Format: otpauth://totp/Issuer:Account?secret=SECRET&issuer=Issuer&algorithm=SHA1&digits=6&period=30
func TOTPSecretToURI(secret string) string {
	return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=%d&period=%d",
		TOTPIssuer, TOTPAccount, secret, TOTPIssuer, TOTPDigits, TOTPPeriod)
}

// GenerateTOTPQRCode generates a QR code PNG for the TOTP secret.
// The QR code encodes an otpauth:// URI that authenticator apps can scan.
func GenerateTOTPQRCode(secret, outputPath string) error {
	uri := TOTPSecretToURI(secret)
	qr, err := qrcode.New(uri, qrcode.Medium)
	if err != nil {
		return fmt.Errorf("generate TOTP QR code: %w", err)
	}
	if err := qr.WriteFile(512, outputPath); err != nil {
		return fmt.Errorf("write TOTP QR code: %w", err)
	}
	// Restrict permissions -- QR contains the TOTP shared secret.
	if err := os.Chmod(outputPath, 0600); err != nil {
		return fmt.Errorf("chmod TOTP QR file: %w", err)
	}
	return nil
}

// PrintTOTPQRToConsole prints a TOTP QR code to stdout using Unicode characters.
func PrintTOTPQRToConsole(secret string) error {
	uri := TOTPSecretToURI(secret)
	qr, err := qrcode.New(uri, qrcode.Medium)
	if err != nil {
		return fmt.Errorf("generate TOTP QR: %w", err)
	}

	art := qr.ToSmallString(false)
	if art != "" {
		fmt.Println("\n--- TOTP QR Code (scan with authenticator app) ---")
		fmt.Print(art)
		fmt.Println("--- End TOTP QR ---")
		return nil
	}

	// Fallback to ASCII
	bitmap := qr.Bitmap()
	fmt.Println("\n--- TOTP QR Code (scan with authenticator app) ---")
	for _, row := range bitmap {
		for _, cell := range row {
			if cell {
				fmt.Print("##")
			} else {
				fmt.Print("  ")
			}
		}
		fmt.Println()
	}
	fmt.Println("--- End TOTP QR ---")
	return nil
}

// FormatTOTPSecret formats a TOTP secret with spaces for human readability.
// Example: "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567" -> "ABCD EFGH IJKL MNOP QRST UVWX YZ23 4567"
func FormatTOTPSecret(secret string) string {
	var parts []string
	for i := 0; i < len(secret); i += 4 {
		end := i + 4
		if end > len(secret) {
			end = len(secret)
		}
		parts = append(parts, secret[i:end])
	}
	return strings.Join(parts, " ")
}
