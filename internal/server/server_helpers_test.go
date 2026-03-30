// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package server

import (
	"testing"
	"time"

	"github.com/secured-port-knock/spk/internal/config"
	"github.com/secured-port-knock/spk/internal/crypto"
	"github.com/secured-port-knock/spk/internal/protocol"
)

// =============================================================================
// verifyTOTP
// =============================================================================

func TestVerifyTOTP_DisabledAlwaysPasses(t *testing.T) {
	logger := &captureLogger{}
	cfg := &config.Config{TOTPEnabled: false}
	payload := &protocol.KnockPayload{TOTP: ""}
	if !verifyTOTP(logger, cfg, payload, "1.2.3.4") {
		t.Error("expected verifyTOTP to return true when TOTP is disabled")
	}
	if len(logger.lines) != 0 {
		t.Error("expected no log output when TOTP is disabled")
	}
}

func TestVerifyTOTP_EnabledEmptySecretPasses(t *testing.T) {
	// TOTPEnabled but TOTPSecret empty -> treated as disabled
	logger := &captureLogger{}
	cfg := &config.Config{TOTPEnabled: true, TOTPSecret: ""}
	payload := &protocol.KnockPayload{TOTP: ""}
	if !verifyTOTP(logger, cfg, payload, "1.2.3.4") {
		t.Error("expected verifyTOTP to return true when TOTPSecret is empty")
	}
}

func TestVerifyTOTP_MissingCodeRejected(t *testing.T) {
	secret, err := crypto.GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	logger := &captureLogger{}
	cfg := &config.Config{TOTPEnabled: true, TOTPSecret: secret}
	payload := &protocol.KnockPayload{TOTP: ""}
	if verifyTOTP(logger, cfg, payload, "10.0.0.1") {
		t.Error("expected verifyTOTP to return false when TOTP code is missing")
	}
	if len(logger.lines) == 0 {
		t.Error("expected rejection log when TOTP code is missing")
	}
}

func TestVerifyTOTP_ValidCodeAccepted(t *testing.T) {
	secret, err := crypto.GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	code, err := crypto.GenerateTOTP(secret, time.Now())
	if err != nil {
		t.Fatalf("GenerateTOTP: %v", err)
	}
	logger := &captureLogger{}
	cfg := &config.Config{TOTPEnabled: true, TOTPSecret: secret}
	payload := &protocol.KnockPayload{TOTP: code}
	if !verifyTOTP(logger, cfg, payload, "10.0.0.1") {
		t.Error("expected verifyTOTP to return true for a valid TOTP code")
	}
}

func TestVerifyTOTP_WrongCodeRejected(t *testing.T) {
	secret, err := crypto.GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	logger := &captureLogger{}
	cfg := &config.Config{TOTPEnabled: true, TOTPSecret: secret}
	payload := &protocol.KnockPayload{TOTP: "000000"}
	// If 000000 happens to be valid (1-in-1M chance) this test may flake;
	// in practice the odds are negligible for a single test run.
	result := verifyTOTP(logger, cfg, payload, "10.0.0.1")
	code, _ := crypto.GenerateTOTP(secret, time.Now())
	if code == "000000" {
		t.Skip("000000 is the actual TOTP code right now; skipping flaky test window")
	}
	if result {
		t.Error("expected verifyTOTP to return false for wrong TOTP code")
	}
	if len(logger.lines) == 0 {
		t.Error("expected rejection log for wrong TOTP code")
	}
}

// =============================================================================
// resolveOpenDuration
// =============================================================================

func TestResolveOpenDuration_UseDefault(t *testing.T) {
	cfg := &config.Config{DefaultOpenDuration: 30, AllowCustomOpenDuration: false}
	got := resolveOpenDuration(cfg, 60)
	if got != 30 {
		t.Errorf("resolveOpenDuration = %d, want 30 (custom not allowed)", got)
	}
}

func TestResolveOpenDuration_ZeroRequestedUsesDefault(t *testing.T) {
	cfg := &config.Config{DefaultOpenDuration: 45, AllowCustomOpenDuration: true}
	got := resolveOpenDuration(cfg, 0)
	if got != 45 {
		t.Errorf("resolveOpenDuration = %d, want 45 for zero request", got)
	}
}

func TestResolveOpenDuration_CustomAllowedNoMax(t *testing.T) {
	cfg := &config.Config{DefaultOpenDuration: 30, AllowCustomOpenDuration: true, MaxOpenDuration: 0}
	got := resolveOpenDuration(cfg, 120)
	if got != 120 {
		t.Errorf("resolveOpenDuration = %d, want 120 (no cap)", got)
	}
}

func TestResolveOpenDuration_ClampsToMax(t *testing.T) {
	cfg := &config.Config{DefaultOpenDuration: 30, AllowCustomOpenDuration: true, MaxOpenDuration: 60}
	got := resolveOpenDuration(cfg, 300)
	if got != 60 {
		t.Errorf("resolveOpenDuration = %d, want 60 (capped at max)", got)
	}
}

func TestResolveOpenDuration_RequestedUnderMax(t *testing.T) {
	cfg := &config.Config{DefaultOpenDuration: 30, AllowCustomOpenDuration: true, MaxOpenDuration: 120}
	got := resolveOpenDuration(cfg, 90)
	if got != 90 {
		t.Errorf("resolveOpenDuration = %d, want 90 (under cap)", got)
	}
}

// =============================================================================
// buildPortOpenCloseCommands
// =============================================================================

func TestBuildPortOpenCloseCommands_IPv4TCP(t *testing.T) {
	cfg := &config.Config{
		OpenTCPCommand:  "iptables -A INPUT -p tcp --dport {{PORT}} -s {{IP}} -j ACCEPT",
		CloseTCPCommand: "iptables -D INPUT -p tcp --dport {{PORT}} -s {{IP}} -j ACCEPT",
	}
	open, close := buildPortOpenCloseCommands(cfg, "tcp", "22", "192.168.1.5")
	wantOpen := "iptables -A INPUT -p tcp --dport 22 -s 192.168.1.5 -j ACCEPT"
	wantClose := "iptables -D INPUT -p tcp --dport 22 -s 192.168.1.5 -j ACCEPT"
	if open != wantOpen {
		t.Errorf("open cmd = %q, want %q", open, wantOpen)
	}
	if close != wantClose {
		t.Errorf("close cmd = %q, want %q", close, wantClose)
	}
}

func TestBuildPortOpenCloseCommands_IPv4UDP(t *testing.T) {
	cfg := &config.Config{
		OpenUDPCommand:  "iptables -A INPUT -p udp --dport {{PORT}} -s {{IP}} -j ACCEPT",
		CloseUDPCommand: "iptables -D INPUT -p udp --dport {{PORT}} -s {{IP}} -j ACCEPT",
	}
	open, close := buildPortOpenCloseCommands(cfg, "udp", "53", "10.0.0.2")
	if open == "" || close == "" {
		t.Error("expected non-empty open/close commands for IPv4 UDP")
	}
	wantOpen := "iptables -A INPUT -p udp --dport 53 -s 10.0.0.2 -j ACCEPT"
	if open != wantOpen {
		t.Errorf("open cmd = %q, want %q", open, wantOpen)
	}
}

func TestBuildPortOpenCloseCommands_IPv6TCPFallsBackToIPv4(t *testing.T) {
	// IPv6 address but no IPv6 template -> falls back to IPv4 template
	cfg := &config.Config{
		OpenTCPCommand:  "ip4 open {{PORT}} {{IP}}",
		CloseTCPCommand: "ip4 close {{PORT}} {{IP}}",
		// OpenTCP6Command intentionally empty
	}
	open, close := buildPortOpenCloseCommands(cfg, "tcp", "443", "2001:db8::1")
	if open != "ip4 open 443 2001:db8::1" {
		t.Errorf("unexpected open cmd for IPv6 fallback: %q", open)
	}
	if close != "ip4 close 443 2001:db8::1" {
		t.Errorf("unexpected close cmd for IPv6 fallback: %q", close)
	}
}

func TestBuildPortOpenCloseCommands_IPv6TCPUsesIPv6Template(t *testing.T) {
	cfg := &config.Config{
		OpenTCPCommand:   "ip4 open {{PORT}} {{IP}}",
		CloseTCPCommand:  "ip4 close {{PORT}} {{IP}}",
		OpenTCP6Command:  "ip6 open {{PORT}} {{IP}}",
		CloseTCP6Command: "ip6 close {{PORT}} {{IP}}",
	}
	open, close := buildPortOpenCloseCommands(cfg, "tcp", "443", "2001:db8::1")
	if open != "ip6 open 443 2001:db8::1" {
		t.Errorf("expected IPv6 template; got open cmd: %q", open)
	}
	if close != "ip6 close 443 2001:db8::1" {
		t.Errorf("expected IPv6 template; got close cmd: %q", close)
	}
}

func TestBuildPortOpenCloseCommands_UnknownProto(t *testing.T) {
	cfg := &config.Config{}
	open, close := buildPortOpenCloseCommands(cfg, "icmp", "0", "1.2.3.4")
	if open != "" || close != "" {
		t.Errorf("expected empty strings for unknown proto; got open=%q close=%q", open, close)
	}
}

// =============================================================================
// buildCloseCmd
// =============================================================================

func TestBuildCloseCmd_IPv4TCP(t *testing.T) {
	cfg := &config.Config{
		CloseTCPCommand: "iptables -D INPUT -p tcp --dport {{PORT}} -s {{IP}} -j ACCEPT",
	}
	got := buildCloseCmd(cfg, "tcp", "22", "192.168.1.5")
	want := "iptables -D INPUT -p tcp --dport 22 -s 192.168.1.5 -j ACCEPT"
	if got != want {
		t.Errorf("buildCloseCmd = %q, want %q", got, want)
	}
}

func TestBuildCloseCmd_IPv4UDP(t *testing.T) {
	cfg := &config.Config{
		CloseUDPCommand: "close-udp {{PORT}} {{IP}}",
	}
	got := buildCloseCmd(cfg, "udp", "53", "10.0.0.1")
	if got == "" {
		t.Error("expected non-empty close command for IPv4 UDP")
	}
}

func TestBuildCloseCmd_IPv6UsesIPv6Template(t *testing.T) {
	cfg := &config.Config{
		CloseTCPCommand:  "ip4-close-tcp {{PORT}} {{IP}}",
		CloseTCP6Command: "ip6-close-tcp {{PORT}} {{IP}}",
	}
	got := buildCloseCmd(cfg, "tcp", "22", "::1")
	if got != "ip6-close-tcp 22 ::1" {
		t.Errorf("buildCloseCmd = %q, want ip6 template", got)
	}
}

func TestBuildCloseCmd_IPv6FallsBackToIPv4(t *testing.T) {
	cfg := &config.Config{
		CloseTCPCommand: "ip4-close-tcp {{PORT}} {{IP}}",
		// CloseTCP6Command empty
	}
	got := buildCloseCmd(cfg, "tcp", "22", "2001:db8::1")
	if got != "ip4-close-tcp 22 2001:db8::1" {
		t.Errorf("buildCloseCmd = %q, expected IPv4 fallback template", got)
	}
}

func TestBuildCloseCmd_UnknownProto(t *testing.T) {
	cfg := &config.Config{}
	got := buildCloseCmd(cfg, "icmp", "0", "1.2.3.4")
	if got != "" {
		t.Errorf("expected empty string for unknown proto; got %q", got)
	}
}

// =============================================================================
// buildOpenAllCommands
// =============================================================================

func TestBuildOpenAllCommands_IPv4(t *testing.T) {
	cfg := &config.Config{
		OpenAllCommand:  "firewall allow all from {{IP}}",
		CloseAllCommand: "firewall deny all from {{IP}}",
	}
	open, close := buildOpenAllCommands(cfg, "192.168.1.100")
	wantOpen := "firewall allow all from 192.168.1.100"
	wantClose := "firewall deny all from 192.168.1.100"
	if open != wantOpen {
		t.Errorf("open-all cmd = %q, want %q", open, wantOpen)
	}
	if close != wantClose {
		t.Errorf("close-all cmd = %q, want %q", close, wantClose)
	}
}

func TestBuildOpenAllCommands_IPv6UsesIPv6Template(t *testing.T) {
	cfg := &config.Config{
		OpenAllCommand:   "ip4-open-all {{IP}}",
		CloseAllCommand:  "ip4-close-all {{IP}}",
		OpenAll6Command:  "ip6-open-all {{IP}}",
		CloseAll6Command: "ip6-close-all {{IP}}",
	}
	open, close := buildOpenAllCommands(cfg, "2001:db8::1")
	if open != "ip6-open-all 2001:db8::1" {
		t.Errorf("open-all for IPv6 = %q, expected ip6 template", open)
	}
	if close != "ip6-close-all 2001:db8::1" {
		t.Errorf("close-all for IPv6 = %q, expected ip6 template", close)
	}
}

func TestBuildOpenAllCommands_IPv6FallsBackToIPv4(t *testing.T) {
	cfg := &config.Config{
		OpenAllCommand:  "ip4-open-all {{IP}}",
		CloseAllCommand: "ip4-close-all {{IP}}",
		// OpenAll6Command empty
	}
	open, close := buildOpenAllCommands(cfg, "::1")
	if open != "ip4-open-all ::1" {
		t.Errorf("open-all fallback = %q, expected IPv4 template", open)
	}
	if close != "ip4-close-all ::1" {
		t.Errorf("close-all fallback = %q, expected IPv4 template", close)
	}
}
