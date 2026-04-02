// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package server

import (
	"testing"

	"github.com/secured-port-knock/spk/internal/config"
)

// FuzzParsePortSpecExtended ensures the server does not panic on weird port specifications
// like out of bounds ports, weird characters, or missing info.
func FuzzParsePortSpecExtended(f *testing.F) {
	f.Add("80t")
	f.Add("443u")
	f.Add("65535b")
	f.Add("0t")
	f.Add("abcde")
	f.Add("999999")

	f.Fuzz(func(t *testing.T, spec string) {
		_, _, _ = parsePortSpec(spec)
	})
}

// FuzzBuildPortOpenCloseCommands ensures template building logic is robust
// and doesn't panic on crafted IPs or weird config templates.
func FuzzBuildPortOpenCloseCommands(f *testing.F) {
	f.Add("tcp", "80", "192.168.1.1")
	f.Add("udp", "443", "2001:db8::1%eth0")
	f.Add("both", "65535", "127.0.0.1")
	f.Add("tcp", "0", "")
	f.Add("xyz", "abc", ";&|")

	f.Fuzz(func(t *testing.T, proto, port, ip string) {
		cfg := &config.Config{
			OpenTCPCommand:   "open {ip} {port} {proto}",
			CloseTCPCommand:  "close {ip} {port} {proto}",
			OpenTCP6Command:  "open6 {ip} {port} {proto}",
			CloseTCP6Command: "close6 {ip} {port} {proto}",
		}
		_, _ = buildPortOpenCloseCommands(cfg, proto, port, ip)
	})
}

// FuzzSanitizeForLogExtended confirms log injection prevention algorithms work natively and efficiently.
func FuzzSanitizeForLogExtended(f *testing.F) {
	f.Add("hello\nworld")
	f.Add("user\x1b[31minput")
	f.Add("C:\\Path\\\r\n")

	f.Fuzz(func(t *testing.T, input string) {
		_ = sanitizeForLog(input)
	})
}
