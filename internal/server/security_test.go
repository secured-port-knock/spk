// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package server

import (
	"testing"
)

func TestParsePortSpecPortRange(t *testing.T) {
	tests := []struct {
		spec    string
		wantErr bool
	}{
		{"t0", true},      // Port 0 invalid
		{"t1", false},     // Min valid port
		{"t65535", false}, // Max valid port
		{"t65536", true},  // Over max
		{"t99999", true},  // Way over max
		{"t100000", true}, // 6 digits
		{"t999999", true}, // Too long spec
		{"t22", false},    // Normal
		{"u53", false},    // Normal UDP
	}

	for _, tt := range tests {
		_, _, err := parsePortSpec(tt.spec)
		if tt.wantErr && err == nil {
			t.Errorf("parsePortSpec(%q) expected error", tt.spec)
		}
		if !tt.wantErr && err != nil {
			t.Errorf("parsePortSpec(%q) unexpected error: %v", tt.spec, err)
		}
	}
}

func TestBuildCommandInjectionPrevention(t *testing.T) {
	template := "iptables -A INPUT -p tcp --dport {{PORT}} -s {{IP}} -j ACCEPT"

	tests := []struct {
		name      string
		ip        string
		port      string
		proto     string
		wantEmpty bool
	}{
		{"valid", "192.168.1.1", "22", "tcp", false},
		{"valid_ipv6", "::1", "22", "tcp", false},
		{"injection_ip_semicolon", "1.2.3.4; rm -rf /", "22", "tcp", true},
		{"injection_ip_pipe", "1.2.3.4 | cat /etc/passwd", "22", "tcp", true},
		{"injection_ip_backtick", "1.2.3.4`whoami`", "22", "tcp", true},
		{"injection_ip_dollar", "1.2.3.4$(id)", "22", "tcp", true},
		{"injection_port_letters", "1.2.3.4", "22abc", "tcp", true},
		{"injection_proto", "1.2.3.4", "22", "tcp; echo pwned", true},
		{"empty_template", "1.2.3.4", "22", "tcp", false},
		{"valid_ipv6_full", "2001:db8:0:0:0:0:0:1", "443", "tcp", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpl := template
			if tt.name == "empty_template" {
				tmpl = ""
			}
			result := BuildCommand(tmpl, tt.ip, tt.port, tt.proto)
			if tt.wantEmpty && result != "" {
				t.Errorf("BuildCommand should return empty for malicious input %q, got: %s", tt.name, result)
			}
			if !tt.wantEmpty && tt.name != "empty_template" && result == "" {
				t.Errorf("BuildCommand should not return empty for valid input %q", tt.name)
			}
		})
	}
}

func TestIsValidIPString(t *testing.T) {
	tests := []struct {
		ip    string
		valid bool
	}{
		{"192.168.1.1", true},
		{"10.0.0.1", true},
		{"::1", true},
		{"2001:db8::1", true},
		{"fe80::1", true},
		{"", false},
		{"abc; rm -rf /", false},
		{"192.168.1.1; whoami", false},
		{"10.0.0.1`id`", false},
		{"1.2.3.4$(cat /etc/passwd)", false},
	}

	for _, tt := range tests {
		got := isValidIPString(tt.ip)
		if got != tt.valid {
			t.Errorf("isValidIPString(%q) = %v, want %v", tt.ip, got, tt.valid)
		}
	}
}

// TestValidateCommandServerCaseInsensitive verifies that validateCommandServer
// accepts uppercase variants of open-/close- prefixes and protocol letters
// (t for TCP, u for UDP), since command strings may arrive in any case.
func TestValidateCommandServerCaseInsensitive(t *testing.T) {
	tests := []struct {
		cmd      string
		wantErr  bool
		wantType string // expected command type ("open", "close", "cust", "")
	}{
		// Lowercase (canonical forms)
		{"open-t22", false, "open"},
		{"open-u53", false, "open"},
		{"close-t443", false, "close"},
		{"close-all", false, "close"},
		{"cust-ping", false, "cust"},
		// Uppercase prefix
		{"OPEN-t22", false, "open"},
		{"CLOSE-t443", false, "close"},
		{"OPEN-ALL", false, "open"},
		{"CLOSE-ALL", false, "close"},
		// Mixed prefix case
		{"Open-t22", false, "open"},
		{"Close-T443", false, "close"},
		// Uppercase protocol letter
		{"open-T22", false, "open"},
		{"open-U53", false, "open"},
		{"close-T443", false, "close"},
		{"close-U53", false, "close"},
		// All uppercase
		{"OPEN-T22", false, "open"},
		{"CLOSE-U53", false, "close"},
		// Batch with mixed case
		{"open-T22,U53", false, "open"},
		{"OPEN-t22,T443,u53", false, "open"},
		{"close-T22,u443", false, "close"},
		// Invalid commands
		{"xxx-t22", true, ""},
		{"open-", true, ""},
		{"close-", true, ""},
		{"open-t0", true, ""},
		{"open-t99999", true, ""},
	}

	for _, tc := range tests {
		cmdType, _, err := validateCommandServer(tc.cmd)
		gotErr := err != nil
		if gotErr != tc.wantErr {
			t.Errorf("validateCommandServer(%q) err=%v, wantErr=%v", tc.cmd, err, tc.wantErr)
			continue
		}
		if !tc.wantErr && cmdType != tc.wantType {
			t.Errorf("validateCommandServer(%q) type=%q, want %q", tc.cmd, cmdType, tc.wantType)
		}
	}
}
