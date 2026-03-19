// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package client

import "testing"

// TestValidateDurationForCommand verifies that --duration is rejected for
// non-open commands and accepted for all open- variants.
func TestValidateDurationForCommand(t *testing.T) {
	tests := []struct {
		cmd      string
		duration int
		wantErr  bool
	}{
		// open- commands: duration is valid
		{"open-t22", 3600, false},
		{"open-t443", 7200, false},
		{"open-u53", 1800, false},
		{"open-all", 3600, false},
		{"open-t22,t443,u53", 3600, false},
		{"OPEN-t22", 3600, false}, // case-insensitive check

		// zero duration: always valid regardless of command type
		{"open-t22", 0, false},
		{"close-t22", 0, false},
		{"cust-1", 0, false},

		// close- commands: duration must be rejected
		{"close-t22", 3600, true},
		{"close-t443", 7200, true},
		{"close-u53", 1800, true},
		{"close-all", 3600, true},
		{"close-t22,t443", 3600, true},

		// cust- commands: duration must be rejected
		{"cust-1", 3600, true},
		{"cust-ping", 7200, true},
		{"cust-restart_ssh", 60, true},
	}

	for _, tc := range tests {
		err := validateDurationForCommand(tc.cmd, tc.duration)
		if (err != nil) != tc.wantErr {
			t.Errorf("validateDurationForCommand(%q, %d) err=%v, wantErr=%v",
				tc.cmd, tc.duration, err, tc.wantErr)
		}
	}
}
