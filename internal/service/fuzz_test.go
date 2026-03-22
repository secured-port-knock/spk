// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package service

import (
	"strings"
	"testing"
)

func FuzzSanitizeServiceLabel(f *testing.F) {
	seeds := []string{
		"",
		"Production",
		"hello world!",
		"prod-1",
		"  space label  ",
		"CAPS_and-mixed 123",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, in string) {
		out := sanitizeServiceLabel(in)

		// Sanitized labels should be idempotent.
		if out != sanitizeServiceLabel(out) {
			t.Fatalf("sanitizeServiceLabel is not idempotent: in=%q out=%q", in, out)
		}

		// Output must be lowercase and restricted to [a-z0-9_-].
		if out != strings.ToLower(out) {
			t.Fatalf("output is not lowercase: %q", out)
		}
		for _, r := range out {
			if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_') {
				t.Fatalf("invalid rune %q in output %q", r, out)
			}
		}
	})
}
