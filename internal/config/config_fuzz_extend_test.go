// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package config

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzParseTOML checks the config deserialization to ensure it handles random
// TOML files or garbled data without panicking.
func FuzzParseTOML(f *testing.F) {
	f.Add([]byte(`mode = "server"`))
	f.Add([]byte(`mode = "client"`))
	f.Add([]byte(`invalid_key = "value"`))
	f.Add([]byte("[server]\nport = 123"))

	f.Fuzz(func(t *testing.T, data []byte) {
		tmpDir := t.TempDir()
		configFile := filepath.Join(tmpDir, "fuzz_test.toml")
		if err := os.WriteFile(configFile, data, 0644); err != nil {
			t.Skipf("Failed writing file: %v", err)
		}
		// Simply call Load to verify it doesn't cause a panic.
		_, _ = Load(configFile)
	})
}
