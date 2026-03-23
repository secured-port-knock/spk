// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package main

import (
	"runtime/debug"
	"strings"
	"testing"

	"github.com/secured-port-knock/spk/internal/sniffer"
)

// makeBuildInfo returns a minimal *debug.BuildInfo with the given module version.
func makeBuildInfo(moduleVersion string) *debug.BuildInfo {
	return &debug.BuildInfo{
		Main: debug.Module{Version: moduleVersion},
	}
}

func TestResolveVersionFromBuildInfo_LdflagsInjected(t *testing.T) {
	// When commit != "Dev", the build scripts injected ldflags.
	// The module version from debug.BuildInfo must be ignored entirely.
	ver, label := resolveVersionFromBuildInfo("1.0.2", "1044", "abc1234", makeBuildInfo("v9.9.9"), true)
	if ver != "1.0.2.1044" {
		t.Errorf("version: got %q, want %q", ver, "1.0.2.1044")
	}
	if label != "abc1234" {
		t.Errorf("commit label: got %q, want %q", label, "abc1234")
	}
}

func TestResolveVersionFromBuildInfo_LdflagsInjected_NoBuildInfo(t *testing.T) {
	// ldflags injected, no build info available -- still uses ldflag values.
	ver, label := resolveVersionFromBuildInfo("1.0.3", "1100", "deadbeef", nil, false)
	if ver != "1.0.3.1100" {
		t.Errorf("version: got %q, want %q", ver, "1.0.3.1100")
	}
	if label != "deadbeef" {
		t.Errorf("commit label: got %q, want %q", label, "deadbeef")
	}
}

func TestResolveVersionFromBuildInfo_GoInstall_RealTag(t *testing.T) {
	// Scenario 1: go install @v1.0.2 -- commit is the sentinel ("Dev"), build
	// info carries a real semver tag. Version is the tag (v-stripped), label
	// is "Go".
	ver, label := resolveVersionFromBuildInfo("1.0.0", "0", "Dev", makeBuildInfo("v1.0.2"), true)
	if ver != "1.0.2" {
		t.Errorf("version: got %q, want %q", ver, "1.0.2")
	}
	if label != "Go" {
		t.Errorf("commit label: got %q, want %q", label, "Go")
	}
}

func TestResolveVersionFromBuildInfo_GoInstall_DevBuild(t *testing.T) {
	// Scenario 2: local 'go build' from source checkout -- commit is the
	// sentinel ("Dev"), build info shows "(devel)" (no tag). Falls back to
	// hardcoded placeholder with the sentinel as label.
	ver, label := resolveVersionFromBuildInfo("1.0.0", "0", "Dev", makeBuildInfo("(devel)"), true)
	if ver != "1.0.0.0" {
		t.Errorf("version: got %q, want %q", ver, "1.0.0.0")
	}
	if label != "Dev" {
		t.Errorf("commit label: got %q, want %q", label, "Dev")
	}
}

func TestResolveVersionFromBuildInfo_GoInstall_EmptyVersion(t *testing.T) {
	// Scenario 3: ReadBuildInfo returns ok=true but Main.Version is empty.
	// Treated as unavailable -- falls back to placeholder.
	ver, label := resolveVersionFromBuildInfo("1.0.0", "0", "Dev", makeBuildInfo(""), true)
	if ver != "1.0.0.0" {
		t.Errorf("version: got %q, want %q", ver, "1.0.0.0")
	}
	if label != "Dev" {
		t.Errorf("commit label: got %q, want %q", label, "Dev")
	}
}

func TestResolveVersionFromBuildInfo_NoBuildInfo(t *testing.T) {
	// ReadBuildInfo returns ok=false. This can happen when the binary is not
	// built with module support (rare in Go 1.11+, but still a valid code path).
	// Falls back to placeholder.
	ver, label := resolveVersionFromBuildInfo("1.0.0", "0", "Dev", nil, false)
	if ver != "1.0.0.0" {
		t.Errorf("version: got %q, want %q", ver, "1.0.0.0")
	}
	if label != "Dev" {
		t.Errorf("commit label: got %q, want %q", label, "Dev")
	}
}

func TestResolveVersionFromBuildInfo_NilBuildInfoOkTrue(t *testing.T) {
	// ok=true but info is nil (defensive: should not happen in practice).
	// Falls back to placeholder.
	ver, label := resolveVersionFromBuildInfo("1.0.0", "0", "Dev", nil, true)
	if ver != "1.0.0.0" {
		t.Errorf("version: got %q, want %q", ver, "1.0.0.0")
	}
	if label != "Dev" {
		t.Errorf("commit label: got %q, want %q", label, "Dev")
	}
}

func TestResolveVersionFromBuildInfo_StripVPrefix(t *testing.T) {
	// Ensure the "v" prefix is stripped regardless of patch digits.
	cases := []struct {
		tag  string
		want string
	}{
		{"v0.1.0", "0.1.0"},
		{"v2.3.4", "2.3.4"},
		{"v1.0.0", "1.0.0"},
	}
	for _, tc := range cases {
		ver, _ := resolveVersionFromBuildInfo("1.0.0", "0", "Dev", makeBuildInfo(tc.tag), true)
		if ver != tc.want {
			t.Errorf("tag %q: got %q, want %q", tc.tag, ver, tc.want)
		}
	}
}

// TestPcapLabelMatchesSniffer verifies that pcapLabel() returns "[With PCAP]"
// or "[No PCAP]" consistent with sniffer.PcapImplemented().
func TestPcapLabelMatchesSniffer(t *testing.T) {
	label := pcapLabel()
	implemented := sniffer.PcapImplemented()
	if implemented && label != "[With PCAP]" {
		t.Errorf("PcapImplemented()=true but pcapLabel()=%q, want \"[With PCAP]\"", label)
	}
	if !implemented && label != "[No PCAP]" {
		t.Errorf("PcapImplemented()=false but pcapLabel()=%q, want \"[No PCAP]\"", label)
	}
}

// TestVersionTagAppendsPForPcapBuilds verifies the "p" suffix is added when
// PCAP support is compiled in.
func TestVersionTagAppendsPForPcapBuilds(t *testing.T) {
	tag := versionTag()
	if sniffer.PcapImplemented() {
		if !strings.HasSuffix(tag, "p") {
			t.Errorf("versionTag()=%q should end with 'p' when PcapImplemented()=true", tag)
		}
	} else {
		if strings.HasSuffix(tag, "p") {
			t.Errorf("versionTag()=%q should NOT end with 'p' when PcapImplemented()=false", tag)
		}
	}
}

func TestVersionString_ContainsGoInstallLabel(t *testing.T) {
	// versionString() delegates to resolveVersionFromBuildInfo which is exercised
	// by the function-level tests above. This smoke test verifies the output is
	// non-empty and contains the PCAP label.
	s := versionString()
	if !strings.Contains(s, "[No PCAP]") && !strings.Contains(s, "[With PCAP]") {
		t.Errorf("versionString() missing PCAP label: %q", s)
	}
	if !strings.Contains(s, "SPK - Secured Port Knock") {
		t.Errorf("versionString() missing product name: %q", s)
	}
}
