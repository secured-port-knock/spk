// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

//go:build testsmoke

package smoke_test

import (
	cryptorand "crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/secured-port-knock/spk/internal/crypto"
	"github.com/secured-port-knock/spk/internal/protocol"
	"github.com/secured-port-knock/spk/internal/sniffer"
)

// stubCmd returns a platform-appropriate command that creates a marker file.
// The marker filename uses {{IP}} and {{PORT}} placeholders, which the server
// substitutes with the actual client IP and port before execution.
func stubCmd(action, markerDir string) string {
	if runtime.GOOS == "windows" {
		// The server runs commands via cmd /C on Windows. Use echo with output
		// redirection to create a zero-byte marker file.
		//
		// Quoted redirection targets fail when Go's exec.Command passes the
		// argument through Windows CreateProcess escaping -- the embedded
		// double-quotes cause cmd.exe to mis-parse the redirection target.
		// Unquoted paths work correctly as long as the path contains no spaces.
		// Go's t.TempDir() produces paths whose segments use camelCase test
		// names and 8.3 short names for the root temp dir, so no spaces appear
		// in practice.
		path := filepath.Join(markerDir, action+"_{{IP}}_{{PORT}}.txt")
		return fmt.Sprintf("echo.>%s", path)
	}
	// Unix: touch with single-quoted path to handle any special characters.
	path := filepath.Join(markerDir, action+"_{{IP}}_{{PORT}}.txt")
	return "touch " + shQuote(path)
}

// shQuote wraps a path in single quotes for use in sh -c commands.
// Any embedded single quote is closed, escaped, and reopened.
func shQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// markerPath returns the expected path of the stub marker file after the server
// substitutes ip and portStr into the stub command template.
func markerPath(markerDir, action, ip, portStr string) string {
	return filepath.Join(markerDir, fmt.Sprintf("%s_%s_%s.txt", action, ip, portStr))
}

// waitForFile polls for the file at path to appear, returning true on success.
func waitForFile(path string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return true
		}
		time.Sleep(250 * time.Millisecond)
	}
	return false
}

// freeUDPPort returns an available UDP port on 127.0.0.1 as reported by the
// OS. There is an inherent TOCTOU window, but this is acceptable for test use.
func freeUDPPort(t *testing.T) int {
	t.Helper()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("freeUDPPort: %v", err)
	}
	port := conn.LocalAddr().(*net.UDPAddr).Port
	conn.Close()
	return port
}

// sendKnock builds a knock packet and writes it to the given UDP address.
func sendKnock(t *testing.T, host string, port int, ek crypto.EncapsulationKey, clientIP, cmd string, openDuration int, opts ...protocol.KnockOptions) {
	t.Helper()
	packet, err := protocol.BuildKnockPacket(ek, clientIP, cmd, openDuration, opts...)
	if err != nil {
		t.Fatalf("BuildKnockPacket(%q): %v", cmd, err)
	}
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatalf("udp dial %s: %v", addr, err)
	}
	defer conn.Close()
	if _, err := conn.Write(packet); err != nil {
		t.Fatalf("udp write to %s: %v", addr, err)
	}
}

// randomPortSeed returns 8 cryptographically random bytes encoded as a
// 16-character hex string, suitable for use as a dynamic port seed.
func randomPortSeed(t *testing.T) string {
	t.Helper()
	b := make([]byte, 8)
	if _, err := cryptorand.Read(b); err != nil {
		t.Fatalf("random seed: %v", err)
	}
	return hex.EncodeToString(b)
}

// snifferAvailable returns true if the given sniffer mode is installed and
// implemented on the current platform.
func snifferAvailable(mode string) bool {
	for _, opt := range sniffer.DetectSniffers() {
		if opt.ID == mode {
			return opt.Installed && opt.Implemented
		}
	}
	return false
}

// sendKnockUntilMarker retries sending a knock packet until the marker file
// appears or the timeout expires. Stealth sniffers (pcap, afpacket, windivert)
// initialize their capture handles asynchronously after the server logs
// "Listening for knock", so the first packet may arrive before the handle
// is open. Retrying compensates for this startup race.
func sendKnockUntilMarker(t *testing.T, srv *testServer, clientIP, cmd string, openDuration int, marker string, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		sendKnock(t, "127.0.0.1", srv.port, srv.ek, clientIP, cmd, openDuration)
		if waitForFile(marker, 1*time.Second) {
			return true
		}
	}
	return false
}

// isRoot reports whether the current process has root / Administrator
// privileges. Used to gate tests that require elevated access.
func isRoot() bool {
	if runtime.GOOS == "windows" {
		f, err := os.Open(`\\.\PHYSICALDRIVE0`)
		if err != nil {
			return false
		}
		f.Close()
		return true
	}
	return os.Getuid() == 0
}
