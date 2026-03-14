// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package sniffer

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// SnifferOption describes an available packet capture method.
type SnifferOption struct {
	ID          string // Config value: "udp", "pcap", "afpacket", etc.
	Name        string // Display name
	Installed   bool   // Detected on system
	Implemented bool   // Actual backend code exists in this build
	Recommended bool   // Recommended for this platform
	Description string // Brief description
	InstallCmd  string // Installation command line 1 (empty if N/A)
	InstallCmd2 string // Installation command line 2 (empty if N/A)
	Maturity    string // "stable", "good", "experimental"
}

// DetectSniffers returns available capture methods for the current platform.
func DetectSniffers() []SnifferOption {
	switch runtime.GOOS {
	case "linux":
		return detectLinuxSniffers()
	case "windows":
		return detectWindowsSniffers()
	case "darwin":
		return detectDarwinSniffers()
	default:
		return []SnifferOption{udpOption(false)}
	}
}

func udpOption(recommended bool) SnifferOption {
	return SnifferOption{
		ID:          "udp",
		Name:        "UDP Socket Listener",
		Installed:   true, // Always available
		Implemented: true,
		Recommended: recommended,
		Description: "Universal, no dependencies. Works everywhere. Port visible in scans.",
		Maturity:    "stable",
	}
}

// RecommendSniffers sets the Recommended field on the best available option.
// Priority: pcap (installed+implemented) > afpacket/windivert (platform) > udp.
func RecommendSniffers(options []SnifferOption) []SnifferOption {
	bestIdx := -1
	bestPri := -1
	for i, opt := range options {
		options[i].Recommended = false
		if !opt.Installed || !opt.Implemented {
			continue
		}
		pri := 0
		switch opt.ID {
		case "pcap":
			pri = 30
		case "afpacket", "windivert":
			pri = 20
		case "udp":
			pri = 10
		}
		if pri > bestPri {
			bestPri = pri
			bestIdx = i
		}
	}
	if bestIdx >= 0 {
		options[bestIdx].Recommended = true
	}
	return options
}

func detectLinuxSniffers() []SnifferOption {
	options := []SnifferOption{udpOption(false)}

	// AF_PACKET - always available on Linux, implemented in pure Go
	options = append(options, SnifferOption{
		ID:          "afpacket",
		Name:        "AF_PACKET (raw socket)",
		Installed:   true,
		Implemented: true,
		Description: "Stealth mode - port invisible in scans. Pure Go, no dependencies. Requires root/CAP_NET_RAW.",
		Maturity:    "stable",
	})

	// Check libpcap (runtime library only -- no -dev package needed)
	pcapInstalled := fileExists("/usr/lib/libpcap.so.1") ||
		fileExists("/usr/lib64/libpcap.so.1") ||
		fileExists("/usr/lib/x86_64-linux-gnu/libpcap.so.1") ||
		fileExists("/usr/lib/aarch64-linux-gnu/libpcap.so.1") ||
		fileExists("/usr/lib/libpcap.so") ||
		fileExists("/usr/lib64/libpcap.so") ||
		fileExists("/usr/lib/x86_64-linux-gnu/libpcap.so") ||
		commandExists("pcap-config")
	options = append(options, SnifferOption{
		ID:          "pcap",
		Name:        "libpcap",
		Installed:   pcapInstalled,
		Implemented: pcapImplemented(),
		Description: "Stealth mode. Cross-platform. Loaded at runtime (no SDK needed at build time).",
		InstallCmd:  "apt-get install -y libpcap0.8     # Debian/Ubuntu (runtime only)",
		InstallCmd2: "yum install -y libpcap            # RHEL/CentOS/Fedora",
		Maturity:    "stable",
	})

	return options
}

func detectWindowsSniffers() []SnifferOption {
	options := []SnifferOption{udpOption(false)}

	// Use %SystemRoot% dynamically instead of hardcoded C:\Windows
	sysRoot := os.Getenv("SystemRoot")
	if sysRoot == "" {
		sysRoot = os.Getenv("WINDIR")
	}
	if sysRoot == "" {
		sysRoot = filepath.Join(os.Getenv("SYSTEMDRIVE"), "Windows")
	}
	sys32 := filepath.Join(sysRoot, "System32")

	// Check Npcap
	npcapInstalled := fileExists(filepath.Join(sys32, "Npcap", "wpcap.dll")) ||
		fileExists(filepath.Join(sys32, "wpcap.dll"))
	options = append(options, SnifferOption{
		ID:          "pcap",
		Name:        "Npcap",
		Installed:   npcapInstalled,
		Implemented: pcapImplemented(),
		Description: "Stealth mode. Cross-platform. Loaded at runtime (no SDK needed at build time).",
		InstallCmd:  "winget install Npcap.Npcap",
		Maturity:    "stable",
	})

	// Check WinDivert
	windivertInstalled := fileExists(filepath.Join(sys32, "WinDivert.dll")) ||
		fileExists(filepath.Join(sys32, "WinDivert64.sys"))
	// Also check the directory of the running executable
	if !windivertInstalled {
		if exe, err := os.Executable(); err == nil {
			exeDir := filepath.Dir(exe)
			windivertInstalled = fileExists(filepath.Join(exeDir, "WinDivert.dll")) &&
				fileExists(filepath.Join(exeDir, "WinDivert64.sys"))
		}
	}
	options = append(options, SnifferOption{
		ID:          "windivert",
		Name:        "WinDivert",
		Installed:   windivertInstalled,
		Implemented: windivertImplemented(),
		Description: "Stealth mode. Kernel-level WFP packet interception. Requires WinDivert driver.",
		InstallCmd:  "Download from https://reqrypt.org/windivert.html",
		Maturity:    "good",
	})

	return options
}

func detectDarwinSniffers() []SnifferOption {
	options := []SnifferOption{udpOption(false)}

	// libpcap is always available on macOS
	options = append(options, SnifferOption{
		ID:          "pcap",
		Name:        "libpcap (BPF)",
		Installed:   true,
		Implemented: pcapImplemented(),
		Recommended: false,
		Description: "Stealth mode. Built into macOS. Loaded at runtime (no SDK needed at build time).",
		Maturity:    "stable",
	})

	return options
}

// commandExists checks if a command is available in PATH.
func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// fileExists checks if a file or directory exists.
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// TestSniffer performs a basic test of the selected sniffer.
func TestSniffer(mode string) error {
	switch mode {
	case "udp":
		// Test UDP socket creation on a random port
		addr, err := resolveAndListen()
		if err != nil {
			return fmt.Errorf("UDP socket test failed: %w", err)
		}
		_ = addr
		return nil
	case "afpacket":
		return testAFPacket()
	case "pcap":
		return testPcap()
	case "windivert":
		return testWinDivert()
	default:
		return fmt.Errorf("sniffer backend not implemented: %s (available: udp, afpacket, pcap, windivert)", mode)
	}
}

func resolveAndListen() (string, error) {
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return "", err
	}
	localAddr := conn.LocalAddr().String()
	conn.Close()
	return localAddr, nil
}
