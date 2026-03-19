//go:build !windows && (!cgo || (!linux && !darwin))

// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package sniffer

import "fmt"

// pcapImplemented returns false when dynamic pcap loading is not available.
// On Windows, pcap is always available (pure Go, no CGO needed).
// On Linux/macOS, pcap requires CGO for dlopen/dlsym (dlfcn.h from libc).
func pcapImplemented() bool { return false }

// NewPcapSniffer returns a stub that errors when pcap is not compiled in.
func NewPcapSniffer(address string, port int) Sniffer {
	return &pcapStub{}
}

type pcapStub struct{}

func (s *pcapStub) Start(handler PacketHandler) error {
	return fmt.Errorf("pcap not available: rebuild with CGO_ENABLED=1 (Linux/macOS) or use Windows")
}

func (s *pcapStub) Stop() error { return nil }

// testPcap returns an error when pcap is not compiled in.
func testPcap() error {
	return fmt.Errorf("pcap not available (binary built without CGO support)")
}
