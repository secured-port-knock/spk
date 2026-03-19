//go:build !windows

// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package sniffer

import "fmt"

// WinDivertSniffer is a stub on non-Windows platforms.
type WinDivertSniffer struct{}

// NewWinDivertSniffer returns a stub on non-Windows platforms.
func NewWinDivertSniffer(address string, port int) *WinDivertSniffer {
	return &WinDivertSniffer{}
}

func (s *WinDivertSniffer) Start(handler PacketHandler) error {
	return fmt.Errorf("WinDivert is only available on Windows")
}

func (s *WinDivertSniffer) Stop() error { return nil }

func testWinDivert() error {
	return fmt.Errorf("WinDivert is only available on Windows")
}

func windivertImplemented() bool { return false }
