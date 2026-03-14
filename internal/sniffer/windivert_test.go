// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package sniffer

import (
	"runtime"
	"testing"
)

// ----------------------------------------------------------------------
//  Factory / integration tests (cross-platform)
// ----------------------------------------------------------------------

func TestNewWinDivertSnifferCreation(t *testing.T) {
	s := NewWinDivertSniffer("0.0.0.0", 9999)
	if s == nil {
		t.Fatal("NewWinDivertSniffer returned nil")
	}
}

func TestNewSnifferWinDivert(t *testing.T) {
	s, err := NewSniffer("windivert", []string{"0.0.0.0"}, 9999)
	if err != nil {
		t.Fatalf("NewSniffer(windivert): %v", err)
	}
	if s == nil {
		t.Fatal("NewSniffer(windivert) returned nil")
	}
}

func TestWinDivertSnifferImplementsInterface(t *testing.T) {
	var _ Sniffer = NewWinDivertSniffer("0.0.0.0", 9999)
}

func TestWinDivertImplementedFlag(t *testing.T) {
	got := windivertImplemented()
	if runtime.GOOS == "windows" {
		if !got {
			t.Error("windivertImplemented() should return true on Windows")
		}
	} else {
		if got {
			t.Errorf("windivertImplemented() should return false on %s", runtime.GOOS)
		}
	}
}

func TestWinDivertDetectSniffers(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("WinDivert detect only relevant on Windows")
	}
	options := DetectSniffers()
	found := false
	for _, opt := range options {
		if opt.ID == "windivert" {
			found = true
			if !opt.Implemented {
				t.Error("WinDivert should be implemented on Windows")
			}
			if opt.Maturity != "good" {
				t.Errorf("WinDivert maturity = %q, want good", opt.Maturity)
			}
			if opt.InstallCmd == "" {
				t.Error("WinDivert should have install command")
			}
		}
	}
	if !found {
		t.Error("WinDivert option not found in DetectSniffers on Windows")
	}
}

func TestWinDivertStubStart(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("stub test only on non-Windows")
	}
	s := NewWinDivertSniffer("0.0.0.0", 9999)
	err := s.Start(func(data []byte, srcIP string) {})
	if err == nil {
		t.Error("Start on stub should return error")
	}
}

func TestWinDivertStubStop(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("stub test only on non-Windows")
	}
	s := NewWinDivertSniffer("0.0.0.0", 9999)
	if err := s.Stop(); err != nil {
		t.Errorf("Stop on stub should not error: %v", err)
	}
}

func TestWinDivertStubTestSniffer(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("stub test only on non-Windows")
	}
	err := TestSniffer("windivert")
	if err == nil {
		t.Error("testWinDivert() should error on non-Windows")
	}
}
