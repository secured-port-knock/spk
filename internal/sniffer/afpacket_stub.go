//go:build !linux

// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package sniffer

import "fmt"

// NewAFPacketSniffer is not supported on this platform.
func NewAFPacketSniffer(address string, port int) *afpacketStub {
	return &afpacketStub{}
}

type afpacketStub struct{}

func (s *afpacketStub) Start(handler PacketHandler) error {
	return fmt.Errorf("AF_PACKET is only available on Linux")
}

func (s *afpacketStub) Stop() error {
	return nil
}

// testAFPacket is not available on non-Linux platforms.
func testAFPacket() error {
	return fmt.Errorf("AF_PACKET is only available on Linux")
}
