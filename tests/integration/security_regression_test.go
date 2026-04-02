// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package integration

import (
	"strings"
	"testing"

	"github.com/secured-port-knock/spk/internal/crypto"
	"github.com/secured-port-knock/spk/internal/protocol"
)

func TestParseKnockPacketRejectsOversizedPacket(t *testing.T) {
	dk, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	oversized := make([]byte, protocol.MaxPacketSize+1)
	_, err = protocol.ParseKnockPacket(dk, oversized, "127.0.0.1", 30)
	if err == nil {
		t.Fatal("expected oversized packet to be rejected")
	}
	if !strings.Contains(err.Error(), "packet too large") {
		t.Fatalf("unexpected error for oversized packet: %v", err)
	}
}

func TestParseKnockPacketAcceptsIPv6SourceWithZoneID(t *testing.T) {
	dk, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	ek := dk.EncapsulationKey()

	packet, err := protocol.BuildKnockPacket(ek, "fe80::1", "open-u53", 120)
	if err != nil {
		t.Fatalf("BuildKnockPacket: %v", err)
	}

	payload, err := protocol.ParseKnockPacket(dk, packet, "fe80::1%eth0", 30)
	if err != nil {
		t.Fatalf("expected zone-stripped IPv6 source to be accepted: %v", err)
	}
	if payload.ClientIP != "fe80::1" {
		t.Fatalf("unexpected payload IP: got %q want fe80::1", payload.ClientIP)
	}
}
