// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
// Package sniffer provides packet capture backends for the knock server.
package sniffer

import (
	"fmt"
	"net"
	"sync"
)

// PacketHandler is called for each received UDP packet.
type PacketHandler func(data []byte, sourceIP string)

// Sniffer is the interface for packet capture backends.
type Sniffer interface {
	// Start begins capturing packets. Blocks until Stop is called.
	Start(handler PacketHandler) error
	// Stop terminates the capture.
	Stop() error
}

// PcapImplemented reports whether this binary was compiled with pcap support.
// On Windows the pcap backend is always compiled in (pure Go, no CGO needed).
// On Linux/macOS it requires CGO; returns false when built with CGO_ENABLED=0.
// This is a compile-time check, not a runtime library probe.
func PcapImplemented() bool { return pcapImplemented() }

// UDPSniffer listens on a UDP socket. Simple, universal, no dependencies.
// Port will appear as open in scans (less stealthy) but works everywhere.
type UDPSniffer struct {
	Address string
	mu      sync.Mutex
	conn    *net.UDPConn
}

// NewUDPSniffer creates a UDP socket listener.
func NewUDPSniffer(address string, port int) *UDPSniffer {
	return &UDPSniffer{
		Address: net.JoinHostPort(address, fmt.Sprintf("%d", port)),
	}
}

// MaxPacketSize is the maximum UDP packet size we accept.
// ML-KEM-1024 ciphertext (1568) + AES nonce (12) + encrypted payload + tag ~2000 bytes.
// With anti-DPI padding: up to ~3200 bytes. Anything over 8192 is suspicious and dropped.
const MaxPacketSize = 8192

// MinPacketSize is the minimum valid knock packet size.
// Based on ML-KEM-768 (smallest supported): ciphertext(1088) + nonce(12) + GCM tag(16) + minimal payload(2).
// ML-KEM-1024 packets are always larger, so this threshold validates both sizes.
const MinPacketSize = 1088 + 12 + 16 + 2 // = 1118

// bind pre-creates the UDP socket without entering the receive loop.
// Called by NewSniffer for specific (non-wildcard) addresses to eliminate the
// race between the server logging "Listening for knock packets..." and the
// socket actually being ready to accept packets. Direct callers of
// NewUDPSniffer (tests, dynamic port rotation) bind lazily in Start instead.
func (s *UDPSniffer) bind() error {
	addr, err := net.ResolveUDPAddr("udp", s.Address)
	if err != nil {
		return fmt.Errorf("resolve address %s: %w", s.Address, err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("listen UDP %s: %w", s.Address, err)
	}
	conn.SetReadBuffer(256 * 1024) // 256 KB read buffer
	s.mu.Lock()
	s.conn = conn
	s.mu.Unlock()
	return nil
}

// Start begins listening for UDP packets.
// If the socket was pre-bound via bind() (called by NewSniffer), Start
// enters the receive loop immediately without re-binding.
func (s *UDPSniffer) Start(handler PacketHandler) error {
	s.mu.Lock()
	conn := s.conn
	s.mu.Unlock()

	if conn == nil {
		// Not pre-bound; bind now (direct NewUDPSniffer usage).
		addr, err := net.ResolveUDPAddr("udp", s.Address)
		if err != nil {
			return fmt.Errorf("resolve address %s: %w", s.Address, err)
		}
		conn, err = net.ListenUDP("udp", addr)
		if err != nil {
			return fmt.Errorf("listen UDP %s: %w", s.Address, err)
		}
		s.mu.Lock()
		s.conn = conn
		s.mu.Unlock()
		conn.SetReadBuffer(256 * 1024) // 256 KB read buffer
	}

	buf := make([]byte, MaxPacketSize+1) // +1 to detect oversized packets
	for {
		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			// Check if we were closed intentionally
			s.mu.Lock()
			closed := s.conn == nil
			s.mu.Unlock()
			if closed {
				return nil
			}
			// Temporary errors - continue
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return fmt.Errorf("read UDP: %w", err)
		}

		if remoteAddr == nil {
			continue
		}

		// Drop oversized packets immediately (possible flood/attack)
		if n > MaxPacketSize {
			continue
		}

		// Drop undersized packets (can't be valid knock)
		if n < MinPacketSize {
			continue
		}

		// Copy packet data (buffer is reused)
		data := make([]byte, n)
		copy(data, buf[:n])
		handler(data, remoteAddr.IP.String())
	}
}

// Stop closes the UDP connection.
func (s *UDPSniffer) Stop() error {
	s.mu.Lock()
	conn := s.conn
	s.conn = nil
	s.mu.Unlock()
	if conn != nil {
		return conn.Close()
	}
	return nil
}

// newUDPSnifferForAddresses creates pre-bound UDPSniffer instances for the
// given addresses. Wildcard addresses bind lazily in Start; specific IPs are
// pre-bound so the socket is ready before the server logs "Listening...".
// Returns a MultiSniffer when more than one address is requested.
func newUDPSnifferForAddresses(addresses []string, port int) (Sniffer, error) {
	if len(addresses) == 1 {
		s := NewUDPSniffer(addresses[0], port)
		if !isWildcardAddr(addresses[0]) {
			if err := s.bind(); err != nil {
				return nil, err
			}
		}
		return s, nil
	}
	sniffers := make([]Sniffer, 0, len(addresses))
	for _, addr := range addresses {
		s := NewUDPSniffer(addr, port)
		if !isWildcardAddr(addr) {
			if err := s.bind(); err != nil {
				for _, prev := range sniffers {
					prev.Stop()
				}
				return nil, err
			}
		}
		sniffers = append(sniffers, s)
	}
	return &MultiSniffer{sniffers: sniffers}, nil
}

// newStealthSnifferForAddresses creates sniffer instances for a stealth mode
// (afpacket, pcap, windivert) using the provided factory. A wildcard address
// or a single address yields one sniffer; multiple specific addresses are
// wrapped in a MultiSniffer.
func newStealthSnifferForAddresses(isWildcard bool, addresses []string, port int, factory func(string, int) Sniffer) Sniffer {
	if isWildcard || len(addresses) == 1 {
		return factory(addresses[0], port)
	}
	sniffers := make([]Sniffer, 0, len(addresses))
	for _, addr := range addresses {
		sniffers = append(sniffers, factory(addr, port))
	}
	return &MultiSniffer{sniffers: sniffers}
}

// NewSniffer creates a sniffer based on the configured mode.
//
// Address semantics:
//   - Wildcard (0.0.0.0 / ::): listen on all IPv4 / IPv6 interfaces.
//   - Specific IP (e.g. 192.168.1.2): validated against local interfaces;
//     returns an error if the address is not assigned to any local interface.
//   - Multiple specific IPs: each address creates its own sniffer instance,
//     combined via MultiSniffer.
//
// UDP mode:
//   - One UDPSniffer per address; multiple addresses use MultiSniffer.
//
// Stealth modes (afpacket, pcap, windivert):
//   - Wildcard addresses use a single sniffer that captures all interfaces.
//   - Specific addresses use one sniffer per address (MultiSniffer when >1).
//   - On Linux, pcap with "any" and afpacket already capture all interfaces,
//     so 0.0.0.0 + :: can be served by one sniffer instance.
func NewSniffer(mode string, addresses []string, port int) (Sniffer, error) {
	if len(addresses) == 0 {
		addresses = []string{"0.0.0.0"}
	}

	// Validate specific addresses exist on the machine before creating sniffers.
	// Wildcards (0.0.0.0, ::) are always valid; specific IPs must be local.
	if err := validateListenAddresses(addresses); err != nil {
		return nil, err
	}

	// For stealth modes, a wildcard address already captures all interfaces.
	// Avoid creating unnecessary per-address instances in that common case.
	isWildcard := hasAnyWildcard(addresses)

	switch mode {
	case "udp", "":
		// Pre-bind the UDP socket for specific (non-wildcard) addresses so that
		// the socket is ready before the server logs "Listening for knock
		// packets...". Wildcard addresses (0.0.0.0, ::) are left to bind lazily
		// in Start to avoid failures on systems without dual-stack IPv6.
		return newUDPSnifferForAddresses(addresses, port)

	case "afpacket":
		// With a wildcard the AF_PACKET socket already captures every interface
		// (dual IPv4+IPv6 sockets, no bind restriction). For specific IPs each
		// sniffer binds to the interface that owns that IP.
		return newStealthSnifferForAddresses(isWildcard, addresses, port, func(addr string, p int) Sniffer {
			return NewAFPacketSniffer(addr, p)
		}), nil

	case "pcap":
		// Linux/pcap uses the "any" device for wildcards (captures all interfaces).
		// macOS/Windows must pick one device; wildcards use the default-route NIC.
		// For multiple specific addresses, open a handle per interface.
		return newStealthSnifferForAddresses(isWildcard, addresses, port, func(addr string, p int) Sniffer {
			return NewPcapSniffer(addr, p)
		}), nil

	case "windivert":
		// WinDivert intercepts at the WFP kernel layer for all interfaces.
		// Specific addresses are validated above; interface filtering happens
		// inside the sniffer via the packet handler IP check.
		return newStealthSnifferForAddresses(isWildcard, addresses, port, func(addr string, p int) Sniffer {
			return NewWinDivertSniffer(addr, p)
		}), nil

	default:
		return nil, fmt.Errorf("unsupported sniffer mode: %s (available: udp, afpacket, pcap, windivert)", mode)
	}
}

// MultiSniffer wraps multiple sniffers and runs them concurrently.
// Used for UDP dual-stack (0.0.0.0 + ::) to listen on both IPv4 and IPv6.
type MultiSniffer struct {
	sniffers []Sniffer
}

// Start runs all wrapped sniffers concurrently. Blocks until Stop is called.
// If any sniffer fails to start, logs the error but continues with others.
func (m *MultiSniffer) Start(handler PacketHandler) error {
	var wg sync.WaitGroup
	errCh := make(chan error, len(m.sniffers))

	for _, s := range m.sniffers {
		wg.Add(1)
		go func(sn Sniffer) {
			defer wg.Done()
			if err := sn.Start(handler); err != nil {
				errCh <- err
			}
		}(s)
	}

	wg.Wait()
	close(errCh)
	for err := range errCh {
		return err // Return first error
	}
	return nil
}

// Stop terminates all wrapped sniffers.
func (m *MultiSniffer) Stop() error {
	var lastErr error
	for _, s := range m.sniffers {
		if err := s.Stop(); err != nil {
			lastErr = err
		}
	}
	return lastErr
}
