//go:build linux

// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package sniffer

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"sync"
	"syscall"
	"unsafe"
)

// AFPacketSniffer captures packets using Linux AF_PACKET raw sockets.
// Stealth mode: no UDP port is opened, packets are captured at the network layer.
// The listen port is invisible to port scans.
// Uses dual sockets (IPv4 + IPv6) with kernel-level BPF filters for efficiency.
// Only UDP packets matching the target port are delivered to userspace.
type AFPacketSniffer struct {
	address string
	port    int
	fds     [2]int // [0]=IPv4 (ETH_P_IP), [1]=IPv6 (ETH_P_IPV6)
	done    chan struct{}
	mu      sync.Mutex
}

// NewAFPacketSniffer creates an AF_PACKET raw socket sniffer.
// Requires root or CAP_NET_RAW capability.
func NewAFPacketSniffer(address string, port int) *AFPacketSniffer {
	return &AFPacketSniffer{
		address: address,
		port:    port,
		done:    make(chan struct{}),
	}
}

// htons converts a uint16 from host to network byte order.
func htons(v uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	return *(*uint16)(unsafe.Pointer(&b[0]))
}

// --- BPF (Berkeley Packet Filter) for kernel-level packet filtering ---
// These filters run in kernel space, so only matching packets (UDP on our port)
// are copied to userspace. This prevents CPU/memory waste on busy servers.

// bpfInsn represents a single BPF instruction (struct sock_filter).
type bpfInsn struct {
	code uint16
	jt   uint8
	jf   uint8
	k    uint32
}

// bpfProg represents a BPF program (struct sock_fprog).
// Go compiler adds correct padding between fields for 32/64-bit alignment.
type bpfProg struct {
	l uint16
	f *bpfInsn
}

const _SO_ATTACH_FILTER = 26

// ipv4UDPPortFilter creates a BPF that matches: IPv4, protocol=UDP, dst_port=port.
// For SOCK_DGRAM AF_PACKET sockets where data starts at the IP header.
func ipv4UDPPortFilter(port uint16) []bpfInsn {
	return []bpfInsn{
		{code: 0x30, k: 9},                          // ldb [9]        - load protocol byte
		{code: 0x15, jt: 0, jf: 3, k: 17},           // jeq #17        - if UDP, continue; else reject
		{code: 0xb1, k: 0},                          // ldxb 4*([0]&0xf) - load IHL*4 into X
		{code: 0x48, k: 2},                          // ldh [x+2]      - load dst port
		{code: 0x15, jt: 0, jf: 1, k: uint32(port)}, // jeq #port      - if match, accept; else reject
		{code: 0x06, k: 0xFFFF},                     // ret #65535     - accept
		{code: 0x06, k: 0},                          // ret #0         - reject
	}
}

// ipv6UDPPortFilter creates a BPF that matches: IPv6, next_header=UDP, dst_port=port.
// Note: does not handle extension headers, but port knocking packets don't use them.
func ipv6UDPPortFilter(port uint16) []bpfInsn {
	return []bpfInsn{
		{code: 0x30, k: 6},                          // ldb [6]        - load next header
		{code: 0x15, jt: 0, jf: 2, k: 17},           // jeq #17        - if UDP, continue; else reject
		{code: 0x28, k: 42},                         // ldh [42]       - load dst port (40 IPv6 + 2)
		{code: 0x15, jt: 0, jf: 1, k: uint32(port)}, // jeq #port      - if match, accept; else reject
		{code: 0x06, k: 0xFFFF},                     // ret #65535     - accept
		{code: 0x06, k: 0},                          // ret #0         - reject
	}
}

// attachBPF attaches a BPF filter program to a socket using SO_ATTACH_FILTER.
func attachBPF(fd int, insns []bpfInsn) error {
	prog := bpfProg{
		l: uint16(len(insns)),
		f: &insns[0],
	}
	_, _, errno := syscall.Syscall6(
		syscall.SYS_SETSOCKOPT,
		uintptr(fd),
		uintptr(syscall.SOL_SOCKET),
		uintptr(_SO_ATTACH_FILTER),
		uintptr(unsafe.Pointer(&prog)),
		uintptr(unsafe.Sizeof(prog)),
		0,
	)
	if errno != 0 {
		return errno
	}
	return nil
}

// Start begins capturing packets using AF_PACKET with dual sockets.
// IPv4 socket (ETH_P_IP) and IPv6 socket (ETH_P_IPV6) run in separate goroutines.
// Kernel-level BPF filters ensure only UDP packets on the target port reach userspace.
// When a specific (non-wildcard) address is configured the sockets are bound to
// the interface that owns that address, restricting capture to that interface.
func (s *AFPacketSniffer) Start(handler PacketHandler) error {
	port := uint16(s.port)

	// IPv4 socket: ETH_P_IP (0x0800)
	fd4, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_DGRAM, int(htons(syscall.ETH_P_IP)))
	if err != nil {
		return fmt.Errorf("AF_PACKET IPv4 socket: %w (need root or CAP_NET_RAW)", err)
	}

	// IPv6 socket: ETH_P_IPV6 (0x86DD)
	fd6, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_DGRAM, int(htons(0x86DD)))
	if err != nil {
		syscall.Close(fd4)
		return fmt.Errorf("AF_PACKET IPv6 socket: %w", err)
	}

	// Bind sockets to a specific interface when a non-wildcard address is given.
	// Without binding, AF_PACKET receives traffic from ALL interfaces.
	// Binding restricts capture to the interface that owns the configured IP.
	if !isWildcardAddr(s.address) {
		ip := net.ParseIP(s.address)
		if ip == nil {
			syscall.Close(fd4)
			syscall.Close(fd6)
			return fmt.Errorf("AF_PACKET: invalid listen address %q", s.address)
		}
		iface, ifErr := localInterfaceByIP(ip)
		if ifErr != nil {
			syscall.Close(fd4)
			syscall.Close(fd6)
			return fmt.Errorf("AF_PACKET: %w", ifErr)
		}
		// Bind the IPv4 socket to this interface index.
		// Linux requires the protocol to match what was set at socket creation.
		if err := syscall.Bind(fd4, &syscall.SockaddrLinklayer{
			Protocol: htons(syscall.ETH_P_IP),
			Ifindex:  iface.Index,
		}); err != nil {
			syscall.Close(fd4)
			syscall.Close(fd6)
			return fmt.Errorf("AF_PACKET: bind IPv4 socket to %s: %w", iface.Name, err)
		}
		// Bind the IPv6 socket to the same interface index.
		if err := syscall.Bind(fd6, &syscall.SockaddrLinklayer{
			Protocol: htons(0x86DD),
			Ifindex:  iface.Index,
		}); err != nil {
			syscall.Close(fd4)
			syscall.Close(fd6)
			return fmt.Errorf("AF_PACKET: bind IPv6 socket to %s: %w", iface.Name, err)
		}
	}

	// Store fds for cleanup
	s.mu.Lock()
	s.fds = [2]int{fd4, fd6}
	s.mu.Unlock()

	// Attach BPF filters - only UDP packets on our port reach userspace
	if bpfErr := attachBPF(fd4, ipv4UDPPortFilter(port)); bpfErr != nil {
		// Log warning but continue (application-level filtering still works as fallback)
		fmt.Fprintf(os.Stderr, "[WARN] AF_PACKET: IPv4 BPF filter attach failed: %v (falling back to app-level filtering)\n", bpfErr)
	}
	if bpfErr := attachBPF(fd6, ipv6UDPPortFilter(port)); bpfErr != nil {
		fmt.Fprintf(os.Stderr, "[WARN] AF_PACKET: IPv6 BPF filter attach failed: %v (falling back to app-level filtering)\n", bpfErr)
	}

	// Set receive buffers (modest: we only get UDP on our port after BPF)
	_ = syscall.SetsockoptInt(fd4, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 256*1024)
	_ = syscall.SetsockoptInt(fd6, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 256*1024)

	// Run both read loops concurrently
	errCh := make(chan error, 2)
	go func() { errCh <- s.readIPv4(fd4, handler) }()
	go func() { errCh <- s.readIPv6(fd6, handler) }()

	// Wait for first error or shutdown
	err = <-errCh
	return err
}

// readIPv4 processes IPv4 UDP packets from the AF_PACKET socket.
// Data from SOCK_DGRAM starts at the IP header (link layer stripped by kernel).
func (s *AFPacketSniffer) readIPv4(fd int, handler PacketHandler) error {
	buf := make([]byte, MaxPacketSize+100)
	// Set receive timeout once (not per-iteration)
	tv := syscall.Timeval{Sec: 1, Usec: 0}
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
	for {
		select {
		case <-s.done:
			return nil
		default:
		}

		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK || err == syscall.EINTR {
				continue
			}
			select {
			case <-s.done:
				return nil
			default:
			}
			return fmt.Errorf("AF_PACKET IPv4 recvfrom: %w", err)
		}

		if n < 28 { // 20 IP + 8 UDP minimum
			continue
		}

		// Verify IPv4 + UDP (BPF should have filtered, but double-check)
		if buf[0]>>4 != 4 || buf[9] != 17 {
			continue
		}

		ihl := int(buf[0]&0x0f) * 4
		if ihl < 20 || ihl+8 > n {
			continue
		}

		// Verify destination port (BPF should have matched, but safety check)
		dstPort := binary.BigEndian.Uint16(buf[ihl+2 : ihl+4])
		if int(dstPort) != s.port {
			continue
		}

		srcIP := net.IPv4(buf[12], buf[13], buf[14], buf[15]).String()
		payloadStart := ihl + 8
		payloadLen := n - payloadStart
		if payloadLen < MinPacketSize || payloadLen > MaxPacketSize {
			continue
		}

		data := make([]byte, payloadLen)
		copy(data, buf[payloadStart:n])
		handler(data, srcIP)
	}
}

// readIPv6 processes IPv6 UDP packets from the AF_PACKET socket.
func (s *AFPacketSniffer) readIPv6(fd int, handler PacketHandler) error {
	buf := make([]byte, MaxPacketSize+100)
	// Set receive timeout once (not per-iteration)
	tv := syscall.Timeval{Sec: 1, Usec: 0}
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
	for {
		select {
		case <-s.done:
			return nil
		default:
		}

		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK || err == syscall.EINTR {
				continue
			}
			select {
			case <-s.done:
				return nil
			default:
			}
			return fmt.Errorf("AF_PACKET IPv6 recvfrom: %w", err)
		}

		if n < 48 { // 40 IPv6 header + 8 UDP minimum
			continue
		}

		// Verify IPv6 + UDP next header (BPF should have filtered)
		if buf[0]>>4 != 6 || buf[6] != 17 {
			continue
		}

		dstPort := binary.BigEndian.Uint16(buf[42:44])
		if int(dstPort) != s.port {
			continue
		}

		srcIP := net.IP(buf[8:24]).String()
		payloadStart := 48 // 40 IPv6 + 8 UDP
		payloadLen := n - payloadStart
		if payloadLen < MinPacketSize || payloadLen > MaxPacketSize {
			continue
		}

		data := make([]byte, payloadLen)
		copy(data, buf[payloadStart:n])
		handler(data, srcIP)
	}
}

// Stop closes both AF_PACKET sockets and terminates capture.
func (s *AFPacketSniffer) Stop() error {
	select {
	case <-s.done:
		return nil
	default:
		close(s.done)
	}
	s.mu.Lock()
	fds := s.fds
	s.fds = [2]int{0, 0}
	s.mu.Unlock()
	for _, fd := range fds {
		if fd > 0 {
			syscall.Close(fd)
		}
	}
	return nil
}

// testAFPacket performs a basic AF_PACKET socket test.
func testAFPacket() error {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_DGRAM, int(htons(syscall.ETH_P_IP)))
	if err != nil {
		return fmt.Errorf("AF_PACKET socket creation failed: %w (need root or CAP_NET_RAW)", err)
	}
	syscall.Close(fd)
	return nil
}
