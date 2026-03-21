//go:build windows

// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package sniffer

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"unsafe"
)

// WinDivertSniffer captures UDP packets using the WinDivert driver on Windows.
// WinDivert intercepts packets at the Windows kernel level (WFP callout driver),
// allowing packet inspection without opening a visible listening port.
//
// Advantages:
//   - Stealth mode: port invisible to scans (like pcap, but without Npcap)
//   - Kernel-level filtering via WinDivert filter expressions
//   - Lower overhead than Npcap for targeted packet capture
//   - Works on Windows 7 through Windows 11
//
// Requirements:
//   - WinDivert driver installed (WinDivert.dll + WinDivert64.sys in System32 or app dir)
//   - Administrator privileges
//   - Download: https://reqrypt.org/windivert.html
type WinDivertSniffer struct {
	address string
	port    int
	done    chan struct{}
	mu      sync.Mutex
	handle  uintptr
}

// NewWinDivertSniffer creates a WinDivert packet sniffer.
func NewWinDivertSniffer(address string, port int) *WinDivertSniffer {
	return &WinDivertSniffer{
		address: address,
		port:    port,
		done:    make(chan struct{}),
	}
}

// ----------------------------------------------------------------------
//  WinDivert DLL interface (loaded dynamically, no CGO needed)
// ----------------------------------------------------------------------

// WinDivert layer constants
const (
	_WINDIVERT_LAYER_NETWORK = 0

	// WinDivert flags
	_WINDIVERT_FLAG_SNIFF = 1 // Sniff mode: don't drop/modify packets
	_WINDIVERT_FLAG_DROP  = 2 // Drop mode: silently drop matching packets

	// WinDivert params
	_WINDIVERT_PARAM_QUEUE_LENGTH = 0
	_WINDIVERT_PARAM_QUEUE_TIME   = 1
	_WINDIVERT_PARAM_QUEUE_SIZE   = 2
)

// windivertAddress is a simplified representation of the WINDIVERT_ADDRESS struct.
// Note: In the real C struct, Sniffed through UDPChecksum are packed as bit fields
// in a single byte. Here they are listed as individual uint8 for documentation
// clarity, but we use the raw 80-byte buffer for actual API calls instead.
type windivertAddress struct {
	Timestamp   int64
	Layer       uint8
	Event       uint8
	Sniffed     uint8 // bit 0
	Outbound    uint8 // bit 1
	Loopback    uint8 // bit 2
	Impostor    uint8 // bit 3
	IPv6        uint8 // bit 4
	IPChecksum  uint8 // bit 5
	TCPChecksum uint8 // bit 6
	UDPChecksum uint8 // bit 7
	Reserved1   uint8
	Reserved2   uint32
	IfIdx       uint32
	SubIfIdx    uint32
}

// We use the raw 80-byte WINDIVERT_ADDRESS struct for API compatibility
const windivertAddressSize = 80

var (
	windivertDLL       *syscall.LazyDLL
	windivertOpen      *syscall.LazyProc
	windivertRecv      *syscall.LazyProc
	windivertSend      *syscall.LazyProc
	windivertClose     *syscall.LazyProc
	windivertSetParam  *syscall.LazyProc
	windivertDLLLoaded bool
	windivertDLLErr    error
	windivertOnce      sync.Once
)

func loadWinDivert() error {
	windivertOnce.Do(func() {
		// Security: Load WinDivert.dll from known safe locations only.
		// First check System32 (preferred), then app directory.
		// Avoids DLL search-order hijacking via current directory or PATH.
		sysDir := os.Getenv("SystemRoot")
		if sysDir == "" {
			sysDir = `C:\Windows`
		}
		sys32Path := filepath.Join(sysDir, "System32", "WinDivert.dll")
		exePath := ""
		if exe, err := os.Executable(); err == nil {
			exePath = filepath.Join(filepath.Dir(exe), "WinDivert.dll")
		}

		dllPath := ""
		if _, err := os.Stat(sys32Path); err == nil {
			dllPath = sys32Path
		} else if exePath != "" {
			if _, err := os.Stat(exePath); err == nil {
				dllPath = exePath
			}
		}
		if dllPath == "" {
			windivertDLLErr = fmt.Errorf("WinDivert.dll not found in System32 or executable directory")
			return
		}

		windivertDLL = syscall.NewLazyDLL(dllPath)
		windivertDLLErr = windivertDLL.Load()
		if windivertDLLErr != nil {
			return
		}
		windivertOpen = windivertDLL.NewProc("WinDivertOpen")
		windivertRecv = windivertDLL.NewProc("WinDivertRecv")
		windivertSend = windivertDLL.NewProc("WinDivertSend")
		windivertClose = windivertDLL.NewProc("WinDivertClose")
		windivertSetParam = windivertDLL.NewProc("WinDivertSetParam")
		windivertDLLLoaded = true
	})
	return windivertDLLErr
}

// ----------------------------------------------------------------------
//  Start / Stop
// ----------------------------------------------------------------------

// Start begins capturing packets via WinDivert.
func (s *WinDivertSniffer) Start(handler PacketHandler) error {
	if err := loadWinDivert(); err != nil {
		return fmt.Errorf("WinDivert: failed to load WinDivert.dll: %w\nInstall from: https://reqrypt.org/windivert.html", err)
	}

	// Build WinDivert filter string:
	// "udp.DstPort == <port>" - only capture UDP packets to our port
	// This creates a kernel-level WFP filter, very efficient.
	filter := fmt.Sprintf("udp.DstPort == %d", s.port)

	// Add address binding if specific interface
	if s.address != "0.0.0.0" && s.address != "::" && s.address != "" {
		ip := net.ParseIP(s.address)
		if ip != nil {
			if ip.To4() != nil {
				filter += fmt.Sprintf(" and ip.DstAddr == %s", ip.String())
			} else {
				filter += fmt.Sprintf(" and ipv6.DstAddr == %s", ip.String())
			}
		}
	}

	filterBytes, err := syscall.BytePtrFromString(filter)
	if err != nil {
		return fmt.Errorf("WinDivert: invalid filter: %w", err)
	}

	// WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, priority=0, WINDIVERT_FLAG_SNIFF)
	// Sniff mode = packets are observed but not consumed (they still reach their destination)
	handle, _, callErr := windivertOpen.Call(
		uintptr(unsafe.Pointer(filterBytes)),
		uintptr(_WINDIVERT_LAYER_NETWORK),
		0, // priority
		uintptr(_WINDIVERT_FLAG_SNIFF),
	)
	if handle == 0 || handle == ^uintptr(0) { // INVALID_HANDLE_VALUE
		return fmt.Errorf("WinDivert: WinDivertOpen failed: %v (need Administrator privileges)", callErr)
	}

	s.mu.Lock()
	s.handle = handle
	s.mu.Unlock()

	// Set queue parameters for our use case
	// Queue length: 4096 packets (default is 4096)
	windivertSetParam.Call(handle, uintptr(_WINDIVERT_PARAM_QUEUE_LENGTH), 4096)
	// Queue time: 500ms (packets older than this are dropped from queue)
	windivertSetParam.Call(handle, uintptr(_WINDIVERT_PARAM_QUEUE_TIME), 500)
	// Queue size: 4MB max queue memory
	windivertSetParam.Call(handle, uintptr(_WINDIVERT_PARAM_QUEUE_SIZE), 4*1024*1024)

	// Packet receive loop
	return s.readLoop(handle, handler)
}

func (s *WinDivertSniffer) readLoop(handle uintptr, handler PacketHandler) error {
	buf := make([]byte, MaxPacketSize+200) // Extra space for IP headers
	addr := make([]byte, windivertAddressSize)

	for {
		select {
		case <-s.done:
			return nil
		default:
		}

		var recvLen uint32
		// WinDivertRecv(handle, pPacket, packetLen, &recvLen, pAddr)
		ret, _, callErr := windivertRecv.Call(
			handle,
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(len(buf)),
			uintptr(unsafe.Pointer(&recvLen)),
			uintptr(unsafe.Pointer(&addr[0])),
		)
		if ret == 0 {
			select {
			case <-s.done:
				return nil
			default:
			}
			// Check if it's a timeout/expected error
			errno := callErr.(syscall.Errno)
			if errno == 995 { // ERROR_OPERATION_ABORTED (handle closed)
				return nil
			}
			if errno == 6 { // ERROR_INVALID_HANDLE
				return nil
			}
			continue // Transient error, retry
		}

		if recvLen == 0 {
			continue
		}

		// WinDivert delivers raw IP packets (no Ethernet header)
		ipData := buf[:recvLen]
		if len(ipData) < 1 {
			continue
		}

		version := ipData[0] >> 4
		switch version {
		case 4:
			s.processIPv4(ipData, handler)
		case 6:
			s.processIPv6(ipData, handler)
		}
	}
}

func (s *WinDivertSniffer) processIPv4(ipData []byte, handler PacketHandler) {
	if len(ipData) < 20 {
		return
	}
	// Verify UDP protocol
	if ipData[9] != 17 {
		return
	}

	ihl := int(ipData[0]&0x0F) * 4
	if ihl < 20 || len(ipData) < ihl+8 {
		return
	}

	// Verify destination port (WinDivert filter should have matched, but safety check)
	dstPort := binary.BigEndian.Uint16(ipData[ihl+2 : ihl+4])
	if int(dstPort) != s.port {
		return
	}

	srcIP := net.IPv4(ipData[12], ipData[13], ipData[14], ipData[15]).String()
	payload := ipData[ihl+8:]
	if len(payload) < MinPacketSize || len(payload) > MaxPacketSize {
		return
	}

	data := make([]byte, len(payload))
	copy(data, payload)
	handler(data, srcIP)
}

func (s *WinDivertSniffer) processIPv6(ipData []byte, handler PacketHandler) {
	if len(ipData) < 40 {
		return
	}

	nextHeader := ipData[6]

	// Skip extension headers to find UDP.
	// Cap iterations to prevent DoS from crafted packets.
	offset := 40
	for i := 0; i < maxIPv6ExtHeaders && nextHeader != 17; i++ {
		switch nextHeader {
		case 0, 43, 60: // Hop-by-Hop, Routing, Destination Options
			if len(ipData) < offset+2 {
				return
			}
			nextHeader = ipData[offset]
			extLen := int(ipData[offset+1]+1) * 8
			offset += extLen
		case 44: // Fragment header
			if len(ipData) < offset+8 {
				return
			}
			nextHeader = ipData[offset]
			offset += 8
		case 59: // No Next Header
			return
		default:
			return
		}
		if offset > len(ipData) {
			return
		}
	}
	if nextHeader != 17 {
		return
	}

	if len(ipData) < offset+8 {
		return
	}

	// Verify destination port
	dstPort := binary.BigEndian.Uint16(ipData[offset+2 : offset+4])
	if int(dstPort) != s.port {
		return
	}

	srcIP := net.IP(ipData[8:24]).String()
	payload := ipData[offset+8:]
	if len(payload) < MinPacketSize || len(payload) > MaxPacketSize {
		return
	}

	data := make([]byte, len(payload))
	copy(data, payload)
	handler(data, srcIP)
}

// Stop closes the WinDivert handle and terminates capture.
func (s *WinDivertSniffer) Stop() error {
	select {
	case <-s.done:
		return nil
	default:
		close(s.done)
	}

	s.mu.Lock()
	h := s.handle
	s.handle = 0
	s.mu.Unlock()

	if h != 0 && windivertDLLLoaded {
		ret, _, callErr := windivertClose.Call(h)
		if ret == 0 {
			return fmt.Errorf("WinDivertClose failed: %v", callErr)
		}
	}
	return nil
}

// testWinDivert performs a basic WinDivert availability test.
func testWinDivert() error {
	if err := loadWinDivert(); err != nil {
		return fmt.Errorf("WinDivert.dll not found: %w\nInstall from: https://reqrypt.org/windivert.html", err)
	}

	// Try to open a minimal filter to test driver availability
	filter, _ := syscall.BytePtrFromString("false") // Match nothing
	handle, _, callErr := windivertOpen.Call(
		uintptr(unsafe.Pointer(filter)),
		uintptr(_WINDIVERT_LAYER_NETWORK),
		0,
		uintptr(_WINDIVERT_FLAG_SNIFF),
	)
	if handle == 0 || handle == ^uintptr(0) {
		return fmt.Errorf("WinDivert driver not loaded: %v (need Administrator)", callErr)
	}
	windivertClose.Call(handle)
	return nil
}

// windivertImplemented returns true on Windows.
func windivertImplemented() bool { return true }
