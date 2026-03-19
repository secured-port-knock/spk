//go:build windows

// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package sniffer

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"unsafe"
)

// PcapSniffer captures packets using Npcap/WinPcap on Windows.
// The DLL is loaded dynamically at runtime -- no SDK or headers needed at
// build time. Stealth mode: the listen port is not opened on the system.
//
// Requirements:
//   - Npcap installed (https://npcap.com)
//   - Administrator privileges for packet capture
type PcapSniffer struct {
	address string
	port    int
	handles []uintptr // one pcap_t* per captured device
	done    chan struct{}
	mu      sync.Mutex
	// wg tracks active captureLoop goroutines so Stop() can wait for them
	// to finish before calling pcap_close(), preventing concurrent use of a
	// pcap handle (pcap_next_ex running while pcap_close is called) that
	// corrupts Npcap's internal state and causes a crash on process exit.
	wg sync.WaitGroup
}

// NewPcapSniffer creates a new pcap-based packet sniffer.
func NewPcapSniffer(address string, port int) Sniffer {
	return &PcapSniffer{
		address: address,
		port:    port,
		done:    make(chan struct{}),
	}
}

// pcapImplemented returns true on Windows (always compiled in, pure Go).
func pcapImplemented() bool { return true }

// ---------- pcap ABI struct definitions (Windows x86/x64) ----------
// These match the Npcap/WinPcap C ABI.
// Windows long is 32 bits even on 64-bit systems (LLP64 model).

type pcapIfT struct {
	next        unsafe.Pointer // *pcapIfT
	name        unsafe.Pointer // *byte (C char*)
	description unsafe.Pointer // *byte
	addresses   unsafe.Pointer // *pcapAddrT
	flags       uint32
	_pad        uint32 // alignment padding on 64-bit
}

type pcapAddrT struct {
	next      unsafe.Pointer // *pcapAddrT
	addr      unsafe.Pointer // *sockaddr
	netmask   unsafe.Pointer
	broadaddr unsafe.Pointer
	dstaddr   unsafe.Pointer
}

// pcapPkthdr matches WinPcap/Npcap struct pcap_pkthdr.
// Windows timeval uses 32-bit long for both tv_sec and tv_usec.
type pcapPkthdr struct {
	tvSec  int32
	tvUsec int32
	caplen uint32
	pktLen uint32
}

type bpfProgram struct {
	bfLen   uint32
	_pad    uint32  // alignment padding on 64-bit
	bfInsns uintptr // *bpf_insn
}

const pcapNetmaskUnknown = 0xffffffff

// ---------- DLL loading ----------

var (
	pcapDLL     *syscall.DLL
	pcapLoaded  bool
	pcapLoadErr error
	pcapOnce    sync.Once

	// kernel32 procs for DLL directory management
	modKernel32          = syscall.NewLazyDLL("kernel32.dll")
	procSetDllDirectoryW = modKernel32.NewProc("SetDllDirectoryW")

	// pcap function pointers (set after DLL load)
	procPcapFindAllDevs *syscall.Proc
	procPcapFreeAllDevs *syscall.Proc
	procPcapOpenLive    *syscall.Proc
	procPcapCompile     *syscall.Proc
	procPcapSetFilter   *syscall.Proc
	procPcapFreeCode    *syscall.Proc
	procPcapDatalink    *syscall.Proc
	procPcapNextEx      *syscall.Proc
	procPcapBreakloop   *syscall.Proc
	procPcapClose       *syscall.Proc
	procPcapGetErr      *syscall.Proc
)

// findWpcapDLL searches known locations for wpcap.dll.
// Returns (full DLL path, DLL directory) or ("","") if not found.
// Supports non-standard Windows installations (D:, E: drives etc.)
// via the SystemRoot / WINDIR / SYSTEMDRIVE environment variables.
func findWpcapDLL() (string, string) {
	sysRoot := os.Getenv("SystemRoot")
	if sysRoot == "" {
		sysRoot = os.Getenv("WINDIR")
	}
	if sysRoot == "" {
		drive := os.Getenv("SYSTEMDRIVE")
		if drive == "" {
			drive = "C:"
		}
		sysRoot = drive + `\Windows`
	}
	sys32 := filepath.Join(sysRoot, "System32")

	// Search order:
	//  1. System32\Npcap  (modern Npcap default location)
	//  2. System32        (legacy WinPcap or Npcap compatibility mode)
	//  3. Executable dir  (portable deployment)
	searchDirs := []string{
		filepath.Join(sys32, "Npcap"),
		sys32,
	}
	if exe, err := os.Executable(); err == nil {
		searchDirs = append(searchDirs, filepath.Dir(exe))
	}

	for _, dir := range searchDirs {
		path := filepath.Join(dir, "wpcap.dll")
		if _, err := os.Stat(path); err == nil {
			return path, dir
		}
	}
	return "", ""
}

// loadPcapLibrary loads wpcap.dll and resolves all required function pointers.
// Uses SetDllDirectoryW to ensure Packet.dll (wpcap.dll dependency) can be
// found in the same directory. Without this, Windows cannot resolve the
// dependency and returns "The specified procedure could not be found".
func loadPcapLibrary() error {
	pcapOnce.Do(func() {
		dllPath, dllDir := findWpcapDLL()
		if dllPath == "" {
			pcapLoadErr = fmt.Errorf("wpcap.dll not found (install Npcap: https://npcap.com)")
			return
		}

		// Set DLL search directory so Packet.dll (a dependency of wpcap.dll
		// that lives in the same Npcap directory) can be located by the
		// Windows loader. This resolves the common "The specified procedure
		// could not be found" error.
		dllDirW, err := syscall.UTF16PtrFromString(dllDir)
		if err != nil {
			pcapLoadErr = fmt.Errorf("invalid DLL directory path: %w", err)
			return
		}
		procSetDllDirectoryW.Call(uintptr(unsafe.Pointer(dllDirW)))

		// Load wpcap.dll (Windows loader now searches dllDir for dependencies)
		pcapDLL, err = syscall.LoadDLL(dllPath)

		// Reset DLL search directory regardless of load result
		procSetDllDirectoryW.Call(0)

		if err != nil {
			pcapLoadErr = fmt.Errorf("load %s: %w", dllPath, err)
			return
		}

		// Resolve function pointers.
		// All these functions are available since libpcap 0.8 / WinPcap 3.0 (2002).
		type fnEntry struct {
			name string
			proc **syscall.Proc
		}
		fns := []fnEntry{
			{"pcap_findalldevs", &procPcapFindAllDevs},
			{"pcap_freealldevs", &procPcapFreeAllDevs},
			{"pcap_open_live", &procPcapOpenLive},
			{"pcap_compile", &procPcapCompile},
			{"pcap_setfilter", &procPcapSetFilter},
			{"pcap_freecode", &procPcapFreeCode},
			{"pcap_datalink", &procPcapDatalink},
			{"pcap_next_ex", &procPcapNextEx},
			{"pcap_breakloop", &procPcapBreakloop},
			{"pcap_close", &procPcapClose},
			{"pcap_geterr", &procPcapGetErr},
		}
		for _, fn := range fns {
			*fn.proc, err = pcapDLL.FindProc(fn.name)
			if err != nil {
				pcapLoadErr = fmt.Errorf("wpcap.dll: missing %s: %w", fn.name, err)
				return
			}
		}
		pcapLoaded = true
	})
	return pcapLoadErr
}

// ---------- PcapSniffer implementation ----------

// Start begins capturing packets using Npcap.
// It opens one pcap handle per device (physical NICs + Npcap loopback) so that
// same-machine traffic -- which Windows routes through internal loopback and
// never puts on a physical wire -- is also captured.
func (s *PcapSniffer) Start(handler PacketHandler) error {
	if err := loadPcapLibrary(); err != nil {
		return fmt.Errorf("Npcap: %w", err)
	}

	devices, err := s.findDevices()
	if err != nil {
		return fmt.Errorf("find capture devices: %w", err)
	}

	// Open a pcap handle for every device.
	handles := make([]uintptr, 0, len(devices))
	for _, dev := range devices {
		h, err := s.openDevHandle(dev)
		if err != nil {
			// Clean up already-opened handles before returning.
			for _, oh := range handles {
				procPcapClose.Call(oh)
			}
			return err
		}
		handles = append(handles, h)
	}

	s.mu.Lock()
	s.handles = handles
	s.mu.Unlock()

	// Resolve link-layer header lengths for each device before launching goroutines.
	type devCapture struct {
		handle     uintptr
		linkType   int
		linkHdrLen int
	}
	caps := make([]devCapture, len(handles))
	for i, h := range handles {
		linkTypeRet, _, _ := procPcapDatalink.Call(h)
		lt := int(int32(linkTypeRet))
		lhl := linkHeaderLen(lt)
		if lhl < 0 {
			for _, oh := range handles {
				procPcapClose.Call(oh)
			}
			return fmt.Errorf("unsupported pcap link type %d on device %s", lt, devices[i])
		}
		caps[i] = devCapture{handle: h, linkType: lt, linkHdrLen: lhl}
	}

	// Capture on all devices concurrently; block until all goroutines exit.
	// s.wg is also used by Stop() to wait before calling pcap_close().
	for _, c := range caps {
		s.wg.Add(1)
		go func(dc devCapture) {
			defer s.wg.Done()
			s.captureLoop(dc.handle, handler, dc.linkType, dc.linkHdrLen) //nolint:errcheck
		}(c)
	}
	s.wg.Wait()
	return nil
}

// openDevHandle opens pcap on a single named device, applies the BPF filter,
// and returns the live capture handle.
func (s *PcapSniffer) openDevHandle(dev string) (uintptr, error) {
	var errbuf [256]byte
	devPtr, _ := syscall.BytePtrFromString(dev)
	handle, _, _ := procPcapOpenLive.Call(
		uintptr(unsafe.Pointer(devPtr)),
		uintptr(MaxPacketSize+200),
		0,   // not promiscuous
		200, // timeout in ms
		uintptr(unsafe.Pointer(&errbuf[0])),
	)
	if handle == 0 {
		return 0, fmt.Errorf("pcap_open_live(%s): %s", dev, cstring(errbuf[:]))
	}

	// Build BPF filter: only UDP packets destined to our port.
	filter := fmt.Sprintf("udp dst port %d", s.port)
	filterPtr, _ := syscall.BytePtrFromString(filter)
	var fp bpfProgram
	ret, _, _ := procPcapCompile.Call(
		handle,
		uintptr(unsafe.Pointer(&fp)),
		uintptr(unsafe.Pointer(filterPtr)),
		1, // optimize
		pcapNetmaskUnknown,
	)
	if int32(ret) != 0 {
		errStr := pcapGetErr(handle)
		procPcapClose.Call(handle)
		return 0, fmt.Errorf("pcap_compile(%s): %s", dev, errStr)
	}

	ret, _, _ = procPcapSetFilter.Call(handle, uintptr(unsafe.Pointer(&fp)))
	if int32(ret) != 0 {
		errStr := pcapGetErr(handle)
		procPcapFreeCode.Call(uintptr(unsafe.Pointer(&fp)))
		procPcapClose.Call(handle)
		return 0, fmt.Errorf("pcap_setfilter(%s): %s", dev, errStr)
	}
	procPcapFreeCode.Call(uintptr(unsafe.Pointer(&fp)))
	return handle, nil
}

func (s *PcapSniffer) captureLoop(handle uintptr, handler PacketHandler, linkType, linkHdrLen int) error {
	var hdrPtr unsafe.Pointer  // *pcap_pkthdr (set by pcap_next_ex)
	var dataPtr unsafe.Pointer // *u_char      (set by pcap_next_ex)

	for {
		select {
		case <-s.done:
			return nil
		default:
		}

		ret, _, _ := procPcapNextEx.Call(
			handle,
			uintptr(unsafe.Pointer(&hdrPtr)),
			uintptr(unsafe.Pointer(&dataPtr)),
		)
		switch int32(ret) {
		case 0: // timeout
			continue
		case -2: // breakloop called
			return nil
		case -1: // error
			select {
			case <-s.done:
				return nil
			default:
				return fmt.Errorf("pcap error: %s", pcapGetErr(handle))
			}
		}

		if hdrPtr == nil || dataPtr == nil {
			continue
		}

		hdr := (*pcapPkthdr)(hdrPtr)
		capLen := int(hdr.caplen)
		if capLen <= linkHdrLen {
			continue
		}

		// Copy packet data to Go-managed memory (pcap buffer is reused)
		raw := make([]byte, capLen)
		copy(raw, unsafe.Slice((*byte)(dataPtr), capLen))

		srcIP, payload := parsePcapPacket(raw, linkType, linkHdrLen)
		if payload == nil {
			continue
		}
		if len(payload) < MinPacketSize || len(payload) > MaxPacketSize {
			continue
		}

		handler(payload, srcIP)
	}
}

// Stop terminates the capture on all devices.
func (s *PcapSniffer) Stop() error {
	select {
	case <-s.done:
		return nil
	default:
		close(s.done)
	}

	s.mu.Lock()
	handles := s.handles
	s.handles = nil
	s.mu.Unlock()

	// Signal each capture loop to break out of pcap_next_ex.
	if pcapLoaded {
		for _, h := range handles {
			if h != 0 {
				procPcapBreakloop.Call(h)
			}
		}
	}

	// Wait for all captureLoop goroutines to finish before closing handles.
	// Calling pcap_close() while pcap_next_ex() is still executing on another
	// goroutine corrupts Npcap's internal DLL state, which causes an access
	// violation (0xc0000005) during ExitProcess when DllMain(DETACH) runs.
	s.wg.Wait()

	if pcapLoaded {
		for _, h := range handles {
			if h != 0 {
				procPcapClose.Call(h)
			}
		}
	}
	return nil
}

// findDevices returns the list of pcap device names to capture on.
//
// On Windows, traffic sent from one process to another on the SAME machine is
// routed through the Windows IP-stack loopback path and never appears on
// physical NIC wires.  Npcap's special \Device\NPF_Loopback adapter captures
// this intra-host traffic.  We therefore always include it alongside any
// physical NIC so that knock packets can be received from both remote hosts
// and the local machine.
//
// For wildcard addresses (0.0.0.0 / :: / empty) we capture on ALL routable
// physical NICs plus the loopback adapter.
// For a specific IP we capture on the matching NIC plus the loopback adapter
// (or return an error if the IP is not a local address).
func (s *PcapSniffer) findDevices() ([]string, error) {
	var alldevsPtr unsafe.Pointer
	var errbuf [256]byte

	ret, _, _ := procPcapFindAllDevs.Call(
		uintptr(unsafe.Pointer(&alldevsPtr)),
		uintptr(unsafe.Pointer(&errbuf[0])),
	)
	if int32(ret) != 0 {
		return nil, fmt.Errorf("pcap_findalldevs: %s", cstring(errbuf[:]))
	}
	if alldevsPtr == nil {
		return nil, fmt.Errorf("no capture devices found (check Administrator privileges and Npcap installation)")
	}
	defer procPcapFreeAllDevs.Call(uintptr(alldevsPtr))

	loopbackDev := pcapFindLoopbackDev(alldevsPtr)

	if isWildcardAddr(s.address) {
		// Capture on every physical routable interface plus the Npcap loopback
		// adapter so intra-host knocks are captured as well.
		devs := pcapFindAllRoutableDev(alldevsPtr)
		if loopbackDev != "" {
			devs = appendUnique(devs, loopbackDev)
		}
		if len(devs) == 0 {
			// Absolute fallback: use first device.
			dev := (*pcapIfT)(alldevsPtr)
			devs = []string{goString(dev.name)}
		}
		return devs, nil
	}

	// Find device whose address list contains the requested IP (IPv4 or IPv6).
	targetIP := net.ParseIP(s.address)
	if targetIP == nil {
		return nil, fmt.Errorf("invalid listen address %q", s.address)
	}
	matchDev := ""
outer:
	for devPtr := alldevsPtr; devPtr != nil; {
		dev := (*pcapIfT)(devPtr)
		for addrPtr := dev.addresses; addrPtr != nil; {
			addr := (*pcapAddrT)(addrPtr)
			if addr.addr != nil {
				if ip4 := sockaddrIPv4(addr.addr); ip4 != "" {
					if targetIP.Equal(net.ParseIP(ip4)) {
						matchDev = goString(dev.name)
						break outer
					}
				}
				if ip6 := sockaddrIPv6(addr.addr); ip6 != "" {
					if targetIP.Equal(net.ParseIP(ip6)) {
						matchDev = goString(dev.name)
						break outer
					}
				}
			}
			addrPtr = addr.next
		}
		devPtr = dev.next
	}

	if matchDev == "" {
		// Address not found on any pcap device -- surface a clear error.
		return nil, fmt.Errorf(
			"no Npcap device found with address %s; "+
				"use 0.0.0.0 to capture on all IPv4 interfaces, "+
				"or verify the address is assigned to a local adapter",
			s.address,
		)
	}

	devs := []string{matchDev}
	// Also capture on the Npcap loopback adapter to catch same-machine traffic.
	if loopbackDev != "" && loopbackDev != matchDev {
		devs = append(devs, loopbackDev)
	}
	return devs, nil
}

// testPcap tests if pcap/Npcap is available and working.
func testPcap() error {
	if err := loadPcapLibrary(); err != nil {
		return fmt.Errorf("Npcap not available: %w", err)
	}

	var alldevsPtr unsafe.Pointer
	var errbuf [256]byte
	ret, _, _ := procPcapFindAllDevs.Call(
		uintptr(unsafe.Pointer(&alldevsPtr)),
		uintptr(unsafe.Pointer(&errbuf[0])),
	)
	if int32(ret) != 0 {
		return fmt.Errorf("pcap_findalldevs: %s", cstring(errbuf[:]))
	}
	if alldevsPtr == nil {
		return fmt.Errorf("no capture devices found (check Npcap installation)")
	}
	procPcapFreeAllDevs.Call(uintptr(alldevsPtr))
	return nil
}

// ---------- Helper functions ----------

// pcapGetErr returns the error string from pcap_geterr.
// Note: go vet flags the uintptr->unsafe.Pointer conversion below, but this is
// a known false positive for Windows DLL interop -- the returned uintptr holds
// a C-allocated pointer from the Npcap DLL and is safe to dereference.
func pcapGetErr(handle uintptr) string {
	r1, _, _ := procPcapGetErr.Call(handle)
	p := unsafe.Pointer(r1) //nolint:unsafeptr // C pointer from DLL call
	if p == nil {
		return "unknown pcap error"
	}
	return goString(p)
}

// cstring converts a null-terminated C byte buffer to a Go string.
func cstring(b []byte) string {
	for i, v := range b {
		if v == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// goString reads a null-terminated C string from memory at ptr.
func goString(ptr unsafe.Pointer) string {
	if ptr == nil {
		return ""
	}
	var buf [256]byte
	for i := range buf {
		b := *(*byte)(unsafe.Add(ptr, i))
		if b == 0 {
			return string(buf[:i])
		}
		buf[i] = b
	}
	return string(buf[:])
}

// sockaddrIPv4 extracts an IPv4 address string from a Windows sockaddr pointer.
// Returns "" if the sockaddr is not AF_INET or the pointer is nil.
func sockaddrIPv4(sa unsafe.Pointer) string {
	if sa == nil {
		return ""
	}
	family := *(*uint16)(sa)
	if family != syscall.AF_INET {
		return ""
	}
	// In sockaddr_in: sin_family(2) + sin_port(2) = offset 4 for sin_addr
	addr := *(*[4]byte)(unsafe.Add(sa, 4))
	return net.IPv4(addr[0], addr[1], addr[2], addr[3]).String()
}

// sockaddrIPv6 extracts an IPv6 address string from a Windows sockaddr pointer.
// sockaddr_in6 layout (Windows, LLP64):
//
//	offset 0  : sin6_family   uint16
//	offset 2  : sin6_port     uint16
//	offset 4  : sin6_flowinfo uint32
//	offset 8  : sin6_addr     [16]byte
//	offset 24 : sin6_scope_id uint32
//
// Returns "" if the sockaddr is not AF_INET6 or the pointer is null.
func sockaddrIPv6(sa unsafe.Pointer) string {
	if sa == nil {
		return ""
	}
	family := *(*uint16)(sa)
	if family != syscall.AF_INET6 {
		return ""
	}
	addr := *(*[16]byte)(unsafe.Add(sa, 8))
	return net.IP(addr[:]).String()
}

// pcapFindLoopbackDev returns the name of the Npcap loopback adapter
// (\Device\NPF_Loopback).  This special adapter captures traffic between
// processes on the same Windows machine -- packets that the IP stack routes
// through internal loopback and that never appear on physical NIC wires.
func pcapFindLoopbackDev(alldevsPtr unsafe.Pointer) string {
	const npcapLoopback = `\Device\NPF_Loopback`
	for devPtr := alldevsPtr; devPtr != nil; {
		dev := (*pcapIfT)(devPtr)
		if goString(dev.name) == npcapLoopback {
			return npcapLoopback
		}
		devPtr = dev.next
	}
	return ""
}

// pcapFindAllRoutableDev returns the names of every pcap device that has at
// least one non-loopback, non-link-local IPv4 address.  These are the
// interfaces that receive traffic from external hosts.
func pcapFindAllRoutableDev(alldevsPtr unsafe.Pointer) []string {
	var devs []string
	for devPtr := alldevsPtr; devPtr != nil; {
		dev := (*pcapIfT)(devPtr)
		for addrPtr := dev.addresses; addrPtr != nil; {
			addr := (*pcapAddrT)(addrPtr)
			if addr.addr != nil {
				ipStr := sockaddrIPv4(addr.addr)
				if ipStr != "" {
					ip := net.ParseIP(ipStr)
					if ip != nil && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
						devs = append(devs, goString(dev.name))
						break // one qualifying address is enough for this device
					}
				}
			}
			addrPtr = addr.next
		}
		devPtr = dev.next
	}
	return devs
}

// appendUnique appends s to slice only if it is not already present.
func appendUnique(slice []string, s string) []string {
	for _, v := range slice {
		if v == s {
			return slice
		}
	}
	return append(slice, s)
}
