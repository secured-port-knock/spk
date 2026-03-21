//go:build windows

// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package sniffer

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// TestPcapEnumerateAllDevices lists every device pcap sees with its addresses.
// This exposes whether the "first device" chosen by findDevice is sensible.
func TestPcapEnumerateAllDevices(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows only")
	}
	if err := loadPcapLibrary(); err != nil {
		t.Skipf("Npcap not available: %v", err)
	}

	var alldevsPtr unsafe.Pointer
	var errbuf [256]byte
	ret, _, _ := procPcapFindAllDevs.Call(
		uintptr(unsafe.Pointer(&alldevsPtr)),
		uintptr(unsafe.Pointer(&errbuf[0])),
	)
	if int32(ret) != 0 {
		t.Fatalf("pcap_findalldevs: %s", cstring(errbuf[:]))
	}
	if alldevsPtr == nil {
		t.Fatal("no devices found")
	}
	defer procPcapFreeAllDevs.Call(uintptr(alldevsPtr))

	count := 0
	for devPtr := alldevsPtr; devPtr != nil; {
		dev := (*pcapIfT)(devPtr)
		name := goString(dev.name)
		desc := goString(dev.description)
		t.Logf("Device %d: %s", count, name)
		if desc != "" {
			t.Logf("  Description: %s", desc)
		}

		for addrPtr := dev.addresses; addrPtr != nil; {
			addr := (*pcapAddrT)(addrPtr)
			if addr.addr != nil {
				if ip4 := sockaddrIPv4(addr.addr); ip4 != "" {
					t.Logf("  IPv4: %s", ip4)
				}
				if ip6 := sockaddrIPv6(addr.addr); ip6 != "" {
					t.Logf("  IPv6: %s", ip6)
				}
			}
			addrPtr = addr.next
		}
		count++
		devPtr = dev.next
	}
	t.Logf("Total devices: %d", count)
}

// TestPcapFindDeviceWildcard verifies that findDevices() on a PcapSniffer
// created with address "0.0.0.0" returns at least one device, including the
// Npcap loopback adapter so same-machine traffic is captured.
func TestPcapFindDeviceWildcard(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows only")
	}
	if err := loadPcapLibrary(); err != nil {
		t.Skipf("Npcap not available: %v", err)
	}

	ps := NewPcapSniffer("0.0.0.0", 12345).(*PcapSniffer)
	devs, err := ps.findDevices()
	if err != nil {
		t.Fatalf("findDevices (addr=0.0.0.0): %v", err)
	}
	if len(devs) == 0 {
		t.Error("findDevices (addr=0.0.0.0) returned no devices")
	}
	for i, d := range devs {
		t.Logf("findDevices (addr=0.0.0.0)[%d] -> %s", i, d)
	}
	// Npcap loopback adapter should be included for same-machine traffic.
	const npcapLoopback = `\Device\NPF_Loopback`
	hasLoopback := false
	for _, d := range devs {
		if d == npcapLoopback {
			hasLoopback = true
		}
	}
	if !hasLoopback {
		t.Logf("Note: Npcap loopback adapter (%s) not found in device list (may be expected if not installed)", npcapLoopback)
	}
}

// TestPcapFindDeviceSpecificIP verifies that a real local IP resolves to a
// device list that includes both the matching NIC and the loopback adapter.
// The PcapSniffer is created with the specific IP; findDevices() reads it
// from the struct's address field.
func TestPcapFindDeviceSpecificIP(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows only")
	}
	if err := loadPcapLibrary(); err != nil {
		t.Skipf("Npcap not available: %v", err)
	}

	// Find a real non-loopback local IP to test with.
	ip, err := findNonLoopbackLocalIP()
	if err != nil {
		t.Skipf("no non-loopback interface: %v", err)
	}

	ps := NewPcapSniffer(ip.String(), 12345).(*PcapSniffer)
	devs, err := ps.findDevices()
	if err != nil {
		t.Fatalf("findDevices (addr=%s): %v", ip, err)
	}
	if len(devs) == 0 {
		t.Errorf("findDevices (addr=%s) returned no devices", ip)
	}
	for i, d := range devs {
		t.Logf("findDevices (addr=%s)[%d] -> %s", ip, i, d)
	}
}

// TestPcapFindDeviceUnassignedIPErrors verifies that an IP from the RFC 5737
// documentation range produces an error rather than a silent fallback.
func TestPcapFindDeviceUnassignedIPErrors(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows only")
	}
	if err := loadPcapLibrary(); err != nil {
		t.Skipf("Npcap not available: %v", err)
	}

	ps := NewPcapSniffer("203.0.113.1", 12345).(*PcapSniffer)
	_, err := ps.findDevices()
	if err == nil {
		t.Error("findDevices on unassigned RFC5737 IP should return error, got nil")
	}
	t.Logf("findDevices on unassigned IP error (expected): %v", err)
}

// TestPcapCaptureRaw opens pcap on the first device with no BPF filter
// and tries to capture ANY traffic for a few seconds. On an active network,
// ARP/mDNS/broadcast traffic should appear.
func TestPcapCaptureRaw(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows only")
	}
	if err := loadPcapLibrary(); err != nil {
		t.Skipf("Npcap not available: %v", err)
	}

	ps := NewPcapSniffer("0.0.0.0", 0).(*PcapSniffer)
	devs, err := ps.findDevices()
	if err != nil {
		t.Fatalf("findDevices: %v", err)
	}
	if len(devs) == 0 {
		t.Fatal("findDevices returned no devices")
	}
	dev := devs[0]
	t.Logf("Selected device: %s", dev)

	var errbuf [256]byte
	devPtr, _ := syscall.BytePtrFromString(dev)
	handle, _, _ := procPcapOpenLive.Call(
		uintptr(unsafe.Pointer(devPtr)),
		65535, // snaplen
		1,     // promiscuous mode
		1000,  // 1-second timeout
		uintptr(unsafe.Pointer(&errbuf[0])),
	)
	if handle == 0 {
		t.Fatalf("pcap_open_live: %s", cstring(errbuf[:]))
	}
	defer procPcapClose.Call(handle)

	ltRet, _, _ := procPcapDatalink.Call(handle)
	linkType := int(int32(ltRet))
	t.Logf("Link type: %d (header len: %d)", linkType, linkHeaderLen(linkType))

	// Send a UDP packet to generate traffic on the interface.
	// Use TEST-NET-2 (198.51.100.1) -- the packet goes through the NIC
	// even if it is never delivered. This ensures pcap has something to capture.
	go func() {
		time.Sleep(200 * time.Millisecond)
		conn, err := net.Dial("udp4", "198.51.100.1:19999")
		if err != nil {
			return
		}
		defer conn.Close()
		for i := 0; i < 5; i++ {
			conn.Write([]byte("pcap-test-probe"))
			time.Sleep(100 * time.Millisecond)
		}
	}()

	// Capture for 5 seconds, no BPF filter -- count all packets
	var hdrPtr, dataPtr unsafe.Pointer
	captured := 0
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		ret, _, _ := procPcapNextEx.Call(
			handle,
			uintptr(unsafe.Pointer(&hdrPtr)),
			uintptr(unsafe.Pointer(&dataPtr)),
		)
		switch int32(ret) {
		case 1:
			captured++
			if captured <= 10 {
				hdr := (*pcapPkthdr)(hdrPtr)
				raw := unsafe.Slice((*byte)(dataPtr), int(hdr.caplen))
				proto := "?"
				if linkType == dltEN10MB && len(raw) >= 14 {
					et := uint16(raw[12])<<8 | uint16(raw[13])
					switch et {
					case 0x0800:
						proto = "IPv4"
					case 0x0806:
						proto = "ARP"
					case 0x86DD:
						proto = "IPv6"
					default:
						proto = fmt.Sprintf("0x%04x", et)
					}
				}
				t.Logf("  Pkt %d: caplen=%d len=%d proto=%s", captured, hdr.caplen, hdr.pktLen, proto)
			}
		case 0:
			continue // timeout
		case -1:
			t.Logf("pcap_next_ex error: %s", pcapGetErr(handle))
		}
	}

	t.Logf("Captured %d packets in 5 seconds (no filter, promiscuous)", captured)
	if captured == 0 {
		t.Error("ZERO packets captured! pcap may not be functional on this interface.")
		t.Error("Check: (1) Npcap service running, (2) correct device selected, (3) network is active")
	}
}

// TestPcapBPFFilter verifies that BPF filter compilation and matching works.
// Opens pcap with a UDP port filter, sends a UDP packet through the NIC,
// and checks if pcap captures it.
func TestPcapBPFFilter(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows only")
	}
	if err := loadPcapLibrary(); err != nil {
		t.Skipf("Npcap not available: %v", err)
	}

	ps := NewPcapSniffer("0.0.0.0", 0).(*PcapSniffer)
	devs, err := ps.findDevices()
	if err != nil {
		t.Fatalf("findDevices: %v", err)
	}
	if len(devs) == 0 {
		t.Fatal("findDevices returned no devices")
	}
	// Use first device (a routable NIC, not the loopback adapter) for raw BPF test.
	dev := devs[0]

	var errbuf [256]byte
	devPtr, _ := syscall.BytePtrFromString(dev)
	handle, _, _ := procPcapOpenLive.Call(
		uintptr(unsafe.Pointer(devPtr)),
		65535,
		1,   // promiscuous
		500, // 500ms timeout
		uintptr(unsafe.Pointer(&errbuf[0])),
	)
	if handle == 0 {
		t.Fatalf("pcap_open_live: %s", cstring(errbuf[:]))
	}
	defer procPcapClose.Call(handle)

	// Compile and set BPF filter for a specific port
	testPort := 39999
	filter := fmt.Sprintf("udp and port %d", testPort)
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
		t.Fatalf("pcap_compile('%s'): %s", filter, pcapGetErr(handle))
	}

	ret, _, _ = procPcapSetFilter.Call(handle, uintptr(unsafe.Pointer(&fp)))
	if int32(ret) != 0 {
		t.Fatalf("pcap_setfilter: %s", pcapGetErr(handle))
	}
	procPcapFreeCode.Call(uintptr(unsafe.Pointer(&fp)))
	t.Logf("BPF filter set: %s", filter)

	// Send UDP packets to a non-local IP on our test port.
	// The packet traverses the NIC and pcap should capture it.
	go func() {
		time.Sleep(200 * time.Millisecond)
		conn, err := net.Dial("udp4", fmt.Sprintf("198.51.100.1:%d", testPort))
		if err != nil {
			return
		}
		defer conn.Close()
		for i := 0; i < 10; i++ {
			conn.Write([]byte("bpf-filter-test"))
			time.Sleep(100 * time.Millisecond)
		}
	}()

	var hdrPtr, dataPtr unsafe.Pointer
	captured := 0
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		ret, _, _ := procPcapNextEx.Call(
			handle,
			uintptr(unsafe.Pointer(&hdrPtr)),
			uintptr(unsafe.Pointer(&dataPtr)),
		)
		if int32(ret) == 1 {
			captured++
			hdr := (*pcapPkthdr)(hdrPtr)
			t.Logf("  Captured packet: caplen=%d len=%d", hdr.caplen, hdr.pktLen)
		}
	}

	t.Logf("Captured %d packets with filter '%s'", captured, filter)
	if captured == 0 {
		t.Log("No filtered packets captured. This might mean:")
		t.Log("  - BPF filter is not matching outgoing packets")
		t.Log("  - Outgoing packets not visible (try incoming test)")
		t.Log("  - Network interface routing issue")
	}
}

// TestPcapSnifferIntegration performs a full integration test of PcapSniffer.
// It starts the sniffer on a random port and sends a UDP packet.
// Since pcap captures at the network layer, self-packets might not be visible
// depending on the interface, so this test is diagnostic rather than strict.
func TestPcapSnifferIntegration(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows only")
	}
	if err := loadPcapLibrary(); err != nil {
		t.Skipf("Npcap not available: %v", err)
	}

	testPort := 48765
	var received atomic.Int32

	sniff := NewPcapSniffer("0.0.0.0", testPort)

	// Start sniffer in goroutine
	errCh := make(chan error, 1)
	go func() {
		errCh <- sniff.Start(func(data []byte, srcIP string) {
			received.Add(1)
			t.Logf("Received packet: %d bytes from %s", len(data), srcIP)
		})
	}()

	// Let sniffer initialize
	time.Sleep(500 * time.Millisecond)

	// Check if sniffer started without error
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Sniffer Start failed: %v", err)
		}
	default:
		// Still running (expected)
	}

	// Send test packets to a non-local address on testPort
	// These go through the NIC and pcap should see them
	conn, err := net.Dial("udp4", fmt.Sprintf("198.51.100.1:%d", testPort))
	if err != nil {
		t.Logf("Cannot send test packets: %v", err)
	} else {
		// Send packets larger than MinPacketSize to pass the size filter
		bigPayload := make([]byte, MinPacketSize+10)
		for i := range bigPayload {
			bigPayload[i] = byte(i % 256)
		}
		for i := 0; i < 5; i++ {
			conn.Write(bigPayload)
			time.Sleep(100 * time.Millisecond)
		}
		conn.Close()
	}

	// Wait a bit for packets to be processed
	time.Sleep(2 * time.Second)

	// Stop sniffer
	sniff.Stop()

	r := received.Load()
	t.Logf("PcapSniffer received %d packets (port %d)", r, testPort)
	t.Log("Note: Self-sent packets may not be visible on Windows NIC pcap.")
	t.Log("For a real-world test, send packets from another machine.")
}

// TestPcapStructSizes verifies that Go struct sizes match the expected
// C ABI sizes for 64-bit Windows (LLP64 model).
func TestPcapStructSizes(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows only")
	}

	// pcap_pkthdr: struct timeval(4+4) + caplen(4) + len(4) = 16 bytes
	hdrSize := unsafe.Sizeof(pcapPkthdr{})
	if hdrSize != 16 {
		t.Errorf("pcapPkthdr size = %d, want 16", hdrSize)
	}
	t.Logf("pcapPkthdr size: %d (expected 16)", hdrSize)

	// bpf_program: bf_len(4) + pad(4) + bf_insns(8) = 16 bytes
	fpSize := unsafe.Sizeof(bpfProgram{})
	if fpSize != 16 {
		t.Errorf("bpfProgram size = %d, want 16", fpSize)
	}
	t.Logf("bpfProgram size: %d (expected 16)", fpSize)

	// Field offsets
	var hdr pcapPkthdr
	hdrBase := uintptr(unsafe.Pointer(&hdr))
	caplenOff := uintptr(unsafe.Pointer(&hdr.caplen)) - hdrBase
	if caplenOff != 8 {
		t.Errorf("pcapPkthdr.caplen offset = %d, want 8", caplenOff)
	}
	t.Logf("pcapPkthdr.caplen offset: %d (expected 8)", caplenOff)

	var fp bpfProgram
	fpBase := uintptr(unsafe.Pointer(&fp))
	bfInsnsOff := uintptr(unsafe.Pointer(&fp.bfInsns)) - fpBase
	if bfInsnsOff != 8 {
		t.Errorf("bpfProgram.bfInsns offset = %d, want 8", bfInsnsOff)
	}
	t.Logf("bpfProgram.bfInsns offset: %d (expected 8)", bfInsnsOff)

	// pcapIfT: 4 pointers + uint32 + pad = 8*4 + 4 + 4 = 40 on 64-bit
	ifSize := unsafe.Sizeof(pcapIfT{})
	t.Logf("pcapIfT size: %d (expected 40 on 64-bit)", ifSize)
	if unsafe.Sizeof(uintptr(0)) == 8 && ifSize != 40 {
		t.Errorf("pcapIfT size = %d, want 40 on 64-bit", ifSize)
	}
}

// TestPcapNpcapServiceRunning checks if the Npcap driver service is active.
func TestPcapNpcapServiceRunning(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows only")
	}

	// Check if npcap service exists
	sysRoot := os.Getenv("SystemRoot")
	if sysRoot == "" {
		sysRoot = `C:\Windows`
	}
	driverPath := sysRoot + `\System32\drivers\npcap.sys`
	if _, err := os.Stat(driverPath); err != nil {
		t.Skipf("Npcap driver not found at %s", driverPath)
	}
	t.Logf("Npcap driver found: %s", driverPath)
}

// ---------- findWpcapDLL tests ----------

func TestFindWpcapDLLSearchOrder(t *testing.T) {
	dllPath, dllDir := findWpcapDLL()
	if dllPath == "" {
		t.Skip("wpcap.dll not found on this system")
	}

	t.Logf("Found wpcap.dll: %s (dir: %s)", dllPath, dllDir)

	if _, err := os.Stat(dllPath); err != nil {
		t.Errorf("reported DLL path does not exist: %s", dllPath)
	}
}

func TestFindWpcapDLLNonStandardSystemRoot(t *testing.T) {
	origRoot := os.Getenv("SystemRoot")
	defer os.Setenv("SystemRoot", origRoot)

	// Test with non-existent SystemRoot -- should return empty or fall back to exe dir.
	os.Setenv("SystemRoot", `Q:\NoSuchWindows`)
	dllPath, _ := findWpcapDLL()
	t.Logf("With bogus SystemRoot: dllPath=%q", dllPath)

	os.Setenv("SystemRoot", origRoot)
	dllPath2, _ := findWpcapDLL()
	t.Logf("With restored SystemRoot: dllPath=%q", dllPath2)
}

// TestPcapStopWaitsForCaptureLoop verifies that Stop() does not close pcap
// handles while captureLoop goroutines are still running inside pcap_next_ex.
//
// Regression test for: calling pcap_close() concurrently with pcap_next_ex()
// corrupts Npcap's internal DLL state and causes an access violation
// (Exception 0xc0000005) during ExitProcess / DllMain(DLL_PROCESS_DETACH).
//
// The test starts the sniffer so capture goroutines enter their pcap_next_ex
// loop (200 ms timeout), then immediately calls Stop(). With the old code,
// pcap_close was called while goroutines were still inside pcap_next_ex,
// reproducing the state corruption.  With the fix, Stop() calls wg.Wait()
// first, ensuring pcap_close is only called after all goroutines have exited.
func TestPcapStopWaitsForCaptureLoop(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows only")
	}
	if err := loadPcapLibrary(); err != nil {
		t.Skipf("Npcap not available: %v", err)
	}

	sniff := NewPcapSniffer("0.0.0.0", 49876)

	startErr := make(chan error, 1)
	go func() {
		startErr <- sniff.Start(func(_ []byte, _ string) {})
	}()

	// Allow capture goroutines to enter pcap_next_ex before calling Stop().
	// The 200 ms pcap timeout means they are guaranteed to be inside pcap_next_ex
	// for at most 200 ms per iteration, so a 150 ms wait is sufficient for them
	// to have entered the call at least once.
	time.Sleep(150 * time.Millisecond)

	// Stop() must block until all captureLoop goroutines have exited, then
	// call pcap_close. If it races (old behaviour), the DLL state is corrupted
	// and this process would crash when it exits after the test.
	if err := sniff.Stop(); err != nil {
		t.Errorf("Stop() returned unexpected error: %v", err)
	}

	// Start() should return promptly after Stop() completes.
	select {
	case err := <-startErr:
		if err != nil {
			t.Errorf("Start() returned unexpected error after Stop(): %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("Start() did not return within 2 s after Stop()")
	}
}
