//go:build (linux || darwin) && cgo

// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package sniffer

/*
#cgo linux LDFLAGS: -ldl

#include <dlfcn.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// ---------- Minimal pcap ABI definitions ----------
// These match the libpcap ABI since version 0.8 (2002).
// No pcap.h header is needed -- the library is loaded at runtime via dlopen.

typedef unsigned int bpf_u_int32;
typedef unsigned char u_char;
typedef void pcap_t;

struct pcap_if_s {
    struct pcap_if_s *next;
    char *name;
    char *description;
    struct pcap_addr_s *addresses;
    bpf_u_int32 flags;
};

struct pcap_addr_s {
    struct pcap_addr_s *next;
    struct sockaddr *addr;
    struct sockaddr *netmask;
    struct sockaddr *broadaddr;
    struct sockaddr *dstaddr;
};

struct pcap_pkthdr_s {
    struct timeval ts;
    bpf_u_int32 caplen;
    bpf_u_int32 len;
};

struct bpf_insn_s {
    unsigned short code;
    unsigned char jt;
    unsigned char jf;
    bpf_u_int32 k;
};

struct bpf_program_s {
    unsigned int bf_len;
    struct bpf_insn_s *bf_insns;
};

// ---------- Function pointer types ----------

typedef int   (*fn_pcap_findalldevs)(struct pcap_if_s**, char*);
typedef void  (*fn_pcap_freealldevs)(struct pcap_if_s*);
typedef pcap_t* (*fn_pcap_open_live)(const char*, int, int, int, char*);
typedef int   (*fn_pcap_compile)(pcap_t*, struct bpf_program_s*, const char*, int, bpf_u_int32);
typedef int   (*fn_pcap_setfilter)(pcap_t*, struct bpf_program_s*);
typedef void  (*fn_pcap_freecode)(struct bpf_program_s*);
typedef int   (*fn_pcap_datalink)(pcap_t*);
typedef int   (*fn_pcap_next_ex)(pcap_t*, struct pcap_pkthdr_s**, const u_char**);
typedef void  (*fn_pcap_breakloop)(pcap_t*);
typedef void  (*fn_pcap_close)(pcap_t*);
typedef char* (*fn_pcap_geterr)(pcap_t*);

// ---------- Resolved function pointers ----------

static void* pcap_dl = NULL;
static fn_pcap_findalldevs  p_findalldevs;
static fn_pcap_freealldevs  p_freealldevs;
static fn_pcap_open_live    p_open_live;
static fn_pcap_compile      p_compile;
static fn_pcap_setfilter    p_setfilter;
static fn_pcap_freecode     p_freecode;
static fn_pcap_datalink     p_datalink;
static fn_pcap_next_ex      p_next_ex;
static fn_pcap_breakloop    p_breakloop;
static fn_pcap_close        p_close;
static fn_pcap_geterr       p_geterr;
static const char* pcap_dl_error = NULL;

// pcap_dyn_load opens the libpcap shared library and resolves symbols.
// Returns 0 on success, -1 on failure.
int pcap_dyn_load(void) {
    if (pcap_dl) return 0;

    // Try multiple library names for broad compatibility.
    // Covers libpcap from 0.8 (2002) through current versions.
    const char* names[] = {
#ifdef __APPLE__
        "libpcap.dylib",
        "libpcap.A.dylib",
        "/usr/lib/libpcap.dylib",
        "/usr/lib/libpcap.A.dylib",
        "/opt/homebrew/lib/libpcap.dylib",
#else
        "libpcap.so.1",
        "libpcap.so.0.8",
        "libpcap.so",
        "/usr/lib/x86_64-linux-gnu/libpcap.so.1",
        "/usr/lib/x86_64-linux-gnu/libpcap.so",
        "/usr/lib/aarch64-linux-gnu/libpcap.so.1",
        "/usr/lib/aarch64-linux-gnu/libpcap.so",
        "/usr/lib64/libpcap.so.1",
        "/usr/lib64/libpcap.so",
        "/usr/lib/libpcap.so.1",
        "/usr/lib/libpcap.so",
#endif
        NULL
    };

    int i;
    for (i = 0; names[i]; i++) {
        pcap_dl = dlopen(names[i], RTLD_LAZY);
        if (pcap_dl) break;
    }
    if (!pcap_dl) {
        pcap_dl_error = dlerror();
        return -1;
    }

    p_findalldevs = (fn_pcap_findalldevs)dlsym(pcap_dl, "pcap_findalldevs");
    p_freealldevs = (fn_pcap_freealldevs)dlsym(pcap_dl, "pcap_freealldevs");
    p_open_live   = (fn_pcap_open_live)dlsym(pcap_dl, "pcap_open_live");
    p_compile     = (fn_pcap_compile)dlsym(pcap_dl, "pcap_compile");
    p_setfilter   = (fn_pcap_setfilter)dlsym(pcap_dl, "pcap_setfilter");
    p_freecode    = (fn_pcap_freecode)dlsym(pcap_dl, "pcap_freecode");
    p_datalink    = (fn_pcap_datalink)dlsym(pcap_dl, "pcap_datalink");
    p_next_ex     = (fn_pcap_next_ex)dlsym(pcap_dl, "pcap_next_ex");
    p_breakloop   = (fn_pcap_breakloop)dlsym(pcap_dl, "pcap_breakloop");
    p_close       = (fn_pcap_close)dlsym(pcap_dl, "pcap_close");
    p_geterr      = (fn_pcap_geterr)dlsym(pcap_dl, "pcap_geterr");

    // Verify critical functions are present
    if (!p_findalldevs || !p_open_live || !p_next_ex || !p_close) {
        pcap_dl_error = "required pcap functions not found in library";
        dlclose(pcap_dl);
        pcap_dl = NULL;
        return -1;
    }
    return 0;
}

const char* pcap_dyn_error(void) {
    return pcap_dl_error ? pcap_dl_error : "unknown error";
}

// ---------- Wrapper functions callable from Go ----------

int wrap_pcap_findalldevs(struct pcap_if_s** alldevs, char* errbuf) {
    if (!p_findalldevs) return -1;
    return p_findalldevs(alldevs, errbuf);
}

void wrap_pcap_freealldevs(struct pcap_if_s* alldevs) {
    if (p_freealldevs) p_freealldevs(alldevs);
}

void* wrap_pcap_open_live(const char* dev, int snaplen, int promisc, int timeout, char* errbuf) {
    if (!p_open_live) return NULL;
    return (void*)p_open_live(dev, snaplen, promisc, timeout, errbuf);
}

int wrap_pcap_compile(void* handle, struct bpf_program_s* fp, const char* str, int optimize, unsigned int netmask) {
    if (!p_compile) return -1;
    return p_compile((pcap_t*)handle, fp, str, optimize, netmask);
}

int wrap_pcap_setfilter(void* handle, struct bpf_program_s* fp) {
    if (!p_setfilter) return -1;
    return p_setfilter((pcap_t*)handle, fp);
}

void wrap_pcap_freecode(struct bpf_program_s* fp) {
    if (p_freecode) p_freecode(fp);
}

int wrap_pcap_datalink(void* handle) {
    if (!p_datalink) return -1;
    return p_datalink((pcap_t*)handle);
}

// wrap_pcap_next_packet calls pcap_next_ex and returns results via out params.
// Returns: 1=packet, 0=timeout, -1=error, -2=breakloop.
// On success (ret=1), *caplen and *data_out are set.
int wrap_pcap_next_packet(void* handle, unsigned int* caplen, unsigned char** data_out) {
    struct pcap_pkthdr_s* hdr = NULL;
    const u_char* data = NULL;
    int ret;
    if (!p_next_ex) return -1;
    ret = p_next_ex((pcap_t*)handle, &hdr, &data);
    if (ret == 1 && hdr && data) {
        *caplen = hdr->caplen;
        *data_out = (unsigned char*)data;
    }
    return ret;
}

void wrap_pcap_breakloop(void* handle) {
    if (p_breakloop) p_breakloop((pcap_t*)handle);
}

void wrap_pcap_close(void* handle) {
    if (p_close) p_close((pcap_t*)handle);
}

const char* wrap_pcap_geterr(void* handle) {
    if (!p_geterr) return "pcap library not loaded";
    return p_geterr((pcap_t*)handle);
}

// ---------- Struct field accessor helpers ----------

const char* pcap_if_name(struct pcap_if_s* dev) {
    return dev ? dev->name : NULL;
}

struct pcap_if_s* pcap_if_next(struct pcap_if_s* dev) {
    return dev ? dev->next : NULL;
}

struct pcap_addr_s* pcap_if_addresses(struct pcap_if_s* dev) {
    return dev ? dev->addresses : NULL;
}

struct pcap_addr_s* pcap_addr_next(struct pcap_addr_s* a) {
    return a ? a->next : NULL;
}

struct sockaddr* pcap_addr_addr(struct pcap_addr_s* a) {
    return a ? a->addr : NULL;
}

// sockaddr_ipv4_str extracts an IPv4 address string from a sockaddr.
// Returns 0 on success, -1 if not AF_INET or on error.
int sockaddr_ipv4_str(struct sockaddr* sa, char* buf, int buflen) {
    if (!sa || !buf || buflen < 16) return -1;
    if (sa->sa_family != AF_INET) return -1;
    struct sockaddr_in* sin = (struct sockaddr_in*)sa;
    unsigned char* ip = (unsigned char*)&sin->sin_addr;
    snprintf(buf, buflen, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
    return 0;
}

// sockaddr_ipv6_str extracts an IPv6 address string from a sockaddr.
// Returns 0 on success, -1 if not AF_INET6 or on error.
int sockaddr_ipv6_str(struct sockaddr* sa, char* buf, int buflen) {
    if (!sa || !buf || buflen < 40) return -1;
    if (sa->sa_family != AF_INET6) return -1;
    // Inline inet_ntop for AF_INET6 to avoid linking against additional libs.
    // sa_data layout for AF_INET6 (POSIX sockaddr_in6):
    //   sin6_family   2 bytes
    //   sin6_port     2 bytes
    //   sin6_flowinfo 4 bytes
    //   sin6_addr    16 bytes  <- offset 8
    //   sin6_scope_id 4 bytes
    struct sockaddr_in6* sin6 = (struct sockaddr_in6*)sa;
    if (inet_ntop(AF_INET6, &sin6->sin6_addr, buf, buflen) == NULL) return -1;
    return 0;
}
*/
import "C"

import (
	"fmt"
	"net"
	"sync"
	"unsafe"
)

// PcapSniffer captures packets using libpcap on Linux/macOS.
// The library is loaded dynamically at runtime via dlopen -- no pcap headers
// or development packages are needed at build time (only dlfcn.h from libc).
// Stealth mode: the listen port is not opened on the system.
//
// Requirements:
//   - libpcap installed on the target machine (runtime only)
//   - Root or CAP_NET_RAW capability
type PcapSniffer struct {
	address string
	port    int
	handle  unsafe.Pointer // pcap_t* opaque handle
	done    chan struct{}
	mu      sync.Mutex
	// wg tracks the active Start() goroutine so Stop() can wait for it to
	// exit before calling pcap_close(), preventing concurrent pcap_close /
	// pcap_next_ex use that corrupts libpcap's internal state.
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

// pcapImplemented returns true when built with CGO (library loaded at runtime).
func pcapImplemented() bool { return true }

var (
	pcapLoadOnce sync.Once
	pcapLoadErr  error
)

func loadPcapLibrary() error {
	pcapLoadOnce.Do(func() {
		if C.pcap_dyn_load() != 0 {
			pcapLoadErr = fmt.Errorf("dlopen libpcap: %s", C.GoString(C.pcap_dyn_error()))
		}
	})
	return pcapLoadErr
}

// Start begins capturing packets using libpcap.
func (s *PcapSniffer) Start(handler PacketHandler) error {
	if err := loadPcapLibrary(); err != nil {
		return fmt.Errorf("libpcap: %w", err)
	}

	// Track this goroutine so Stop() can wait before calling pcap_close().
	s.wg.Add(1)
	defer s.wg.Done()

	dev, err := s.findDevice()
	if err != nil {
		return fmt.Errorf("find capture device: %w", err)
	}

	var errbuf [256]C.char
	cdev := C.CString(dev)
	defer C.free(unsafe.Pointer(cdev))

	// pcap_open_live(device, snaplen, promisc, timeout_ms, errbuf)
	handle := C.wrap_pcap_open_live(cdev, C.int(MaxPacketSize+200), 0, 200, &errbuf[0])
	if handle == nil {
		return fmt.Errorf("pcap_open_live(%s): %s", dev, C.GoString(&errbuf[0]))
	}

	s.mu.Lock()
	s.handle = handle
	s.mu.Unlock()

	// Set BPF filter: only UDP packets destined to our port
	filter := fmt.Sprintf("udp dst port %d", s.port)
	cfilter := C.CString(filter)
	defer C.free(unsafe.Pointer(cfilter))

	var fp C.struct_bpf_program_s
	if C.wrap_pcap_compile(handle, &fp, cfilter, 1, C.uint(0xffffffff)) != 0 {
		errStr := C.GoString(C.wrap_pcap_geterr(handle))
		C.wrap_pcap_close(handle)
		return fmt.Errorf("pcap_compile: %s", errStr)
	}

	if C.wrap_pcap_setfilter(handle, &fp) != 0 {
		errStr := C.GoString(C.wrap_pcap_geterr(handle))
		C.wrap_pcap_freecode(&fp)
		C.wrap_pcap_close(handle)
		return fmt.Errorf("pcap_setfilter: %s", errStr)
	}
	C.wrap_pcap_freecode(&fp)

	// Determine link-layer type
	linkType := int(C.wrap_pcap_datalink(handle))
	linkHdrLen := linkHeaderLen(linkType)
	if linkHdrLen < 0 {
		C.wrap_pcap_close(handle)
		return fmt.Errorf("unsupported pcap link type: %d", linkType)
	}

	// Packet capture loop
	var capLen C.uint
	var pktData *C.uchar

	for {
		select {
		case <-s.done:
			return nil
		default:
		}

		ret := C.wrap_pcap_next_packet(handle, &capLen, &pktData)
		switch ret {
		case 0: // timeout
			continue
		case -2: // breakloop called
			return nil
		case -1: // error
			select {
			case <-s.done:
				return nil
			default:
				return fmt.Errorf("pcap error: %s", C.GoString(C.wrap_pcap_geterr(handle)))
			}
		}

		cl := int(capLen)
		if cl <= linkHdrLen {
			continue
		}

		// Copy packet data to Go memory (pcap buffer is reused)
		raw := C.GoBytes(unsafe.Pointer(pktData), C.int(capLen))

		// Parse packet: link layer -> IP -> UDP -> payload
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

// Stop terminates the capture.
func (s *PcapSniffer) Stop() error {
	select {
	case <-s.done:
		return nil
	default:
		close(s.done)
	}

	s.mu.Lock()
	h := s.handle
	s.handle = nil
	s.mu.Unlock()

	// Signal the capture loop to return from pcap_next_ex.
	if h != nil {
		C.wrap_pcap_breakloop(h)
	}

	// Wait for Start() to fully exit before calling pcap_close().
	// pcap_close() frees the pcap_t; calling it while pcap_next_ex() is
	// still running on another goroutine is a use-after-free.
	s.wg.Wait()

	if h != nil {
		C.wrap_pcap_close(h)
	}
	return nil
}

// findDevice selects the pcap capture device matching the bind address.
// For wildcard addresses (0.0.0.0, ::, empty) it prefers the Linux "any"
// device (captures all interfaces) and falls back to default-route selection.
// For a specific IP it scans all device addresses (IPv4 and IPv6) for an
// exact match and returns an error rather than silently falling back.
func (s *PcapSniffer) findDevice() (string, error) {
	var alldevs *C.struct_pcap_if_s
	var errbuf [256]C.char

	if C.wrap_pcap_findalldevs(&alldevs, &errbuf[0]) != 0 {
		return "", fmt.Errorf("pcap_findalldevs: %s", C.GoString(&errbuf[0]))
	}
	defer C.wrap_pcap_freealldevs(alldevs)

	if alldevs == nil {
		return "", fmt.Errorf("no capture devices found (check root/admin permissions and libpcap installation)")
	}

	// Binding to all interfaces
	if isWildcardAddr(s.address) {
		// Prefer "any" device on Linux (captures all interfaces, IPv4 + IPv6)
		for dev := alldevs; dev != nil; dev = C.pcap_if_next(dev) {
			name := C.GoString(C.pcap_if_name(dev))
			if name == "any" {
				return name, nil
			}
		}
		// No "any" device (macOS). Find device matching default route.
		if dev := pcapFindDefaultRouteDevUnix(alldevs); dev != "" {
			return dev, nil
		}
		return C.GoString(C.pcap_if_name(alldevs)), nil
	}

	// Find device whose address list contains the requested IP (IPv4 or IPv6).
	targetIP := net.ParseIP(s.address)
	if targetIP == nil {
		return "", fmt.Errorf("invalid listen address %q", s.address)
	}
	for dev := alldevs; dev != nil; dev = C.pcap_if_next(dev) {
		for addr := C.pcap_if_addresses(dev); addr != nil; addr = C.pcap_addr_next(addr) {
			sa := C.pcap_addr_addr(addr)
			if sa == nil {
				continue
			}
			// Check IPv4
			var buf4 [64]C.char
			if C.sockaddr_ipv4_str(sa, &buf4[0], 64) == 0 {
				if targetIP.Equal(net.ParseIP(C.GoString(&buf4[0]))) {
					return C.GoString(C.pcap_if_name(dev)), nil
				}
			}
			// Check IPv6
			var buf6 [64]C.char
			if C.sockaddr_ipv6_str(sa, &buf6[0], 64) == 0 {
				if targetIP.Equal(net.ParseIP(C.GoString(&buf6[0]))) {
					return C.GoString(C.pcap_if_name(dev)), nil
				}
			}
		}
	}

	// Address not found on any pcap device -- surface a clear error.
	return "", fmt.Errorf(
		"no pcap device found with address %s; "+
			"use 0.0.0.0 for all IPv4 interfaces, :: for all IPv6, "+
			"or verify the address is assigned to a local interface",
		s.address,
	)
}

// pcapFindDefaultRouteDevUnix finds the pcap device matching the OS default
// outbound IP. Used on macOS which lacks the Linux "any" device.
func pcapFindDefaultRouteDevUnix(alldevs *C.struct_pcap_if_s) string {
	conn, err := net.Dial("udp4", "8.8.8.8:53")
	if err != nil {
		return ""
	}
	defer conn.Close()
	localAddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || localAddr.IP == nil {
		return ""
	}
	localIP := localAddr.IP

	for dev := alldevs; dev != nil; dev = C.pcap_if_next(dev) {
		for addr := C.pcap_if_addresses(dev); addr != nil; addr = C.pcap_addr_next(addr) {
			sa := C.pcap_addr_addr(addr)
			if sa == nil {
				continue
			}
			var buf [64]C.char
			if C.sockaddr_ipv4_str(sa, &buf[0], 64) == 0 {
				devIP := C.GoString(&buf[0])
				if localIP.Equal(net.ParseIP(devIP)) {
					return C.GoString(C.pcap_if_name(dev))
				}
			}
		}
	}
	return ""
}

// pcapDevInfo holds metadata for a single pcap-visible network interface.
// Used by tests without requiring import "C" in test files.
type pcapDevInfo struct {
	Name  string
	IPv4s []string
	IPv6s []string
}

// pcapListDeviceInfos returns all pcap-visible interfaces with their addresses.
func pcapListDeviceInfos() ([]pcapDevInfo, error) {
	if err := loadPcapLibrary(); err != nil {
		return nil, err
	}
	var alldevs *C.struct_pcap_if_s
	var errbuf [256]C.char
	if C.wrap_pcap_findalldevs(&alldevs, &errbuf[0]) != 0 {
		return nil, fmt.Errorf("pcap_findalldevs: %s", C.GoString(&errbuf[0]))
	}
	if alldevs == nil {
		return nil, fmt.Errorf("no devices found")
	}
	defer C.wrap_pcap_freealldevs(alldevs)

	var out []pcapDevInfo
	for dev := alldevs; dev != nil; dev = C.pcap_if_next(dev) {
		info := pcapDevInfo{Name: C.GoString(C.pcap_if_name(dev))}
		for addr := C.pcap_if_addresses(dev); addr != nil; addr = C.pcap_addr_next(addr) {
			sa := C.pcap_addr_addr(addr)
			if sa == nil {
				continue
			}
			var buf4 [64]C.char
			if C.sockaddr_ipv4_str(sa, &buf4[0], 64) == 0 {
				info.IPv4s = append(info.IPv4s, C.GoString(&buf4[0]))
			}
			var buf6 [64]C.char
			if C.sockaddr_ipv6_str(sa, &buf6[0], 64) == 0 {
				info.IPv6s = append(info.IPv6s, C.GoString(&buf6[0]))
			}
		}
		out = append(out, info)
	}
	return out, nil
}

// pcapRawCaptureHandle is an unrestricted pcap capture handle for test use.
// Unlike PcapSniffer, it applies no BPF filter and imposes no payload constraints.
type pcapRawCaptureHandle struct {
	handle   unsafe.Pointer
	linkType int
}

// pcapOpenRaw opens a raw pcap capture on the given device with no BPF filter.
// snaplen: max bytes per packet; promisc: 1=promiscuous; timeoutMs: read timeout.
func pcapOpenRaw(dev string, snaplen, promisc, timeoutMs int) (*pcapRawCaptureHandle, error) {
	if err := loadPcapLibrary(); err != nil {
		return nil, err
	}
	var errbuf [256]C.char
	cdev := C.CString(dev)
	defer C.free(unsafe.Pointer(cdev))

	handle := C.wrap_pcap_open_live(cdev, C.int(snaplen), C.int(promisc), C.int(timeoutMs), &errbuf[0])
	if handle == nil {
		return nil, fmt.Errorf("pcap_open_live(%s): %s", dev, C.GoString(&errbuf[0]))
	}
	lt := int(C.wrap_pcap_datalink(handle))
	return &pcapRawCaptureHandle{handle: handle, linkType: lt}, nil
}

// ReadNext reads the next packet from the handle.
// Returns (data, linkType, nil) on success, (nil, 0, nil) on timeout/breakloop,
// or (nil, 0, err) on a pcap error.
func (h *pcapRawCaptureHandle) ReadNext() ([]byte, int, error) {
	var capLen C.uint
	var pktData *C.uchar
	ret := int(C.wrap_pcap_next_packet(h.handle, &capLen, &pktData))
	switch ret {
	case 1:
		raw := C.GoBytes(unsafe.Pointer(pktData), C.int(capLen))
		return raw, h.linkType, nil
	case 0, -2:
		return nil, 0, nil // timeout or breakloop
	default:
		return nil, 0, fmt.Errorf("pcap error: %s", C.GoString(C.wrap_pcap_geterr(h.handle)))
	}
}

// Close closes the raw capture handle.
func (h *pcapRawCaptureHandle) Close() {
	if h.handle != nil {
		C.wrap_pcap_close(h.handle)
		h.handle = nil
	}
}

// testPcap tests if libpcap is available and working.
func testPcap() error {
	if err := loadPcapLibrary(); err != nil {
		return fmt.Errorf("libpcap not available: %w", err)
	}

	var alldevs *C.struct_pcap_if_s
	var errbuf [256]C.char
	if C.wrap_pcap_findalldevs(&alldevs, &errbuf[0]) != 0 {
		return fmt.Errorf("pcap_findalldevs: %s", C.GoString(&errbuf[0]))
	}
	if alldevs == nil {
		return fmt.Errorf("no capture devices found (check libpcap installation)")
	}
	C.wrap_pcap_freealldevs(alldevs)
	return nil
}
