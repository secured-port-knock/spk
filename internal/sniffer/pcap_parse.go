// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package sniffer

import (
	"encoding/binary"
	"net"
)

// Link-layer type constants (from pcap DLT_ values).
const (
	dltNull     = 0   // BSD loopback
	dltEN10MB   = 1   // Ethernet
	dltRaw12    = 12  // Raw IP (Linux variant)
	dltRaw101   = 101 // Raw IP
	dltLinuxSLL = 113 // Linux cooked capture
)

// maxIPv6ExtHeaders caps the number of IPv6 extension headers
// we will traverse before giving up. RFC 8200 does not define an
// upper bound, but real-world packets rarely exceed 3-4 headers.
// This prevents CPU waste on crafted packets with long header chains.
const maxIPv6ExtHeaders = 10

// linkHeaderLen returns the link-layer header length for the given DLT type.
// Returns -1 for unsupported types.
func linkHeaderLen(linkType int) int {
	switch linkType {
	case dltEN10MB:
		return 14
	case dltNull:
		return 4
	case dltLinuxSLL:
		return 16
	case dltRaw12, dltRaw101:
		return 0
	default:
		return -1
	}
}

// parsePcapPacket extracts the source IP and UDP payload from a captured packet.
// Returns ("", nil) if the packet is not a valid UDP packet for our purposes.
func parsePcapPacket(raw []byte, linkType, linkHdrLen int) (string, []byte) {
	if len(raw) <= linkHdrLen {
		return "", nil
	}

	ipData := raw[linkHdrLen:]

	// For Ethernet, verify ethertype
	if linkType == dltEN10MB && len(raw) >= 14 {
		etherType := binary.BigEndian.Uint16(raw[12:14])
		// Handle VLAN (802.1Q)
		if etherType == 0x8100 && len(raw) >= 18 {
			etherType = binary.BigEndian.Uint16(raw[16:18])
			ipData = raw[18:]
		}
		if etherType != 0x0800 && etherType != 0x86DD {
			return "", nil // Not IPv4/IPv6
		}
	}

	// For BSD loopback, check address family (little-endian 4-byte value)
	if linkType == dltNull && len(raw) >= 4 {
		af := binary.LittleEndian.Uint32(raw[:4])
		// AF_INET=2, AF_INET6 varies by OS:
		//   Linux=10, macOS=24 or 30, FreeBSD=28, Windows=23
		if af != 2 && af != 10 && af != 23 && af != 24 && af != 28 && af != 30 {
			return "", nil
		}
	}

	// For Linux cooked, check protocol type at bytes 14-15
	if linkType == dltLinuxSLL && len(raw) >= 16 {
		proto := binary.BigEndian.Uint16(raw[14:16])
		if proto != 0x0800 && proto != 0x86DD {
			return "", nil
		}
	}

	if len(ipData) < 1 {
		return "", nil
	}

	version := ipData[0] >> 4
	switch version {
	case 4:
		return parseIPv4UDP(ipData)
	case 6:
		return parseIPv6UDP(ipData)
	default:
		return "", nil
	}
}

// parseIPv4UDP extracts source IP and UDP payload from an IPv4 packet.
func parseIPv4UDP(ipData []byte) (string, []byte) {
	if len(ipData) < 20 {
		return "", nil
	}

	ihl := int(ipData[0]&0x0F) * 4
	if ihl < 20 || len(ipData) < ihl {
		return "", nil
	}

	protocol := ipData[9]
	if protocol != 17 { // Not UDP
		return "", nil
	}

	srcIP := net.IPv4(ipData[12], ipData[13], ipData[14], ipData[15]).String()

	udpData := ipData[ihl:]
	if len(udpData) < 8 {
		return "", nil
	}

	// UDP payload starts after 8-byte UDP header
	payload := udpData[8:]
	return srcIP, payload
}

// parseIPv6UDP extracts source IP and UDP payload from an IPv6 packet.
func parseIPv6UDP(ipData []byte) (string, []byte) {
	if len(ipData) < 40 {
		return "", nil
	}

	nextHeader := ipData[6]
	srcIP := net.IP(ipData[8:24]).String()

	// Skip extension headers to find UDP (protocol 17).
	// Cap iterations to prevent DoS from crafted packets with
	// many or circular extension header chains.
	offset := 40
	for i := 0; i < maxIPv6ExtHeaders && nextHeader != 17; i++ {
		switch nextHeader {
		case 0, 43, 60: // Hop-by-Hop, Routing, Destination Options
			if len(ipData) < offset+2 {
				return "", nil
			}
			nextHeader = ipData[offset]
			extLen := int(ipData[offset+1]+1) * 8
			offset += extLen
		case 44: // Fragment header (fixed 8 bytes)
			if len(ipData) < offset+8 {
				return "", nil
			}
			nextHeader = ipData[offset]
			offset += 8
		case 59: // No Next Header
			return "", nil
		default:
			return "", nil // Unknown extension
		}
		if offset > len(ipData) {
			return "", nil
		}
	}
	if nextHeader != 17 {
		return "", nil
	}

	udpData := ipData[offset:]
	if len(udpData) < 8 {
		return "", nil
	}

	payload := udpData[8:]
	return srcIP, payload
}
