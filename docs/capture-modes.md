# Packet Capture Modes

During setup, the server detects available capture methods:

| Mode | Platform | Stealth | IPv4/IPv6 | Dependencies | Status |
|---|---|---|---|---|---|
| UDP Socket | All | No (port visible) | Both | None | **Stable** |
| libpcap/Npcap | All | Yes | Both | libpcap / Npcap (auto-enabled for native builds) | **Stable** |
| AF_PACKET | Linux | Yes | Both | None (built-in, root/CAP_NET_RAW, BPF-filtered) | **Stable** |
| WinDivert | Windows | Yes | Both | [WinDivert driver](https://reqrypt.org/windivert.html) | **Good** |

> **Stealth mode**: The listen port is invisible to port scans. Only the sniffer sees the packet at the network layer.

> **AF_PACKET filtering**: Uses dual sockets (ETH_P_IP + ETH_P_IPV6) with kernel-level Berkeley Packet Filters (BPF) to capture only UDP packets on the target port. This prevents CPU/memory waste from irrelevant traffic on busy servers.

pcap is automatically included when zig is available (all targets) or when building natively with GCC. Use `NOPCAP=1` or `-nopcap` to disable. See [Build Toolchain Priority](compilation.md#build-toolchain-priority) for details.

The setup wizard detects all available capture methods and recommends the best one (pcap > AF_PACKET/WinDivert > UDP). The recommended option is pre-selected as the default.

## Sniffer Behavior on Multi-Interface Systems

| Mode | `0.0.0.0` | Specific IP |
|---|---|---|
| `udp` | Socket binds to all interfaces | Socket binds to that exact address |
| `afpacket` (Linux) | Captures all interfaces (raw socket, both IPv4+IPv6) | Binds socket to the specific interface only |
| `pcap` (Linux) | Uses the `any` device -- captures all interfaces | Opens capture handle for the matching interface |
| `pcap` (Windows/macOS) | Picks the default-route interface[1] | Opens capture handle for the matching interface |
| `windivert` (Windows) | Kernel WFP capture for all interfaces | Validated, WFP captures all interfaces |

> [1] Windows and macOS lack a pcap "any" device. When `0.0.0.0` is used, SPK selects the interface with the default route (the one used for outbound internet traffic). If you need to capture knock packets arriving on a different interface, specify that interface's IP directly.

## Startup Validation

When the server starts, it verifies the selected capture backend is functional before accepting packets. This catches common issues like missing Npcap, unloaded WinDivert driver, or insufficient permissions for AF_PACKET. If the validation fails, the server exits with a descriptive error message.

## Stealth Mode and Hardware Firewalls

**Symptom:** Server is running in stealth mode (afpacket/pcap/windivert), the port is invisible to scans, but knocks never arrive.

**Cause:** A hardware firewall, cloud security group, or upstream NAT is dropping incoming UDP packets on the listen port because no application is bound to it. Stealth sniffers capture at the network layer without binding a port -- but upstream network devices don't know this.

**Solutions:**
- **Allow the UDP port** in your cloud security group / hardware firewall -- even though no socket is bound, the traffic must reach the server's network interface
- **Use the `udp` sniffer mode** if you cannot control upstream firewall rules (trades stealth for reliability)
- Verify traffic reaches the host: `tcpdump -i any udp port <port>` (Linux) or Wireshark (Windows)
