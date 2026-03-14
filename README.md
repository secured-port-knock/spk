# SPK (Secured Port Knock)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.24+-00ADD8?logo=go&logoColor=white)](go.mod)
[![CI](https://github.com/Secured-Port-Knock/Secured-Port-Knock/actions/workflows/ci.yml/badge.svg)](https://github.com/Secured-Port-Knock/Secured-Port-Knock/actions/workflows/ci.yml)
[![Build](https://github.com/Secured-Port-Knock/Secured-Port-Knock/actions/workflows/build.yml/badge.svg)](https://github.com/Secured-Port-Knock/Secured-Port-Knock/actions/workflows/build.yml)

> **Development Status**
>
> SPK is still under active development. Not all features have been fully tested and edge cases may exist. This project was built for personal use -- use it at your own discretion.
>
> If you encounter any issues, please open a report in the [Issues](../../issues) section. Include a screenshot and steps to reproduce when possible -- it helps a lot. I may or may not have time to address every report, but all feedback is appreciated.
>
> It is highly recommended that you have a backup method to access your server.

**What is SPK (Secured Port Knock)**

SPK is a single-packet authorization (SPA) port knocking tool that uses ML-KEM (FIPS 203) for post-quantum key encapsulation and AES-256-GCM for authenticated encryption. Its main purpose is to add a secured authentication layer for legacy interfaces -- preventing services from being exposed directly on the internet. A single encrypted UDP packet is all that's needed to open firewall ports -- no handshake, no response, no attack surface. SPK does not implement user-level authentication; it controls network access to the services behind it.

## The Problem

Every internet-facing service is a target. Attackers scan entire IPv4 ranges in minutes, exploiting any reachable port -- from SSH brute-force to zero-day exploits like the XZ backdoor (CVE-2024-3094). Traditional defenses have significant gaps:

- **VPNs** add complexity, require always-on connections, and become their own attack surface (Ivanti, Fortinet CVEs)
- **IP whitelisting** breaks for mobile/dynamic IPs, remote teams, and CGNAT environments
- **Fail2ban / rate limiting** only reacts *after* failed attempts -- attackers have already touched your service
- **Legacy port knocking** (knockd) uses plaintext TCP sequences that are trivially sniffed and replayed

The core issue: **services must be reachable to be usable, but reachable means attackable.** SPK solves this by making services invisible until authenticated with post-quantum cryptography. No port is open, no service responds, no scanner finds anything -- until a valid knock arrives.

**Use cases:**
- Protect SSH, RDP, admin panels, databases, and IoT devices without VPN overhead
- Secure legacy services that cannot be patched or updated (industrial control, embedded systems)
- Add a pre-authentication layer in front of any TCP/UDP service
- Zero-response architecture: server never replies, eliminating reflection/amplification attacks entirely

## Security and Features

| Feature | Implementation |
|---|---|
| Post-Quantum Crypto | ML-KEM-768/1024 (FIPS 203), NIST-approved and resistant to quantum attacks |
| Single Packet | One UDP packet carries the full encapsulated key + encrypted payload |
| Replay Protection | Timestamp window combined with unique nonce tracking ensures captured packets cannot be reused |
| IP Spoofing Protection | Client IP is encrypted inside the payload; server decrypts and rejects any mismatch |
| Forward Secrecy | Each packet uses an ephemeral key -- compromising one reveals nothing about past or future knocks |
| Tamper Detection | AES-256-GCM authenticated encryption covers the entire payload, making any modification detectable |
| Key Exchange | Asymmetric (ML-KEM) -- every knock generates a new symmetric key, so no two knocks share cryptographic material |
| Secure Key Storage | Server public key stored in OS credential manager (Windows DPAPI, macOS Keychain, Linux Secret Service) -- encrypted at rest, bound to user account |
| 2FA / TOTP | Optional second factor via RFC 6238 time-based codes (Google Authenticator, Authy, etc.) |
| Cross-Platform | Windows, Linux, macOS |

### Packet Format

```
[ML-KEM Ciphertext (1088 or 1568 bytes)] [AES-GCM Nonce (12 bytes)] [Encrypted Payload]
```

| KEM Size | Ciphertext | Total (no padding) | Fits 1500 MTU? |
|---|---|---|---|
| ML-KEM-768 (default) | 1088 bytes | ~1170-1190 bytes | **Yes** |
| ML-KEM-1024 | 1568 bytes | ~1650-1670 bytes | No (requires IP fragmentation) |

> **WARNING: MTU** -- ML-KEM-1024 packets always exceed the standard 1500-byte Ethernet MTU. On WAN/internet connections, fragmented UDP packets may be silently dropped by firewalls, NAT devices, or ISP equipment. **Use ML-KEM-768 (default) for reliable WAN connectivity.** ML-KEM-1024 is suitable for LAN environments or networks known to handle IP fragmentation correctly.

See [docs/knock-protocol.md](docs/knock-protocol.md) for the complete wire format, binary payload layout, and encryption details.

Optionally, TOTP (Time-based One-Time Password, RFC 6238) can be enabled as an additional authentication factor. See [docs/security.md - TOTP](docs/security.md#totp-two-factor-authentication) for details.

## Quick Start

### Download

Download the latest release for your platform from [GitHub Releases](../../releases). Verify the binary runs:

```bash
./spk --version
# SPK - Secured Port Knock - 1.0.0.1000 (abc1234) [No PCAP]    -- non-pcap build
# SPK - Secured Port Knock - 1.0.0.1000 (abc1234) [With PCAP]  -- pcap build
```

To build from source, see [docs/compilation.md](docs/compilation.md).

### Server Setup

```bash
# Run interactive setup (generates keys, config, and exports)
./spk --server --setup

# Or just run - auto-detects first launch and prompts for setup
./spk

# Edit config (TOML format) to set your firewall commands
# Example for iptables:
#   open_tcp_command = "iptables -A INPUT -p tcp --dport {{PORT}} -s {{IP}} -j ACCEPT"
#   close_tcp_command = "iptables -D INPUT -p tcp --dport {{PORT}} -s {{IP}} -j ACCEPT"

# Start server
./spk --server
```

### Client Setup

```bash
# Copy activation.b64 from server to client machine, then:
./spk --client --setup

# Send commands:
./spk --client --cmd open-t22
./spk --client --cmd open-t22 --timeout 7200
./spk --client --cmd close-t22
./spk --client --cmd open-all
./spk --client --cmd cust-1

# Shorthand (auto-detects client mode from config):
./spk open-t22
./spk open-t22 --timeout 3600
./spk open-t22 --ip 203.0.113.50
./spk open-t22,t443              # Batch: multiple ports in one packet

# With TOTP (when server has TOTP enabled):
./spk --client --cmd open-t22 --totp 123456
./spk open-t22 --totp 482901
```

> **Protect your activation bundle and server public key.** The activation bundle (`activation.b64` / QR code) contains the server's ML-KEM public key. Anyone who has this key can send valid knock packets to open your firewall. Treat the activation bundle like a private key:
> - **Encrypt it for transport:** `spk --server --export` prompts for a password; use one when sending over email or messaging apps. If the password is forgotten before client import, re-export from the server (no keypair change needed).
> - **Delete after import:** Once `spk --client --setup` has imported it, delete the file from all intermediate storage.
> - **Use the OS credential manager:** SPK can store the imported key in Windows Credential Manager / DPAPI, macOS Keychain, or Linux Secret Service. See [docs/security.md - Secure Key Storage](docs/security.md#secure-key-storage).

### Re-export Activation Bundle

```bash
./spk --server --export
# Prompts for optional password encryption
# Outputs: activation.b64, activation_qr.png, console QR, and TOTP QR (if enabled)
```

### Service Install / Uninstall

SPK can install itself as a system service on Linux (systemd / OpenWRT procd), Windows (SCM), and macOS (launchd).

```bash
# Install as a system service (auto-detects init system)
sudo ./spk --install

# Install with custom config and log directories
sudo ./spk --install --cfgdir /etc/myspk --logdir /var/log/myspk

# Uninstall (lists all SPK services and prompts which to remove)
sudo ./spk --uninstall
```

During `--install`, SPK validates that `spk_server.toml`, `server.key`, and `server.crt` exist in the config directory. You are then prompted for an optional **display label** (e.g., `production`).

The label serves two purposes:
- It changes the **service name** to `spk_<label>` (e.g., `spk_production`) so multiple instances can coexist on the same machine without conflicting.
- It sets the display name to `Secured Port Knock (production)` for easy identification.

If no label is provided, the service name is simply `spk`.

If a service with the same name already exists, `--install` will refuse with a conflict error -- either uninstall the existing service first or choose a different label.

During `--uninstall`, SPK discovers all installed SPK-related services, lists their names and startup commands, and prompts you to choose which one to remove. Press Enter without selecting to cancel.

**Platform behavior:**

| Platform | Init System | Default name | With label `prod` |
|---|---|---|---|
| Linux (systemd) | systemd unit | `spk.service` | `spk_prod.service` |
| Linux (OpenWRT) | procd init.d | `/etc/init.d/spk` | `/etc/init.d/spk_prod` |
| Windows | SCM (sc.exe) | service `spk` | service `spk_prod` |
| macOS | launchd plist | `com.spk.spk` | `com.spk.spk_prod` |

**Linux security hardening (systemd):** The generated unit uses `ProtectHome=read-only` (not `=true`) so binaries located under `/root` or `/home` can still be executed. `ProtectSystem=strict` makes the OS filesystem read-only, while `ReadWritePaths` grants write access to the config and log directories.

## Command Reference

### Server Mode

| Flag | Description |
|---|---|
| `--server` | Run in server mode |
| `--setup` | Interactive first-time setup |
| `--export` | Re-export activation bundle (prompts for encryption) |
| `--install` | Install as system service |
| `--uninstall` | Remove system service |
| `--cfgdir DIR` | Custom config directory (overrides platform default) |
| `--logdir DIR` | Custom log directory (overrides platform default) |

### Client Mode

| Flag | Description |
|---|---|
| `--client` | Run in client mode |
| `--setup` | Interactive first-time setup |
| `--cmd CMD` | Send command (e.g., `open-t22`, `close-all`) |
| `--timeout N` | Custom timeout in seconds |
| `--host ADDR` | Override server address |
| `--ip ADDR` | Client IP override (IPv4 or IPv6, auto-detected if empty) |
| `--totp CODE` | TOTP 6-digit code from authenticator app (required if server has TOTP enabled) |
| `--cfgdir DIR` | Custom config directory (overrides platform default) |
| `--logdir DIR` | Custom log directory (overrides platform default) |

### Command Formats

| Command | Description |
|---|---|
| `open-t<port>` | Open TCP port (e.g., `open-t22`) |
| `open-u<port>` | Open UDP port (e.g., `open-u53`) |
| `close-t<port>` | Close TCP port |
| `close-u<port>` | Close UDP port |
| `open-all` | Open all allowed ports |
| `close-all` | Close all ports opened by this client |
| `open-t<p1>,t<p2>,...` | Batch open multiple ports (e.g., `open-t22,t443,u53`) |
| `cust-<id>` | Execute custom command (e.g., `cust-1`, `cust-ping`) |

## Configuration

See [docs/configuration.md](docs/configuration.md) for the full server and client TOML configuration reference, including firewall command examples for iptables, ip6tables, ufw, nftables, and Windows Firewall.

## Troubleshooting

### ML-KEM-1024 or Padded Packets Not Arriving

**Symptom:** Knocks work with ML-KEM-768 (no padding) but fail with ML-KEM-1024, or fail when padding is enabled with KEM-768.

**Cause:** Packets exceeding the 1500-byte Ethernet MTU require IP fragmentation. Many WAN firewalls, NAT devices, and ISP equipment silently drop fragmented UDP packets.

**Solutions:**
- **Use ML-KEM-768** (default) -- packets are ~1170-1190 bytes without padding, well within MTU
- **Limit padding:** Set `padding_max_bytes = 96` (or less) to keep KEM-768 packets under 1472 bytes (UDP payload limit after IP+UDP headers)
- **For KEM-1024:** Only use on LANs or networks where IP fragmentation is known to work. Test with `ping -f -l 1800 <server_ip>` (Windows) or `ping -M do -s 1800 <server_ip>` (Linux) to verify

### Stealth Mode Not Working

See [docs/capture-modes.md - Stealth Mode and Hardware Firewalls](docs/capture-modes.md#stealth-mode-and-hardware-firewalls).

### Server Time Sync

**Symptom:** Knocks are rejected with timestamp errors ("timestamp too far in the past/future").

**Cause:** The server clock is out of sync. SPK requires client and server clocks to be within `timestamp_tolerance` seconds of each other (default: 30s).

**Solutions:**
- **Enable NTP** on the server: `timedatectl set-ntp true` (Linux systemd) or Windows Time service
- **Increase tolerance** in server config: `timestamp_tolerance = 60` (up to 300s recommended max)
- Dynamic port rotation also depends on synchronized clocks -- if the clocks drift by more than `dynamic_port_window / 2`, the client and server may compute different ports

## FAQ

**Q: Can SPK be used as an IP whitelist/blacklist replacement?**

Yes. SPK effectively replaces static IP whitelists by dynamically opening firewall rules for authenticated clients. Unlike IP whitelists, SPK works with dynamic IPs, mobile users, and CGNAT environments. Each authorized knock opens the firewall for a specific IP and duration, then automatically closes it.

**Q: Will antivirus flag the binary as a virus?**

If built with [UPX](https://github.com/upx/upx/releases) compression (enabled by default when UPX is installed), some antivirus products may flag the binary as suspicious because UPX is commonly used by malware to evade detection. Additionally, builds with pcap/sniffer support may trigger heuristic detections because the binary loads packet capture libraries (wpcap.dll / libpcap) at runtime -- a pattern also associated with network sniffing malware. These are **false positives**. To avoid them, either build without UPX (remove UPX from PATH), add an exception in your antivirus, or use the non-pcap build (UDP sniffer mode).

**Q: Does SPK require a persistent connection?**

No. Each knock is a single UDP datagram -- fire and forget. There is no handshake, session, keepalive, or response. The client sends one packet and exits. This makes SPK ideal for low-bandwidth, high-latency, or intermittent connections.

**Q: Can I use SPK on IoT / embedded devices?**

Yes. SPK compiles to a single static binary with no runtime dependencies (when built with `CGO_ENABLED=0`). The binary is ~6-8 MB (or ~3 MB with UPX). It runs on Linux ARM64 (Raspberry Pi, OpenWRT routers), Windows, and macOS. The single-packet design minimizes bandwidth and processing.

**Q: Does SPK support multiple users?**

SPK does not have built-in multi-user support -- a single server instance uses one key pair and one configuration. However, nothing prevents running multiple SPK instances on the same machine with different keys, ports, and configurations using the `--label` flag (e.g., `spk --server --label user1`). Each instance operates independently with its own service, config directory, and firewall rules.

**Q: What happens if the server crashes while ports are open?**

SPK persists open-port state to `state.json`. On restart, it recovers state and closes any ports whose timeouts have expired. If `close_ports_on_crash = true` (default), all ports are closed immediately on recovery. The graceful shutdown handler (SIGINT/SIGTERM) also closes all ports before exit.

**Q: How does SPK handle multiple clients behind the same NAT?**

Each knock is independent -- multiple clients behind the same NAT can knock simultaneously. The nonce ensures each packet is unique even if timestamps match. IP matching verifies the NAT's public IP (via STUN), so all clients behind the same NAT share the same firewall rules for that external IP.

**Q: Can I run SPK alongside other services on the same port?**

In stealth mode (pcap, AF_PACKET, WinDivert), SPK captures packets at the network layer without binding the port, so the port appears closed to scanners. However, another service cannot bind the same port while SPK is listening. In UDP socket mode, the port is bound normally.

**Q: Why no TCP support for knock packets?**

TCP requires a handshake (SYN/SYN-ACK/ACK) before data transfer, which reveals the server is listening and creates attack surface. UDP allows fire-and-forget: one packet, no response, no state. This is fundamental to SPK's zero-response architecture.

**Q: What's the difference between ML-KEM-768 and ML-KEM-1024?**

Both are NIST-approved post-quantum algorithms (FIPS 203). ML-KEM-768 provides NIST security level 3 (~192-bit classical), and ML-KEM-1024 provides level 5 (~256-bit classical). The practical difference for SPK is packet size: KEM-768 fits within standard MTU (1500 bytes), while KEM-1024 requires IP fragmentation and may be dropped by some ISPs/firewalls. **ML-KEM-768 is recommended for all deployments.**

## Files

See [docs/files.md](docs/files.md) for a complete list of generated files, default paths per platform, and project source structure.

## Documentation

| Document | Contents |
|---|---|
| [docs/configuration.md](docs/configuration.md) | Server and client TOML configuration, firewall command examples |
| [docs/files.md](docs/files.md) | Generated files, default paths, project source structure |
| [docs/compilation.md](docs/compilation.md) | Building from source, cross-compilation, packaging (.deb / .rpm) |
| [docs/security.md](docs/security.md) | Security design, dynamic port rotation, anti-replay, client IP detection, key storage, TOTP |
| [docs/knock-protocol.md](docs/knock-protocol.md) | UDP packet wire format, binary payload layout, padding, security checks |
| [docs/activation.md](docs/activation.md) | Activation bundle binary format, encrypted bundles, parsing instructions |
| [docs/integration.md](docs/integration.md) | Third-party client integration guide, pseudocode, library recommendations |
| [docs/capture-modes.md](docs/capture-modes.md) | Packet capture modes (UDP, pcap, AF_PACKET, WinDivert), multi-interface behavior |
| [docs/testing.md](docs/testing.md) | Test categories, running tests, CI workflow, Build workflow, Release workflow |

## Runtime Requirements

- Root/Administrator privileges for packet capture and firewall management
- **For pcap sniffer mode (optional):** libpcap (Linux) / Npcap (Windows) / libpcap (macOS, built-in)

For build requirements (Go 1.24+, zig, GCC, nfpm), see [docs/compilation.md](docs/compilation.md#build-requirements).

## License

MIT License. Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com). See [LICENSE](LICENSE) for the full text.

### Third-Party Licenses

The full copyright notices and license texts for all third-party dependencies are
provided in [THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES), as required by the
BSD-3-Clause license terms of the golang.org/x packages.

| Dependency | Version | License |
|---|---|---|
| [BurntSushi/toml](https://github.com/BurntSushi/toml) | v1.6.0 | MIT |
| [skip2/go-qrcode](https://github.com/skip2/go-qrcode) | v0.0.0-20200617195104 | MIT |
| [golang.org/x/crypto](https://pkg.go.dev/golang.org/x/crypto) | v0.35.0 | BSD-3-Clause |
| [golang.org/x/sys](https://pkg.go.dev/golang.org/x/sys) | v0.30.0 | BSD-3-Clause |

