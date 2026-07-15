# SPK (Secured Port Knock)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.25+-00ADD8?logo=go&logoColor=white)](go.mod)
[![CI](https://github.com/secured-port-knock/spk/actions/workflows/ci.yml/badge.svg)](https://github.com/secured-port-knock/spk/actions/workflows/ci.yml)
[![Build](https://github.com/secured-port-knock/spk/actions/workflows/build.yml/badge.svg)](https://github.com/secured-port-knock/spk/actions/workflows/build.yml)
[![CodeQL](https://github.com/secured-port-knock/spk/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/secured-port-knock/spk/actions/workflows/github-code-scanning/codeql)
[![Dependency Graph](https://github.com/secured-port-knock/spk/actions/workflows/dependabot/update-graph/badge.svg)](https://github.com/secured-port-knock/spk/actions/workflows/dependabot/update-graph)

> [!WARNING]
> SPK is under active development and was built for personal use -- use at your own discretion, and keep a backup method to access your server.
>
> Found a bug? Open a report in [Issues](../../issues) with the app version, commit sha, and steps to reproduce.

**What is SPK (Secured Port Knock)**

SPK is a single-packet authorization (SPA) port knocking tool that uses ML-KEM (FIPS 203) for post-quantum key encapsulation and AES-256-GCM for authenticated encryption. Firewall ports stay closed to everyone until a valid, authenticated knock arrives -- a single encrypted UDP packet, no handshake, no response. Only then does the server open access for that specific IP. This eliminates the visible attack surface exploited by mass scanners and opportunistic exploits (e.g. the XZ backdoor, CVE-2024-3094), and unlike traditional knockd-style port knocking, there is no plaintext sequence to capture and replay. See [docs/security.md](docs/security.md) for the full security analysis.

> [!NOTE]
> SPK authenticates knocks, not users. User identity (SSH keys, MFA, etc.) is the job of the service behind the firewall. For per-user access policies, run multiple SPK instances -- see the [FAQ](#faq).

**Use cases:**
- Protect SSH, RDP, admin panels, databases, and IoT devices without VPN overhead
- Secure legacy services that cannot be patched (industrial control, embedded systems)
- Add a pre-authentication layer in front of any TCP/UDP service
- Zero-response architecture: the server never replies, so there is no reflection/amplification vector

## Security and Features

| Feature | Implementation |
|---|---|
| Post-Quantum Crypto | ML-KEM-768/1024 (FIPS 203), NIST-approved and resistant to quantum attacks |
| Single Packet | One UDP packet carries the full encapsulated key + encrypted payload |
| Replay Protection | Timestamp window combined with unique nonce tracking ensures captured packets cannot be reused |
| IP Spoofing Protection | Client IP is encrypted inside the payload; server decrypts and rejects any mismatch |
| Key Freshness | Each knock generates a fresh independent shared secret via ML-KEM encapsulation -- compromising one knock's AES key reveals nothing about any other (see [docs/security.md](docs/security.md#key-freshness)) |
| Tamper Detection | AES-256-GCM authenticated encryption covers the entire payload, making any modification detectable |
| Key Exchange | Asymmetric (ML-KEM) -- the server holds a static keypair; each client encapsulation produces a brand-new 32-byte AES key delivered to the server |
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

> [!WARNING]
> ML-KEM-1024 packets always exceed the standard 1500-byte Ethernet MTU, and fragmented UDP is often silently dropped on WAN paths. **Use ML-KEM-768 (default) for WAN**; reserve ML-KEM-1024 for LANs known to handle IP fragmentation.

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

### Install via go install

If you have Go 1.25+ installed, you can install SPK directly from source without cloning the
repository:

```bash
go install github.com/secured-port-knock/spk@latest
```

This installs a pure-Go build (no pcap stealth mode). For pcap support or production server
deployments, use the release binaries. See [docs/compilation.md](docs/compilation.md#install-via-go-install)
for details and limitations.

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
./spk --client --cmd open-t22 --duration 7200
./spk --client --cmd open-t22,t443,u53      # Batch open in one packet
./spk --client --cmd close-t22
./spk --client --cmd close-t22,t443         # Batch close in one packet
./spk --client --cmd open-all
./spk --client --cmd cust-1

# Shorthand (auto-detects client mode from config):
./spk open-t22
./spk open-t22 --duration 3600
./spk open-t22 --ip 203.0.113.50
./spk open-t22,t443,u53                     # Batch open shorthand
./spk close-t22,t443                        # Batch close shorthand

# With TOTP (when server has TOTP enabled):
./spk --client --cmd open-t22 --totp 123456
./spk open-t22 --totp 482901
```

> [!CAUTION]
> The activation bundle (`activation.b64` / QR code) contains the server's ML-KEM public key -- anyone who has it can open your firewall. Treat it like a private key:
> - **Encrypt it for transport:** `spk --server --export` prompts for a password; use one when sending over email or messaging apps.
> - **Delete after import:** once `spk --client --setup` has imported it, delete the file from all intermediate storage.
> - **Use the OS credential manager** for the imported key -- see [docs/security.md - Secure Key Storage](docs/security.md#secure-key-storage).

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

During `--install`, SPK validates that `spk_server.toml`, `server.key`, and `server.crt` exist in the config directory, then prompts for an optional **display label** (e.g., `production`). The label changes the service name to `spk_<label>` so multiple instances can coexist; without a label the service is named `spk`. If a service with the same name already exists, `--install` refuses -- uninstall it first or pick a different label.

During `--uninstall`, SPK lists all installed SPK services and prompts which to remove (press Enter to cancel).

**Platform behavior:**

| Platform | Init System | Default name | With label `prod` |
|---|---|---|---|
| Linux (systemd) | systemd unit | `spk.service` | `spk_prod.service` |
| Linux (OpenWRT) | procd init.d | `/etc/init.d/spk` | `/etc/init.d/spk_prod` |
| Windows | SCM (sc.exe) | service `spk` | service `spk_prod` |
| macOS | launchd plist | `com.spk.spk` | `com.spk.spk_prod` |

> [!NOTE]
> On systemd, the generated unit is sandboxed: `ProtectSystem=strict` makes the OS filesystem read-only, `ReadWritePaths` allows only the config and log directories, and `ProtectHome=read-only` keeps binaries under `/root` or `/home` executable.

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
| `--duration N` | Custom open duration in seconds (open- commands only) |
| `--host ADDR` | Override server address |
| `--ip ADDR` | Client IP override (IPv4 or IPv6, auto-detected if empty) |
| `--totp CODE` | TOTP 6-digit code from authenticator app (required if server has TOTP enabled) |
| `--delete-key` | Delete the imported server key from secure storage |
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
| `close-t<p1>,t<p2>,...` | Batch close multiple ports (e.g., `close-t22,t443`) |
| `cust-<id>` | Execute custom command (e.g., `cust-1`, `cust-ping`) |

## Configuration

See [docs/configuration.md](docs/configuration.md) for the full server and client TOML configuration reference, including firewall command examples for iptables, ip6tables, ufw, nftables, and Windows Firewall.

## Troubleshooting

### ML-KEM-1024 or Padded Packets Not Arriving

Packets over the 1500-byte MTU require IP fragmentation, and many WAN firewalls, NAT devices, and ISPs silently drop fragmented UDP.

- **Use ML-KEM-768** (default) -- packets stay well within MTU
- **Limit padding:** set `padding_max_bytes = 96` (or less) to keep KEM-768 packets under the 1472-byte UDP payload limit
- **For KEM-1024:** use only on networks where fragmentation is known to work; verify with `ping -f -l 1800 <server_ip>` (Windows) or `ping -M do -s 1800 <server_ip>` (Linux)

### Stealth Mode Not Working

See [docs/capture-modes.md - Stealth Mode and Hardware Firewalls](docs/capture-modes.md#stealth-mode-and-hardware-firewalls).

### Server Time Sync

Knocks rejected with "timestamp too far in the past/future" mean the client and server clocks differ by more than `timestamp_tolerance` (default: 30s).

- **Enable NTP** on the server: `timedatectl set-ntp true` (Linux systemd) or the Windows Time service
- **Increase tolerance** in server config: `timestamp_tolerance = 60` (up to 300s recommended max)
- Dynamic port rotation also needs synchronized clocks -- drift beyond `dynamic_port_window / 2` makes client and server compute different ports

## FAQ

**Q: Can SPK be used as an IP whitelist/blacklist replacement?**

Yes. Each authorized knock opens the firewall for a specific IP and duration, then automatically closes it -- unlike static whitelists, this works with dynamic IPs, mobile users, and CGNAT.

**Q: Will antivirus flag the binary as a virus?**

Possibly. [UPX](https://github.com/upx/upx/releases) compression (enabled by default when UPX is installed) and runtime loading of packet capture libraries (wpcap.dll / libpcap) are both patterns associated with malware, so some products raise heuristic detections. These are **false positives** -- build without UPX, add an antivirus exception, or use the non-pcap build.

**Q: Does SPK require a persistent connection?**

No. Each knock is a single UDP datagram -- no handshake, session, keepalive, or response. The client sends one packet and exits, which suits low-bandwidth, high-latency, or intermittent connections.

**Q: Can I use SPK on IoT / embedded devices?**

Yes. SPK compiles to a single static binary (~6-8 MB, or ~3 MB with UPX) with no runtime dependencies when built with `CGO_ENABLED=0`. It runs on Linux ARM64 (Raspberry Pi, OpenWRT routers), Windows, and macOS.

**Q: Does SPK support multiple users?**

Not directly -- a server instance uses one key pair and one configuration. For per-user policies (different allowed ports, keys, individual revocation), run one instance per user, each with its own `--cfgdir` and service label:

```bash
# Set up instance for alice:
sudo ./spk --server --setup --cfgdir /etc/spk-alice
sudo ./spk --server --install --cfgdir /etc/spk-alice  # enter label "alice" when prompted

# Set up instance for bob:
sudo ./spk --server --setup --cfgdir /etc/spk-bob
sudo ./spk --server --install --cfgdir /etc/spk-bob    # enter label "bob" when prompted
```

Each instance runs as an independent service (`spk_alice`, `spk_bob`) with its own keys and rules.

**Q: What happens if the server crashes while ports are open?**

Open-port state is persisted to `state.json`. On restart, SPK recovers it and closes expired ports -- or all ports immediately if `close_ports_on_crash = true` (default). Graceful shutdown (SIGINT/SIGTERM) also closes all ports before exit.

**Q: How does SPK handle multiple clients behind the same NAT?**

Each knock is independent; the nonce keeps packets unique even with matching timestamps. Since all clients share the NAT's public IP (detected via STUN), they share the firewall rules opened for that IP.

**Q: Can I run SPK alongside other services on the same port?**

In stealth mode (pcap, AF_PACKET, WinDivert), SPK captures at the network layer without binding the port, so the port appears closed to scanners -- but another service still cannot bind it while SPK listens. In UDP socket mode, the port is bound normally.

**Q: Why no TCP support for knock packets?**

A TCP handshake reveals the server is listening and creates attack surface. UDP is fire-and-forget: one packet, no response, no state -- fundamental to SPK's zero-response architecture.

**Q: What's the difference between ML-KEM-768 and ML-KEM-1024?**

Both are NIST-approved (FIPS 203). KEM-768 is security level 3 (~192-bit classical), KEM-1024 level 5 (~256-bit). The practical difference is packet size: KEM-768 fits within a 1500-byte MTU; KEM-1024 requires IP fragmentation and may be dropped. **ML-KEM-768 is recommended for all deployments.**

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

For build requirements (Go 1.25+, zig, GCC, nfpm), see [docs/compilation.md](docs/compilation.md#build-requirements).

## License

MIT License. Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com). See [LICENSE](LICENSE) for the full text.

### Third-Party Licenses

The full copyright notices and license texts for all third-party dependencies are
provided in [THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES), as required by the
BSD-3-Clause license terms of the golang.org/x packages.

| Dependency | License |
|---|---|
| [BurntSushi/toml](https://github.com/BurntSushi/toml) | MIT |
| [skip2/go-qrcode](https://github.com/skip2/go-qrcode) | MIT |
| [golang.org/x/crypto](https://pkg.go.dev/golang.org/x/crypto) | BSD-3-Clause |
| [golang.org/x/sys](https://pkg.go.dev/golang.org/x/sys) | BSD-3-Clause |

