# Configuration

## Server Config (TOML)

The setup wizard generates a config file with comments. Key settings:

```toml
# -- Network --
listen_addresses = ["0.0.0.0", "::"]  # Bind IPv4 + IPv6 (default)
sniffer_mode = "udp"           # "udp" (universal), "afpacket" (stealth, Linux),
                               # "pcap" (stealth, cross-platform),
                               # "windivert" (stealth, Windows)
# listen_port = "dynamic" or a port number (e.g. 45678) for fixed port
listen_port = "dynamic"

# -- ML-KEM key size (768 or 1024, default: 768) --
# 768 = NIST level 3 (~AES-192), packets fit within 1500 MTU (recommended for WAN)
# 1024 = NIST level 5 (~AES-256), packets exceed MTU and require IP fragmentation
kem_size = 768

# -- Dynamic port rotation --
port_seed = "a1b2c3d4..."       # 16-hex-char shared seed (generated during setup)
dynamic_port_window = 600       # Rotation period in seconds (60-86400, default 600)
dynamic_port_min = 10000        # Minimum port in rotation range (default: 10000)
dynamic_port_max = 65000        # Maximum port in rotation range (default: 65000)

# -- Security policies --
allow_custom_port = false            # Can clients request arbitrary ports?
allow_custom_open_duration = false   # Can clients set their own open duration?
allow_open_all = false               # Allow "open-all" command?
allowed_ports = ["t22"]              # Whitelisted ports (t=TCP, u=UDP)

# -- Security --
match_incoming_ip = true        # Verify knock's embedded IP matches UDP source
max_nonce_cache = 10000         # Max nonces to track (prevents memory exhaustion)
timestamp_tolerance = 30        # Seconds of clock drift allowed (default: 30)
nonce_expiry = 120              # Seconds to remember used nonces (default: 120)

# -- Open Duration --
default_open_duration = 3600    # Default port open duration (seconds)
max_open_duration = 86400       # Maximum allowed open duration

# -- Firewall commands (use {{IP}} and {{PORT}} placeholders) --
# NOTE: if a close command is left empty while the corresponding open command is set,
# the open command still runs but no auto-close timer is set -- the port stays open
# permanently until manually closed (a [WARN] is logged after each such open).
open_tcp_command = "iptables -A INPUT -p tcp --dport {{PORT}} -s {{IP}} -j ACCEPT"
close_tcp_command = "iptables -D INPUT -p tcp --dport {{PORT}} -s {{IP}} -j ACCEPT"
open_udp_command = "iptables -A INPUT -p udp --dport {{PORT}} -s {{IP}} -j ACCEPT"
close_udp_command = "iptables -D INPUT -p udp --dport {{PORT}} -s {{IP}} -j ACCEPT"
# open_all_command and close_all_command run when client sends "open-all" / "close-all".
# Used only when allow_open_all = true. Leave empty to skip.
# NOTE: if close_all_command is empty but open_all_command is set, the open-all command
# still runs but the port(s) will remain open permanently (no auto-close timer is set).
open_all_command = ""
close_all_command = ""

# -- IPv6 firewall commands (use ip6tables for IPv6 clients) --
# Automatically used when client IP is IPv6.
open_tcp6_command = "ip6tables -A INPUT -p tcp --dport {{PORT}} -s {{IP}} -j ACCEPT"
close_tcp6_command = "ip6tables -D INPUT -p tcp --dport {{PORT}} -s {{IP}} -j ACCEPT"
open_udp6_command = "ip6tables -A INPUT -p udp --dport {{PORT}} -s {{IP}} -j ACCEPT"
close_udp6_command = "ip6tables -D INPUT -p udp --dport {{PORT}} -s {{IP}} -j ACCEPT"
open_all6_command = ""
close_all6_command = ""

# -- Logging --
log_max_size_mb = 10            # Max log file size before rotation (MB, default: 10)
log_max_backups = 5             # Number of rotated log files to keep (default: 5)
log_max_age_days = 30           # Max age of rotated log files in days (default: 30)
log_flood_limit_ps = 100        # Max log lines per second (0 = unlimited, default: 100)
log_command_output = false      # Log each command before execution and its stdout/stderr output

# -- Crash recovery --
close_ports_on_crash = true     # Close all opened ports on crash recovery (default: true)

# -- Command execution --
cmd_timeout = 0.5               # Timeout in seconds for open/close/custom commands (default: 0.5)
                                # Prevents hung firewall commands from blocking the server

# -- TOTP (optional second factor, for extra assurance) --
# When enabled, each knock must include a 6-digit TOTP code from an authenticator app.
# The TOTP secret is stored ONLY in the authenticator app, never in the client config.
# totp_enabled = false
# totp_secret = ""              # 32-char base32 secret (generated during setup)

# -- Custom commands (client sends "cust-<id>", server runs the mapped command) --
[custom_commands]
1 = "systemctl restart sshd"
ping = "echo pong"
```

## `listen_addresses` and Multi-Interface Support

`listen_addresses` controls which network interfaces accept knock packets.

| Value | Meaning |
|---|---|
| `["0.0.0.0"]` | All IPv4 interfaces |
| `["::"]` | All IPv6 interfaces |
| `["0.0.0.0", "::"]` | All IPv4 **and** IPv6 interfaces (dual-stack, default) |
| `["192.168.1.2"]` | Only the interface that owns `192.168.1.2` |
| `["192.168.1.2", "10.0.0.1"]` | Two specific interfaces simultaneously |

**Specific IP validation**: SPK validates non-wildcard addresses against local interfaces at startup. If the IP is not assigned to any interface the server refuses to start with a clear error -- no silent fallback to a random interface.

For sniffer-mode behavior on multi-interface systems, see [capture-modes.md](capture-modes.md).

## Client Config (TOML)

Client configuration is stored in a user-writable location -- no root or Administrator
privileges are required.

Default config directory:
- Linux / macOS: `~/.config/spk/spk_client.toml` (respects `$XDG_CONFIG_HOME`)
- Windows: `<exe_dir>\config\spk_client.toml`

Use `--cfgdir DIR` to override.

**Logging is disabled by default in client mode.** The client outputs results directly
to stdout. To enable file logging, pass `--logdir DIR` on the command line.

```toml
server_host = "example.com"
server_port = "dynamic"          # "dynamic" or a port number (e.g. 45678)
                                 # Using a fixed port disables dynamic rotation
port_seed = "a1b2c3d4..."
dynamic_port_window = 600        # Must match server's window
dynamic_port_min = 10000         # Must match server's dynamic_port_min
dynamic_port_max = 65000         # Must match server's dynamic_port_max
key_storage_mode = "file"        # "file" or "credential_manager"

# -- STUN servers for WAN IP detection (client-only) --
stun_servers = ["stun.cloudflare.com:3478", "stun.l.google.com:19302", "stun1.l.google.com:19302"]

# -- Padding (optional, default: disabled) --
# padding_enabled = true
# padding_min_bytes = 64        # Minimum padding bytes (default: 64)
# padding_max_bytes = 96        # Use <=96 with KEM-768 to stay within MTU (default: 512, max: 2048)
```

> **Note:** Client IP is set per-command via `--ip` flag, not in the config file.

## Firewall Command Examples

**iptables (IPv4 + IPv6):**
```toml
open_tcp_command = "iptables -A INPUT -p tcp --dport {{PORT}} -s {{IP}} -j ACCEPT"
close_tcp_command = "iptables -D INPUT -p tcp --dport {{PORT}} -s {{IP}} -j ACCEPT"
open_udp_command = "iptables -A INPUT -p udp --dport {{PORT}} -s {{IP}} -j ACCEPT"
close_udp_command = "iptables -D INPUT -p udp --dport {{PORT}} -s {{IP}} -j ACCEPT"
open_tcp6_command = "ip6tables -A INPUT -p tcp --dport {{PORT}} -s {{IP}} -j ACCEPT"
close_tcp6_command = "ip6tables -D INPUT -p tcp --dport {{PORT}} -s {{IP}} -j ACCEPT"
open_udp6_command = "ip6tables -A INPUT -p udp --dport {{PORT}} -s {{IP}} -j ACCEPT"
close_udp6_command = "ip6tables -D INPUT -p udp --dport {{PORT}} -s {{IP}} -j ACCEPT"
```

**ufw:**
```toml
open_tcp_command = "ufw allow from {{IP}} to any port {{PORT}} proto tcp"
close_tcp_command = "ufw delete allow from {{IP}} to any port {{PORT}} proto tcp"
open_udp_command = "ufw allow from {{IP}} to any port {{PORT}} proto udp"
close_udp_command = "ufw delete allow from {{IP}} to any port {{PORT}} proto udp"
```

**nftables (inet family handles both IPv4 and IPv6):**
```toml
open_tcp_command = "nft add rule inet filter input ip saddr {{IP}} tcp dport {{PORT}} accept"
open_udp_command = "nft add rule inet filter input ip saddr {{IP}} udp dport {{PORT}} accept"
# For IPv6, use ip6 saddr:
open_tcp6_command = "nft add rule inet filter input ip6 saddr {{IP}} tcp dport {{PORT}} accept"
open_udp6_command = "nft add rule inet filter input ip6 saddr {{IP}} udp dport {{PORT}} accept"
```

**Windows Firewall:**
```toml
# netsh handles both IPv4 and IPv6 natively - same command templates work for both
open_tcp_command = "netsh advfirewall firewall add rule name=\"SPK_{{IP}}_{{PORT}}\" dir=in action=allow protocol=tcp localport={{PORT}} remoteip={{IP}}"
close_tcp_command = "netsh advfirewall firewall delete rule name=\"SPK_{{IP}}_{{PORT}}\""
open_udp_command = "netsh advfirewall firewall add rule name=\"SPK_{{IP}}_{{PORT}}_U\" dir=in action=allow protocol=udp localport={{PORT}} remoteip={{IP}}"
close_udp_command = "netsh advfirewall firewall delete rule name=\"SPK_{{IP}}_{{PORT}}_U\""
```
