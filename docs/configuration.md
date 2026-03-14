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

# -- Dynamic port rotation --
port_seed = "a1b2c3d4..."       # 16-hex-char shared seed (generated during setup)
dynamic_port_window = 600       # Rotation period in seconds (60-86400, default 600)

# -- Security policies --
allow_custom_port = false       # Can clients request arbitrary ports?
allow_custom_timeout = false    # Can clients set their own timeout?
allow_open_all = false          # Allow "open-all" command?
allowed_ports = ["t22"]         # Whitelisted ports (t=TCP, u=UDP)

# -- Security --
match_incoming_ip = true        # Verify knock's embedded IP matches UDP source
max_nonce_cache = 10000         # Max nonces to track (prevents memory exhaustion)
timestamp_tolerance = 30        # Seconds of clock drift allowed (default: 30)
nonce_expiry = 120              # Seconds to remember used nonces (default: 120)

# -- Timeouts --
default_timeout = 3600          # Default port open duration (seconds)
max_timeout = 86400             # Maximum allowed timeout

# -- Firewall commands (use {{IP}} and {{PORT}} placeholders) --
open_tcp_command = "iptables -A INPUT -p tcp --dport {{PORT}} -s {{IP}} -j ACCEPT"
close_tcp_command = "iptables -D INPUT -p tcp --dport {{PORT}} -s {{IP}} -j ACCEPT"

# -- IPv6 firewall commands (use ip6tables for IPv6 clients) --
# Automatically used when client IP is IPv6.
open_tcp6_command = "ip6tables -A INPUT -p tcp --dport {{PORT}} -s {{IP}} -j ACCEPT"
close_tcp6_command = "ip6tables -D INPUT -p tcp --dport {{PORT}} -s {{IP}} -j ACCEPT"

# -- Logging --
log_command_output = false      # Log stdout/stderr of executed commands

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

```toml
server_host = "example.com"
server_port = "dynamic"          # "dynamic" or a port number (e.g. 45678)
                                 # Using a fixed port disables dynamic rotation
port_seed = "a1b2c3d4..."
dynamic_port_window = 600       # Must match server's window
key_storage_mode = "file"       # "file" or "credential_manager"

# -- STUN servers for WAN IP detection (client-only) --
stun_servers = ["stun.cloudflare.com:3478", "stun.l.google.com:19302", "stun1.l.google.com:19302"]

# -- Padding (optional, default: disabled) --
# padding_enabled = true
# padding_min_bytes = 8
# padding_max_bytes = 96        # Use <=96 with KEM-768 to stay within MTU (max: 2048)
```

> **Note:** Client IP is set per-command via `--ip` flag, not in the config file.

## Firewall Command Examples

**iptables (IPv4):**
```toml
open_tcp_command = "iptables -A INPUT -p tcp --dport {{PORT}} -s {{IP}} -j ACCEPT"
close_tcp_command = "iptables -D INPUT -p tcp --dport {{PORT}} -s {{IP}} -j ACCEPT"
```

**ip6tables (IPv6):**
```toml
open_tcp6_command = "ip6tables -A INPUT -p tcp --dport {{PORT}} -s {{IP}} -j ACCEPT"
close_tcp6_command = "ip6tables -D INPUT -p tcp --dport {{PORT}} -s {{IP}} -j ACCEPT"
```

**ufw:**
```toml
open_tcp_command = "ufw allow from {{IP}} to any port {{PORT}} proto tcp"
close_tcp_command = "ufw delete allow from {{IP}} to any port {{PORT}} proto tcp"
```

**nftables (inet family handles both IPv4 and IPv6):**
```toml
open_tcp_command = "nft add rule inet filter input ip saddr {{IP}} tcp dport {{PORT}} accept"
# For IPv6, use the same commands if using inet family, or set ip6 saddr:
open_tcp6_command = "nft add rule inet filter input ip6 saddr {{IP}} tcp dport {{PORT}} accept"
```

**Windows Firewall:**
```toml
# netsh handles both IPv4 and IPv6 natively - same command templates work for both
open_tcp_command = "netsh advfirewall firewall add rule name=\"SPK_{{IP}}_{{PORT}}\" dir=in action=allow protocol=tcp localport={{PORT}} remoteip={{IP}}"
close_tcp_command = "netsh advfirewall firewall delete rule name=\"SPK_{{IP}}_{{PORT}}\""
```
