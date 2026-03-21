# Security

> **Security Policy:** We take security seriously. If you discover a security vulnerability or flaw in SPK, please report it immediately by opening an issue in the [Security](../../security) section. Include as much detail as possible to help us reproduce and fix the problem.

This document covers SPK's security architecture, threat model, and defense mechanisms.

## Security Analysis

### Attacks Considered and Mitigations

| Attack | Mitigation |
|---|---|
| **Replay** | Nonce tracking + timestamp + authenticated encryption (see [Anti-Replay](#anti-replay-mechanism)) |
| **MITM / Packet Modification** | AES-256-GCM authentication - any bit flip causes decryption failure |
| **MITM / Key Interception** | Server public key is **never** sent over the knock channel -- distributed out-of-band via activation bundle (see [below](#public-key-distribution--mitm)) |
| **IP Spoofing** | Client IP encrypted in payload; server validates against UDP source |
| **Packet Forwarding / Relay** | Same as IP spoofing - relayed packet's source IP won't match |
| **UDP Reflection / Amplification** | Server **never** sends responses - zero amplification factor |
| **Port Scanning** | Dynamic port rotation changes the listen port every N seconds |
| **Brute Force** | ML-KEM-768 = 192-bit security level; ML-KEM-1024 = 256-bit; AES-256-GCM |
| **Quantum Attacks** | ML-KEM is NIST-approved post-quantum (FIPS 203) |
| **Key Extraction** | Private key file has 0600 permissions; optional DPAPI/Keychain storage |
| **Nonce Exhaustion** | Configurable max cache with automatic LRU eviction |
| **State File Injection** | Recovered commands validated against firewall-binary allowlist + injection blocklist |
| **Command Injection** | All firewall command parameters sanitized; strict input validation |
| **Timing Attacks** | No response sent - attacker gets no timing information |
| **CPU DoS (packet flood)** | Dynamic port rotation hides the listen port; sniffer validates packet size (1118-8192 bytes) before processing; no response to invalid packets; no state allocated before authentication |
| **Clock Skew** | Configurable timestamp tolerance (default 30s); NTP recommended |
| **DPI / Traffic Fingerprinting** | Optional padding randomizes packet size (see [Padding](knock-protocol.md#padding)) |
| **TOTP 2FA** | Optional TOTP (RFC 6238) adds a second factor -- attacker needs the secret even with the public key |

### Public Key Distribution & MITM

The server's ML-KEM public key is **never transmitted over the network** during knock operations. The key exchange works as follows:

1. **Server setup** generates an ML-KEM keypair (768 or 1024, selected during setup). The private key stays on the server (`server.key`). The public key is embedded in an **activation bundle** (`activation.b64`).
2. **Activation bundle transfer** happens **out-of-band**: file copy (USB, SCP, email), QR code scan, or pasting the base64 string directly. This is a one-time step.
3. **Client setup** imports the activation bundle and stores the public key locally (file or credential manager).
4. **Every knock** the client uses the locally-stored public key to perform ML-KEM encapsulation, producing a fresh shared secret + ciphertext. Only the ciphertext (not the public key) travels over the network.

**Why a passive MITM cannot forge knocks:**

- An attacker monitoring the knock channel sees only ML-KEM ciphertexts and AES-256-GCM encrypted payloads. The public key is never present in any network packet.
- Without the public key, the attacker cannot perform ML-KEM encapsulation to create valid ciphertexts.
- Without the private key, the attacker cannot decapsulate captured ciphertexts to learn the shared secret.
- The server never sends any response, so there is no handshake to intercept or manipulate.

**The only way to compromise key distribution** is to intercept the activation bundle during the out-of-band transfer. Mitigations:

- **Use encrypted bundles:** `spk --server --export` prompts for an optional password. A password-protected bundle is AES-256-GCM encrypted and safe to send over email, messaging apps, or shared storage. Only the recipient who knows the password can import it.
- **Password is not recoverable:** If the password is forgotten before the client imports the bundle, generate a new export with `spk --server --export`. The server keypair is unchanged. SPK never stores the bundle password.
- **Delete after import:** Once `spk --client --setup` has imported the bundle, delete the bundle file from any intermediate storage (email sent folder, USB drives, clipboard history).
- **Use secure transfer channels:** SCP or encrypted email for unencrypted bundles. QR code scanning reduces clipboard/file exposure.
- **Verify the bundle fingerprint** if your transfer channel does not guarantee integrity.

### What's NOT Protected

- **Traffic analysis**: An observer can see that a UDP packet was sent to the server (but not its contents or which port was opened). Enable padding to randomize packet sizes and make fingerprinting harder.
- **Key compromise**: If the private key is stolen, an attacker can decrypt new packets. Rotate keys using `--server --setup`.
- **Network-level DoS**: A sustained UDP flood can consume the server's network bandwidth or CPU. Dynamic port rotation is the primary defense (attackers must discover the port before flooding). Bandwidth saturation requires upstream filtering (cloud firewall, ISP null-routing, etc.).
- **Physical access**: An attacker with root access to the server can read the private key.

### Secure Key Storage

The server's ML-KEM public key (encapsulation key) and the activation bundle are the most sensitive client-side assets. Anyone who possesses the server public key can construct valid knock packets (unless TOTP is also enabled). **Treat the activation bundle and the server public key exactly like a private key** -- if either is leaked, an attacker can open your firewall ports.

**Recommended practices:**

1. **Encrypt the bundle for transport.** When exporting (`spk --server --export`), set a password. The bundle is then AES-256-GCM encrypted and safe to transfer over untrusted channels. Remember the password: if it is forgotten before the client imports the bundle, you must re-export.
2. **Delete after import.** Once `spk --client --setup` has imported the bundle, delete the file and any copies from email, USB drives, and clipboard history.
3. **Store the imported key in the OS credential manager.** SPK supports the following backends -- chosen during client setup:

| Platform | Storage Backend | Method |
|---|---|---|
| Windows | Credential Manager + DPAPI | `cmdkey` + `ProtectedData.Protect()` |
| macOS | Keychain | `security add-generic-password` |
| Linux | Secret Service | `secret-tool store` |

The setup wizard tests the secure storage before committing: writes a test credential, reads it back, verifies, and cleans up. If the test fails, you are prompted to choose file-based storage instead.

Keys stored in credential managers are encrypted with your OS user credentials -- they can only be accessed by the same user account on the same machine. This prevents accidental leakage through backups, screenshots, or other programs reading config directories.

### Anti-Replay Mechanism

SPK uses a **three-layer** anti-replay defense:

#### Layer 1: Authenticated Encryption (AES-256-GCM)

The nonce is **inside** the encrypted payload, not outside. An attacker cannot:

- **Flip bits** in the ciphertext to change the nonce - GCM authentication fails immediately
- **Re-encrypt** with a different nonce - they don't have the shared secret
- **Re-encapsulate** with a new KEM - produces a different shared secret, decryption fails

Even a single bit flip anywhere in the packet causes complete decryption failure.

#### Layer 2: Nonce Tracking

After successful decryption, the server records the 32-byte hex nonce. Any packet with a previously-seen nonce is rejected. This catches exact-copy replay attacks.

The nonce cache has a configurable maximum size (`max_nonce_cache`, default 10,000 entries). When full, expired entries are swept first, then the oldest entries are evicted to make room. This prevents memory exhaustion under sustained traffic.

#### Layer 3: Timestamp Validation

The packet timestamp must be within `timestamp_tolerance` (default 30s) of the server's clock. Packets outside this window are rejected regardless of nonce.

#### Gap Analysis

The system enforces `nonce_expiry >= timestamp_tolerance` on startup (auto-corrected if misconfigured). This ensures there is **no gap** where a replayed packet could pass:

| Time since original packet | Timestamp check | Nonce check | Result |
|---|---|---|---|
| 0-30s (within tolerance) | PASS | **REJECT** (seen before) | Replay blocked |
| 30s-2min (past tolerance) | **REJECT** (too old) | Would also reject | Double-blocked |
| 2min+ (nonce expired) | **REJECT** (too old) | Would also reject | Still blocked |

**Bottom line**: An attacker with a captured packet can never replay it. The authenticated encryption prevents modification, nonce tracking prevents exact replay, and the timestamp window eventually makes the packet unusable.

### Client IP Detection

The knock payload includes the client's IP address for anti-spoofing verification. SPK automatically detects the correct IP:

#### LAN Targets (Private IP)

When the server is on a private network (10.x.x.x, 172.16-31.x.x, 192.168.x.x, loopback, link-local), the client uses the OS routing table to select the correct local interface. This works correctly with multiple network interfaces - the OS picks the interface that would route to the server.

#### WAN Targets (Public IP)

When the server is on a public IP, the client uses **STUN** (Session Traversal Utilities for NAT, RFC 5389) to detect its own public IP:

1. Sends a lightweight UDP Binding Request to each configured STUN server in turn
2. Uses the first successful response (XOR-MAPPED-ADDRESS)
3. Uses the discovered WAN IP in the knock packet

This handles NAT transparently - the client learns the same IP that the server will see.

STUN servers are configured in the client config via `stun_servers`:
```toml
stun_servers = ["stun.cloudflare.com:3478", "stun.l.google.com:19302", "stun1.l.google.com:19302"]
```

**Disabling STUN:** Set `stun_servers` to an empty array or comment it out entirely to disable STUN:
```toml
# stun_servers = [...]   # commented out -- STUN disabled
# or:
stun_servers = []
```
When STUN is disabled, the client uses the local network interface IP selected by the OS routing table and prints a warning at connect time. This is the correct behaviour for LAN or VPN setups where the server can already see your local IP. It will likely cause IP mismatch failures if you are behind internet NAT -- use `--ip` or re-enable `stun_servers` in those cases.

#### CGNAT Detection

SPK automatically detects Carrier-Grade NAT (CGNAT) environments (100.64.0.0/10). When the target server is on a CGNAT IP, the client recognizes this as a private/LAN target and uses the local interface IP rather than performing STUN discovery.

#### Manual Override

Use `--ip` to specify a fixed client IP (useful for static WAN IPs or VPN setups):

```bash
./spk --client --cmd open-t22 --ip 203.0.113.50
./spk --client --cmd open-t22 --ip 2001:db8::1    # IPv6
```

#### NAT Environments

When `match_incoming_ip = false` is set, the server does not verify that the UDP source IP matches the IP embedded in the knock payload. The IP supplied by the client in the encrypted payload is taken as-is and used to open firewall ports. The authenticated encryption still prevents all packet modification, so the security reduction is minimal -- only relay attacks from a compromised network path become possible.

This also helps scenarios where an admin wants to manually authorize a remote user -- simply pass the remote IP using the `--ip` flag with `match_incoming_ip = false`.

### Dynamic Port Rotation

SPK can rotate its listen port automatically using a shared seed, making port scanning ineffective.

During server setup, a random 8-byte seed is generated. Both server and client derive the current port from:

```
port = HMAC-SHA256(seed, floor(unix_time / window)) mod 55000 + 10000
```

- The rotation period is **configurable** (default 600 seconds / 10 minutes, range 60-86400)
- Both sides compute the same port independently - no communication needed
- Port range: 10000-64999
- The seed and window are included in the exported bundle so clients learn them automatically
- Server wakes up precisely at each window boundary (within 1s), so client and server switch ports in sync

The rotation period can be changed in config (`dynamic_port_window`) and is embedded in the client bundle. Both sides must use the same window or the ports won't match.

Disable dynamic port by answering "no" during setup; the server will listen on a fixed port instead.

### CPU DoS Mitigation

Every received packet requires ML-KEM decapsulation + AES-256-GCM decryption before the server can determine whether it is legitimate. Since UDP source addresses are trivially spoofed, per-IP rate limiting is ineffective -- an attacker can rotate source IPs freely. Instead, SPK relies on a defense-in-depth approach:

1. **Dynamic port rotation** -- the listen port changes every N seconds using a HMAC-derived schedule shared only with authorized clients. An attacker must first discover the current port before flooding, and the window is short-lived. This is the most effective mitigation.
2. **Sniffer-layer size filter** -- the sniffer drops packets smaller than 1118 bytes (minimum ML-KEM-768 packet) or larger than 8192 bytes **before** any cryptographic work. This eliminates trivial small-packet floods at near-zero cost.
3. **No response** -- the server never replies, so attackers get no feedback about whether packets are reaching the correct port.
4. **No state or allocation before authentication** -- invalid packets are rejected quickly with minimal memory allocation.
5. **Fast rejection path** -- packets that fail size validation, KEM decapsulation, or GCM authentication are discarded immediately with no further processing.
6. **Concurrency limiter** -- the server caps concurrent knock-processing goroutines at 9999. When the pool is exhausted, additional packets are dropped with a warning log rather than spawning unbounded goroutines.
7. **IPv6 extension header cap** -- packet parsers limit IPv6 extension header traversal to 10 headers. Crafted packets with excessive extension header chains are discarded, preventing parser-level CPU waste.

For deployments facing sustained high-volume attacks, combine dynamic port rotation with upstream network-level filtering (cloud firewall rules, ISP null-routing, or kernel-level rate limiting via `iptables -m hashlimit`).

## Fail-Safe Mechanisms

- **State persistence**: Open port records are saved to `state.json`. On crash/restart, the server recovers state and closes expired ports.
- **State validation**: Recovered close commands are checked for injection patterns (`;`, `|`, `&&`, `` ` ``, `$()`, etc.) before execution. Tampered entries are skipped with a log warning.
- **Automatic timeout**: Every open port has a timeout (default 3600s). When expired, the close command executes automatically.
- **Graceful shutdown**: On SIGINT/SIGTERM, all open ports are closed before exit, depends on settings.
- **No response**: Server never sends responses - zero attack surface for the knock listener.
- **Nonce-expiry validation**: Server ensures `nonce_expiry >= timestamp_tolerance` on startup, auto-correcting if misconfigured.

## TOTP (Two-Factor Authentication)

TOTP (Time-based One-Time Password, RFC 6238) adds an optional second authentication factor. When enabled, each knock must include a valid 6-digit code from a third-party authenticator app.

### How It Works

1. **During server setup**, SPK generates a random 160-bit secret (base32-encoded, 32 characters)
2. **The secret is displayed as a QR code** (and saved to `totp_qr.png`) for scanning into an authenticator app (Google Authenticator, Authy, Microsoft Authenticator, etc.)
3. **The secret is stored ONLY in two places**: the server config and the authenticator app on the user's phone/device
4. **The client never has the TOTP secret** -- it is not included in the activation bundle
5. **Each knock must include a 6-digit code** from the authenticator app, passed via the `--totp` flag

### Why Use TOTP?

TOTP is **not strictly necessary** for security -- the ML-KEM encryption and nonce tracking already prevent unauthorized access. TOTP adds defense-in-depth:

- **Key compromise**: If the server's private or public key is stolen, an attacker still needs the TOTP secret (on a separate device) to send valid knocks
- **Insider threat**: A user with the activation bundle cannot knock without also possessing the authenticator device

### TOTP Parameters

| Parameter | Value |
|---|---|
| Algorithm | HMAC-SHA1 (RFC 4226/6238 standard) |
| Digits | 6 |
| Period | 30 seconds |
| Tolerance | +/- 1 step (accepts codes from 30s ago to 30s ahead) |
| Secret | 160-bit random, base32-encoded (32 chars) |
| Issuer | `SPK` (displayed in authenticator app) |
| Account | `SPK_Server` |

### Usage

```bash
# Server: enable TOTP during setup (interactive prompt)
./spk --server --setup

# Server: re-export bundle and display TOTP QR code
./spk --server --export

# Client: include TOTP code with each knock
./spk open-t22 --totp 482901
./spk --client --cmd open-t22 --totp 123456
```
