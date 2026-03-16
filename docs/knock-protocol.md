# UDP Packet Protocol

This document describes the wire format and binary payload layout of SPK knock packets.

## Knock Packet Overview

Each knock is a single UDP datagram (~1170-2100 bytes depending on KEM size, command length, and padding).

**Outer wire format:**

```
[ML-KEM Ciphertext (1088 or 1568 bytes)] [AES-GCM Nonce (12 bytes)] [Encrypted Payload + GCM Tag (16 bytes)]
```

Maximum packet size: **8192 bytes**. Minimum valid packet: **1118 bytes** (ML-KEM-768).

| KEM Size | Ciphertext | Total (no padding) | Fits 1500 MTU? |
|---|---|---|---|
| ML-KEM-768 (default) | 1088 bytes | ~1170-1190 bytes | **Yes** |
| ML-KEM-1024 | 1568 bytes | ~1650-1670 bytes | No (requires IP fragmentation) |

## Binary Payload Layout

The payload uses a compact binary format (not JSON). Fields are packed sequentially:

```
[Version:1][Flags:1][Timestamp:8][Nonce:32][IP:4|16][Timeout:4][CmdLen:1][CmdType:1][CmdData:N-1][TOTP:6?][Pad:rest]
```

**Flags byte (bit field):**

| Bit | Mask | Meaning |
|---|---|---|
| 0 | `0x01` | IPv6: ClientIP is 16 bytes (otherwise 4 bytes for IPv4) |
| 1 | `0x02` | TOTP: 6-byte ASCII TOTP code follows command |
| 2 | `0x04` | Padding: random bytes fill remaining space |

**Command type byte:**

| Value | Meaning | Example full command |
|---|---|---|
| `0x00` | open | `open-t22` (CmdData = `t22`) |
| `0x01` | close | `close-t22` (CmdData = `t22`) |
| `0x02` | cust | `cust-myaction` (CmdData = `myaction`) |

**Field layout:**

| Field | Size | Encoding | Description |
|---|---|---|---|
| Version | 1 byte | uint8 | Must be `1` |
| Flags | 1 byte | bit field | See above |
| Timestamp | 8 bytes | uint64 big-endian | Unix seconds |
| Nonce | 32 bytes | raw random bytes | Anti-replay (not hex-encoded on wire) |
| ClientIP | 4 or 16 bytes | raw `net.IP` bytes | IPv4 (4 bytes) or IPv6 (16 bytes, see flags bit 0) |
| Timeout | 4 bytes | uint32 big-endian | Requested timeout in seconds (0 = server default) |
| CmdLen | 1 byte | uint8 | Total length of CmdType + CmdData (min 1, max 255) |
| CmdType | 1 byte | uint8 | Command type (0x00=open, 0x01=close, 0x02=cust) |
| CmdData | N-1 bytes | ASCII | Command-specific data (e.g. `t22`, `t22,u53`, `myaction`) |
| TOTP | 6 bytes | ASCII digits | Only present if flags bit 1 is set |
| Padding | rest | random bytes | Only present if flags bit 2 is set; fills remaining space |

**Minimum payload size:** 51 bytes (version + flags + timestamp + nonce + IPv4 + timeout + cmdlen + cmdtype with no data).

## Padding

The optional padding field adds random bytes inside the encrypted payload. Because it is inside the AES-256-GCM envelope:

- Observers cannot see the padding content -- only total packet size is visible
- Each packet has a different size, defeating fixed-length fingerprinting
- The server parses and ignores this field; it does not affect processing
- Padding is authenticated by GCM -- tampering is detected
- Use padding size of <= 96 with KEM-768 to stay within MTU

Client config controls:
```toml
padding_enabled = true
padding_min_bytes = 64     # Minimum random bytes (default: 64)
padding_max_bytes = 96     # Maximum random bytes (default: 512, use <=96 with KEM-768 to stay within MTU; max: 2048)
```

## Security Checks (server side)

1. **Size check** -- packet must be between 1118 and 8192 bytes
2. **Decrypt** -- ML-KEM decapsulate (768 or 1024) -> AES-256-GCM decrypt (fails if wrong key or tampered)
3. **Binary decode** -- plaintext must be valid binary payload (minimum 51 bytes, correct structure)
4. **Protocol version** -- version byte must equal `1`
5. **Command type** -- binary command type must be 0x00 (open), 0x01 (close), or 0x02 (cust)
6. **Field validation** -- nonce is 32 raw bytes, command <= 254 data bytes, IP is valid 4 or 16 bytes, timeout 0-604800
7. **Timestamp** -- must be within +/- `timestamp_tolerance` (default 30s) of server clock
8. **IP match** -- decoded IP must equal UDP source IP (when `match_incoming_ip = true`)
9. **Nonce uniqueness** -- nonce must not have been seen before (anti-replay)
10. **TOTP verification** -- if TOTP is enabled, the TOTP field must contain a valid 6-digit code (+/- 30s tolerance)
11. **Command validation** -- command must start with `open-`, `close-`, or `cust-`; port specs must be valid (t/u prefix, 1-65535); all bytes must be printable ASCII
12. **Port allowlist** -- port must be in the `allowed_ports` list (unless custom port is enabled)
13. **Deduplication** -- duplicate open requests for the same IP:port:proto refresh the timeout instead of creating duplicate firewall rules

## UDP Packet Size

Each knock packet size depends on the ML-KEM key size selected during server setup:

**ML-KEM-768 (default, recommended for WAN):**

| Component | Size |
|---|---|
| ML-KEM-768 ciphertext | 1088 bytes |
| AES-GCM nonce | 12 bytes |
| Encrypted binary payload | ~55-75 bytes (without padding) |
| Padding (optional) | 0-2048 bytes |
| GCM authentication tag | 16 bytes |
| **Total (no padding)** | **~1170-1190 bytes** |
| **Total (with safe padding, <=96 bytes)** | **~1270-1290 bytes** |

> **Fits in standard 1500-byte MTU** - no IP fragmentation needed.

**ML-KEM-1024 (higher security margin):**

| Component | Size |
|---|---|
| ML-KEM-1024 ciphertext | 1568 bytes |
| AES-GCM nonce | 12 bytes |
| Encrypted binary payload | ~55-75 bytes (without padding) |
| Padding (optional) | 0-2048 bytes |
| GCM authentication tag | 16 bytes |
| **Total (no padding)** | **~1650-1670 bytes** |
| **Total (with default padding)** | **~1800-2100 bytes** |

> **Always exceeds 1500-byte MTU** -- requires IP fragmentation.

The server accepts packets up to **8192 bytes** maximum.

### IP Fragmentation

Standard Ethernet MTU is 1500 bytes. After IP (20B) and UDP (8B) headers, the max single-frame payload is **1472 bytes**.

**ML-KEM-768 (default):** Knock packets are ~1170-1190 bytes without padding, comfortably within the 1472-byte limit. With conservative padding (<=96 bytes), packets reach ~1270-1290 bytes and still fit within MTU. **No IP fragmentation occurs.**

**ML-KEM-1024:** Knock packets are ~1650+ bytes, **always exceeding MTU**. IP fragmentation will occur on standard Ethernet networks.

**WAN/Internet:**

- Many firewalls, NAT devices, and ISP equipment **silently drop fragmented UDP packets**
- Cloud providers (AWS, GCP, Azure) may have policies against or limitations on IP fragments
- Carrier-Grade NAT (CGNAT) environments are particularly problematic for fragmented UDP
- **Selecting ML-KEM-1024 may cause knocks to fail over WAN connections**

**Recommendation:** Use **ML-KEM-768** (the default) for all WAN/internet deployments. ML-KEM-1024 is suitable for LAN environments or networks you control where IP fragmentation is known to work correctly.

**Impact when fragmentation works:**

- The OS transparently reassembles IP fragments before delivering to the UDP socket - the server receives the complete packet. No application-level changes needed.
- The server's read buffer (8192 bytes) comfortably handles reassembled packets.

## Encryption

```python
# Pseudocode
plaintext = payload                             # binary payload from above

# ML-KEM encapsulation (FIPS 203) - use the KEM size from the bundle
# ML-KEM-768: ek=1184 bytes, ciphertext=1088 bytes, shared_key=32 bytes
# ML-KEM-1024: ek=1568 bytes, ciphertext=1568 bytes, shared_key=32 bytes
shared_key, kem_ciphertext = ML_KEM_Encapsulate(encapsulation_key)
# shared_key: 32 bytes
# kem_ciphertext: 1088 bytes (768) or 1568 bytes (1024)

# AES-256-GCM encryption
aes_nonce = random_bytes(12)               # 12 random bytes
aes_ciphertext_and_tag = AES_256_GCM_Seal(
    key   = shared_key,
    nonce = aes_nonce,
    plaintext = plaintext,
    aad   = nil                            # no additional authenticated data
)
# aes_ciphertext_and_tag includes the 16-byte GCM auth tag appended

# Assemble the wire packet
packet = kem_ciphertext + aes_nonce + aes_ciphertext_and_tag
```

| Component | Size (ML-KEM-768) | Size (ML-KEM-1024) |
|---|---|---|
| `kem_ciphertext` | 1088 bytes | 1568 bytes |
| `aes_nonce` | 12 bytes | 12 bytes |
| `aes_ciphertext_and_tag` | len(plaintext) + 16 | len(plaintext) + 16 |
| **Total** | 1100 + len(plaintext) + 16 | 1580 + len(plaintext) + 16 |

## Cryptographic Requirements

| Algorithm | Standard | Parameters |
|---|---|---|
| ML-KEM-768 | FIPS 203 | Encapsulation key: 1184 bytes, ciphertext: 1088 bytes, shared key: 32 bytes |
| ML-KEM-1024 | FIPS 203 | Encapsulation key: 1568 bytes, ciphertext: 1568 bytes, shared key: 32 bytes |
| AES-256-GCM | NIST SP 800-38D | Key: 32 bytes, nonce: 12 bytes, tag: 16 bytes |
| HMAC-SHA256 | RFC 2104 / FIPS 198-1 | For dynamic port computation only |
| Argon2id | RFC 9106 | For encrypted bundle decryption only (time=3, mem=64MB, threads=4, keyLen=32) |
