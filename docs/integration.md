# Third-Party Client Integration Guide

This document provides everything needed to build a third-party SPK client in any programming language.

## Overview

A SPK client performs these steps:

1. **Parse the activation bundle** to extract the server's ML-KEM public key, KEM size, port configuration, and policies
2. **Compute the target port** (static or dynamic using HMAC-SHA256)
3. **Build the knock packet** - KEM encapsulate + AES-256-GCM encrypt a compact binary payload
4. **Send** a single UDP datagram to the server

The server never responds - there is no handshake, no acknowledgment, and no error feedback.

## Step 1: Parse the Activation Bundle

See [Activation Bundle Format](activation.md) for the complete binary layout and parsing instructions.

## Step 2: Compute the Target Port

**Static port:** Use the `port` value from the bundle directly.

**Dynamic port:** Compute using HMAC-SHA256:

```python
# Pseudocode
window_seconds = window if window > 0 else 600
time_window = floor(current_unix_time / window_seconds)
time_bytes = uint64_big_endian(time_window)     # 8 bytes

hmac_result = HMAC-SHA256(key=seed, message=time_bytes)
port_raw = uint16_big_endian(hmac_result[0:2])  # first 2 bytes
target_port = (port_raw % 55000) + 10000        # range [10000, 65000)
```

Both client and server independently compute the same port. The port changes every `window_seconds`.

## Step 3: Build the Knock Packet

### 3a. Construct the Binary Payload

See [Knock Protocol - Binary Payload Layout](knock-protocol.md#binary-payload-layout) for the complete field layout.

```python
# Pseudocode: build binary payload (protocol v1)
import struct

flags = 0x00
ip_bytes = parse_ip(client_ip)      # 4 bytes (IPv4) or 16 bytes (IPv6)
if len(ip_bytes) == 16:
    flags |= 0x01                    # flagIPv6

nonce = random_bytes(32)             # 32 raw random bytes

# Encode command as binary type + data
# "open-t22" -> type=0x00, data=b"t22"
# "close-t22" -> type=0x01, data=b"t22"
# "cust-myaction" -> type=0x02, data=b"myaction"
cmd_type, cmd_data = encode_command_binary(command)
assert 1 + len(cmd_data) <= 255     # CmdLen fits in 1 byte

totp_bytes = b''
if totp_code:
    flags |= 0x02                    # flagTOTP
    totp_bytes = totp_code.encode('ascii')  # exactly 6 bytes
    assert len(totp_bytes) == 6

pad_bytes = b''
if padding_enabled:
    flags |= 0x04                    # flagPadding
    pad_len = random_int(min_padding, max_padding)
    pad_bytes = random_bytes(pad_len)

cmd_len = 1 + len(cmd_data)          # type byte + data bytes
payload = (
    struct.pack('!B', 1)                     # Version = 1
    + struct.pack('!B', flags)               # Flags
    + struct.pack('!Q', unix_timestamp)      # Timestamp (uint64 BE)
    + nonce                                   # 32 raw bytes
    + ip_bytes                                # 4 or 16 bytes
    + struct.pack('!I', timeout)             # Timeout (uint32 BE)
    + struct.pack('!B', cmd_len)             # CmdLen
    + struct.pack('!B', cmd_type)            # CmdType (0x00/0x01/0x02)
    + cmd_data                                # CmdData
    + totp_bytes                              # TOTP (0 or 6 bytes)
    + pad_bytes                               # Padding (0+ bytes)
)
```

### 3b. Encrypt the Payload

See [Knock Protocol - Encryption](knock-protocol.md#encryption) for the full encryption details.

```python
# Pseudocode
plaintext = payload                             # binary payload from step 3a

# ML-KEM encapsulation (FIPS 203)
shared_key, kem_ciphertext = ML_KEM_Encapsulate(encapsulation_key)

# AES-256-GCM encryption
aes_nonce = random_bytes(12)
aes_ciphertext_and_tag = AES_256_GCM_Seal(
    key   = shared_key,
    nonce = aes_nonce,
    plaintext = plaintext,
    aad   = nil
)

# Assemble the wire packet
packet = kem_ciphertext + aes_nonce + aes_ciphertext_and_tag
```

### 3c. Send via UDP

Send the assembled `packet` as a single UDP datagram to `server_host:target_port`.

```python
socket = UDP_socket()
socket.sendto(packet, (server_host, target_port))
```

No response will be received. The server processes the packet silently.

## Minimal Client Implementation Checklist

- [ ] Parse activation bundle (base64 decode -> detect format -> decompress -> extract key + config)
- [ ] Optionally decrypt bundle with Argon2id + AES-256-GCM if password-protected
- [ ] Store the ML-KEM encapsulation key (1184 bytes for 768, 1568 bytes for 1024)
- [ ] Note the KEM size from the bundle (768 or 1024) for correct encapsulation
- [ ] Compute dynamic port via HMAC-SHA256 (if dynamic port enabled)
- [ ] Generate 32 random bytes for the nonce
- [ ] Determine current unix timestamp (seconds)
- [ ] Determine client's source IP (the IP the server will see) and encode as 4 or 16 raw bytes
- [ ] Build binary payload: `[Version:1][Flags:1][Timestamp:8][Nonce:32][IP:4|16][Timeout:4][CmdLen:1][CmdType:1][CmdData:N-1][TOTP:6?][Pad:rest]`
- [ ] ML-KEM encapsulate (768 or 1024, matching bundle's KEM size) with the stored public key -> get shared_key + ciphertext
- [ ] AES-256-GCM encrypt the binary payload with shared_key -> get nonce + ciphertext+tag
- [ ] Concatenate: kem_ciphertext (1088 or 1568) + aes_nonce (12) + aes_ciphertext_and_tag
- [ ] Send as single UDP datagram (ML-KEM-768: ~1150-1500 bytes; ML-KEM-1024: ~1640-2100 bytes)
- [ ] Optionally set flags bit 1 and include 6-byte TOTP code (if server requires TOTP)

## Library Recommendations

| Language | ML-KEM (FIPS 203) | AES-256-GCM |
|---|---|---|
| Go 1.24+ | `crypto/mlkem` (stdlib, 768 + 1024) | `crypto/aes` + `crypto/cipher` |
| Rust | `pqcrypto-kyber` or `ml-kem` crate | `aes-gcm` crate |
| Python | `pqcrypto` / `liboqs-python` | `cryptography` (Fernet) or `pycryptodome` |
| C/C++ | [liboqs](https://github.com/open-quantum-safe/liboqs) | OpenSSL / libsodium |
| Java | [Bouncy Castle](https://www.bouncycastle.org/) (bc-pqc) | `javax.crypto.Cipher` |
| JavaScript/Node | [liboqs-node](https://github.com/nicktacik/liboqs-node) | `crypto` module (built-in) |

> **Important:** ML-KEM is the standardized name (FIPS 203). SPK supports both ML-KEM-768 and ML-KEM-1024. Some libraries may still use the draft name "Kyber" or "CRYSTALS-Kyber". Ensure the implementation matches FIPS 203 - the final standard has minor differences from earlier Kyber drafts.
