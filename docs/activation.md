# Activation Bundle Format

The activation bundle is required to set up an SPK client. It contains the server's ML-KEM encapsulation key, listen port (or dynamic port seed), open duration defaults, and policy flags -- everything a client needs to construct valid knock packets. Without activation, the client has no key material and cannot communicate with the server.

> [!CAUTION]
> The activation bundle contains the server's public key -- anyone who obtains it can construct valid knock packets and open your firewall ports (unless TOTP is also enabled). Treat it like a private key: delete it from intermediate storage after import, and store the imported key in the OS credential manager. See [security.md - Secure Key Storage](security.md#secure-key-storage).

> [!TIP]
> Set a password when exporting (`spk --server --export`) to AES-256-GCM encrypt the bundle -- strongly recommended when sending it over insecure channels. The recipient supplies the same password during `spk --client --setup`.

During server setup (`spk --server --setup`), the activation bundle is generated automatically and saved as `activation.b64` (text) and `activation_qr.png` (QR code). Transfer either to the client machine and run `spk --client --setup` to import it.

- **activation.b64**: binary layout (below), base64-encoded
- **activation_qr.png**: binary layout (below), raw bytes

Both encode the same logical content. The binary always starts with the `"SPK"` magic prefix (see Binary Layout).

## Binary Layout

```
"SPK"          (3 bytes)  -- magic / version identifier
Version        (1 byte)   -- bundle version (2)
Flags          (1 byte)   -- bit field (bits 4-7 reserved, must be zero):
                             bit 0: custom open duration allowed
                             bit 1: custom port allowed
                             bit 2: open-all allowed
                             bit 3: dynamic port enabled
[Port]         (2 bytes)  -- static listen port (only if dynamic=0)
[Seed]         (8 bytes)  -- dynamic port seed (only if dynamic=1)
OpenDuration   (4 bytes)  -- default open duration in seconds (big-endian)
Window         (4 bytes)  -- dynamic port rotation period in seconds (0 = default 600)
[RangeMin]     (2 bytes)  -- dynamic port range lower bound, INCLUSIVE (only if dynamic=1, big-endian)
[RangeMax]     (2 bytes)  -- dynamic port range upper bound, INCLUSIVE (only if dynamic=1, big-endian)
KEM Size       (2 bytes)  -- ML-KEM key size: 768 or 1024 (big-endian)
Encapsulation Key (variable) -- ML-KEM public key (1184 bytes for 768, 1568 bytes for 1024)
CRC32          (4 bytes)  -- CRC32/IEEE checksum of all preceding bytes (big-endian)
```

Total: ~1207-1599 bytes depending on KEM size and flags (SPK magic + binary payload + 4-byte CRC32). Fits QR Medium EC.

> [!IMPORTANT]
> Only version `2` bundles are accepted. Version 1 bundles (which had no port range field) must be rejected with a message telling the user to re-export on the server. Dynamic-port bundles always carry the range field; static-port bundles never do. Parsers must reject a range with min < 1 or min >= max, and any flags with reserved bits set.

> [!IMPORTANT]
> The final 4 bytes are a CRC32/IEEE checksum over all preceding bytes. Parsers MUST verify it and reject bundles with a mismatched or missing checksum.

## Encrypted Bundles

When a password is set during server export (`spk --server --export`), bundles use an encrypted wrapper. This is recommended whenever the bundle must travel over an untrusted channel. The recipient provides the password at import time (`spk --client --setup`).

> [!IMPORTANT]
> A forgotten password is not recoverable -- SPK never stores it. Re-run `spk --server --export` to generate a new bundle; the server keypair is unchanged.

```
"SPKE"         (4 bytes)  -- encrypted bundle magic
Salt           (32 bytes) -- random salt for Argon2id
Encrypted Data (variable) -- AES-256-GCM(Argon2id(password, salt), raw_payload)
```

## Encrypted Bundle Decryption

When the bundle starts with `"SPKE"`:

1. Extract `salt` (bytes 4-35, 32 bytes) and `encrypted_data` (bytes 36+)
2. Derive key: `key = Argon2id(password, salt, time=3, memory=65536 KB, threads=4, keyLen=32)`
3. Split encrypted_data: `nonce = encrypted_data[0:12]`, `ciphertext = encrypted_data[12:]`
4. Decrypt: `raw = AES-256-GCM-Open(key, nonce, ciphertext, aad=nil)`
5. Parse raw as the binary layout (see above - starts with `"SPK"` + version + flags + ...)

## Parsing the Bundle

The activation bundle is provided as a base64 string (from `activation.b64`).

```
decoded = base64_decode(activation_b64_string)
```

**Detect format:**
- If `decoded` starts with `"SPKE"` (4 bytes) -> encrypted bundle (see [Encrypted Bundle Decryption](#encrypted-bundle-decryption))
- If `decoded` starts with `"SPK"` (3 bytes, but NOT `"SPKE"`) -> unencrypted bundle

**Parse unencrypted bundle:**

The decoded data IS the binary layout (it starts with `"SPK"`).
Parse it directly:

```
decoded[0:3]   = "SPK"       // magic (3 bytes) -- verify, then skip
decoded[3]     = 0x02        // version byte (must be 2; reject 1 with a re-export hint)
decoded[4]     = flags       // bit field (1 byte); reject if bits 4-7 set
                             //   bit 0 (0x01): allow custom open duration
                             //   bit 1 (0x02): allow custom port
                             //   bit 2 (0x04): allow open-all
                             //   bit 3 (0x08): dynamic port enabled

if flags & 0x08:  // dynamic port
    decoded[5:13]  = seed              // 8-byte dynamic port seed
    offset = 13
else:             // static port
    decoded[5:7]   = port              // uint16 big-endian, static listen port
    offset = 7

decoded[offset : offset+4]   = open_duration   // uint32 big-endian, default open duration in seconds
decoded[offset+4 : offset+8] = window    // uint32 big-endian, port rotation period (0 = default 600s)

if flags & 0x08:  // dynamic port: range always present, both bounds INCLUSIVE
    decoded[offset+8 : offset+10]  = range_min  // uint16 big-endian
    decoded[offset+10 : offset+12] = range_max  // uint16 big-endian
    // reject if range_min < 1 or range_min >= range_max
    offset += 4

decoded[offset+8 : offset+10] = kem_size // uint16 big-endian, 768 or 1024

// Determine encapsulation key size from kem_size:
//   768  -> ek_size = 1184 bytes
//   1024 -> ek_size = 1568 bytes
ek_size = 1184 if kem_size == 768 else 1568
decoded[offset+10 : offset+10+ek_size] = encapsulation_key

// CRC32 trailer (4 bytes, big-endian) -- REQUIRED:
//   crc32_stored  = uint32 big-endian at decoded[offset+10+ek_size : offset+10+ek_size+4]
//   crc32_computed = CRC32/IEEE over decoded[0 : offset+10+ek_size]
//   MUST verify: crc32_stored == crc32_computed; reject bundle if mismatch or if field is absent
//   Total expected length: offset + 10 + ek_size + 4
//   Any other length: reject as malformed
```

> [!NOTE]
> Only version byte `2` is accepted. Reject version `1` with a message telling the user to re-export the bundle on the server.

**Summary of extracted values:**

| Value | Type | Description |
|---|---|---|
| `flags` | byte | Policy bit field |
| `seed` | 8 bytes | Dynamic port seed (only if dynamic) |
| `port` | uint16 | Static listen port (only if not dynamic) |
| `open_duration` | uint32 | Default open duration in seconds |
| `window` | uint32 | Port rotation period in seconds (0 = 600) |
| `range_min` | uint16 | Dynamic port range lower bound, inclusive (dynamic bundles only) |
| `range_max` | uint16 | Dynamic port range upper bound, inclusive (dynamic bundles only) |
| `kem_size` | uint16 | ML-KEM key size: 768 or 1024 |
| `encapsulation_key` | 1184 or 1568 bytes | ML-KEM public (encapsulation) key |
| `crc32` | uint32 (big-endian) | CRC32/IEEE checksum of all preceding bytes (mandatory) |
