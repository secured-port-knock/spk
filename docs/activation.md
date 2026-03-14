# Activation Bundle Format

The activation bundle is required to set up an SPK client. It contains the server's ML-KEM encapsulation key, listen port (or dynamic port seed), timeout defaults, and policy flags -- everything a client needs to construct valid knock packets. Without activation, the client has no key material and cannot communicate with the server.

> **Security Warning:** The activation bundle contains the server's public key (encapsulation key). Treat it with the same care as a private key. Anyone who obtains this bundle can construct valid knock packets and open your firewall ports (unless TOTP is also enabled as a second factor). After importing the bundle on the client, delete it from any intermediate storage (email, USB, shared drives, clipboard history). SPK supports storing the imported key in your operating system's credential manager (Windows Credential Manager / DPAPI, macOS Keychain, Linux Secret Service) to prevent accidental exposure. See [security.md - Secure Key Storage](security.md#secure-key-storage) for details.
>
> **Encrypted bundles for safe transport:** When exporting (`spk --server --export`), SPK prompts for an optional password. If a password is set, the bundle is AES-256-GCM encrypted before being saved or displayed. This is strongly recommended when transporting the bundle over insecure channels (email, messaging apps, shared storage). The recipient must supply the same password during `spk --client --setup` to decrypt and import the bundle.

During server setup (`spk --server --setup`), the activation bundle is generated automatically and saved as `activation.b64` (text) and `activation_qr.png` (QR code). Transfer either to the client machine and run `spk --client --setup` to import it.

- **activation.b64**: `"SK"` prefix + zlib-compressed binary, then base64-encoded
- **activation_qr.png**: `"SK"` prefix + zlib-compressed binary (raw bytes, no base64)

Both encode the same logical content; QR uses raw binary for better space utilization (Medium error correction).

## Binary Layout (inside compressed payload)

```
"SK"           (2 bytes)  -- magic / version identifier
Version        (1 byte)   -- bundle version (1)
Flags          (1 byte)   -- bit field:
                             bit 0: custom timeout allowed
                             bit 1: custom port allowed
                             bit 2: open-all allowed
                             bit 3: dynamic port enabled
[Port]         (2 bytes)  -- static listen port (only if dynamic=0)
[Seed]         (8 bytes)  -- dynamic port seed (only if dynamic=1)
Timeout        (4 bytes)  -- default timeout in seconds (big-endian)
Window         (4 bytes)  -- dynamic port rotation period in seconds (0 = default 600)
KEM Size       (2 bytes)  -- ML-KEM key size: 768 or 1024 (big-endian)
Encapsulation Key (variable) -- ML-KEM public key (1184 bytes for 768, 1568 bytes for 1024)
```

Total uncompressed: ~1200-1585 bytes depending on KEM size. After zlib + raw binary: fits QR Medium EC.

## Encrypted Bundles

When a password is set during server export (`spk --server --export`), bundles use an encrypted wrapper. This is recommended whenever the bundle must travel over an untrusted channel. The recipient provides the password at import time (`spk --client --setup`).

> **Important:** If the password is forgotten before the client imports the bundle, there is no recovery path for that export. Re-run `spk --server --export` on the server to generate a new bundle. The server keypair is unchanged -- only the export needs to be repeated. SPK never stores the bundle password.

```
"SKE"          (3 bytes)  -- encrypted bundle magic
Salt           (32 bytes) -- random salt for Argon2id
Encrypted Data (variable) -- AES-256-GCM(Argon2id(password, salt), compressed_payload)
```

## Encrypted Bundle Decryption

When the bundle starts with `"SKE"`:

1. Extract `salt` (bytes 3-34, 32 bytes) and `encrypted_data` (bytes 35+)
2. Derive key: `key = Argon2id(password, salt, time=3, memory=65536 KB, threads=4, keyLen=32)`
3. Split encrypted_data: `nonce = encrypted_data[0:12]`, `ciphertext = encrypted_data[12:]`
4. Decrypt: `compressed = AES-256-GCM-Open(key, nonce, ciphertext, aad=nil)`
5. Decompress: `raw = zlib_decompress(compressed)`
6. Parse raw as the binary layout (see above - starts with `"SK"` + version + flags + ...)

## Parsing the Bundle

The activation bundle is provided as a base64 string (from `activation.b64`).

```
decoded = base64_decode(activation_b64_string)
```

**Detect format:**
- If `decoded` starts with `"SKE"` (3 bytes) -> encrypted bundle (see [Encrypted Bundle Decryption](#encrypted-bundle-decryption))
- If `decoded` starts with `"SK"` (2 bytes, but NOT `"SKE"`) -> unencrypted bundle

**Parse unencrypted bundle:**

```
magic              = decoded[0:2]        // "SK" - skip these
compressed_data    = decoded[2:]         // rest is zlib-compressed
raw                = zlib_decompress(compressed_data)
```

**Parse the decompressed binary:**

```
raw[0:2]   = "SK"        // magic (2 bytes)
raw[2]     = 0x01        // version byte (must be 1)
raw[3]     = flags       // bit field (1 byte)
                         //   bit 0 (0x01): allow custom timeout
                         //   bit 1 (0x02): allow custom port
                         //   bit 2 (0x04): allow open-all
                         //   bit 3 (0x08): dynamic port enabled

if flags & 0x08:  // dynamic port
    raw[4:12]  = seed              // 8-byte dynamic port seed
    offset = 12
else:             // static port
    raw[4:6]   = port              // uint16 big-endian, static listen port
    offset = 6

raw[offset : offset+4]   = timeout   // uint32 big-endian, default timeout seconds
raw[offset+4 : offset+8] = window    // uint32 big-endian, port rotation period (0 = default 600s)
raw[offset+8 : offset+10] = kem_size // uint16 big-endian, 768 or 1024

// Determine encapsulation key size from kem_size:
//   768  -> ek_size = 1184 bytes
//   1024 -> ek_size = 1568 bytes
ek_size = 1184 if kem_size == 768 else 1568
raw[offset+10 : offset+10+ek_size] = encapsulation_key
```

> **Note:** Only version byte `1` is accepted.

**Summary of extracted values:**

| Value | Type | Description |
|---|---|---|
| `flags` | byte | Policy bit field |
| `seed` | 8 bytes | Dynamic port seed (only if dynamic) |
| `port` | uint16 | Static listen port (only if not dynamic) |
| `timeout` | uint32 | Default timeout in seconds |
| `window` | uint32 | Port rotation period in seconds (0 = 600) |
| `kem_size` | uint16 | ML-KEM key size: 768 or 1024 |
| `encapsulation_key` | 1184 or 1568 bytes | ML-KEM public (encapsulation) key |
