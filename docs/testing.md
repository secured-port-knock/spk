# Testing

## Running Tests

```bash
# Run all unit tests
go test ./... -v

# Run specific package
go test ./internal/server/ -v

# With coverage
make coverage

# Quick (no -v)
make test-short
```

## Test Categories

Tests cover the following areas:

### Cryptography & Protocol
- **ML-KEM**: Key generation, encryption round-trips, cross-KEM rejection (768 vs 1024), PEM persistence
- **Bundle encoding**: v1 binary format, encrypted bundles, KEM size field, corrupted bundle rejection
- **Protocol**: Binary encoding/decoding, version checks, command validation, rejection error messages
- **TOTP**: RFC 4226 test vectors, round-trip validation, QR generation, integration with knock flow
- **Dynamic port**: Deterministic derivation, window boundary behavior, seed validation
- **Padding**: Edge cases (min/max, disabled), random fill within range

### Security
- **Anti-replay**: Nonce tracking, timestamp validation, cache eviction (max_nonce_cache)
- **Future timestamp injection**: Knocks with timestamps far in the future are rejected; packets within tolerance are accepted
- **Command injection**: Shell metacharacter prevention in IP/port/command fields
- **IP binding**: Client IP embedded in encrypted payload and verified against source
- **Key freshness**: Each knock generates a fresh shared secret via ML-KEM encapsulation; no key reuse across knocks
- **State recovery**: Crash recovery with state.json, close_ports_on_crash behavior
- **Security hardening**: Systemd unit sandboxing, directory permissions
- **Server policy enforcement**: open-all denied when disabled, unlisted ports denied, TOTP required enforcement

### Server & Command Execution
- **Command execution**: ExecuteCommandTimeout with process group kill (Linux/Windows/macOS)
- **Execution fuzz**: Arbitrary strings through shell execution pipeline
- **Timeout enforcement**: Commands killed within configured timeout + process cleanup
- **Concurrent execution**: Multiple simultaneous commands without interference
- **Partial output capture**: Stdout/stderr captured even when commands time out or fail
- **Command output logging**: CMD-OUTPUT logged for successful, failed, and timed-out commands
- **Deduplication**: TryReserve/RefreshExpiry dedup prevents duplicate command execution
- **Close command**: Port close with tracker cleanup and error handling
- **Graceful shutdown**: shutdownCh channel, Stop(), pending goroutine drain

### Logging
- **File writer ordering**: File-first MultiWriter ensures log writes succeed even when stdout is unavailable (Windows service)
- **Log rotation**: Size-based rotation with backup retention
- **Flood protection**: Rate limiting for repeated messages

### Networking & Capture
- **STUN parsing**: WAN IP detection from STUN responses, NAT/CGNAT scenarios
- **STUN fuzz**: Arbitrary bytes into STUN response parser
- **STUN property tests**: XOR-MAPPED-ADDRESS roundtrip, IPv6, truncated attributes, unknown attribute skip
- **Capture modes**: pcap packet parsing, AF_PACKET, WinDivert
- **Sniffer**: Factory creation, multi-address binding, interface detection
- **pcap (Windows)**: WinPcap/Npcap dynamic loading

### Configuration
- **Config validation**: TOML round-trips, required field checks, value ranges
- **KEM config**: ML-KEM-768/1024 selection, server/client agreement
- **TOTP config**: Secret generation, enable/disable toggling

### Integration Tests
- **End-to-end**: Full knock flow with both KEM sizes (768, 1024)
- **TOTP integration**: Knock with TOTP code, rejection without code
- **Padding integration**: Padded knocks across KEM sizes
- **Security properties**: Key freshness verification, hardening checks
- **Config directory**: Custom cfgdir/logdir via flags
- **Vulnerability scanning**: govulncheck for known CVEs in dependencies

### Fuzz Testing
Go native fuzz tests cover every boundary where untrusted data enters the system:

| Package | Fuzz Target | What It Tests |
|---|---|---|
| `crypto` | `FuzzDecapsulateAndDecrypt` | Random bytes into KEM+AES decryption pipeline |
| `crypto` | `FuzzSymmetricDecrypt`, `FuzzSymmetricRoundtrip` | AES-256-GCM with arbitrary ciphertext |
| `crypto` | `FuzzEncryptDecryptRoundtrip` | Full ML-KEM encapsulate/decapsulate cycle |
| `crypto` | `FuzzParseExportBundle`, `FuzzParseExportBundleRaw` | Malformed export bundles |
| `crypto` | `FuzzDecodeBinary` | Binary format parser with arbitrary bytes |
| `crypto` | `FuzzValidateTOTP`, `FuzzGenerateTOTP` | TOTP with arbitrary secrets and codes |
| `crypto` | `FuzzComputeDynamicPortForWindow` | Dynamic port with arbitrary seeds and windows |
| `protocol` | `FuzzDecodePayload` | Binary payload decoder with all flag combinations |
| `protocol` | `FuzzParseKnockPacket` | Full packet decrypt+parse with random ciphertext |
| `protocol` | `FuzzValidateCommand` | Command string validation with arbitrary input |
| `protocol` | `FuzzEncodeDecodePayloadRoundtrip` | Encode/decode consistency property |
| `sniffer` | `FuzzParsePcapPacket` | Raw pcap frames across all link types |
| `sniffer` | `FuzzParseIPv4UDP`, `FuzzParseIPv6UDP` | IP+UDP header parsing with corruption |
| `config` | `FuzzConfigValidate` | Config validation with 15 randomized parameters |
| `config` | `FuzzConfigLoad` | Arbitrary TOML into config loader |
| `server` | `FuzzBuildCommand` | Command template substitution with injection attempts |
| `server` | `FuzzIsValidRecoveredCommand` | State file command allowlist validation |
| `server` | `FuzzParsePortSpec` | Port specification parser |
| `server` | `FuzzSanitizeForLog` | Log sanitizer with control characters |
| `server` | `FuzzExecuteCommandTimeout` | Arbitrary strings through command execution pipeline |
| `client` | `FuzzParseSTUNResponse` | Malformed STUN responses into parser |
| `service` | `FuzzSanitizeServiceLabel` | Service label normalization invariants and allowed character set |
| `integration` | `FuzzRawBytesIntoPipeline` | Random bytes through full decrypt+parse+command pipeline |
| `integration` | `FuzzUDPReceiveSimulation` | Simulated UDP receive through entire server pipeline |
| `integration` | `FuzzExportBundlePortFuzz` | Export bundle port encoding round-trip |

### Property-Based and Mutation-Resilient Tests
Tests designed to catch regressions from code mutations:

- **Tamper detection**: Single-bit flip at every byte position in an encrypted packet
- **Truncation resistance**: Payload truncated at every offset boundary
- **Wrong-key rejection**: Packets encrypted for key A always rejected by key B
- **Anti-replay**: Nonce tracker rejects all replayed nonces under concurrent pressure
- **Future timestamp**: Packets with timestamps beyond tolerance are rejected; packets within tolerance are accepted
- **Injection resistance**: Shell metacharacters in IP/port/protocol fields never reach command output
- **State file injection**: Malicious commands in recovered state always blocked by allowlist
- **TOTP time-window**: Codes from +/-30s accepted, wrong-secret codes rejected
- **TOTP enforcement**: TOTP-enabled server rejects knocks with missing or wrong-secret TOTP codes
- **Policy enforcement**: open-all command denied when disabled; ports not in allowed_ports denied when custom-port disabled
- **Padding neutrality**: Variable padding never alters payload field values
- **IPv6 address preservation**: Various IPv6 formats survive the full encrypt/decrypt cycle
- **Packet uniqueness**: Identical inputs produce cryptographically distinct packets
- **Nonce entropy**: Generated nonces have no common prefixes exceeding 4 bytes
- **MTU compliance**: KEM768 packets with common commands fit within 1500-byte Ethernet MTU
- **Concurrent safety**: Pipeline handles 50+ concurrent valid+garbage packets correctly

### Running Fuzz Tests

```bash
# Run a specific fuzz target for 30 seconds
go test ./internal/crypto/ -fuzz=FuzzDecapsulateAndDecrypt -fuzztime=30s

# Run all fuzz targets in a package (each runs briefly as a unit test)
go test ./internal/crypto/ -run=Fuzz

# Run integration fuzz targets
go test ./tests/integration/ -fuzz=FuzzRawBytesIntoPipeline -fuzztime=60s

# Run all fuzz targets across the project (seed corpus only)
go test ./... -run=Fuzz
```

## Build Script Tests

```powershell
# Run unit tests via build script (Windows)
.\build.ps1 -test

# Run sniffer hardware tests (requires Npcap/libpcap installed)
.\build.ps1 -testSniffer

# Coverage report
.\build.ps1 -coverage
```

```bash
# Linux/macOS
./build.sh -test
./build.sh -testSniffer
```

## Continuous Integration

The project uses three GitHub Actions workflows. For build and release workflow documentation, see [compilation.md](compilation.md).

### CI Workflow (`.github/workflows/ci.yml`)

Runs on every push and pull request to `main`/`master`.

| Job | Platform(s) | Description |
|---|---|---|
| **unit-tests** | Ubuntu, Windows, macOS | All unit tests |
| **coverage** | Ubuntu | Coverage report uploaded as artifact |
| **integration-tests** | Ubuntu, Windows, macOS | End-to-end knock flow tests |
| **sniffer-tests-linux** | Ubuntu | Sniffer tests with libpcap + AF_PACKET (requires sudo) |
| **sniffer-tests-windows** | Windows | Non-pcap sniffer tests (Npcap unavailable in CI) |
| **sniffer-tests-macos** | macOS | Sniffer tests with built-in libpcap (requires sudo) |
| **lint** | Ubuntu | `go vet`, `gofmt`, `ineffassign`, `misspell`, **gocognit** |
| **govulncheck** | Ubuntu | Vulnerability scanning (informational, non-blocking) |

The `lint` job enforces a cognitive complexity limit of **25** on all production code using
[gocognit](https://github.com/uudashr/gocognit). Test helpers are exempt. Run it locally:

```bash
# Install gocognit
go install github.com/uudashr/gocognit/cmd/gocognit@latest

# Check all production code (threshold 25)
gocognit -over 25 ./internal/app/ ./internal/client/ ./internal/config/ \
  ./internal/crypto/ ./internal/logging/ ./internal/protocol/ \
  ./internal/server/ ./internal/service/ \
  | grep -v '_test\.go'
```

To run locally what the CI workflow runs:

```bash
go test ./... -count=1 -timeout 120s
go vet ./...
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
```
