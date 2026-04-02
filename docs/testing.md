# Testing

## Running Tests

```bash
# Run all unit tests + fuzz seed corpus
go test ./... -v

# Run fuzz seed corpus only
go test ./... -run=^Fuzz

# Run specific package
go test ./internal/server/ -v

# With coverage
make coverage

# Quick (no -v)
make test-short

# Run all test phases: smoke, unit+integration, fuzz, sniffer
make testall           # Linux/macOS via build.sh
.\build.ps1 -testall   # Windows
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

Integration tests in `tests/integration/` are pure Go and require no compiled
binary or sniffer hardware. They run as part of the normal `go test ./...`
command and are included in `-test` and `-testall` alongside unit tests.

### Smoke Tests (tag: testsmoke)

End-to-end tests that build the SPK binary, run it as a subprocess, and verify
the full UDP knock lifecycle. These require no special privileges in UDP mode.
Stealth sniffer modes (pcap, afpacket, windivert) require root/Administrator.

In CI the smoke tests are split into three separate platform jobs:

- **smoke-tests-linux**: libpcap installed; runs as root via `sudo -E` so pcap
  and AF_PACKET sniffer smoke tests execute (not just skip).
- **smoke-tests-macos**: libpcap built into the OS; runs as root via `sudo -E`
  so the pcap sniffer smoke test executes.
- **smoke-tests-windows**: WinDivert downloaded from the official release zip
  and installed to System32; pcap auto-skips (Npcap silent install not available
  without the OEM license).

The build scripts (`build.sh -testsmoke`, `build.ps1 -testsmoke`) also escalate
via `sudo -E` on Linux/macOS when not already root and sudo is available.

The smoke tests are split across focused files:

- `smoke_main_test.go` -- TestMain, binary build, module root discovery
- `smoke_setup_test.go` -- server setup structs and subprocess management
- `smoke_helpers_test.go` -- utility functions (stub commands, markers, port helpers)
- `smoke_udp_test.go` -- UDP knock scenario tests
- `smoke_sniffer_test.go` -- sniffer backend tests (pcap, afpacket, windivert)

Run with:

```bash
# Linux / macOS
./build.sh -testsmoke

# Windows
.\build.ps1 -testsmoke

# Or directly via go test
go test -buildvcs=false -v -count=1 -timeout 300s -tags testsmoke ./tests/smoke/
```

| Test | What It Verifies |
|---|---|
| `TestSmokeUDPBasicKnock` | Single open-t22 knock executes open command |
| `TestSmokeUDPCloseOnShutdown` | Graceful shutdown executes close commands for all open ports |
| `TestSmokeUDPCloseOnExpiry` | Port close command fires after open duration expires |
| `TestSmokeUDPTOTP` | Valid TOTP accepted; missing TOTP rejected |
| `TestSmokeUDPDynamicPort` | Client and server compute same dynamic port from shared seed |
| `TestSmokeUDPAllowedPorts` | Ports not in allowed_ports are denied; listed ports are accepted |
| `TestSmokeUDPAllowOpenAll` | open-all with allow_open_all=true fires open_all_command |
| `TestSmokeUDPAllowOpenAllDenied` | open-all with allow_open_all=false is denied |
| `TestSmokeUDPMatchIncomingIP` | Spoofed payload IP rejected; matching source IP accepted |
| `TestSmokePcapSniffer` | Full round-trip via pcap backend (skips without Npcap/libpcap or root) |
| `TestSmokeAfPacketSniffer` | Full round-trip via AF_PACKET backend (Linux + root only) |
| `TestSmokeWinDivertSniffer` | Full round-trip via WinDivert backend (Windows + Administrator only) |

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

Seed corpus tests run automatically as part of `-test` and `-testall` in the build
scripts. The seed corpus exercises every entry point with known-good and known-bad
inputs without performing mutation-based fuzzing.

CI runs two separate fuzz jobs:

- **fuzz-seed-corpus**: Runs all `Fuzz*` targets against their seed corpuses only
  (`-run=^Fuzz`). Fast, deterministic, and required for every PR.
- **fuzz-mutation**: Runs each `Fuzz*` target with actual mutation for 10 s
  (`-fuzz=^FuzzName$ -fuzztime=10s`). Generates inputs beyond the seed corpus and
  catches bugs that seed-only testing misses. Fails CI if a new crash is found.

To run mutation fuzzing locally for a specific target:

```bash
# Run a specific fuzz target for 30 seconds (mutation fuzzing)
go test ./internal/crypto/ -fuzz=FuzzDecapsulateAndDecrypt -fuzztime=30s

# Run all fuzz targets in a package (seed corpus only, no mutation)
go test ./internal/crypto/ -run=^Fuzz

# Run integration fuzz targets (mutation)
go test ./tests/integration/ -fuzz=FuzzRawBytesIntoPipeline -fuzztime=60s

# Run all fuzz seed corpus tests across the project
go test ./... -run=^Fuzz
```

## Build Script Tests

```powershell
# Run unit + integration tests + fuzz seed corpus (Windows)
.\build.ps1 -test

# Run all tests: smoke, unit+integration, fuzz, sniffer
.\build.ps1 -testall

# Run sniffer hardware tests (requires Npcap/libpcap installed)
.\build.ps1 -testSniffer

# Run end-to-end smoke tests
.\build.ps1 -testsmoke

# Coverage report
.\build.ps1 -coverage
```

```bash
# Linux/macOS
./build.sh -test          # unit + integration tests + fuzz seed corpus
./build.sh -testall       # all tests: smoke, unit+integration, fuzz, sniffer
./build.sh -testSniffer   # sniffer hardware tests
./build.sh -testsmoke     # end-to-end smoke tests
```

All test modes route temporary files through `$TMPDIR/spk/` (Linux/macOS) or
`%TEMP%\spk\` (Windows) and remove that directory after the test run completes.

## Continuous Integration

The project uses three GitHub Actions workflows. For build and release workflow documentation, see [compilation.md](compilation.md).

### CI Workflow (`.github/workflows/ci.yml`)

Runs on every push and pull request to `main`/`master`.

| Job | Platform(s) | Description |
|---|---|---|
| **smoke-tests** | Ubuntu, Windows, macOS | End-to-end smoke tests (UDP mode; no elevated privileges needed) |
| **unit-tests** | Ubuntu, Windows, macOS | Unit + integration tests (`./...`) |
| **fuzz-seed-corpus** | Ubuntu | All Fuzz* targets run against their seed corpuses (no mutation) |
| **coverage** | Ubuntu | Same tests as unit-tests with `-coverprofile`; artifact uploaded to Codecov |
| **sniffer-tests-linux** | Ubuntu | Sniffer tests with libpcap + AF_PACKET (requires sudo) |
| **sniffer-tests-windows** | Windows | Non-pcap sniffer tests (Npcap unavailable in CI) |
| **sniffer-tests-macos** | macOS | Sniffer tests with built-in libpcap (requires sudo) |
| **lint** | Ubuntu | `go vet`, `gofmt`, `ineffassign`, `misspell`, **gocognit** |
| **govulncheck** | Ubuntu | Vulnerability scanning (informational, non-blocking) |

The `lint` job enforces a cognitive complexity limit of **25** on all production code using
[gocognit](https://github.com/uudashr/gocognit). Test helpers and test files are also kept
below this threshold for readability. Run it locally:

```bash
# Install gocognit
go install github.com/uudashr/gocognit/cmd/gocognit@latest

# Check all code (threshold 25, production + tests)
gocognit -over 25 .

# Check production code only (CI mode, test files excluded)
gocognit -over 25 -ignore '_test\.go' ./internal/
```

To run locally what the CI workflow runs:

```bash
# Unit + integration tests (all platforms)
go test ./... -count=1 -timeout 120s

# Fuzz seed corpus (all platforms)
go test ./... -run=^Fuzz -count=1 -timeout 120s

# Vet and format check
go vet ./...
gofmt -l .

# Vulnerability scan
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
```

The release workflow uses `./build.sh -testall` (Linux/macOS) or `.\build.ps1 -testall`
(Windows) which runs all four phases: smoke tests, unit + integration, fuzz seed corpus,
and sniffer hardware tests (with graceful skip when Npcap/libpcap is absent).
