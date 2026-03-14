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
- **Command injection**: Shell metacharacter prevention in IP/port/command fields
- **IP binding**: Client IP embedded in encrypted payload and verified against source
- **Forward secrecy**: Each knock uses ephemeral keys; no key reuse across knocks
- **State recovery**: Crash recovery with state.json, close_ports_on_crash behavior
- **Security hardening**: Systemd unit sandboxing, directory permissions

### Server & Command Execution
- **Command execution**: ExecuteCommandTimeout with process group kill (Linux/Windows/macOS)
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
- **Security properties**: Forward secrecy verification, hardening checks
- **Config directory**: Custom cfgdir/logdir via flags
- **Vulnerability scanning**: govulncheck for known CVEs in dependencies

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
| **vet** | Ubuntu | `go vet ./...` static analysis |
| **govulncheck** | Ubuntu | Vulnerability scanning (informational, non-blocking) |

To run locally what the CI workflow runs:

```bash
go test ./... -count=1 -timeout 120s
go vet ./...
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
```
