# Files

## Generated Files

| File | Description |
|---|---|
| `server.key` | ML-KEM private key (PEM format, **keep secret**) |
| `server.crt` | ML-KEM encapsulation key (PEM format, **treat as secret** -- distributed only via activation bundle) |
| `spk_server.toml` | Server configuration (TOML) |
| `spk_client.toml` | Client configuration (TOML) |
| `activation.b64` | Base64-encoded key bundle (public key + KEM size + seed/port + policies). **Treat like a private key** -- delete after client import |
| `activation_qr.png` | QR code of the key bundle (raw binary, Medium EC). **Treat like a private key** -- delete after client import |
| `totp_qr.png` | TOTP QR code for authenticator apps (when TOTP enabled) |
| `state.json` | Server state for crash recovery |
| `spk_server.log` | Server log (rotated, max 10 MB x 5 backups) |
| `spk_client.log` | Client log (only written when --logdir is specified) |
| `SPK_ServerKey.dpapi` | DPAPI-encrypted server key (Windows only, stored in client config directory) |

## Default Paths

### Server (requires root / Administrator)

| Platform | Config and Keys | Logs |
|---|---|---|
| Linux / macOS | `/etc/spk/` (requires root or `CAP_DAC_OVERRIDE`) | `/var/log/spk/` |
| Windows | `<exe_dir>\config\` | `<exe_dir>\log\` |

If `/etc/spk` cannot be accessed, SPK exits with an error and suggests running as root, fixing permissions, or using `--cfgdir`.
If `/var/log/spk` cannot be created or written, a warning is printed and logging falls back to stdout. Use `--logdir` to direct logs elsewhere.

### Client (no elevated privileges required)

| Platform | Config and Keys | Logs |
|---|---|---|
| Linux / macOS | `~/.config/spk/` (respects `$XDG_CONFIG_HOME`) | Disabled by default; enabled only when `--logdir` is specified |
| Windows | `<exe_dir>\config\` | Disabled by default; enabled only when `--logdir` is specified |

Use `--cfgdir` and `--logdir` to override these defaults on any platform.

> **Re-export**: Run `spk --server --export` to regenerate `activation.b64` and `activation_qr.png` after config changes.

## Project Source Structure

```
cmd/spk/            - Application entry point, Windows service handler
internal/
  client/           - Client-side logic (setup, WAN IP detection, STUN)
  config/           - TOML config parsing and validation
  crypto/           - ML-KEM key management, AES-256-GCM, TOTP, dynamic port, bundle export
  logging/          - Structured logging with rotation and flood protection
  protocol/         - Binary packet encoding/decoding, nonce tracking
  server/           - Server core (knock handling, firewall commands, port tracker)
  service/          - System service install/uninstall (systemd, SCM, launchd, procd)
  sniffer/          - Packet capture backends (UDP, pcap, AF_PACKET, WinDivert)
tests/integration/  - End-to-end integration tests
docs/               - Documentation
version/              - Version metadata
  version_base.txt    - Base version string (e.g. 1.0.0)
  build_number.txt    - Auto-incremented build number
build.ps1             - Windows build script (PowerShell)
build.sh              - Linux/macOS build script (bash)
build.cmd             - Windows CMD wrapper for build.ps1
Makefile              - Make targets for build/test/coverage
.github/workflows/    - GitHub Actions CI and release workflows
  ci.yml              - Continuous integration (tests, sniffer tests, linting)
  build.yml           - Build script verification across all platforms
  release.yml         - Manual release and beta publishing
```
