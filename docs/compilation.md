# Building & Compilation

This document covers building SPK from source, cross-compilation, and Linux packaging.

## Build Requirements

| Tool | Required | Purpose |
|---|---|---|
| **Go 1.24+** | Yes | `crypto/mlkem` standard library support |
| **zig** | Optional | Cross-compile Linux/macOS with pcap (`zig cc` as CGO compiler) |
| **GCC** | Optional | Native builds with pcap (fallback when zig is not installed) |
| **UPX** | Optional | Compress binaries (~50% smaller) |
| **nfpm** | Optional | Build `.deb` / `.rpm` Linux packages |

Install zig: [ziglang.org/download](https://ziglang.org/download/) (`winget install zig.zig` / `brew install zig` / `snap install zig`)

Install nfpm: `go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest`

## Build Scripts

**Windows PowerShell:**

```powershell
.\build.ps1                        # Build windows/amd64 + linux/amd64
.\build.ps1 -all                   # Build all platform/arch combinations
.\build.ps1 -windows               # Build windows/amd64 + windows/arm64
.\build.ps1 -linux                 # Build linux/amd64 + linux/arm64
.\build.ps1 -darwin                # Build darwin/amd64 + darwin/arm64
.\build.ps1 -windows -amd64       # Build windows/amd64 only
.\build.ps1 -linux -arm64         # Build linux/arm64 only
.\build.ps1 -nopcap               # Disable pcap for all targets
.\build.ps1 -test                  # Run unit tests
.\build.ps1 -testSniffer          # Run sniffer hardware tests (requires Npcap)
.\build.ps1 -coverage             # Run tests with coverage
.\build.ps1 -clean                # Clean build artifacts
.\build.ps1 -linux -deb           # Build linux + create .deb packages
.\build.ps1 -linux -rpm           # Build linux + create .rpm packages
.\build.ps1 -linux -deb -rpm      # Build linux + both .deb and .rpm
```

**Linux/macOS:**

```bash
./build.sh                         # Default: linux + windows amd64
./build.sh -all                    # All platforms
./build.sh -darwin                 # darwin/amd64 + darwin/arm64
./build.sh -linux -amd64           # linux/amd64 only
./build.sh -nopcap                 # Disable pcap for all targets
./build.sh -test                   # Run unit tests
./build.sh -testSniffer           # Run sniffer hardware tests (requires libpcap)
./build.sh -linux -deb             # Build linux + create .deb packages
./build.sh -linux -rpm             # Build linux + create .rpm packages
./build.sh -linux -deb -rpm        # Build linux + both .deb and .rpm
```

**Makefile:**

```bash
make build                  # Native build (attempts pcap)
make build NOPCAP=1         # Native build without pcap
make cross                  # All platforms (delegates to build.sh)
make test                   # Run tests
make coverage               # Tests with coverage report
```

**Windows CMD:**

```cmd
build.cmd                   # Forwards to build.ps1
build.cmd -nopcap           # Without pcap sniffer
build.cmd -all              # All platforms
```

## Build Versioning

The base version is stored in `version/version_base.txt` (e.g. `1.0.0`) and the build number in `version/build_number.txt`. Build scripts read the base version from the file and auto-increment the build number on each build. The full version format is `<BASE>.<BUILD>` (e.g. `1.0.0.1000`) and is injected via linker flags.

Pcap-capable file**names** append `p` (e.g. `spk_1.0.0.1000p-linux-amd64`). The `--version` flag shows a human-readable form:

```bash
./spk --version
# SPK - Secured Port Knock - 1.0.0.1000 (abc1234) [No PCAP]    -- non-pcap build
# SPK - Secured Port Knock - 1.0.0.1000 (abc1234) [With PCAP]  -- pcap build
```

The `p` suffix in the filename helps distinguish pcap-capable binaries when multiple builds are stored together. The `[With PCAP]` / `[No PCAP]` label in the version output makes the capability immediately clear at runtime.

To pin an exact version without auto-incrementing or writing back to version files, set `VERSION` and `BUILD_NUMBER` as environment variables before invoking the build script:

```bash
VERSION=1.0.0 BUILD_NUMBER=1000 ./build.sh -linux
```

```powershell
$env:VERSION="1.0.0"; $env:BUILD_NUMBER="1000"; .\build.ps1 -linux
```

## Build Toolchain Priority

All builds attempt pcap by default. pcap is a **runtime-only** dependency -- no SDK or development headers are needed at compile time. The build scripts apply this priority:

1. **Windows targets** -- always built with pcap. Pure Go, `CGO_ENABLED=0`. Loads `wpcap.dll` (Npcap) at runtime. No zig, no SDK needed.
2. **Darwin targets on non-macOS host** -- always built **without** pcap (no-pcap fallback, no error). The zig 0.13.x Mach-O linker rejects `-Wl,-x` which Go injects unconditionally for CGO darwin builds. Only a native Apple toolchain (clang) can link darwin CGO binaries correctly.
3. **Linux/darwin + zig (native macOS host only for darwin)** -- built with pcap using `zig cc` as the CGO compiler. Loads `libpcap.so` / `libpcap.dylib` at runtime via `dlopen` (only `dlfcn.h` needed at compile time -- part of libc, always available with zig's bundled sysroot).
4. **Linux/darwin + GCC/clang (native only)** -- built with pcap using `gcc` / `clang`. Same runtime loading. macOS native darwin targets fall through to this path when zig is not installed.
5. **No CGO toolchain for Linux/darwin** -- builds without pcap (pure Go, `CGO_ENABLED=0`).

Pcap-enabled binaries have `p` appended to the version (e.g., `spk_1.0.0.1000p-linux-amd64`). Non-pcap binaries omit it (e.g., `spk_1.0.0.1000-linux-amd64`). If a pcap build fails unexpectedly, the scripts exit with an error rather than silently falling back.

## Cross-Compilation

When [zig](https://ziglang.org/) is installed, Linux and Windows cross-compiled targets include pcap via `zig cc` as the CGO C compiler. Darwin targets being built on a non-macOS host **always produce no-pcap binaries** regardless of zig availability (see [Known Limitations](#known-limitations)). Without zig, all cross targets are built as pure Go (`CGO_ENABLED=0`, no pcap).

```powershell
# Build for all platforms (pcap for linux/windows cross targets if zig is available)
.\build.ps1 -all

# AMD64 only across all platforms
.\build.ps1 -amd64

# ARM64 only across all platforms
.\build.ps1 -arm64
```

```bash
# Linux/macOS
make cross               # All platforms
./build.sh -all          # Same, shell version
./build.sh -amd64        # All platforms, amd64 only
```

Zig target triples used: `x86_64-linux-gnu`, `aarch64-linux-gnu`, `x86_64-windows-gnu`, `aarch64-windows-gnu`, `x86_64-macos`, `aarch64-macos`.

> Without zig, cross-compiled targets support UDP, AF_PACKET, and WinDivert sniffers. Only the pcap sniffer mode requires zig (for cross linux/windows targets) or GCC/clang (for native targets).

### pcap availability by host/target matrix

| Build host | windows/* | linux/amd64 (native) | linux/arm64 (cross) | darwin/amd64 | darwin/arm64 |
|---|---|---|---|---|---|
| **Linux + zig** | pcap | pcap | pcap | no-pcap | no-pcap |
| **Linux, no zig** | pcap | pcap (gcc) | no-pcap | no-pcap | no-pcap |
| **macOS arm64 + zig** | pcap | pcap | pcap | no-pcap (cross-arch) | pcap (native, clang) |
| **macOS arm64, no zig** | pcap | no-pcap | no-pcap | no-pcap (cross-arch) | pcap (native, clang) |
| **macOS amd64 + zig** | pcap | pcap | pcap | pcap (native, clang) | no-pcap (cross-arch) |
| **macOS amd64, no zig** | pcap | no-pcap | no-pcap | pcap (native, clang) | no-pcap (cross-arch) |
| **Windows + zig** | pcap | pcap | pcap | no-pcap | no-pcap |
| **Windows, no zig** | pcap | no-pcap | no-pcap | no-pcap | no-pcap |

no-pcap = falls back to no-pcap binary (no error, build succeeds)

## Runtime pcap Requirements

No pcap SDK or development headers are needed at **compile** time. Install the runtime library on the **target** machine only:

| Platform | Install |
|---|---|
| Linux (Debian/Ubuntu) | `apt install libpcap0.8` (**not** `-dev`) |
| Linux (RHEL/Fedora) | `yum install libpcap` |
| macOS | Built-in (`/usr/lib/libpcap.dylib`) -- nothing to install |
| Windows | `winget install Npcap.Npcap` (installs `wpcap.dll`) |

## Manual Go Build

```bash
# Windows pcap: pure Go, no CGO needed (wpcap.dll loaded at runtime)
GOOS=windows CGO_ENABLED=0 go build -ldflags "-s -w -X main.pcapBuild=1" -o spk.exe ./cmd/spk/

# Linux pcap: CGO with dlfcn.h only, no pcap SDK needed (libpcap.so loaded at runtime)
CGO_ENABLED=1 CC="zig cc -target x86_64-linux-gnu" go build -ldflags "-s -w -X main.pcapBuild=1" -o spk_linux ./cmd/spk/

# macOS pcap (native host): CGO with clang (native toolchain)
CGO_ENABLED=1 go build -ldflags "-s -w -X main.pcapBuild=1" -o spk_darwin ./cmd/spk/

# Build without pcap (pure Go, no CGO dependency, any host/target)
CGO_ENABLED=0 go build -ldflags "-s -w" -o spk ./cmd/spk/
```

> **Note:** Cross-compiling darwin with CGO (e.g. via `zig cc -target x86_64-macos`) is not
> supported with zig 0.13.x. Go's `cmd/link` unconditionally passes `-Wl,-x` to the external
> linker for darwin CGO builds, but zig's Mach-O linker rejects that flag. Use a native macOS
> host with the Apple clang toolchain to produce darwin pcap-capable binaries.

## Known Limitations

### Darwin pcap cross-compilation (zig 0.13.x)

Building darwin targets with pcap from a non-macOS host (Linux or Windows) is not supported with zig 0.13.x. The root cause is a missing feature in zig's Mach-O linker: Go's `cmd/link` unconditionally passes `-Wl,-x` to the external linker when CGO is enabled for darwin, but zig's Mach-O linker rejects that flag with `error: unsupported linker arg: -x`.

**Workaround:** The build scripts skip zig entirely for all darwin targets. pcap is only attempted when the build host IS darwin AND the target arch matches the host arch (i.e. truly native). In all other cases a no-pcap binary is produced silently (no error, build succeeds). Cross-arch darwin builds on the same OS (e.g. darwin/amd64 on an arm64 macOS host) also fall back to no-pcap.

To get pcap-enabled darwin binaries for both architectures, build each on its matching native runner:
- `darwin/arm64`: build on an arm64 macOS host (e.g. `macos-latest` GitHub Actions runner)
- `darwin/amd64`: build on an Intel (x86_64) macOS host (e.g. `macos-##-intel` GitHub Actions runner)

The release workflow uses both `macos-latest` and `macos-##-intel` runners so that all darwin releases include pcap.

When zig adds full Mach-O `-x` support this guard can be removed.

## Linux Packaging (.deb / .rpm)

The build scripts support creating `.deb` and `.rpm` packages using [nfpm](https://nfpm.goreleaser.com/). Packages install the `spk` binary to `/usr/bin/spk` with 755 permissions. No service files are included -- use `spk --install` after installation to set up the system service.

**Prerequisites:** Install nfpm: `go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest`

> If nfpm is not found when `-deb` or `-rpm` is requested, the build scripts automatically install it via `go install`.

**Examples:**

```bash
# Build linux binaries + .deb packages
./build.sh -linux -deb

# Build linux binaries + .rpm packages
./build.sh -linux -rpm

# Build linux binaries + both .deb and .rpm
./build.sh -linux -deb -rpm

# Specific arch + deb
./build.sh -linux -arm64 -deb
```

```powershell
# Windows PowerShell (cross-compile)
.\build.ps1 -linux -deb
.\build.ps1 -linux -amd64 -rpm
.\build.ps1 -linux -deb -rpm
```

**Output:**
```
build/linux/spk_1.0.0.1000p-linux-amd64
build/linux/spk_1.0.0.1000p-linux-amd64.deb
build/linux/spk_1.0.0.1000p-linux-amd64.rpm
build/linux/spk_1.0.0.1000p-linux-arm64
build/linux/spk_1.0.0.1000p-linux-arm64.deb
build/linux/spk_1.0.0.1000p-linux-arm64.rpm
```

**Install the package:**
```bash
# Debian/Ubuntu
sudo dpkg -i spk_1.0.0.1000p-linux-amd64.deb

# RHEL/Fedora
sudo rpm -i spk_1.0.0.1000p-linux-amd64.rpm

# Then set up the server and install as service
sudo spk --server --setup
sudo spk --install
```

## GitHub Actions Workflows

### CI Workflow (`.github/workflows/ci.yml`)

Runs automatically on every push and pull request to `main`/`master`.

| Job | Platform(s) | Description |
|---|---|---|
| **unit-tests** | Ubuntu, Windows, macOS | All unit tests |
| **coverage** | Ubuntu | Coverage report uploaded as artifact |
| **integration-tests** | Ubuntu, Windows, macOS | End-to-end knock flow tests |
| **sniffer-tests-linux** | Ubuntu | Sniffer tests with libpcap + AF_PACKET |
| **sniffer-tests-windows** | Windows | Non-pcap sniffer tests (Npcap unavailable in CI) |
| **sniffer-tests-macos** | macOS | Sniffer tests with built-in libpcap |
| **vet** | Ubuntu | `go vet ./...` static analysis |
| **govulncheck** | Ubuntu | Vulnerability scanning (informational, non-blocking) |

### Build Workflow (`.github/workflows/build.yml`)

Runs automatically on every push and pull request. Verifies build script correctness across all platforms and architectures, both with and without zig.

| Job | Runner | Description |
|---|---|---|
| **build-scripts-linux** | ubuntu-latest | Cross-compile all 6 targets with zig; deb+rpm packaging |
| **build-scripts-macos** | macos-latest (arm64) | Cross-compile all 6 targets with zig; deb+rpm packaging |
| **build-scripts-macos-intel** | macos-##-intel (amd64) | Cross-compile all 6 targets with zig; deb+rpm packaging |
| **build-scripts-windows** | windows-latest | Cross-compile all 6 targets with zig; deb+rpm packaging |
| **build-scripts-linux-nozig** | ubuntu-latest | Build all targets without zig; verify expected pcap/no-pcap output |
| **build-scripts-macos-nozig** | macos-latest (arm64) | Build all targets without zig; verify expected pcap/no-pcap output |
| **build-scripts-macos-intel-nozig** | macos-##-intel (amd64) | Build all targets without zig; verify expected pcap/no-pcap output |
| **build-scripts-windows-nozig** | windows-latest | Build all targets without zig; verify expected pcap/no-pcap output |

The `*-nozig` jobs assert the correct pcap/no-pcap outcome per target when zig is absent:

| Runner | windows/* | linux/amd64 | linux/arm64 | darwin/amd64 | darwin/arm64 |
|---|---|---|---|---|---|
| ubuntu-latest | pcap | pcap (gcc) | no-pcap | no-pcap | no-pcap |
| macos-latest (arm64) | pcap | no-pcap | no-pcap | no-pcap | pcap (clang) |
| macos-##-intel (amd64) | pcap | no-pcap | no-pcap | pcap (clang) | no-pcap |
| windows-latest | pcap | no-pcap | no-pcap | no-pcap | no-pcap |

### Release Workflow (`.github/workflows/release.yml`)

Triggered manually via `workflow_dispatch`.

**Inputs:**

| Input | Required | Description |
|---|---|---|
| `release_type` | Yes | `beta` (tagged as pre-release) or `release` |
| `version` | No | Base version override (defaults to `version/version_base.txt`) |
| `build_number` | No | Build number override (defaults to current + 1) |
| `release_description` | No | Release notes (can be edited later on GitHub) |

**Jobs:**

| Job | Runner | Description |
|---|---|---|
| **ci-tests** | Ubuntu, Windows, macOS | Unit + integration tests; fail-fast |
| **resolve-version** | ubuntu-latest | Reads `version/` files, applies user overrides, emits version outputs |
| **build-linux** | ubuntu-latest | `build.sh -linux -deb -rpm` -- amd64 pcap (gcc), arm64 pcap (zig) |
| **build-windows** | windows-latest | `build.ps1 -windows` -- amd64/arm64 always pcap (pure Go) |
| **build-macos-arm64** | macos-latest (arm64) | `build.sh -darwin -arm64` -- arm64 pcap (native clang) |
| **build-macos-amd64** | macos-##-intel (amd64) | `build.sh -darwin -amd64` -- amd64 pcap (native Intel clang) |
| **publish** | ubuntu-latest | Collects artifacts, verifies pcap, commits version files, creates GitHub Release |

**Steps:**
1. Runs CI tests on all three platforms -- fails fast on any error
2. Resolves version and build number from `version/` files, applying any user overrides
3. Builds 10 release artifacts using native build scripts (no UPX):
   - Linux: `build.sh -linux -deb -rpm` -- amd64 pcap (gcc), arm64 pcap (zig)
   - Windows: `build.ps1 -windows` -- amd64/arm64 always pcap (pure Go)
   - macOS arm64 (`macos-latest`): `build.sh -darwin -arm64` -- arm64 pcap (native clang)
   - macOS amd64 (`macos-##-intel`): `build.sh -darwin -amd64` -- amd64 pcap (native Intel clang)
4. Verifies pcap binaries exist for linux/amd64, linux/arm64, windows/amd64, windows/arm64, darwin/amd64, darwin/arm64
5. If any build fails, the release is aborted and version files are not modified
6. Updates `version/version_base.txt` (if version was changed) and `version/build_number.txt`
7. Commits and pushes the updated version files
8. Computes SHA256 checksums for all release files
9. Creates a GitHub Release with all 10 files attached

If any build fails, the workflow aborts -- no version files are modified and no release is created.
