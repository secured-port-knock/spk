# Building & Compilation

This document covers building SPK from source, cross-compilation, and Linux packaging.

## Build Requirements

| Tool | Required | Purpose |
|---|---|---|
| **Go 1.25+** | Yes | `crypto/mlkem` standard library support (`go 1.25.0` in `go.mod`) |
| **zig** | Optional | Cross-compile Linux/macOS with pcap (`zig cc` as CGO compiler) |
| **GCC** | Optional | Native builds with pcap (fallback when zig is not installed) |
| **UPX** | Optional | Compress binaries (~50% smaller); pass `-upx` to enable |
| **nfpm** | Optional | Build `.deb` / `.rpm` Linux packages |

Install zig: [ziglang.org/download](https://ziglang.org/download/) (`winget install zig.zig` / `brew install zig` / `snap install zig`)

Install nfpm: `go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest`

## Install via go install

The quickest way to install SPK without cloning the repository is `go install`. This builds a
pure-Go binary (no pcap) and places it in `$GOPATH/bin` (or `$HOME/go/bin`):

```bash
# Latest stable release
go install github.com/secured-port-knock/spk@latest

# Specific release
go install github.com/secured-port-knock/spk@v1.0.4
```

**Limitations of go install compared to release binaries:**

- **No pcap / stealth mode.** pcap requires CGO, which `go install` does not use here. The installed
  binary supports UDP socket mode and AF_PACKET/WinDivert. For pcap stealth mode, use a release
  binary or the build scripts.
- **No UPX compression.** Binary is larger (~6-8 MB vs ~3 MB for a UPX-compressed release build).
- **No version metadata.** Build-script linker flags are not injected; SPK instead reads the module
  version via `runtime/debug.ReadBuildInfo()` and labels the build `(Go)`:

  ```
  SPK - Secured Port Knock - 1.0.2 (Go) [No PCAP]
  ```

  With no tag available (e.g. `go install` of a local copy), it falls back to `1.0.0.0 (Dev) [No PCAP]`.

> [!TIP]
> `go install` is convenient for client-only use or quick testing. For production server deployments, use the release binaries.

## Build Scripts

All three scripts accept the same flags. Run the one for your OS:

| Platform | Command |
|---|---|
| Linux / macOS | `./build.sh [flags]` |
| Windows (PowerShell) | `.\build.ps1 [flags]` |
| Windows (CMD) | `build.cmd [flags]` (forwards to `build.ps1`) |

| Flag | Effect |
|---|---|
| `-windows` / `-linux` / `-darwin` | Select platform(s); combine freely |
| `-amd64` / `-arm64` | Select architecture(s); combine freely |
| `-all` | Build every platform/arch combination |
| `-nopcap` | Disable pcap for Linux/macOS targets (Windows is always pcap) |
| `-upx` | Enable UPX binary compression (requires `upx` in `PATH`) |
| `-deb` / `-rpm` | Package linux builds as .deb/.rpm (combine with `-linux`) |
| `-test` | Run unit + integration tests + fuzz seed corpus |
| `-testall` | Run the full suite: smoke, unit+integration, fuzz, sniffer |
| `-testSniffer` | Run sniffer hardware tests (requires libpcap/Npcap) |
| `-testsmoke` | Run end-to-end smoke tests (builds a binary) |
| `-coverage` | Run tests with a coverage report |
| `-clean` | Remove build artifacts |

Example: `./build.sh -linux -arm64 -deb` builds linux/arm64 and packages it as `.deb`.

> [!NOTE]
> With no flags, all three scripts build windows/amd64 + linux/amd64. Darwin is
> always opt-in (`-darwin` or `-all`). See [Build Toolchain Priority](#build-toolchain-priority)
> for how pcap support is decided per target.

**Makefile** (Linux/macOS convenience wrapper; not flag-based):

```bash
make build                  # Native build (attempts pcap)
make build NOPCAP=1         # Native build without pcap
make cross                  # All platforms (delegates to build.sh -all)
make test                   # Run unit + integration tests + fuzz seed corpus
make testall                # Run all tests (delegates to build.sh -testall)
make testfuzz               # Run fuzz seed corpus only
make coverage               # Tests with coverage report
```

## Build Versioning

The base version is stored in `version/version_base.txt` (e.g. `1.0.0`) and the build number in `version/build_number.txt`. Build scripts read the base version from the file and auto-increment the build number on each build. The full version format is `<BASE>.<BUILD>` (e.g. `1.0.0.1000`) and is injected via linker flags.

Pcap-capable file**names** append `p` (e.g. `spk_1.0.0.1000p-linux-amd64`). The `--version` flag shows a human-readable form:

```bash
./spk --version
# SPK - Secured Port Knock - 1.0.0.1000 (abc1234) [No PCAP]    -- non-pcap build
# SPK - Secured Port Knock - 1.0.0.1000 (abc1234) [With PCAP]  -- pcap build
```

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
2. **Darwin targets on non-macOS host** -- always built **without** pcap (no-pcap fallback, no error). See [Known Limitations](#known-limitations).
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

> [!NOTE]
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
GOOS=windows CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o spk.exe ./

# Linux pcap: CGO with dlfcn.h only, no pcap SDK needed (libpcap.so loaded at runtime)
CGO_ENABLED=1 CC="zig cc -target x86_64-linux-gnu" go build -trimpath -ldflags "-s -w" -o spk_linux ./

# macOS pcap (native host): CGO with clang (native toolchain)
CGO_ENABLED=1 go build -trimpath -ldflags "-s -w" -o spk_darwin ./

# Build without pcap (pure Go, no CGO dependency, any host/target)
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o spk ./
```

> [!NOTE]
> Cross-compiling darwin with CGO is not supported -- see [Known Limitations](#known-limitations).

## Known Limitations

### Darwin pcap cross-compilation (zig 0.13.x)

Building darwin targets with pcap from a non-macOS host is not supported: Go's `cmd/link` unconditionally passes `-Wl,-x` to the external linker for darwin CGO builds, and zig 0.13.x's Mach-O linker rejects that flag. The build scripts therefore attempt pcap for darwin only on a truly native build (darwin host, matching arch); every other darwin build silently produces a no-pcap binary. When zig adds Mach-O `-x` support this guard can be removed.

To get pcap-enabled darwin binaries for both architectures, build each on its matching native host (arm64 and Intel macOS). The release workflow uses both `macos-latest` and `macos-##-intel` runners for this reason.

## Linux Packaging (.deb / .rpm)

The build scripts support creating `.deb` and `.rpm` packages using [nfpm](https://nfpm.goreleaser.com/). Packages install the `spk` binary to `/usr/bin/spk` with 755 permissions. No service files are included -- use `spk --install` after installation to set up the system service.

**Prerequisites:** Install nfpm: `go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest`

> [!NOTE]
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

The CI workflow (`.github/workflows/ci.yml`) is documented in [testing.md](testing.md#continuous-integration).

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

**Tag format:**

| Release type | Git tag | Example | Go install |
|---|---|---|---|
| Stable release | `v{VERSION}` | `v1.0.4` | `@latest` picks this up |
| Beta pre-release | `v{VERSION}-beta.{BUILD}` | `v1.0.4-beta.1044` | excluded from `@latest` |

Tags follow [semver](https://semver.org/) so the module is compatible with standard Go tooling:
`go install github.com/secured-port-knock/spk@latest` installs the latest stable release.
Binary filenames still embed the full four-part version (e.g. `spk_1.0.2.1044p-linux-amd64`).

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
3. Builds 10 release artifacts using the build scripts above (no UPX) and verifies a pcap binary exists for every platform/arch
4. Commits the updated `version/` files, computes SHA256 checksums, and creates a GitHub Release with all files attached

If any build fails, the workflow aborts -- no version files are modified and no release is created.
