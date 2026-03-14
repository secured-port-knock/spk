#!/usr/bin/env bash
# Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
# SPDX-License-Identifier: MIT
# SPK build script for Linux/macOS
# Usage:
#   ./build.sh                    # Build linux/amd64 + windows/amd64
#   ./build.sh -windows           # Build windows/amd64 + windows/arm64
#   ./build.sh -linux             # Build linux/amd64 + linux/arm64
#   ./build.sh -darwin            # Build darwin/amd64 + darwin/arm64
#   ./build.sh -amd64             # Build all platforms for amd64 only
#   ./build.sh -arm64             # Build all platforms for arm64 only
#   ./build.sh -linux -amd64      # Build linux/amd64 only
#   ./build.sh -linux -arm64      # Build linux/arm64 only
#   ./build.sh -windows -amd64    # Build windows/amd64 only
#   ./build.sh -windows -arm64    # Build windows/arm64 only
#   ./build.sh -all               # Build all platform/arch combinations
#   ./build.sh -nopcap            # Disable pcap for Linux/Darwin builds
#   ./build.sh -test              # Run tests
#   ./build.sh -coverage          # Run tests with coverage
#   ./build.sh -clean             # Clean build artifacts
#   ./build.sh -linux -deb        # Build linux + create .deb packages
#   ./build.sh -linux -rpm        # Build linux + create .rpm packages
#   ./build.sh -linux -deb -rpm   # Build linux + both .deb and .rpm
#
# pcap (dynamic loading -- no SDK or headers needed at compile time):
#   Windows    -- always built with pcap (pure Go, CGO_ENABLED=0).
#                 Loads wpcap.dll (Npcap) at runtime.
#   Linux/macOS -- built with pcap when a C compiler is available
#                 (zig for cross-builds, gcc for native). Uses CGO only
#                 for dlfcn.h (dlopen/dlsym). Loads libpcap.so/.dylib
#                 at runtime. Use -nopcap to force CGO_ENABLED=0.
#
# Filename convention:
#   spk_<VERSION>p-<OS>-<ARCH>[.exe]   (pcap-capable build)
#   spk_<VERSION>-<OS>-<ARCH>[.exe]    (no pcap support)
set -e

BINARY="spk"
COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "dev")

# Read base version from version/version_base.txt (env VERSION overrides)
VERSION_BASE_FILE="$(dirname "$0")/version/version_base.txt"
if [ -z "${VERSION}" ] && [ -f "${VERSION_BASE_FILE}" ]; then
  VERSION=$(head -1 "${VERSION_BASE_FILE}" 2>/dev/null | tr -cd '0-9.')
fi
VERSION="${VERSION:-1.0.0}"

# Auto-increment build number (or use BUILD_NUMBER env var to pin an exact value)
# When BUILD_NUMBER is set externally, the file is NOT written -- callers manage versioning.
BUILD_NUMBER_FILE="$(dirname "$0")/version/build_number.txt"
SKIP_BUILD_NUMBER_BUMP=false
if [ -n "${BUILD_NUMBER}" ]; then
  SKIP_BUILD_NUMBER_BUMP=true
else
  BUILD_NUMBER=0
  if [ -f "${BUILD_NUMBER_FILE}" ]; then
    BUILD_NUMBER=$(head -1 "${BUILD_NUMBER_FILE}" 2>/dev/null | tr -cd '0-9')
    [ -z "${BUILD_NUMBER}" ] && BUILD_NUMBER=0
  fi
  BUILD_NUMBER=$((BUILD_NUMBER + 1))
fi
if ! $SKIP_BUILD_NUMBER_BUMP; then
  printf '%s\n' "${BUILD_NUMBER}" > "${BUILD_NUMBER_FILE}"
fi

FULL_VERSION="${VERSION}.${BUILD_NUMBER}"
LDFLAGS="-X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildNumber=${BUILD_NUMBER} -s -w"
BUILD_DIR="build"

echo "SPK Build Script"
echo "========================"
echo "Version: ${FULL_VERSION}"
echo "Commit:  ${COMMIT}"
echo ""

# Parse arguments
BUILD_WINDOWS=false
BUILD_LINUX=false
BUILD_DARWIN=false
INCLUDE_AMD64=false
INCLUDE_ARM64=false
RUN_TEST=false
RUN_SNIFFER_TEST=false
RUN_COVERAGE=false
RUN_CLEAN=false
DISABLE_PCAP=false
BUILD_DEB=false
BUILD_RPM=false
HAS_PLATFORM=false
HAS_ARCH=false

for arg in "$@"; do
  case "$arg" in
    -windows)      BUILD_WINDOWS=true; HAS_PLATFORM=true ;;
    -linux)        BUILD_LINUX=true; HAS_PLATFORM=true ;;
    -darwin)       BUILD_DARWIN=true; HAS_PLATFORM=true ;;
    -amd64)        INCLUDE_AMD64=true; HAS_ARCH=true ;;
    -arm64)        INCLUDE_ARM64=true; HAS_ARCH=true ;;
    -all)          BUILD_WINDOWS=true; BUILD_LINUX=true; BUILD_DARWIN=true; INCLUDE_AMD64=true; INCLUDE_ARM64=true; HAS_PLATFORM=true; HAS_ARCH=true ;;
    -test)         RUN_TEST=true ;;
    -testSniffer) RUN_SNIFFER_TEST=true ;;
    -coverage)     RUN_COVERAGE=true ;;
    -clean)        RUN_CLEAN=true ;;
    -nopcap)       DISABLE_PCAP=true ;;
    -deb)          BUILD_DEB=true ;;
    -rpm)          BUILD_RPM=true ;;
    *)             echo "Unknown argument: $arg"; echo "Usage: $0 [-windows] [-linux] [-darwin] [-amd64] [-arm64] [-all] [-nopcap] [-test] [-testSniffer] [-coverage] [-clean] [-deb] [-rpm]"; exit 1 ;;
  esac
done

if $RUN_TEST; then
  echo "Running tests (excluding sniffer hardware tests -- use -testSniffer for those)..."
  go test ./... -count=1
  exit 0
fi

# -testSniffer: verify pcap/sniffer library presence, then run hardware tests.
if $RUN_SNIFFER_TEST; then
  OS="$(uname -s 2>/dev/null || echo Windows)"
  echo "Running sniffer tests on ${OS}..."
  echo ""

  SNIFFER_OK=true

  if [ "${OS}" = "Linux" ]; then
    # Check for libpcap
    if ! ldconfig -p 2>/dev/null | grep -q 'libpcap\.so' && \
       ! ls /usr/lib*/libpcap.so* /usr/lib*/*/libpcap.so* 2>/dev/null | head -1 | grep -q libpcap; then
      echo "WARNING: libpcap not found."
      echo "  Install with: sudo apt-get install libpcap-dev"
      echo "  (or equivalent for your distro)"
      SNIFFER_OK=false
    fi
  fi

  if ! $SNIFFER_OK; then
    echo ""
    echo "Sniffer tests require the pcap library. Install it and re-run -testSniffer."
    exit 1
  fi

  # Build the sniffer test binary first (verifies it compiles on this platform)
  echo "Building sniffer test binary..."
  if ! go test -c -o /tmp/spk_sniffer_test ./internal/sniffer/ 2>&1; then
    echo "ERROR: sniffer test binary failed to compile."
    exit 1
  fi
  echo "Sniffer test binary compiled successfully."
  echo ""

  # Run the platform-specific sniffer tests
  if [ "${OS}" = "Linux" ]; then
    echo "Running Linux sniffer tests (pcap + AF_PACKET)..."
    sudo go test -v -count=1 -timeout 120s ./internal/sniffer/ -run "TestPcap|TestAFPacket|TestSniffer"
  elif [ "${OS}" = "Darwin" ]; then
    echo "Running macOS sniffer tests (pcap)..."
    sudo go test -v -count=1 -timeout 120s ./internal/sniffer/ -run "TestPcap|TestSniffer"
  else
    echo "Running sniffer tests (all backends)..."
    go test -v -count=1 -timeout 120s ./internal/sniffer/ -run "TestPcap|TestAFPacket|TestWinDivert|TestSniffer"
  fi
  exit 0
fi

if $RUN_COVERAGE; then
  echo "Running tests with coverage..."
  go test ./... -coverprofile=coverage.out
  go tool cover -html=coverage.out -o coverage.html
  echo "Coverage report: coverage.html"
  exit 0
fi

if $RUN_CLEAN; then
  echo "Cleaning..."
  rm -f ${BINARY} ${BINARY}.exe ${BINARY}_*
  rm -rf "${BUILD_DIR}"
  rm -f coverage.out coverage.html
  echo "Clean complete."
  exit 0
fi

# Default: build linux + windows amd64
if ! $HAS_PLATFORM; then
  BUILD_LINUX=true
  BUILD_WINDOWS=true
fi

if $HAS_PLATFORM && ! $HAS_ARCH; then
  INCLUDE_AMD64=true
  INCLUDE_ARM64=true
elif $HAS_ARCH && ! $HAS_PLATFORM; then
  BUILD_WINDOWS=true
  BUILD_LINUX=true
  BUILD_DARWIN=true
elif ! $HAS_PLATFORM && ! $HAS_ARCH; then
  INCLUDE_AMD64=true
fi

# Wipe build directory
rm -rf "${BUILD_DIR}"

# Collect platform/arch targets
declare -a TARGETS

if $BUILD_WINDOWS; then
  $INCLUDE_AMD64 && TARGETS+=("windows/amd64/.exe/windows")
  $INCLUDE_ARM64 && TARGETS+=("windows/arm64/.exe/windows")
fi

if $BUILD_LINUX; then
  $INCLUDE_AMD64 && TARGETS+=("linux/amd64//linux")
  $INCLUDE_ARM64 && TARGETS+=("linux/arm64//linux")
fi

if $BUILD_DARWIN; then
  $INCLUDE_AMD64 && TARGETS+=("darwin/amd64//darwin")
  $INCLUDE_ARM64 && TARGETS+=("darwin/arm64//darwin")
fi

echo "Building ${#TARGETS[@]} target(s)..."

# Detect host OS/arch
HOST_GOOS=$(go env GOOS 2>/dev/null || uname -s | tr '[:upper:]' '[:lower:]')
HOST_GOARCH=$(go env GOARCH 2>/dev/null || echo "amd64")

# Detect zig (needed only for cross-compiling Linux/Darwin with pcap)
ZIG_AVAILABLE=false
if command -v zig &>/dev/null; then
  ZIG_AVAILABLE=true
  echo "Zig: found ($(command -v zig))"
else
  echo "Zig: not found (Linux/Darwin cross-builds will not include pcap)"
fi

# Detect GCC (native fallback)
GCC_AVAILABLE=false
if command -v gcc &>/dev/null; then
  GCC_AVAILABLE=true
fi

# Check for UPX (binary compression)
UPX_AVAILABLE=false
if command -v upx &>/dev/null; then
  UPX_AVAILABLE=true
  echo "UPX: found ($(command -v upx))"
else
  echo "UPX: not found (binaries will not be compressed)"
fi

# Check for nfpm (needed for -deb / -rpm packaging)
NFPM_AVAILABLE=false
if command -v nfpm &>/dev/null; then
  NFPM_AVAILABLE=true
  echo "nfpm: found ($(command -v nfpm))"
else
  if $BUILD_DEB || $BUILD_RPM; then
    echo "nfpm: not found -- auto-installing..."
    go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest 2>/dev/null
    if command -v nfpm &>/dev/null; then
      NFPM_AVAILABLE=true
      echo "nfpm: installed ($(command -v nfpm))"
    else
      echo "ERROR: nfpm auto-install failed"
      echo "  Install manually: go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest"
      exit 1
    fi
  fi
fi
echo ""

# Zig target triple lookup
zig_target_triple() {
  local goos="$1" goarch="$2"
  case "${goos}/${goarch}" in
    linux/amd64)   echo "x86_64-linux-gnu" ;;
    linux/arm64)   echo "aarch64-linux-gnu" ;;
    windows/amd64) echo "x86_64-windows-gnu" ;;
    windows/arm64) echo "aarch64-windows-gnu" ;;
    darwin/amd64)  echo "x86_64-macos" ;;
    darwin/arm64)  echo "aarch64-macos" ;;
    *)             echo "" ;;
  esac
}

# Build helper: build_one <goos> <goarch> <ext> <subdir> <pcap:1|0> <cc_override>
build_one() {
  local goos="$1" goarch="$2" ext="$3" subdir="$4" pcap="$5" cc="$6"
  local ver_suffix="${FULL_VERSION}"
  if [ "$pcap" = "1" ]; then ver_suffix="${FULL_VERSION}p"; fi

  local outdir="${BUILD_DIR}/${subdir}"
  mkdir -p "${outdir}"
  local output="${outdir}/${BINARY}_${ver_suffix}-${goos}-${goarch}${ext}"

  local cgo_enabled="0"
  local extra_ldflags=""

  if [ "$pcap" = "1" ]; then
    if [ "$goos" = "windows" ]; then
      # Windows pcap: pure Go, no CGO needed
      cgo_enabled="0"
    else
      # Linux/Darwin pcap: CGO for dlfcn.h only (no pcap headers needed)
      cgo_enabled="1"
    fi
    extra_ldflags=" -X main.pcapBuild=1"
    echo "  Building ${output}... (pcap)"
  else
    echo "  Building ${output}..."
  fi

  local ldflags="${LDFLAGS}${extra_ldflags}"

  # Use subshell so env changes do not leak. Export CC with proper quoting
  # to avoid word-split issues with values like "zig cc -target x86_64-linux-gnu".
  if (
    export GOOS="${goos}" GOARCH="${goarch}" CGO_ENABLED="${cgo_enabled}"
    if [ -n "$cc" ]; then export CC="$cc"; fi
    go build -ldflags "${ldflags}" -o "${output}" ./cmd/spk/
  ); then
    # UPX compress if available
    if $UPX_AVAILABLE && [ -f "${output}" ]; then
      local orig_size
      orig_size=$(stat -f%z "${output}" 2>/dev/null || stat -c%s "${output}" 2>/dev/null || echo 0)
      if upx --best --lzma -q "${output}" 2>/dev/null; then
        local new_size
        new_size=$(stat -f%z "${output}" 2>/dev/null || stat -c%s "${output}" 2>/dev/null || echo 0)
        echo "    -> UPX compressed: ${new_size} bytes (was ${orig_size})"
      else
        echo "    -> UPX skipped for ${output}"
      fi
    fi
    return 0
  else
    echo "    FAILED: ${output}"
    rm -f "${output}"
    return 1
  fi
}

for target in "${TARGETS[@]}"; do
  IFS='/' read -r goos goarch ext subdir <<< "$target"

  IS_NATIVE=false
  if [ "${goos}" = "${HOST_GOOS}" ] && [ "${goarch}" = "${HOST_GOARCH}" ]; then
    IS_NATIVE=true
  fi

  if [ "${goos}" = "windows" ]; then
    # Windows: always pcap (pure Go, CGO_ENABLED=0)
    build_one "$goos" "$goarch" "$ext" "$subdir" 1 ""
  elif $DISABLE_PCAP; then
    # -nopcap: build without pcap
    build_one "$goos" "$goarch" "$ext" "$subdir" 0 ""
  elif [ "${goos}" = "darwin" ]; then
    # zig 0.13 Mach-O linker rejects -Wl,-x which Go injects for all CGO darwin builds.
    # Only a native Apple clang can link darwin CGO binaries correctly.
    # Use native gcc/clang only when host IS darwin AND arch matches; no-pcap otherwise.
    if $IS_NATIVE && $GCC_AVAILABLE; then
      if ! build_one "$goos" "$goarch" "$ext" "$subdir" 1 "gcc"; then
        echo "ERROR: pcap build failed for ${goos}/${goarch}"
        exit 1
      fi
    else
      echo "    (darwin pcap requires native Apple clang for exact host arch; using no-pcap)"
      build_one "$goos" "$goarch" "$ext" "$subdir" 0 ""
    fi
  elif $ZIG_AVAILABLE; then
    ZIG_TARGET=$(zig_target_triple "$goos" "$goarch")
    if [ -n "$ZIG_TARGET" ]; then
      if ! build_one "$goos" "$goarch" "$ext" "$subdir" 1 "zig cc -target ${ZIG_TARGET}"; then
        echo "ERROR: pcap build failed for ${goos}/${goarch}"
        exit 1
      fi
    else
      build_one "$goos" "$goarch" "$ext" "$subdir" 0 ""
    fi
  elif $IS_NATIVE && $GCC_AVAILABLE; then
    if ! build_one "$goos" "$goarch" "$ext" "$subdir" 1 "gcc"; then
      echo "ERROR: pcap build failed for ${goos}/${goarch}"
      exit 1
    fi
  else
    if ! $IS_NATIVE; then
      echo "    (cross build without zig -- no pcap)"
    else
      echo "    (no C compiler found -- no pcap)"
    fi
    build_one "$goos" "$goarch" "$ext" "$subdir" 0 ""
  fi
done

# -- Package Linux binaries with nfpm if -deb or -rpm requested --------
package_nfpm() {
  local binary_path="$1" goarch="$2" format="$3"

  # Map Go arch to package arch
  local pkg_arch
  if [ "$format" = "deb" ]; then
    case "$goarch" in
      amd64) pkg_arch="amd64" ;;
      arm64) pkg_arch="arm64" ;;
      *)     pkg_arch="$goarch" ;;
    esac
  else
    case "$goarch" in
      amd64) pkg_arch="x86_64" ;;
      arm64) pkg_arch="aarch64" ;;
      *)     pkg_arch="$goarch" ;;
    esac
  fi

  local out_dir
  out_dir=$(dirname "$binary_path")
  local base_name
  base_name=$(basename "$binary_path")
  local pkg_file="${out_dir}/${base_name}.${format}"

  # Generate nfpm config
  local tmp_yaml
  tmp_yaml=$(mktemp /tmp/nfpm_XXXXXX.yaml)
  cat > "$tmp_yaml" <<NFPMEOF
name: spk
arch: ${pkg_arch}
version: ${FULL_VERSION}
maintainer: "Jack L. (Cpt-JackL) <https://jack-l.com>"
description: "Secured Port Knock - SPA port knocking with ML-KEM post-quantum cryptography"
homepage: "https://github.com/pjaol/knock"
license: MIT
contents:
  - src: ${binary_path}
    dst: /usr/bin/spk
    file_info:
      mode: 0755
NFPMEOF

  echo "  Packaging ${pkg_file}..."
  if nfpm pkg --config "$tmp_yaml" --packager "$format" --target "$pkg_file"; then
    local size
    size=$(stat -f%z "$pkg_file" 2>/dev/null || stat -c%s "$pkg_file" 2>/dev/null || echo 0)
    echo "    -> ${size} bytes"
  else
    echo "    FAILED: ${pkg_file}"
  fi
  rm -f "$tmp_yaml"
}

if $NFPM_AVAILABLE && ($BUILD_DEB || $BUILD_RPM); then
  echo ""
  echo "Packaging Linux binaries..."

  for bin in "${BUILD_DIR}"/linux/spk_*; do
    [ -f "$bin" ] || continue
    # Skip packages themselves
    case "$bin" in *.deb|*.rpm) continue ;; esac

    # Extract arch from filename: spk_1.0.0.52p-linux-amd64
    arch=""
    case "$bin" in
      *-linux-amd64*) arch="amd64" ;;
      *-linux-arm64*) arch="arm64" ;;
    esac
    [ -z "$arch" ] && continue

    if $BUILD_DEB; then
      package_nfpm "$bin" "$arch" "deb"
    fi
    if $BUILD_RPM; then
      package_nfpm "$bin" "$arch" "rpm"
    fi
  done
fi

echo ""
echo "Build complete. Output in ${BUILD_DIR}/"
find "${BUILD_DIR}" -type f | sort
