#!/usr/bin/env bash
# Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
# SPDX-License-Identifier: MIT
# SPK build script for Linux/macOS.
# See "Build Scripts" in docs/compilation.md for usage, flags, and pcap
# toolchain priority.
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
  fi
fi
# Decimal whatever the spelling. "08" would be read as octal by the arithmetic
# below and fail, and "007" would name the binary differently from build.ps1,
# which reads the same value as 7. Anything that is not digits counts as 0.
BUILD_NUMBER=$(printf '%s' "${BUILD_NUMBER}" | tr -cd '0-9')
BUILD_NUMBER=$((10#${BUILD_NUMBER:-0}))
MODULE="github.com/secured-port-knock/spk/internal/app"
FULL_VERSION="${VERSION}.${BUILD_NUMBER}"
LDFLAGS="-X ${MODULE}.version=${VERSION} -X ${MODULE}.commit=${COMMIT} -X ${MODULE}.buildNumber=${BUILD_NUMBER} -s -w"
BUILD_DIR="build"

# take_build_number is called only once a build is actually going to happen.
# This build takes the number the file holds and leaves the next one behind:
# the convention build.ps1, the release workflow and the sibling projects
# share. Taking the number the file was bumped TO instead would stamp this
# build one ahead of the release built from the same starting file.
#
# It is NOT called for -test, -clean and the other actions, because a run that
# produces no binary must not consume a version.
take_build_number() {
  $SKIP_BUILD_NUMBER_BUMP && return 0
  # flock serialises concurrent invocations. It is missing on some hosts (Git
  # Bash for Windows, macOS without util-linux), so its absence is expected and
  # quiet; the same steps then run unprotected.
  local taken
  taken=$( {
    exec 200>"${BUILD_NUMBER_FILE}.lock"
    flock -x 200
    _cur=$(head -1 "${BUILD_NUMBER_FILE}" 2>/dev/null | tr -cd '0-9')
    _cur=$((10#${_cur:-0}))
    printf '%s\n' "$((_cur + 1))" > "${BUILD_NUMBER_FILE}"
    printf '%s' "${_cur}"
  } 2>/dev/null ) || taken=""
  if [ -n "${taken}" ]; then
    BUILD_NUMBER="${taken}"
  else
    printf '%s\n' "$((BUILD_NUMBER + 1))" > "${BUILD_NUMBER_FILE}"
  fi
  FULL_VERSION="${VERSION}.${BUILD_NUMBER}"
  LDFLAGS="-X ${MODULE}.version=${VERSION} -X ${MODULE}.commit=${COMMIT} -X ${MODULE}.buildNumber=${BUILD_NUMBER} -s -w"
}

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
RUN_TESTALL=false
RUN_SNIFFER_TEST=false
RUN_SCRIPTS=false
RUN_INTEGRATION=false
RUN_E2E=false
BUILD_NATIVE=false
RUN_TESTSMOKE=false
RUN_COVERAGE=false
RUN_CLEAN=false
DISABLE_PCAP=false
BUILD_DEB=false
BUILD_RPM=false
HAS_PLATFORM=false
HAS_ARCH=false

usage() {
  cat <<'USAGE'
Usage: build.sh [targets] [actions]

Targets:
  -windows -linux -darwin    select platform(s)
  -amd64 -arm64              select architecture(s)
  -all                       every platform and architecture
  -native                    this host's platform and architecture only
  -nopcap                    build Linux/macOS without pcap support

Actions:
  -test          unit tests + fuzz seed corpus (excluding sniffer)
  -integration   integration tests
  -teste2e       end-to-end tests (none in this project; see -testsmoke)
  -testsmoke     end-to-end smoke tests
  -testscripts   the build scripts, against a copy of the tree
  -testsniffer   sniffer hardware tests (requires libpcap/Npcap)
  -testall       every suite above, in order
  -coverage      unit tests with an HTML coverage report
  -clean         remove build artifacts
  -deb -rpm      package linux builds (combine with -linux or -all)
USAGE
}

# no_suite <name> -- this project has no such suite. The flag is accepted so
# the same commands work across every project; it reports and succeeds.
no_suite() {
  echo "No $1 tests in this project."
  exit 0
}

for arg in "$@"; do
  case "$arg" in
    -windows)      BUILD_WINDOWS=true; HAS_PLATFORM=true ;;
    -linux)        BUILD_LINUX=true; HAS_PLATFORM=true ;;
    -darwin)       BUILD_DARWIN=true; HAS_PLATFORM=true ;;
    -amd64)        INCLUDE_AMD64=true; HAS_ARCH=true ;;
    -arm64)        INCLUDE_ARM64=true; HAS_ARCH=true ;;
    -all)          BUILD_WINDOWS=true; BUILD_LINUX=true; BUILD_DARWIN=true; INCLUDE_AMD64=true; INCLUDE_ARM64=true; HAS_PLATFORM=true; HAS_ARCH=true ;;
    -native)       BUILD_NATIVE=true; HAS_PLATFORM=true; HAS_ARCH=true ;;
    -test)         RUN_TEST=true ;;
    -testall)      RUN_TESTALL=true ;;
    -integration)  RUN_INTEGRATION=true ;;
    -teste2e)      RUN_E2E=true ;;
    -testsmoke)    RUN_TESTSMOKE=true ;;
    -testscripts)  RUN_SCRIPTS=true ;;
    # -testSniffer is the old spelling; every other flag is lower case.
    -testsniffer|-testSniffer) RUN_SNIFFER_TEST=true ;;
    -coverage)     RUN_COVERAGE=true ;;
    -clean)        RUN_CLEAN=true ;;
    -nopcap)       DISABLE_PCAP=true ;;
    -deb)          BUILD_DEB=true ;;
    -rpm)          BUILD_RPM=true ;;
    *)             echo "Unknown argument: $arg"; echo ""; usage; exit 1 ;;
  esac
done

# Helper: create $TMPDIR/spk and override TMPDIR in the current shell.
# The original TMPDIR is saved in _SPK_SAVED_TMPDIR so that spk_test_tmp_exit
# can restore it.  Call directly -- NOT with $(...) -- to avoid a subshell
# that would prevent the export from reaching the parent shell.
# Usage: spk_test_tmp_enter
_SPK_SAVED_TMPDIR=""
spk_test_tmp_enter() {
  _SPK_SAVED_TMPDIR="${TMPDIR:-/tmp}"
  # Strip trailing slash: on macOS TMPDIR is typically set to a path ending
  # with '/' (e.g. /var/folders/.../T/).  Appending /spk without stripping it
  # produces a double-slash path that os.TempDir() returns verbatim (Go does
  # not clean it), causing string-equality comparisons in tests to fail because
  # the production code passes paths through filepath.Clean internally.
  _SPK_SAVED_TMPDIR="${_SPK_SAVED_TMPDIR%/}"
  local spk_tmp="${_SPK_SAVED_TMPDIR}/spk"
  mkdir -p "${spk_tmp}"
  export TMPDIR="${spk_tmp}"
}

# Helper: restore TMPDIR and remove $TMPDIR/spk.
# Usage: spk_test_tmp_exit
spk_test_tmp_exit() {
  local spk_tmp="${_SPK_SAVED_TMPDIR}/spk"
  export TMPDIR="${_SPK_SAVED_TMPDIR}"
  rm -rf "${spk_tmp}" 2>/dev/null || true
}

if $RUN_TESTSMOKE; then
  echo "Running end-to-end smoke tests (tag: testsmoke)..."
  # Use sudo -E when not already root so pcap/afpacket smoke tests run.
  # -E preserves GOPATH, TMPDIR, and the module cache for the internal
  # go build call inside TestMain. Tests skip gracefully without root.
  SMOKE_RUNNER=""
  if [ "$(id -u)" != "0" ] && command -v sudo >/dev/null 2>&1; then
    SMOKE_RUNNER="sudo -E"
  fi
  spk_test_tmp_enter
  if ! ${SMOKE_RUNNER} go test -buildvcs=false -count=1 -timeout 300s -tags testsmoke ./tests/smoke/; then
    spk_test_tmp_exit
    exit 1
  fi
  spk_test_tmp_exit
  exit 0
fi

$RUN_E2E && no_suite "end-to-end"

if $RUN_INTEGRATION; then
  echo "Running integration tests..."
  spk_test_tmp_enter
  if ! go test -buildvcs=false -count=1 -timeout 300s ./tests/integration/; then
    spk_test_tmp_exit
    echo "Integration tests failed"
    exit 1
  fi
  spk_test_tmp_exit
  echo "Integration tests passed."
  exit 0
fi

if $RUN_SCRIPTS; then
  echo "Running build script tests..."
  # No TMPDIR redirection here: the suite controls TMPDIR itself so it can
  # check that the generated nfpm config does not outlive a run.
  go test -tags scripts -count=1 -timeout 900s ./tests/scripts/ || { echo "Build script tests failed"; exit 1; }
  echo "Build script tests passed."
  exit 0
fi

if $RUN_TEST; then
  echo "Running unit tests + fuzz seed corpus (excluding sniffer -- use -testSniffer for those)..."
  PACKAGES=$(go list -buildvcs=false ./... | grep -v '/sniffer$')
  spk_test_tmp_enter
  if ! go test -buildvcs=false -count=1 ${PACKAGES}; then
    spk_test_tmp_exit
    echo "Tests failed!"
    exit 1
  fi
  echo ""
  echo "Running fuzz seed corpus..."
  if ! go test -buildvcs=false -count=1 -run "^Fuzz" ${PACKAGES}; then
    spk_test_tmp_exit
    echo "Fuzz seed corpus tests failed!"
    exit 1
  fi
  spk_test_tmp_exit
  exit 0
fi

if $RUN_TESTALL; then
  echo "Running all tests (smoke, unit+integration, fuzz, sniffer)..."
  echo ""
  spk_test_tmp_enter
  FAILED=false

  # Phase 1: smoke tests (requires SPK binary subprocess)
  echo "[1/4] Smoke tests..."
  SMOKE_RUNNER=""
  if [ "$(id -u)" != "0" ] && command -v sudo >/dev/null 2>&1; then
    SMOKE_RUNNER="sudo -E"
  fi
  if ! ${SMOKE_RUNNER} go test -buildvcs=false -count=1 -timeout 300s -tags testsmoke ./tests/smoke/; then
    FAILED=true; echo "ERROR: Smoke tests failed."
  fi

  if ! $FAILED; then
    # Phase 2: unit + integration tests (pure Go, no binary or hardware needed)
    echo ""
    echo "[2/4] Unit + integration tests..."
    UNIT_PKGS=$(go list -buildvcs=false ./... | grep -v '/sniffer$')
    if ! go test -buildvcs=false -count=1 ${UNIT_PKGS}; then
      FAILED=true; echo "ERROR: Unit + integration tests failed."
    fi
  fi

  if ! $FAILED; then
    # Phase 3: fuzz seed corpus
    echo ""
    echo "[3/4] Fuzz seed corpus..."
    if ! go test -buildvcs=false -count=1 -run "^Fuzz" ${UNIT_PKGS}; then
      FAILED=true; echo "ERROR: Fuzz seed corpus tests failed."
    fi
  fi

  if ! $FAILED; then
    # Phase 4: sniffer hardware tests (requires pcap library / Npcap)
    echo ""
    echo "[4/4] Sniffer hardware tests..."
    OS="$(uname -s 2>/dev/null || echo Unknown)"
    SNIFFER_OK=true
    if [ "${OS}" = "Linux" ]; then
      if ! ldconfig -p 2>/dev/null | grep -q 'libpcap\.so' && \
         ! ls /usr/lib*/libpcap.so* /usr/lib*/*/libpcap.so* 2>/dev/null | head -1 | grep -q libpcap; then
        echo "  WARNING: libpcap not found -- skipping sniffer tests."
        echo "  Install with: sudo apt-get install libpcap-dev"
        SNIFFER_OK=false
      fi
    fi
    if $SNIFFER_OK; then
      # Use ${TMPDIR:-/tmp} as a fallback in case TMPDIR is unexpectedly unset
      # (e.g. environment reset between phases on some CI runners).
      SNIFFER_BIN="${TMPDIR:-/tmp}/spk_sniffer_test"
      if ! go test -buildvcs=false -c -o "${SNIFFER_BIN}" ./internal/sniffer/ 2>&1; then
        FAILED=true; echo "ERROR: sniffer test binary failed to compile."
      else
        if [ "${OS}" = "Linux" ]; then
          if ! sudo -E go test -buildvcs=false -count=1 -timeout 120s ./internal/sniffer/ -run "TestPcap|TestAFPacket|TestSniffer"; then
            FAILED=true; echo "ERROR: Sniffer tests failed."
          fi
        elif [ "${OS}" = "Darwin" ]; then
          if ! sudo -E go test -buildvcs=false -count=1 -timeout 120s ./internal/sniffer/ -run "TestPcap|TestSniffer"; then
            FAILED=true; echo "ERROR: Sniffer tests failed."
          fi
        else
          if ! go test -buildvcs=false -count=1 -timeout 120s ./internal/sniffer/ -run "TestPcap|TestAFPacket|TestWinDivert|TestSniffer"; then
            FAILED=true; echo "ERROR: Sniffer tests failed."
          fi
        fi
      fi
    fi
  fi

  spk_test_tmp_exit
  if $FAILED; then
    echo ""
    echo "One or more test phases failed."
    exit 1
  fi
  echo ""
  echo "All tests passed."
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

  spk_test_tmp_enter

  # Build the sniffer test binary first (verifies it compiles on this platform).
  # Use ${TMPDIR:-/tmp} as a fallback in case TMPDIR is unexpectedly unset.
  echo "Building sniffer test binary..."
  SNIFFER_BIN="${TMPDIR:-/tmp}/spk_sniffer_test"
  if ! go test -buildvcs=false -c -o "${SNIFFER_BIN}" ./internal/sniffer/ 2>&1; then
    spk_test_tmp_exit
    echo "ERROR: sniffer test binary failed to compile."
    exit 1
  fi
  echo "Sniffer test binary compiled successfully."
  echo ""

  # Run the platform-specific sniffer tests
  if [ "${OS}" = "Linux" ]; then
    echo "Running Linux sniffer tests (pcap + AF_PACKET)..."
    if ! sudo -E go test -buildvcs=false -count=1 -timeout 120s ./internal/sniffer/ -run "TestPcap|TestAFPacket|TestSniffer"; then
      spk_test_tmp_exit
      echo "ERROR: Sniffer tests failed."
      exit 1
    fi
  elif [ "${OS}" = "Darwin" ]; then
    echo "Running macOS sniffer tests (pcap)..."
    if ! sudo -E go test -buildvcs=false -count=1 -timeout 120s ./internal/sniffer/ -run "TestPcap|TestSniffer"; then
      spk_test_tmp_exit
      echo "ERROR: Sniffer tests failed."
      exit 1
    fi
  else
    echo "Running sniffer tests (all backends)..."
    if ! go test -buildvcs=false -count=1 -timeout 120s ./internal/sniffer/ -run "TestPcap|TestAFPacket|TestWinDivert|TestSniffer"; then
      spk_test_tmp_exit
      echo "ERROR: Sniffer tests failed."
      exit 1
    fi
  fi
  spk_test_tmp_exit
  exit 0
fi

if $RUN_COVERAGE; then
  echo "Running tests with coverage (excluding sniffer -- use -testSniffer for those)..."
  PACKAGES=$(go list -buildvcs=false ./... | grep -v '/sniffer$')
  spk_test_tmp_enter
  if ! go test -buildvcs=false ${PACKAGES} -coverprofile=coverage.out; then
    spk_test_tmp_exit
    exit 1
  fi
  spk_test_tmp_exit
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

# -native: this host only, whatever it is.
if $BUILD_NATIVE; then
  NATIVE_GOOS=$(go env GOOS)
  NATIVE_GOARCH=$(go env GOARCH)
  case "${NATIVE_GOOS}" in
    windows) BUILD_WINDOWS=true ;;
    linux)   BUILD_LINUX=true ;;
    darwin)  BUILD_DARWIN=true ;;
    *)       echo "Unsupported host platform: ${NATIVE_GOOS}"; exit 1 ;;
  esac
  case "${NATIVE_GOARCH}" in
    amd64) INCLUDE_AMD64=true ;;
    arm64) INCLUDE_ARM64=true ;;
    *)     echo "Unsupported host architecture: ${NATIVE_GOARCH}"; exit 1 ;;
  esac
fi

# Default: build linux + windows amd64
if ! $HAS_PLATFORM; then
  BUILD_LINUX=true
  BUILD_WINDOWS=true
fi

if $BUILD_NATIVE; then
  : # already resolved above; do not widen the selection
elif $HAS_PLATFORM && ! $HAS_ARCH; then
  INCLUDE_AMD64=true
  INCLUDE_ARM64=true
elif $HAS_ARCH && ! $HAS_PLATFORM; then
  BUILD_WINDOWS=true
  BUILD_LINUX=true
  BUILD_DARWIN=true
elif ! $HAS_PLATFORM && ! $HAS_ARCH; then
  INCLUDE_AMD64=true
fi

# A build is definitely happening now, so take the build number and leave the
# next one in the file.
take_build_number

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

# find_nfpm prints the nfpm executable: the one on PATH, or the one go install
# leaves in GOBIN (GOPATH/bin by default), which is not always on PATH.
find_nfpm() {
  if command -v nfpm 2>/dev/null; then
    return 0
  fi
  local gobin cand
  gobin=$(go env GOBIN 2>/dev/null)
  [ -z "$gobin" ] && gobin="$(go env GOPATH 2>/dev/null)/bin"
  for cand in "$gobin/nfpm" "$gobin/nfpm.exe"; do
    if [ -x "$cand" ]; then
      echo "$cand"
      return 0
    fi
  done
  return 1
}

# Check for nfpm (needed for -deb / -rpm packaging)
NFPM_AVAILABLE=false
NFPM_BIN=""
if NFPM_BIN=$(find_nfpm); then
  NFPM_AVAILABLE=true
  echo "nfpm: found (${NFPM_BIN})"
elif $BUILD_DEB || $BUILD_RPM; then
  echo "nfpm: not found -- auto-installing..."
  # The install's own output is kept: when it fails, the reason has to be on
  # the screen, and under set -e a silenced failure would end the script with
  # nothing to explain it.
  if ! go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest; then
    echo "ERROR: nfpm auto-install failed"
    echo "  Install manually: go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest"
    exit 1
  fi
  if ! NFPM_BIN=$(find_nfpm); then
    echo "ERROR: nfpm was installed but cannot be found in GOBIN or on PATH"
    exit 1
  fi
  NFPM_AVAILABLE=true
  echo "nfpm: installed (${NFPM_BIN})"
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
    go build -buildvcs=false -trimpath -ldflags "${ldflags}" -o "${output}" ./
  ); then
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

  # Generate nfpm config. The X's must end the template: BSD mktemp, as on
  # macOS, takes anything after them literally and would reuse one fixed name
  # for every run.
  local tmp_yaml
  tmp_yaml=$(mktemp "${TMPDIR:-/tmp}/nfpm_XXXXXX") || return 1
  cat > "$tmp_yaml" <<NFPMEOF
name: spk
arch: ${pkg_arch}
version: ${FULL_VERSION}
maintainer: "Jack L. (Cpt-JackL) <https://jack-l.com>"
description: "Secured Port Knock - SPA port knocking with ML-KEM post-quantum cryptography"
homepage: "https://github.com/secured-port-knock/spk"
license: MIT
contents:
  - src: ${binary_path}
    dst: /usr/bin/spk
    file_info:
      mode: 0755
NFPMEOF

  echo "  Packaging ${pkg_file}..."
  if ! "$NFPM_BIN" pkg --config "$tmp_yaml" --packager "$format" --target "$pkg_file"; then
    rm -f "$tmp_yaml"
    echo "    FAILED: ${pkg_file}"
    return 1
  fi
  rm -f "$tmp_yaml"
  local size
  size=$(stat -f%z "$pkg_file" 2>/dev/null || stat -c%s "$pkg_file" 2>/dev/null || echo 0)
  echo "    -> ${size} bytes"
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

    # A package that failed to build ends the run, as a failed compile does:
    # the release ships whatever is in build/linux, and "Build complete" must
    # not be printed over a missing file.
    if $BUILD_DEB; then
      package_nfpm "$bin" "$arch" "deb" || exit 1
    fi
    if $BUILD_RPM; then
      package_nfpm "$bin" "$arch" "rpm" || exit 1
    fi
  done
fi

echo ""
echo "Build complete. Output in ${BUILD_DIR}/"
find "${BUILD_DIR}" -type f | sort
