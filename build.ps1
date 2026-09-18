# Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
# SPDX-License-Identifier: MIT
# SPK build script for Windows PowerShell.
# See "Build Scripts" in docs/compilation.md for usage, flags, and pcap
# toolchain priority.
#
# Filename convention:
#   spk_<VERSION>p-<OS>-<ARCH>[.exe]   (pcap-capable build)
#   spk_<VERSION>-<OS>-<ARCH>[.exe]    (no pcap support)
param(
    [switch]$windows,
    [switch]$linux,
    [switch]$darwin,
    [switch]$amd64,
    [switch]$arm64,
    [switch]$all,
    [switch]$native,
    [switch]$nopcap,
    [switch]$test,
    [switch]$testall,
    [switch]$integration,
    [switch]$teste2e,
    # PowerShell matches parameter names case-insensitively, so -testSniffer
    # keeps working; every other flag is lower case.
    [switch]$testsniffer,
    [switch]$testsmoke,
    [switch]$testscripts,
    [switch]$coverage,
    [switch]$clean,
    [switch]$deb,
    [switch]$rpm,
    # Anything not matched above. build.sh rejects unknown flags; without
    # this PowerShell would silently ignore a typo and run a default build.
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Rest
)

# Show-Usage prints the same flag list as build.sh.
function Show-Usage {
    @"
Usage: build.ps1 [targets] [actions]

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
"@ | Write-Host
}

if ($Rest) {
    Write-Host "Unknown argument: $($Rest -join ' ')"
    Write-Host ""
    Show-Usage
    exit 1
}

$Binary = "spk"

# Outside a git checkout (a source tarball, or the copy the script tests build
# in) git writes to stderr. Errors are tolerated explicitly here so the lookup
# stays harmless if this script ever adopts $ErrorActionPreference = "Stop",
# under which a bare stderr write would end the run before it started.
$Commit = ""
$prevErrorAction = $ErrorActionPreference
$ErrorActionPreference = "Continue"
try { $Commit = (git rev-parse --short HEAD 2>$null) } catch { $Commit = "" }
$ErrorActionPreference = $prevErrorAction
if (-not $Commit) { $Commit = "dev" }

# Read base version from version/version_base.txt
$VersionBaseFile = Join-Path $PSScriptRoot "version\version_base.txt"
if (Test-Path $VersionBaseFile) {
    $Version = (Get-Content $VersionBaseFile -ErrorAction SilentlyContinue | Select-Object -First 1).Trim()
}
if (-not $Version) { $Version = "1.0.0" }
if ($env:VERSION) { $Version = $env:VERSION }

# Auto-increment build number (or use BUILD_NUMBER env var to pin an exact value)
# When $env:BUILD_NUMBER is set, the file is NOT written -- callers manage versioning.
$BuildNumberFile = Join-Path $PSScriptRoot "version\build_number.txt"
$SkipBuildNumberBump = $false
if ($env:BUILD_NUMBER) {
    # Only the digits count, and a value with none is 0, which is what build.sh
    # does with the same input; "007" is 7 on both.
    $rawEnv = $env:BUILD_NUMBER -replace '[^0-9]', ''
    $BuildNumber = if ($rawEnv) { [int]$rawEnv } else { 0 }
    $SkipBuildNumberBump = $true
} else {
    $BuildNumber = 0
    if (Test-Path $BuildNumberFile) {
        $raw = (Get-Content $BuildNumberFile -Raw -ErrorAction SilentlyContinue).Trim() -replace '[^0-9]', ''
        if ($raw) { $BuildNumber = [int]$raw }
    }
}
$Module = "github.com/secured-port-knock/spk/internal/app"
$FullVersion = "$Version.$BuildNumber"
$LDFlags = "-X ${Module}.version=$Version -X ${Module}.commit=$Commit -X ${Module}.buildNumber=$BuildNumber"
$BuildDir = "build"

# Take-BuildNumber is called only once a build is actually going to happen.
# This build takes the number the file holds and leaves the next one behind:
# the convention build.sh, the release workflow and the sibling projects
# share. Taking the number the file was bumped TO instead would stamp this
# build one ahead of the release built from the same starting file.
#
# It is NOT called for -test, -clean and the other actions, because a run that
# produces no binary must not consume a version.
#
# A named system Mutex keeps concurrent PowerShell builds from taking the same
# number or corrupting the file.
function Take-BuildNumber {
    if ($SkipBuildNumberBump) { return }
    $mtx = [System.Threading.Mutex]::new($false, "Global\SPKBuildNumber")
    try {
        $null = $mtx.WaitOne()
        # Re-read under the lock to handle the TOCTOU window.
        $lockedRaw = (Get-Content $BuildNumberFile -Raw -ErrorAction SilentlyContinue).Trim() -replace '[^0-9]', ''
        $lockedNum = if ($lockedRaw) { [int]$lockedRaw } else { 0 }
        $script:BuildNumber = $lockedNum
        Set-Content $BuildNumberFile ($lockedNum + 1)
    } finally {
        $mtx.ReleaseMutex()
        $mtx.Dispose()
    }
    $script:FullVersion = "$Version.$script:BuildNumber"
    $script:LDFlags = "-X ${Module}.version=$Version -X ${Module}.commit=$Commit -X ${Module}.buildNumber=$script:BuildNumber"
}

Write-Host "SPK Build Script" -ForegroundColor Cyan
Write-Host "========================"
Write-Host "Version: $FullVersion"
Write-Host "Commit:  $Commit"

# -- Detect toolchain ------------------------------------------------

# Find-Nfpm returns the nfpm executable: the one on PATH, or the one go install
# leaves in GOBIN (GOPATH\bin by default), which is not always on PATH.
function Find-Nfpm {
    $cmd = Get-Command nfpm -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $gobin = (go env GOBIN)
    if (-not $gobin) { $gobin = Join-Path (go env GOPATH) "bin" }
    foreach ($name in "nfpm.exe", "nfpm") {
        $cand = Join-Path $gobin $name
        if (Test-Path $cand) { return $cand }
    }
    return $null
}

# nfpm (needed for -deb / -rpm packaging)
$NfpmAvailable = $false
$NfpmPath = Find-Nfpm
if ($NfpmPath) {
    $NfpmAvailable = $true
    Write-Host "nfpm:    found ($NfpmPath)" -ForegroundColor Green
} elseif ($deb.IsPresent -or $rpm.IsPresent) {
    Write-Host "nfpm:    not found -- auto-installing..." -ForegroundColor Yellow
    # The install's own output is kept, so a failure says why.
    go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest
    if ($LASTEXITCODE -ne 0) {
        Write-Host "nfpm:    auto-install failed" -ForegroundColor Red
        Write-Host "         Install manually: go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest" -ForegroundColor Yellow
        exit 1
    }
    $NfpmPath = Find-Nfpm
    if (-not $NfpmPath) {
        Write-Host "nfpm:    installed, but not found in GOBIN or on PATH" -ForegroundColor Red
        exit 1
    }
    $NfpmAvailable = $true
    Write-Host "nfpm:    installed ($NfpmPath)" -ForegroundColor Green
}

# Zig (needed only for cross-compiling Linux/Darwin with pcap)
$ZigAvailable = $false
$ZigPath = Get-Command zig -ErrorAction SilentlyContinue
if ($ZigPath) {
    $ZigAvailable = $true
    Write-Host "Zig:     found ($($ZigPath.Source))" -ForegroundColor Green
} else {
    Write-Host "Zig:     not found (Linux/Darwin cross-builds will not include pcap)" -ForegroundColor Yellow
}

# GCC (native fallback for Linux/Darwin)
$gccNative = Get-Command gcc -ErrorAction SilentlyContinue

Write-Host ""

# Handle test/coverage/clean/testsmoke first
# Helper: set up $TMP/spk test temp dir, returns original TEMP and the spk path.
function Enter-TestTmp {
    $origTemp = $env:TEMP
    $origTmp  = $env:TMP
    $spkTmp   = Join-Path $origTemp "spk"
    New-Item -ItemType Directory -Path $spkTmp -Force | Out-Null
    $env:TEMP = $spkTmp
    $env:TMP  = $spkTmp
    return @{ OrigTemp = $origTemp; OrigTmp = $origTmp; SpkTmp = $spkTmp }
}

# Helper: restore TEMP/TMP and clean up $TMP/spk.
function Exit-TestTmp($saved) {
    $env:TEMP = $saved.OrigTemp
    $env:TMP  = $saved.OrigTmp
    Remove-Item $saved.SpkTmp -Recurse -Force -ErrorAction SilentlyContinue
}

# No-Suite: this project has no such suite. The flag is accepted so the same
# commands work across every project; it reports and succeeds.
function No-Suite($name) {
    Write-Host "No $name tests in this project."
    exit 0
}

if ($teste2e) { No-Suite "end-to-end" }

if ($integration) {
    Write-Host "Running integration tests..." -ForegroundColor Green
    $saved = Enter-TestTmp
    try {
        go test -buildvcs=false -count=1 -timeout 300s ./tests/integration/
        if ($LASTEXITCODE -ne 0) {
            Write-Host "Integration tests failed" -ForegroundColor Red
            exit 1
        }
    } finally {
        Exit-TestTmp $saved
    }
    Write-Host "Integration tests passed." -ForegroundColor Green
    exit 0
}

if ($testsmoke) {
    Write-Host "Running end-to-end smoke tests (tag: testsmoke)..." -ForegroundColor Green
    $saved = Enter-TestTmp
    try {
        go test -buildvcs=false -count=1 -timeout 300s -tags testsmoke ./tests/smoke/
        if ($LASTEXITCODE -ne 0) {
            Write-Host "Smoke tests failed!" -ForegroundColor Red
            exit 1
        }
    } finally {
        Exit-TestTmp $saved
    }
    exit 0
}

if ($testscripts) {
    Write-Host "Running build script tests..." -ForegroundColor Green
    # No temp redirection here: the suite controls TEMP itself so it can check
    # that the generated nfpm config does not outlive a run.
    go test -tags scripts -count=1 -timeout 900s ./tests/scripts/
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Build script tests failed" -ForegroundColor Red
        exit 1
    }
    Write-Host "Build script tests passed." -ForegroundColor Green
    exit 0
}

if ($test) {
    Write-Host "Running unit tests + fuzz seed corpus (excluding sniffer -- use -testsniffer for those)..." -ForegroundColor Green
    $packages = & go list -buildvcs=false ./... | Where-Object { $_ -notlike '*/sniffer' }
    $saved = Enter-TestTmp
    try {
        go test -buildvcs=false -count=1 $packages
        if ($LASTEXITCODE -ne 0) {
            Write-Host "Tests failed!" -ForegroundColor Red
            exit 1
        }
        Write-Host ""
        Write-Host "Running fuzz seed corpus..." -ForegroundColor Cyan
        go test -buildvcs=false -count=1 -run "^Fuzz" $packages
        if ($LASTEXITCODE -ne 0) {
            Write-Host "Fuzz seed corpus tests failed!" -ForegroundColor Red
            exit 1
        }
    } finally {
        Exit-TestTmp $saved
    }
    exit 0
}

if ($testall) {
    Write-Host "Running all tests (smoke, unit+integration, fuzz, sniffer)..." -ForegroundColor Green
    Write-Host ""
    $saved = Enter-TestTmp
    $failed = $false
    try {
        # Phase 1: smoke tests (requires SPK binary subprocess)
        Write-Host "[1/4] Smoke tests..." -ForegroundColor Cyan
        go test -buildvcs=false -count=1 -timeout 300s -tags testsmoke ./tests/smoke/
        if ($LASTEXITCODE -ne 0) { $failed = $true; throw "Smoke tests failed" }

        # Phase 2: unit + integration tests (pure Go, no binary or hardware needed)
        Write-Host ""
        Write-Host "[2/4] Unit + integration tests..." -ForegroundColor Cyan
        $unitPkgs = & go list -buildvcs=false ./... | Where-Object { $_ -notlike '*/sniffer' }
        go test -buildvcs=false -count=1 $unitPkgs
        if ($LASTEXITCODE -ne 0) { $failed = $true; throw "Unit + integration tests failed" }

        # Phase 3: fuzz seed corpus
        Write-Host ""
        Write-Host "[3/4] Fuzz seed corpus..." -ForegroundColor Cyan
        go test -buildvcs=false -count=1 -run "^Fuzz" $unitPkgs
        if ($LASTEXITCODE -ne 0) { $failed = $true; throw "Fuzz seed corpus tests failed" }

        # Phase 4: sniffer hardware tests (Npcap or WinDivert or both)
        Write-Host ""
        Write-Host "[4/4] Sniffer hardware tests..." -ForegroundColor Cyan
        $sys32 = "$env:SystemRoot\System32"
        $npcapInstalled = (Test-Path "$sys32\Npcap\wpcap.dll") -or (Test-Path "$sys32\wpcap.dll")
        $windivertInstalled = (Test-Path "$sys32\WinDivert.dll") -or (Test-Path "$sys32\WinDivert64.sys")
        if (-not $npcapInstalled -and -not $windivertInstalled) {
            Write-Host "  INFO: Neither Npcap nor WinDivert found -- skipping sniffer hardware tests." -ForegroundColor Yellow
            Write-Host "  Install Npcap:     winget install Npcap.Npcap" -ForegroundColor Yellow
            Write-Host "  Install WinDivert: https://reqrypt.org/windivert.html" -ForegroundColor Yellow
        } else {
            if ($npcapInstalled)     { Write-Host "  Npcap found."     -ForegroundColor Green }
            if ($windivertInstalled) { Write-Host "  WinDivert found." -ForegroundColor Green }
            $runFilter = "TestSniffer"
            if ($npcapInstalled)     { $runFilter += "|TestPcap" }
            if ($windivertInstalled) { $runFilter += "|TestWinDivert" }
            $snifferBin = Join-Path $saved.SpkTmp "spk_sniffer_test.exe"
            go test -buildvcs=false -c -o $snifferBin ./internal/sniffer/
            if ($LASTEXITCODE -ne 0) { $failed = $true; throw "Sniffer test binary failed to compile" }
            go test -buildvcs=false -count=1 -timeout 120s ./internal/sniffer/ -run $runFilter
            if ($LASTEXITCODE -ne 0) { $failed = $true; throw "Sniffer tests failed" }
        }
    } catch {
        Write-Host ""
        Write-Host "ERROR: $_" -ForegroundColor Red
    } finally {
        Exit-TestTmp $saved
    }
    if ($failed) { exit 1 }
    Write-Host ""
    Write-Host "All tests passed." -ForegroundColor Green
    exit 0
}

if ($testsniffer) {
    Write-Host "Running sniffer hardware tests on Windows..." -ForegroundColor Green
    Write-Host ""

    $sys32 = "$env:SystemRoot\System32"
    $npcapInstalled = (Test-Path "$sys32\Npcap\wpcap.dll") -or (Test-Path "$sys32\wpcap.dll")
    $windivertInstalled = (Test-Path "$sys32\WinDivert.dll") -or (Test-Path "$sys32\WinDivert64.sys")

    if (-not $npcapInstalled -and -not $windivertInstalled) {
        Write-Host "ERROR: Neither Npcap nor WinDivert found." -ForegroundColor Red
        Write-Host "  Install Npcap:     winget install Npcap.Npcap" -ForegroundColor Yellow
        Write-Host "  Install WinDivert: https://reqrypt.org/windivert.html" -ForegroundColor Yellow
        exit 1
    }
    if ($npcapInstalled)     { Write-Host "Npcap found."     -ForegroundColor Green }
    if ($windivertInstalled) { Write-Host "WinDivert found." -ForegroundColor Green }
    Write-Host ""

    $runFilter = "TestSniffer"
    if ($npcapInstalled)     { $runFilter += "|TestPcap" }
    if ($windivertInstalled) { $runFilter += "|TestWinDivert" }

    $saved = Enter-TestTmp
    $snifferFailed = $false
    try {
        # Build the sniffer test binary first (verifies it compiles)
        Write-Host "Building sniffer test binary..." -ForegroundColor Cyan
        $snifferBin = Join-Path $saved.SpkTmp "spk_sniffer_test.exe"
        go test -buildvcs=false -c -o $snifferBin ./internal/sniffer/
        if ($LASTEXITCODE -ne 0) {
            Write-Host "ERROR: sniffer test binary failed to compile." -ForegroundColor Red
            $snifferFailed = $true
        } else {
            Write-Host "Sniffer test binary compiled successfully." -ForegroundColor Green
            Write-Host ""

            # Run the Windows-specific sniffer tests
            go test -buildvcs=false -count=1 -timeout 120s ./internal/sniffer/ -run $runFilter
            if ($LASTEXITCODE -ne 0) {
                Write-Host "ERROR: Sniffer tests failed." -ForegroundColor Red
                $snifferFailed = $true
            }
        }
    } finally {
        Exit-TestTmp $saved
    }
    if ($snifferFailed) { exit 1 }
    exit 0
}

if ($coverage) {
    Write-Host "Running tests with coverage (excluding sniffer -- use -testsniffer for those)..." -ForegroundColor Green
    $packages = & go list -buildvcs=false ./... | Where-Object { $_ -notlike '*/sniffer' }
    $saved = Enter-TestTmp
    $coverFailed = $false
    try {
        go test -buildvcs=false $packages -coverprofile=coverage.out
        if ($LASTEXITCODE -ne 0) {
            Write-Host "Tests failed!" -ForegroundColor Red
            $coverFailed = $true
        } else {
            go tool cover -html=coverage.out -o coverage.html
            Write-Host "Coverage report: coverage.html" -ForegroundColor Green
        }
    } finally {
        Exit-TestTmp $saved
    }
    if ($coverFailed) { exit 1 }
    exit 0
}

if ($clean) {
    Write-Host "Cleaning..." -ForegroundColor Yellow
    Get-ChildItem -Path . -Filter "$Binary*" -File -ErrorAction SilentlyContinue | Remove-Item -Force
    Remove-Item $BuildDir -Recurse -ErrorAction SilentlyContinue
    Remove-Item coverage.out -ErrorAction SilentlyContinue
    Remove-Item coverage.html -ErrorAction SilentlyContinue
    Write-Host "Clean complete."
    exit 0
}

# Wipe build directory
if (Test-Path $BuildDir) {
    Remove-Item $BuildDir -Recurse -Force
}

# Determine platforms to build
$platforms = @()
$osExplicit  = $windows.IsPresent -or $linux.IsPresent -or $darwin.IsPresent
$archExplicit = $amd64.IsPresent -or $arm64.IsPresent

if ($native) {
    # -native: this host only, whatever it is.
    $nativeOS = (go env GOOS)
    $nativeArch = (go env GOARCH)
    if ($nativeOS -notin @("windows", "linux", "darwin")) {
        Write-Host "Unsupported host platform: $nativeOS" -ForegroundColor Red
        exit 1
    }
    if ($nativeArch -notin @("amd64", "arm64")) {
        Write-Host "Unsupported host architecture: $nativeArch" -ForegroundColor Red
        exit 1
    }
    $selectedOS = @($nativeOS)
    $selectedArch = @($nativeArch)
} elseif ($all) {
    $selectedOS = @("windows", "linux", "darwin")
    $selectedArch = @("amd64", "arm64")
} elseif ($osExplicit -and $archExplicit) {
    $selectedOS = @()
    if ($windows.IsPresent) { $selectedOS += "windows" }
    if ($linux.IsPresent)   { $selectedOS += "linux" }
    if ($darwin.IsPresent)  { $selectedOS += "darwin" }
    $selectedArch = @()
    if ($amd64.IsPresent) { $selectedArch += "amd64" }
    if ($arm64.IsPresent) { $selectedArch += "arm64" }
} elseif ($osExplicit) {
    $selectedOS = @()
    if ($windows.IsPresent) { $selectedOS += "windows" }
    if ($linux.IsPresent)   { $selectedOS += "linux" }
    if ($darwin.IsPresent)  { $selectedOS += "darwin" }
    $selectedArch = @("amd64", "arm64")
} elseif ($amd64.IsPresent -and -not $arm64.IsPresent) {
    $selectedOS = @("windows", "linux", "darwin")
    $selectedArch = @("amd64")
} elseif ($arm64.IsPresent -and -not $amd64.IsPresent) {
    $selectedOS = @("windows", "linux", "darwin")
    $selectedArch = @("arm64")
} elseif ($amd64.IsPresent -and $arm64.IsPresent) {
    $selectedOS = @("windows", "linux", "darwin")
    $selectedArch = @("amd64", "arm64")
} else {
    # Default: windows+linux, amd64 only
    $selectedOS = @("windows", "linux")
    $selectedArch = @("amd64")
}

$extMap = @{ "windows" = ".exe"; "linux" = ""; "darwin" = "" }
$dirMap = @{ "windows" = "windows"; "linux" = "linux"; "darwin" = "darwin" }

foreach ($os in $selectedOS) {
    foreach ($arch in $selectedArch) {
        $platforms += @{ GOOS = $os; GOARCH = $arch; Ext = $extMap[$os]; Dir = $dirMap[$os] }
    }
}

# A build is definitely happening now, so take the build number and leave the
# next one in the file.
Take-BuildNumber

Write-Host "Building $($platforms.Count) target(s)..." -ForegroundColor Green

# Zig target triple map
$zigTargetMap = @{
    "linux/amd64"   = "x86_64-linux-gnu"
    "linux/arm64"   = "aarch64-linux-gnu"
    "windows/amd64" = "x86_64-windows-gnu"
    "windows/arm64" = "aarch64-windows-gnu"
    "darwin/amd64"  = "x86_64-macos"
    "darwin/arm64"  = "aarch64-macos"
}

# Detect host OS/arch
$hostGOOS = (go env GOOS 2>$null)
if (-not $hostGOOS) { $hostGOOS = "windows" }
$hostGOARCH = (go env GOARCH 2>$null)
if (-not $hostGOARCH) { $hostGOARCH = "amd64" }

# Clear-GoEnv drops the per-target variables so they do not outlive the script
# in the calling session, whichever way the script ends.
function Clear-GoEnv {
    Remove-Item Env:\GOOS, Env:\GOARCH, Env:\CGO_ENABLED, Env:\CC, `
        Env:\CGO_CFLAGS, Env:\CGO_LDFLAGS -ErrorAction SilentlyContinue
}

# -- Build function ---------------------------------------------------
function Build-Target($p, [bool]$pcap, [string]$ccOverride) {
    $versionSuffix = if ($pcap) { "${FullVersion}p" } else { "$FullVersion" }
    $outDir = "$BuildDir/$($p.Dir)"
    if (-not (Test-Path $outDir)) {
        New-Item -ItemType Directory -Path $outDir -Force | Out-Null
    }
    $output = "$outDir/${Binary}_${versionSuffix}-$($p.GOOS)-$($p.GOARCH)$($p.Ext)"
    $env:GOOS = $p.GOOS
    $env:GOARCH = $p.GOARCH

    $ldflags = "$LDFlags"

    if ($pcap) {
        if ($p.GOOS -eq "windows") {
            # Windows pcap: pure Go, no CGO needed
            $env:CGO_ENABLED = "0"
            Remove-Item Env:\CC -ErrorAction SilentlyContinue
        } else {
            # Linux/Darwin pcap: CGO for dlfcn.h only (no pcap headers needed)
            $env:CGO_ENABLED = "1"
            $env:CC = $ccOverride
        }
        Remove-Item Env:\CGO_CFLAGS -ErrorAction SilentlyContinue
        Remove-Item Env:\CGO_LDFLAGS -ErrorAction SilentlyContinue
        Write-Host "  Building $output... (pcap)" -ForegroundColor Green
    } else {
        $env:CGO_ENABLED = "0"
        Remove-Item Env:\CC -ErrorAction SilentlyContinue
        Remove-Item Env:\CGO_CFLAGS -ErrorAction SilentlyContinue
        Remove-Item Env:\CGO_LDFLAGS -ErrorAction SilentlyContinue
        Write-Host "  Building $output..."
    }

    $buildArgs = @("build", "-buildvcs=false", "-trimpath", "-ldflags", "$ldflags -s -w", "-o", $output, "./")

    & go @buildArgs
    if ($LASTEXITCODE -ne 0) {
        Write-Host "    FAILED: $output" -ForegroundColor Red
        Remove-Item $output -ErrorAction SilentlyContinue
        if ($pcap) {
            Write-Host "ERROR: pcap build failed for $($p.GOOS)/$($p.GOARCH)" -ForegroundColor Red
        }
        Clear-GoEnv
        # A compile error ends the run, as it does in build.sh. A partial build
        # that went on to report "Build complete" would be shipped as if whole.
        exit 1
    }

    $origSize = (Get-Item $output).Length
    Write-Host "    -> $([math]::Round($origSize/1MB, 2)) MB" -ForegroundColor White
}

# -- nfpm packaging function -------------------------------------------
function Package-Nfpm([string]$binaryPath, [string]$goarch, [string]$format) {
    # Map Go arch to deb/rpm arch names
    $archMap = @{
        "amd64" = if ($format -eq "deb") { "amd64" } else { "x86_64" }
        "arm64" = if ($format -eq "deb") { "arm64" } else { "aarch64" }
    }
    $pkgArch = $archMap[$goarch]
    if (-not $pkgArch) { $pkgArch = $goarch }

    $outDir = Split-Path $binaryPath
    # Use the full filename (not GetFileNameWithoutExtension -- that strips the arch
    # segment since versioned names like spk_1.0.0.60p-linux-amd64 have a 'dotted' path).
    $binName = (Get-Item $binaryPath).Name
    $pkgFile = "$outDir/${binName}.${format}"

    # Generate nfpm config in a temp file
    $nfpmYaml = @"
name: spk
arch: $pkgArch
version: $FullVersion
maintainer: Jack L. (Cpt-JackL) <https://jack-l.com>
description: Secured Port Knock - SPA port knocking with ML-KEM post-quantum cryptography
homepage: https://github.com/secured-port-knock/spk
license: MIT
contents:
  - src: $($binaryPath.Replace('\', '/'))
    dst: /usr/bin/spk
    file_info:
      mode: 0755
"@

    $tmpYaml = Join-Path $env:TEMP "nfpm_$(Get-Random).yaml"
    Set-Content -Path $tmpYaml -Value $nfpmYaml -Encoding UTF8

    Write-Host "  Packaging $pkgFile..." -ForegroundColor Magenta
    & $NfpmPath pkg --config $tmpYaml --packager $format --target $pkgFile
    $exitCode = $LASTEXITCODE
    Remove-Item $tmpYaml -ErrorAction SilentlyContinue

    if ($exitCode -ne 0) {
        Write-Host "    FAILED: $pkgFile" -ForegroundColor Red
        Clear-GoEnv
        exit 1
    }
    $size = (Get-Item $pkgFile).Length
    Write-Host "    -> $([math]::Round($size/1KB, 1)) KB" -ForegroundColor Magenta
}

# -- Main build loop --------------------------------------------------
foreach ($p in $platforms) {
    $isNative = ($p.GOOS -eq $hostGOOS) -and ($p.GOARCH -eq $hostGOARCH)
    $crossKey = "$($p.GOOS)/$($p.GOARCH)"

    if ($p.GOOS -eq "windows") {
        # Windows: always pcap (pure Go, CGO_ENABLED=0)
        Build-Target $p $true ""
    } elseif ($nopcap) {
        # -nopcap: build Linux/Darwin without pcap (CGO_ENABLED=0)
        Build-Target $p $false ""
    } elseif ($p.GOOS -eq "darwin") {
        # zig 0.13 Mach-O linker rejects -Wl,-x which Go injects for all CGO darwin builds.
        # Only a native Apple clang can link darwin CGO binaries correctly.
        # Use native gcc/clang only when host IS darwin AND arch matches; no-pcap otherwise.
        if ($isNative -and $gccNative) {
            Build-Target $p $true "gcc"
        } else {
            Write-Host "    (darwin pcap requires native Apple clang for exact host arch; using no-pcap)" -ForegroundColor Yellow
            Build-Target $p $false ""
        }
    } elseif ($ZigAvailable) {
        # Cross-build with zig: CGO for dlfcn.h (linux targets only; darwin handled above)
        $zigTarget = $zigTargetMap[$crossKey]
        if ($zigTarget) {
            $zigCC = "zig cc -target $zigTarget"
            Build-Target $p $true $zigCC
        } else {
            Build-Target $p $false ""
        }
    } elseif ($isNative -and $gccNative) {
        # Native build with gcc/clang
        Build-Target $p $true "gcc"
    } else {
        # No C compiler available
        if (-not $isNative) {
            Write-Host "    (cross build without zig -- no pcap)" -ForegroundColor Yellow
        } else {
            Write-Host "    (no C compiler found -- no pcap)" -ForegroundColor Yellow
        }
        Build-Target $p $false ""
    }
}

# -- Package Linux binaries with nfpm if -deb or -rpm requested --------
if ($NfpmAvailable -and ($deb.IsPresent -or $rpm.IsPresent)) {
    Write-Host ""
    Write-Host "Packaging Linux binaries..." -ForegroundColor Magenta

    # Collect linux binaries -- match full filename like spk_1.0.0.60p-linux-amd64
    # (Cannot use $_.Extension: PowerShell treats the last dot-segment as extension,
    # so a versioned name like spk_1.0.0.60p-linux-amd64 has Extension '.60p-linux-amd64'.)
    $linuxBinaries = Get-ChildItem "$BuildDir/linux" -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^spk_.*-linux-(amd64|arm64)$' }

    foreach ($bin in $linuxBinaries) {
        # Extract arch from filename: spk_1.0.0.52p-linux-amd64
        if ($bin.Name -match '-linux-(amd64|arm64)$') {
            $arch = $Matches[1]
            if ($deb.IsPresent) {
                Package-Nfpm $bin.FullName $arch "deb"
            }
            if ($rpm.IsPresent) {
                Package-Nfpm $bin.FullName $arch "rpm"
            }
        }
    }
}

# Reset environment
Clear-GoEnv

Write-Host ""
Write-Host "Build complete. Output in $BuildDir/" -ForegroundColor Green
Get-ChildItem $BuildDir -Recurse -File | ForEach-Object {
    Write-Host "  $($_.FullName.Replace((Get-Location).Path + '\', ''))"
}
