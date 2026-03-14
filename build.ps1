# Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
# SPDX-License-Identifier: MIT
# SPK build script for Windows PowerShell
# Usage:
#   .\build.ps1                   # Build windows/amd64 + linux/amd64
#   .\build.ps1 -windows          # Build windows/amd64 + windows/arm64
#   .\build.ps1 -linux            # Build linux/amd64 + linux/arm64
#   .\build.ps1 -darwin           # Build darwin/amd64 + darwin/arm64
#   .\build.ps1 -amd64            # Build all platforms for amd64 only
#   .\build.ps1 -arm64            # Build all platforms for arm64 only
#   .\build.ps1 -linux -amd64     # Build linux/amd64 only
#   .\build.ps1 -linux -arm64     # Build linux/arm64 only
#   .\build.ps1 -windows -amd64   # Build windows/amd64 only
#   .\build.ps1 -windows -arm64   # Build windows/arm64 only
#   .\build.ps1 -all              # Build all platform/arch combinations
#   .\build.ps1 -nopcap           # Disable pcap for Linux/Darwin builds
#   .\build.ps1 -test             # Run tests (excluding sniffer hardware tests)
#   .\build.ps1 -testSniffer      # Run sniffer hardware tests (requires Npcap on Windows)
#   .\build.ps1 -coverage         # Run tests with coverage
#   .\build.ps1 -clean            # Clean build artifacts
#   .\build.ps1 -linux -deb       # Build linux + create .deb packages
#   .\build.ps1 -linux -rpm       # Build linux + create .rpm packages
#   .\build.ps1 -linux -deb -rpm  # Build linux + both .deb and .rpm
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
#
# UPX: If upx is installed, binaries are automatically compressed.
param(
    [switch]$windows,
    [switch]$linux,
    [switch]$darwin,
    [switch]$amd64,
    [switch]$arm64,
    [switch]$all,
    [switch]$nopcap,
    [switch]$test,
    [switch]$testSniffer,
    [switch]$coverage,
    [switch]$clean,
    [switch]$deb,
    [switch]$rpm
)

$Binary = "spk"
$Commit = try { git rev-parse --short HEAD 2>$null } catch { "dev" }
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
    $BuildNumber = [int]$env:BUILD_NUMBER
    $SkipBuildNumberBump = $true
} else {
    $BuildNumber = 0
    if (Test-Path $BuildNumberFile) {
        $raw = (Get-Content $BuildNumberFile -Raw -ErrorAction SilentlyContinue).Trim() -replace '[^0-9]', ''
        if ($raw) { $BuildNumber = [int]$raw }
    }
    $BuildNumber++
}
if (-not $SkipBuildNumberBump) {
    Set-Content $BuildNumberFile $BuildNumber
}

$FullVersion = "$Version.$BuildNumber"
$LDFlags = "-X main.version=$Version -X main.commit=$Commit -X main.buildNumber=$BuildNumber"
$BuildDir = "build"

Write-Host "SPK Build Script" -ForegroundColor Cyan
Write-Host "========================"
Write-Host "Version: $FullVersion"
Write-Host "Commit:  $Commit"

# -- Detect toolchain ------------------------------------------------

# nfpm (needed for -deb / -rpm packaging)
$NfpmAvailable = $false
$NfpmPath = Get-Command nfpm -ErrorAction SilentlyContinue
if ($NfpmPath) {
    $NfpmAvailable = $true
    Write-Host "nfpm:    found ($($NfpmPath.Source))" -ForegroundColor Green
} else {
    if ($deb.IsPresent -or $rpm.IsPresent) {
        Write-Host "nfpm:    not found -- auto-installing..." -ForegroundColor Yellow
        & go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest 2>&1 | Out-Null
        $NfpmPath = Get-Command nfpm -ErrorAction SilentlyContinue
        if ($NfpmPath) {
            $NfpmAvailable = $true
            Write-Host "nfpm:    installed ($($NfpmPath.Source))" -ForegroundColor Green
        } else {
            Write-Host "nfpm:    auto-install failed" -ForegroundColor Red
            Write-Host "         Install manually: go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest" -ForegroundColor Yellow
            exit 1
        }
    }
}

# UPX
$UPXAvailable = $false
$UPXPath = Get-Command upx -ErrorAction SilentlyContinue
if ($UPXPath) {
    $UPXAvailable = $true
    Write-Host "UPX:     found ($($UPXPath.Source))" -ForegroundColor Green
} else {
    Write-Host "UPX:     not found (binaries will not be compressed)" -ForegroundColor Yellow
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

# Handle test/coverage/clean first
if ($test) {
    Write-Host "Running tests (excluding sniffer hardware tests -- use -testSniffer for those)..." -ForegroundColor Green
    go test ./... -count=1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Tests failed!" -ForegroundColor Red
        exit 1
    }
    exit 0
}

if ($testSniffer) {
    Write-Host "Running sniffer hardware tests on Windows..." -ForegroundColor Green
    Write-Host ""

    # Check for Npcap
    $npcapPath = "$env:SystemRoot\System32\Npcap\wpcap.dll"
    if (-not (Test-Path $npcapPath)) {
        Write-Host "WARNING: Npcap not found at $npcapPath" -ForegroundColor Red
        Write-Host "  Download and install from: https://npcap.com" -ForegroundColor Yellow
        Write-Host "  Sniffer tests require Npcap to capture packets." -ForegroundColor Yellow
        exit 1
    }
    Write-Host "Npcap found: $npcapPath" -ForegroundColor Green
    Write-Host ""

    # Build the sniffer test binary first (verifies it compiles)
    Write-Host "Building sniffer test binary..." -ForegroundColor Cyan
    go test -c -o "$env:TEMP\spk_sniffer_test.exe" ./internal/sniffer/
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: sniffer test binary failed to compile." -ForegroundColor Red
        exit 1
    }
    Write-Host "Sniffer test binary compiled successfully." -ForegroundColor Green
    Write-Host ""

    # Run the Windows-specific sniffer tests (pcap + WinDivert)
    go test -v -count=1 -timeout 120s ./internal/sniffer/ -run "TestPcap|TestWinDivert|TestSniffer"
    exit 0
}

if ($coverage) {
    Write-Host "Running tests with coverage..." -ForegroundColor Green
    go test ./... -coverprofile=coverage.out
    go tool cover -html=coverage.out -o coverage.html
    Write-Host "Coverage report: coverage.html" -ForegroundColor Green
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

if ($all) {
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
        $ldflags += " -X main.pcapBuild=1"
        Write-Host "  Building $output... (pcap)" -ForegroundColor Green
    } else {
        $env:CGO_ENABLED = "0"
        Remove-Item Env:\CC -ErrorAction SilentlyContinue
        Remove-Item Env:\CGO_CFLAGS -ErrorAction SilentlyContinue
        Remove-Item Env:\CGO_LDFLAGS -ErrorAction SilentlyContinue
        Write-Host "  Building $output..."
    }

    $buildArgs = @("build", "-ldflags", "$ldflags -s -w", "-o", $output, "./cmd/spk/")

    & go @buildArgs
    if ($LASTEXITCODE -ne 0) {
        Write-Host "    FAILED: $output" -ForegroundColor Red
        Remove-Item $output -ErrorAction SilentlyContinue
        return $false
    }

    $origSize = (Get-Item $output).Length
    if ($UPXAvailable) {
        upx --best --lzma -q $output 2>$null
        if ($LASTEXITCODE -eq 0) {
            $newSize = (Get-Item $output).Length
            $ratio = [math]::Round(($newSize / $origSize) * 100, 1)
            Write-Host "    -> $([math]::Round($newSize/1MB, 2)) MB (UPX: $ratio%)" -ForegroundColor Cyan
        } else {
            Write-Host "    -> $([math]::Round($origSize/1MB, 2)) MB (UPX skipped)" -ForegroundColor Yellow
        }
    } else {
        Write-Host "    -> $([math]::Round($origSize/1MB, 2)) MB" -ForegroundColor White
    }
    return $true
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
homepage: https://github.com/pjaol/knock
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
    & nfpm pkg --config $tmpYaml --packager $format --target $pkgFile
    $exitCode = $LASTEXITCODE
    Remove-Item $tmpYaml -ErrorAction SilentlyContinue

    if ($exitCode -ne 0) {
        Write-Host "    FAILED: $pkgFile" -ForegroundColor Red
        return
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
        Build-Target $p $true "" | Out-Null
    } elseif ($nopcap) {
        # -nopcap: build Linux/Darwin without pcap (CGO_ENABLED=0)
        Build-Target $p $false "" | Out-Null
    } elseif ($p.GOOS -eq "darwin") {
        # zig 0.13 Mach-O linker rejects -Wl,-x which Go injects for all CGO darwin builds.
        # Only a native Apple clang can link darwin CGO binaries correctly.
        # Use native gcc/clang only when host IS darwin AND arch matches; no-pcap otherwise.
        if ($isNative -and $gccNative) {
            $pcapOk = Build-Target $p $true "gcc"
            if (-not $pcapOk) {
                Write-Host "ERROR: pcap build failed for $crossKey" -ForegroundColor Red
                exit 1
            }
        } else {
            Write-Host "    (darwin pcap requires native Apple clang for exact host arch; using no-pcap)" -ForegroundColor Yellow
            Build-Target $p $false "" | Out-Null
        }
    } elseif ($ZigAvailable) {
        # Cross-build with zig: CGO for dlfcn.h (linux targets only; darwin handled above)
        $zigTarget = $zigTargetMap[$crossKey]
        if ($zigTarget) {
            $zigCC = "zig cc -target $zigTarget"
            $pcapOk = Build-Target $p $true $zigCC
            if (-not $pcapOk) {
                Write-Host "ERROR: pcap build failed for $crossKey" -ForegroundColor Red
                exit 1
            }
        } else {
            Build-Target $p $false "" | Out-Null
        }
    } elseif ($isNative -and $gccNative) {
        # Native build with gcc/clang
        $pcapOk = Build-Target $p $true "gcc"
        if (-not $pcapOk) {
            Write-Host "ERROR: pcap build failed for $crossKey" -ForegroundColor Red
            exit 1
        }
    } else {
        # No C compiler available
        if (-not $isNative) {
            Write-Host "    (cross build without zig -- no pcap)" -ForegroundColor Yellow
        } else {
            Write-Host "    (no C compiler found -- no pcap)" -ForegroundColor Yellow
        }
        Build-Target $p $false "" | Out-Null
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
Remove-Item Env:\GOOS -ErrorAction SilentlyContinue
Remove-Item Env:\GOARCH -ErrorAction SilentlyContinue
Remove-Item Env:\CGO_ENABLED -ErrorAction SilentlyContinue
Remove-Item Env:\CC -ErrorAction SilentlyContinue
Remove-Item Env:\CGO_CFLAGS -ErrorAction SilentlyContinue
Remove-Item Env:\CGO_LDFLAGS -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "Build complete. Output in $BuildDir/" -ForegroundColor Green
Get-ChildItem $BuildDir -Recurse -File | ForEach-Object {
    Write-Host "  $($_.FullName.Replace((Get-Location).Path + '\', ''))"
}
