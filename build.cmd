@echo off
REM Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
REM SPDX-License-Identifier: MIT
REM SPK build script for Windows CMD
REM This is a convenience wrapper that launches build.ps1 with PowerShell.
REM All arguments are forwarded.
REM
REM Examples:
REM   build.cmd                    Build windows/amd64 + linux/amd64
REM   build.cmd -all               Build all platform/arch combos
REM   build.cmd -nopcap            Build without pcap sniffer (CGO_ENABLED=0)
REM   build.cmd -test              Run unit tests + fuzz seed corpus
REM   build.cmd -testall           Run all tests: smoke, unit, fuzz, integration, sniffer
REM   build.cmd -testSniffer       Run sniffer hardware tests (requires Npcap)
REM   build.cmd -testsmoke         Run end-to-end smoke tests
REM   build.cmd -clean             Clean build artifacts
REM   build.cmd -windows -arm64    Build Windows amd64 + arm64
REM
REM Binaries: spk_<VER>[p]-<OS>-<ARCH>[.exe]  (p = pcap)

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0build.ps1" %*
