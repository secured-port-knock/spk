@echo off
REM Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
REM SPDX-License-Identifier: MIT
REM SPK build script for Windows CMD.
REM Forwards all arguments to build.ps1 - see "Build Scripts" in
REM docs/compilation.md for usage and flags.
REM
REM Binaries: spk_<VER>[p]-<OS>-<ARCH>[.exe]  (p = pcap)

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0build.ps1" %*
