@echo off
REM ============================================================================
REM P2P Mesh Network — Windows Native Build Script
REM ============================================================================
REM
REM Builds Windows native executables (mesh-tunnel.exe, mesh-relay.exe,
REM mesh-stun.exe) from within a Windows Rust environment.
REM
REM Prerequisites:
REM   1. Rust installed (https://rustup.rs) — stable toolchain
REM   2. Visual Studio 2022 Build Tools or VS 2022 with "Desktop development
REM      with C++" workload (for MSVC linker)
REM   3. Run from "Developer Command Prompt for VS 2022" OR from any terminal
REM      after running: call "C:\Program Files\Microsoft Visual
REM      Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
REM
REM Usage:
REM   scripts\build-windows.bat [--release|--debug]
REM
REM Output:
REM   target\[debug|release]\mesh-tunnel.exe
REM   target\[debug|release]\mesh-relay.exe
REM   target\[debug|release]\mesh-stun.exe
REM ============================================================================

setlocal enabledelayedexpansion

set SCRIPT_DIR=%~dp0
set PROJECT_DIR=%SCRIPT_DIR%..
cd /d "%PROJECT_DIR%"

REM Default to release
set PROFILE=release
if /I "%1"=="--debug" set PROFILE=debug
if /I "%1"=="-d" set PROFILE=debug

echo [P2P Mesh] Windows Native Build
echo [P2P Mesh] Profile: %PROFILE%
echo [P2P Mesh] Project: %CD%

REM Set RUSTFLAGS for Windows-specific optimizations (optional)
set RUSTFLAGS=

REM Build the three Windows-compatible binaries
REM mesh-overlay requires TUN device (Linux/macOS only) and is excluded.
echo.
echo [P2P Mesh] Building mesh-tunnel...
cargo build --%PROFILE% --bin mesh-tunnel
if %ERRORLEVEL% neq 0 (
    echo [ERROR] mesh-tunnel build failed!
    exit /b 1
)

echo.
echo [P2P Mesh] Building mesh-relay...
cargo build --%PROFILE% --bin mesh-relay
if %ERRORLEVEL% neq 0 (
    echo [ERROR] mesh-relay build failed!
    exit /b 1
)

echo.
echo [P2P Mesh] Building mesh-stun...
cargo build --%PROFILE% --bin mesh-stun
if %ERRORLEVEL% neq 0 (
    echo [ERROR] mesh-stun build failed!
    exit /b 1
)

echo.
echo [P2P Mesh] All binaries built successfully!
echo.
echo Built files:
dir /b target\%PROFILE%\mesh-tunnel.exe target\%PROFILE%\mesh-relay.exe target\%PROFILE%\mesh-stun.exe 2>nul

echo.
echo [P2P Mesh] Done!
exit /b 0
