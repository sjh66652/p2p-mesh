<#
.SYNOPSIS
    P2P Mesh Network — Windows Native Build Script (PowerShell)
.DESCRIPTION
    Builds Windows native executables for mesh-tunnel, mesh-relay, and mesh-stun
    from within a Windows Rust environment.

.PREREQUISITES
    1. Rust installed (https://rustup.rs) — stable toolchain
    2. Visual Studio 2022 Build Tools or VS 2022 with "Desktop development
       with C++" workload (for MSVC linker)
    3. Run from "Developer Command Prompt for VS 2022" OR from any terminal
       after running: & "C:\Program Files\Microsoft Visual
       Studio\2022\Community\VC\Auxiliary\Build\vcvars64.ps1"

.PARAMETER Release
    Build in release mode (default: $true)

.PARAMETER Debug
    Build in debug mode (overrides -Release)

.EXAMPLE
    .\scripts\build-windows.ps1 -Release
    .\scripts\build-windows.ps1 -Debug
#>

param(
    [switch]$Release = $true,
    [switch]$Debug
)

# If -Debug is specified, override to debug
if ($Debug) { $Release = $false }

$Profile = if ($Release) { "release" } else { "debug" }
$ProjectRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
Set-Location $ProjectRoot

Write-Host "[P2P Mesh] Windows Native Build" -ForegroundColor Cyan
Write-Host "[P2P Mesh] Profile: $Profile" -ForegroundColor Cyan
Write-Host "[P2P Mesh] Project: $ProjectRoot" -ForegroundColor Cyan

# Build mesh-tunnel
Write-Host "[P2P Mesh] Building mesh-tunnel..." -ForegroundColor Yellow
$result = (cargo build --$Profile --bin mesh-tunnel 2>&1)
if ($LASTEXITCODE -ne 0) {
    Write-Host "[ERROR] mesh-tunnel build failed!" -ForegroundColor Red
    $result | Out-String | Write-Host
    exit 1
}

# Build mesh-relay
Write-Host "[P2P Mesh] Building mesh-relay..." -ForegroundColor Yellow
$result = (cargo build --$Profile --bin mesh-relay 2>&1)
if ($LASTEXITCODE -ne 0) {
    Write-Host "[ERROR] mesh-relay build failed!" -ForegroundColor Red
    $result | Out-String | Write-Host
    exit 1
}

# Build mesh-stun
Write-Host "[P2P Mesh] Building mesh-stun..." -ForegroundColor Yellow
$result = (cargo build --$Profile --bin mesh-stun 2>&1)
if ($LASTEXITCODE -ne 0) {
    Write-Host "[ERROR] mesh-stun build failed!" -ForegroundColor Red
    $result | Out-String | Write-Host
    exit 1
}

# Report
Write-Host "`n[P2P Mesh] All binaries built successfully!" -ForegroundColor Green
Write-Host "[P2P Mesh] Output: $ProjectRoot\target\$Profile\" -ForegroundColor Green
Get-ChildItem "$ProjectRoot\target\$Profile\mesh-*.exe" -ErrorAction SilentlyContinue |
    ForEach-Object { Write-Host "  $($_.Name) — $([math]::Round($_.Length/1KB, 1)) KB" }

Write-Host "`n[P2P Mesh] Done!" -ForegroundColor Cyan
exit 0
