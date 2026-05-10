<#
.SYNOPSIS
    P2P Mesh Network — One-Click Build & Package (Windows)
.DESCRIPTION
    Builds all 3 Windows binaries (mesh-tunnel, mesh-relay, mesh-stun),
    copies to an output directory, and creates config templates.
    mesh-overlay is Linux/macOS only (requires TUN device).

.PREREQUISITES
    1. Rust installed (https://rustup.rs) — stable toolchain 1.80+
    2. Visual Studio 2022 Build Tools with "Desktop development with C++" workload
    3. Run from "Developer Command Prompt for VS 2022" OR after:
       & "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.ps1"

.EXAMPLE
    .\scripts\build-all.ps1
    .\scripts\build-all.ps1 -OutputDir "C:\p2p-mesh-release"
#>

param(
    [string]$OutputDir = "",
    [switch]$SkipBuild = $false
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
$Binaries = @("mesh-tunnel", "mesh-relay", "mesh-stun")

# ============ Banner ============
Write-Host "╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║       P2P Mesh Network — Windows Build & Package v2.0.0          ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# ============ Output directory ============
if (-not $OutputDir) {
    $OutputDir = Join-Path $ProjectRoot "release"
}
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
New-Item -ItemType Directory -Force -Path "$OutputDir\configs" | Out-Null
Write-Host "[i] Output directory: $OutputDir" -ForegroundColor Cyan

# ============ Check Rust ============
Write-Host "[i] Checking Rust toolchain..." -ForegroundColor Cyan
$cargoVersion = (cargo --version 2>$null)
if (-not $cargoVersion) {
    Write-Host "[X] Cargo not found. Install Rust from https://rustup.rs" -ForegroundColor Red
    exit 1
}
Write-Host "[OK] $cargoVersion" -ForegroundColor Green

# ============ Build ============
if (-not $SkipBuild) {
    Set-Location $ProjectRoot

    foreach ($bin in $Binaries) {
        Write-Host ""
        Write-Host "══════════════════════════════════════════════════════════════════" -ForegroundColor Yellow
        Write-Host "[i] Building $bin..." -ForegroundColor Yellow
        Write-Host "══════════════════════════════════════════════════════════════════" -ForegroundColor Yellow

        $result = (cargo build --release --bin $bin 2>&1)
        if ($LASTEXITCODE -ne 0) {
            Write-Host "[X] $bin build FAILED!" -ForegroundColor Red
            $result | Out-String | Write-Host -ForegroundColor Red
            exit 1
        }
        Write-Host "[OK] $bin built successfully" -ForegroundColor Green
    }
}

# ============ Copy binaries ============
Write-Host ""
Write-Host "[i] Copying binaries to $OutputDir..." -ForegroundColor Cyan

$binDir = "$ProjectRoot\target\release"
foreach ($bin in $Binaries) {
    $src = Join-Path $binDir "$bin.exe"
    $dst = Join-Path $OutputDir "$bin.exe"
    if (Test-Path $src) {
        Copy-Item $src -Destination $dst -Force
        $size = "{0:N1} MB" -f ((Get-Item $dst).Length / 1MB)
        Write-Host "[OK] $bin.exe — $size" -ForegroundColor Green
    } else {
        Write-Host "[X] $bin.exe not found at $src" -ForegroundColor Red
    }
}

# ============ Create config templates ============
Write-Host ""
Write-Host "[i] Creating config templates..." -ForegroundColor Cyan

# mesh-tunnel client config
@"
# P2P Mesh Network — mesh-tunnel Client Configuration
# Copy to: %APPDATA%\p2p-mesh\client.toml

[client]
mode = "tunnel"
listen_port = 51820

[server]
api_url = "https://your-mesh-server.example.com"
auth_token = "YOUR_JWT_TOKEN_HERE"
ws_url = "wss://your-mesh-server.example.com/api/v1/ws"

[stun]
server = "stun.your-mesh-server.example.com:3478"

[logging]
level = "info"

[advanced]
max_connections = 100
heartbeat_interval = 30
health_check_interval = 10
quic_idle_timeout = 30
ai_routing_enabled = false
"@ | Out-File -FilePath "$OutputDir\configs\client.toml" -Encoding utf8

# mesh-relay server config
@"
# P2P Mesh Network — mesh-relay Configuration
# Copy to: /etc/p2p-mesh/relay.toml (Linux) or %ProgramData%\p2p-mesh\relay.toml (Windows)

[relay]
node_id = "relay-us-east-1"
port = 51821
region = "us-east"
max_connections = 1000
bandwidth_mbps = 1000

[server]
api_url = "https://your-mesh-server.example.com"
# Set RELAY_AUTH_TOKEN env var (never in config file)

[heartbeat]
interval_seconds = 30

[logging]
level = "info"
"@ | Out-File -FilePath "$OutputDir\configs\relay.toml" -Encoding utf8

# mesh-stun server config
@"
# P2P Mesh Network — mesh-stun Configuration
# Copy to: /etc/p2p-mesh/stun.toml (Linux) or %ProgramData%\p2p-mesh\stun.toml (Windows)

[stun]
bind = "0.0.0.0"
port = 3478

[logging]
level = "info"
"@ | Out-File -FilePath "$OutputDir\configs\stun.toml" -Encoding utf8

# Environment variables template
@"
# P2P Mesh Network — Environment Variables
# Copy to: system environment or .env file

# Client auth token (JWT)
MESH_TOKEN=your_jwt_token_here

# Relay auth token
RELAY_AUTH_TOKEN=your_relay_auth_token_here

# API server URL
API_URL=https://your-mesh-server.example.com

# Relay node ID
RELAY_ID=relay-us-east-1

# Region
REGION=us-east

# STUN port
RELAY_PORT=51821

# Max connections
RELAY_MAX_CONNECTIONS=1000

# Bandwidth capacity (Mbps)
RELAY_BANDWIDTH_MBPS=1000

# Heartbeat interval (seconds)
HEARTBEAT_INTERVAL=30

# Hole punching HMAC key (64 hex chars)
# Generate: openssl rand -hex 32
PUNCH_HMAC_KEY=
"@ | Out-File -FilePath "$OutputDir\configs\.env.example" -Encoding utf8

Write-Host "[OK] Config templates created" -ForegroundColor Green

# ============ Summary ============
Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║  Build & Package Complete!                                       ║" -ForegroundColor Green
Write-Host "╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "Binaries ($OutputDir):" -ForegroundColor White
Get-ChildItem "$OutputDir\*.exe" | ForEach-Object {
    $size = "{0:N1} MB" -f ($_.Length / 1MB)
    Write-Host "  $($_.Name) — $size" -ForegroundColor Cyan
}
Write-Host ""
Write-Host "Configs ($OutputDir\configs):" -ForegroundColor White
Get-ChildItem "$OutputDir\configs\*" | ForEach-Object {
    Write-Host "  $($_.Name)" -ForegroundColor Cyan
}
Write-Host ""
Write-Host "Next steps:" -ForegroundColor White
Write-Host "  1. Edit configs in $OutputDir\configs\" -ForegroundColor Cyan
Write-Host "  2. Set environment variables from configs\.env.example" -ForegroundColor Cyan
Write-Host "  3. Install service (as Admin):" -ForegroundColor Cyan
Write-Host "     sc.exe create P2PMeshTunnel binPath= `"$OutputDir\mesh-tunnel.exe`" start= auto" -ForegroundColor Cyan
Write-Host "     sc.exe create P2PMeshRelay binPath= `"$OutputDir\mesh-relay.exe`" start= auto" -ForegroundColor Cyan
Write-Host "     sc.exe create P2PMeshStun binPath= `"$OutputDir\mesh-stun.exe`" start= auto" -ForegroundColor Cyan
Write-Host ""

exit 0
