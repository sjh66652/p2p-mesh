# ╔══════════════════════════════════════════════════════════════════╗
# ║       P2P Mesh Network - Client One-Click Deploy (Windows)       ║
# ║       PowerShell Script                                          ║
# ╚══════════════════════════════════════════════════════════════════╝
#
# Usage (Run as Administrator in PowerShell):
#   .\scripts\deploy-client.ps1
#   .\scripts\deploy-client.ps1 -Server "https://mesh.yourdomain.com" -Token "<auth_token>"
#   .\scripts\deploy-client.ps1 -Uninstall
#
# Requirements:
#   - Windows 10 (1809+) or Windows Server 2019+
#   - PowerShell 5.1+ (run as Administrator)
#   - Visual Studio Build Tools or LLVM/Clang

param(
    [string]$Server = "",
    [string]$Token = "",
    [string]$Mode = "tunnel",
    [switch]$Uninstall = $false,
    [switch]$Help = $false
)

# Functions
function Write-Banner {
    Write-Host "==============================================================" -ForegroundColor Cyan
    Write-Host "  P2P Mesh Network - Client Deployment (Windows) v2.0.0" -ForegroundColor Cyan
    Write-Host "==============================================================" -ForegroundColor Cyan
}

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $color = switch ($Level) {
        "SUCCESS" { "Green" }
        "WARN"    { "Yellow" }
        "ERROR"   { "Red" }
        "INFO"    { "Cyan" }
        default   { "White" }
    }
    $prefix = switch ($Level) {
        "SUCCESS" { "[OK]" }
        "WARN"    { "[!]" }
        "ERROR"   { "[X]" }
        "INFO"    { "[i]" }
        default   { "   " }
    }
    Write-Host "$prefix $Message" -ForegroundColor $color
    $logLine = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $Level $Message"
    Add-Content -Path "$env:TEMP\p2p-mesh-client-deploy.log" -Value $logLine
}

# System check
function Test-System {
    Write-Log "Checking system environment..." "INFO"
    $os = Get-CimInstance Win32_OperatingSystem
    Write-Log "OS: $($os.Caption) ($($os.Version))" "INFO"
    Write-Log "CPU: $env:PROCESSOR_ARCHITECTURE" "INFO"
    $memGB = [math]::Round($os.TotalVisibleMemorySize / 1MB, 1)
    Write-Log "Memory: $memGB GB" "INFO"

    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Log "Recommend running as Administrator (some features need elevated privileges)" "WARN"
    }
    Write-Log "System check complete" "SUCCESS"
}

# Install Rust
function Install-Rust {
    Write-Log "Checking Rust toolchain..." "INFO"

    $rustInstalled = Get-Command rustc -ErrorAction SilentlyContinue
    if ($rustInstalled) {
        $version = & rustc --version 2>$null
        Write-Log "Rust already installed: $version" "SUCCESS"
    }
    else {
        Write-Log "Installing Rust toolchain..." "INFO"
        Write-Log "Downloading rustup-init.exe..." "INFO"

        $rustupUrl = "https://static.rust-lang.org/rustup/dist/x86_64-pc-windows-msvc/rustup-init.exe"
        $rustupPath = Join-Path $env:TEMP "rustup-init.exe"

        try {
            Invoke-WebRequest -Uri $rustupUrl -OutFile $rustupPath -UseBasicParsing
            Write-Log "Running rustup installer (this may take a few minutes)..." "INFO"
            & $rustupPath -y --default-toolchain stable 2>&1 | Out-Null
            Remove-Item $rustupPath -Force -ErrorAction SilentlyContinue

            # Refresh PATH
            $cargoBin = Join-Path $env:USERPROFILE ".cargo\bin"
            $env:PATH = "$cargoBin;$env:PATH"
            Write-Log "Rust installation complete" "SUCCESS"
        }
        catch {
            Write-Log "Rust installation failed: $_" "ERROR"
            Write-Log "Please install manually: https://rustup.rs" "INFO"
            exit 1
        }
    }

    # Verify Cargo
    $cargoPath = Join-Path $env:USERPROFILE ".cargo\bin\cargo.exe"
    if (-not (Test-Path $cargoPath)) {
        Write-Log "Cargo not found. Ensure Rust is installed correctly." "ERROR"
        exit 1
    }
}

# Check build tools
function Test-BuildTools {
    Write-Log "Checking C++ build tools..." "INFO"

    # Check Visual Studio Build Tools
    $vsWhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vsWhere) {
        $vsPath = & $vsWhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2>$null
        if ($vsPath) {
            Write-Log "Visual Studio Build Tools found: $vsPath" "SUCCESS"
            return
        }
    }

    # Check Clang/LLVM
    $clangPath = Get-Command clang -ErrorAction SilentlyContinue
    if ($clangPath) {
        Write-Log "Clang/LLVM found" "SUCCESS"
        return
    }

    Write-Log "C++ build tools not found." "WARN"
    Write-Log "Rust on Windows requires Visual C++ Build Tools or LLVM/Clang." "INFO"
    Write-Log "Install options:" "INFO"
    Write-Log "  1. winget install Microsoft.VisualStudio.2022.BuildTools --silent" "INFO"
    Write-Log "  2. https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2022" "INFO"
    Write-Log "  Select 'Desktop development with C++' workload" "INFO"
    Write-Log "Re-run this script after installation." "INFO"
    exit 1
}

# Build client binary
function Build-Client {
    Write-Log "Building mesh-tunnel client..." "INFO"

    $projectDir = Split-Path -Parent $PSScriptRoot
    $dataPlaneDir = Join-Path $projectDir "data-plane"

    if (-not (Test-Path (Join-Path $dataPlaneDir "Cargo.toml"))) {
        Write-Log "Cargo.toml not found: $dataPlaneDir" "ERROR"
        exit 1
    }

    Push-Location $dataPlaneDir
    try {
        $buildResult = & cargo build --release --bin mesh-tunnel 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Log "Build failed:" "ERROR"
            Write-Host $buildResult
            exit 1
        }
    }
    finally {
        Pop-Location
    }

    $binaryPath = Join-Path $dataPlaneDir "target\release\mesh-tunnel.exe"
    if (Test-Path $binaryPath) {
        $size = "{0:N1} MB" -f ((Get-Item $binaryPath).Length / 1MB)
        Write-Log "Build successful! Binary size: $size" "SUCCESS"
    }
    else {
        Write-Log "Build failed: mesh-tunnel.exe not found" "ERROR"
        exit 1
    }
}

# Install binary
function Install-Binary {
    Write-Log "Installing mesh-tunnel..." "INFO"

    $installDir = Join-Path $env:ProgramFiles "P2P-Mesh-Client"
    $projectDir = Split-Path -Parent $PSScriptRoot
    $binaryPath = Join-Path $projectDir "data-plane\target\release\mesh-tunnel.exe"

    New-Item -ItemType Directory -Force -Path "$installDir\bin" | Out-Null
    New-Item -ItemType Directory -Force -Path "$installDir\config" | Out-Null
    New-Item -ItemType Directory -Force -Path "$installDir\logs" | Out-Null

    Copy-Item $binaryPath -Destination "$installDir\bin\mesh-tunnel.exe" -Force

    # Add to system PATH
    $currentPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
    $binPath = Join-Path $installDir "bin"
    if ($currentPath -notlike "*$binPath*") {
        [Environment]::SetEnvironmentVariable("PATH", "$currentPath;$binPath", "Machine")
        Write-Log "Added to system PATH" "SUCCESS"
    }

    Write-Log "Installation complete: $installDir" "SUCCESS"
}

# Interactive configuration
function Set-ClientConfig {
    Write-Log "Configuring client..." "INFO"

    $configDir = Join-Path $env:APPDATA "p2p-mesh"
    $configFile = Join-Path $configDir "client.toml"
    New-Item -ItemType Directory -Force -Path $configDir | Out-Null

    if (Test-Path $configFile) {
        Write-Log "Config file exists: $configFile" "WARN"
        $overwrite = Read-Host "  Overwrite? [y/N]"
        if ($overwrite -notmatch '^[Yy]$') {
            Write-Log "Keeping existing config" "INFO"
            return
        }
    }

    # API server
    $apiServer = $Server
    if (-not $apiServer) {
        $apiServer = Read-Host "  API server URL (e.g. https://mesh.yourdomain.com)"
        if (-not $apiServer) { $apiServer = "http://localhost:8000" }
    }

    # Auth token
    $authToken = $Token
    if (-not $authToken) {
        $authToken = Read-Host "  Auth token (leave blank to configure later)"
    }

    # Listen port
    $listenPort = Read-Host "  Local listen port [51820]"
    if (-not $listenPort) { $listenPort = "51820" }

    # Log level
    $logLevel = Read-Host "  Log level (trace/debug/info/warn/error) [info]"
    if (-not $logLevel) { $logLevel = "info" }

    # Write config
    $content = @"
# P2P Mesh Network - Client Configuration (Windows)
# Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

[client]
mode = "tunnel"
listen_port = $listenPort

[server]
api_url = "$apiServer"
auth_token = "$authToken"

[logging]
level = "$logLevel"

[advanced]
max_connections = 100
heartbeat_interval = 30
health_check_interval = 10
quic_idle_timeout = 30
ai_routing_enabled = false
"@

    $content | Out-File -FilePath $configFile -Encoding utf8
    Write-Log "Config saved: $configFile" "SUCCESS"

    $tokenDisplay = if ($authToken -and $authToken.Length -gt 0) { "$($authToken.Substring(0, [Math]::Min(8, $authToken.Length)))..." } else { "not set" }
    Write-Host ""
    Write-Host "Configuration summary:" -ForegroundColor White
    Write-Host "  Server:       $apiServer" -ForegroundColor Cyan
    Write-Host "  Listen port:  $listenPort" -ForegroundColor Cyan
    Write-Host "  Token:        $tokenDisplay" -ForegroundColor Cyan
    Write-Host ""
}

# Install Windows Service
function Install-WindowsService {
    Write-Log "Installing Windows service..." "INFO"

    $installDir = Join-Path $env:ProgramFiles "P2P-Mesh-Client"
    $configDir = Join-Path $env:APPDATA "p2p-mesh"
    $serviceName = "P2PMeshTunnel"

    # Remove existing
    $existingService = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($existingService) {
        Write-Log "Service exists, stopping and removing..." "WARN"
        Stop-Service $serviceName -Force -ErrorAction SilentlyContinue
        sc.exe delete $serviceName 2>&1 | Out-Null
        Start-Sleep -Seconds 2
    }

    $binaryPath = Join-Path $installDir "bin\mesh-tunnel.exe"
    $configPath = Join-Path $configDir "client.toml"

    # sc.exe requires binPath= format with space after =
    $binArg = "`"$binaryPath`" --config `"$configPath`""

    $result = sc.exe create $serviceName binPath= $binArg start= auto DisplayName= "P2P Mesh Tunnel Client" obj= LocalSystem 2>&1

    if ($LASTEXITCODE -eq 0) {
        sc.exe failure $serviceName reset= 86400 actions= restart/5000/restart/10000/restart/30000 2>&1 | Out-Null
        sc.exe description $serviceName "P2P Mesh Network - Mesh Tunnel Client Service" 2>&1 | Out-Null

        Start-Service $serviceName -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 3

        $svc = Get-Service $serviceName -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq 'Running') {
            Write-Log "Windows service installed and running" "SUCCESS"
        }
        else {
            Write-Log "Service installed but may not be running. Check logs." "WARN"
            $logHint = "Get-EventLog -LogName Application -Source P2PMeshTunnel"
            Write-Log "  View logs: $logHint" "INFO"
        }
    }
    else {
        Write-Log "Failed to create Windows service: $result" "ERROR"
        Write-Log "You can also run manually:" "INFO"
        Write-Log "  $binaryPath --config $configPath" "INFO"
    }
}

# Create desktop shortcut
function New-DesktopShortcut {
    Write-Log "Creating desktop shortcut..." "INFO"

    $installDir = Join-Path $env:ProgramFiles "P2P-Mesh-Client"
    $desktopPath = [Environment]::GetFolderPath("Desktop")

    # Create launcher batch file
    $batPath = Join-Path $installDir "bin\start-tunnel.bat"
    $batContent = "@echo off`r`necho Starting P2P Mesh Tunnel Client...`r`n`"$installDir\bin\mesh-tunnel.exe`" --config `"%APPDATA%\p2p-mesh\client.toml`"`r`npause`r`n"
    $batContent | Out-File -FilePath $batPath -Encoding ASCII

    # Create shortcut
    $WshShell = New-Object -ComObject WScript.Shell
    $shortcutPath = Join-Path $desktopPath "P2P Mesh Tunnel.lnk"
    $Shortcut = $WshShell.CreateShortcut($shortcutPath)
    $Shortcut.TargetPath = $batPath
    $Shortcut.WorkingDirectory = $installDir
    $Shortcut.Description = "Start P2P Mesh Tunnel Client"
    $Shortcut.Save()

    Write-Log "Desktop shortcut created" "SUCCESS"
}

# Connection test
function Test-Connection {
    Write-Log "Testing connectivity..." "INFO"

    $apiUrl = if ($Server) { $Server } else { "http://localhost:8000" }

    try {
        $response = Invoke-WebRequest -Uri "$apiUrl/health" -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
        Write-Log "API reachable: $apiUrl (status: $($response.StatusCode))" "SUCCESS"
    }
    catch {
        Write-Log "API not reachable: $apiUrl" "WARN"
        Write-Log "Please check firewall and network settings" "INFO"
    }
}

# Uninstall
function Uninstall-Client {
    Write-Host "=== P2P Mesh Client Uninstall ===" -ForegroundColor Yellow
    Write-Host ""

    $installDir = Join-Path $env:ProgramFiles "P2P-Mesh-Client"
    $configDir = Join-Path $env:APPDATA "p2p-mesh"
    $serviceName = "P2PMeshTunnel"

    # Stop and delete service
    $existingService = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($existingService) {
        Stop-Service $serviceName -Force -ErrorAction SilentlyContinue
        sc.exe delete $serviceName 2>&1 | Out-Null
        Write-Log "Windows service removed" "SUCCESS"
    }

    # Remove install dir
    if (Test-Path $installDir) {
        Remove-Item $installDir -Recurse -Force -ErrorAction SilentlyContinue
        Write-Log "Install directory removed: $installDir" "SUCCESS"
    }

    # Keep config unless user says otherwise
    if (Test-Path $configDir) {
        Write-Log "Config preserved at: $configDir" "WARN"
        $deleteConfig = Read-Host "  Delete config files? [y/N]"
        if ($deleteConfig -match '^[Yy]$') {
            Remove-Item $configDir -Recurse -Force
            Write-Log "Config files deleted" "SUCCESS"
        }
    }

    # Remove desktop shortcut
    $desktopPath = [Environment]::GetFolderPath("Desktop")
    $shortcutPath = Join-Path $desktopPath "P2P Mesh Tunnel.lnk"
    if (Test-Path $shortcutPath) {
        Remove-Item $shortcutPath -Force
        Write-Log "Desktop shortcut removed" "SUCCESS"
    }

    Write-Host ""
    Write-Log "Uninstall complete" "SUCCESS"
    exit 0
}

# Help
function Show-Help {
    Write-Host @"
P2P Mesh Network - Windows Client Deployment Script

Usage:
  .\scripts\deploy-client.ps1 [options]

Options:
  -Server <URL>     API server URL
  -Token <TOKEN>    Auth token
  -Uninstall        Uninstall the client
  -Help             Show this help

Examples:
  .\scripts\deploy-client.ps1 -Server "https://mesh.example.com" -Token "eyJ..."
  .\scripts\deploy-client.ps1 -Uninstall
"@
    exit 0
}

# Main
function Main {
    if ($Help) { Show-Help }
    if ($Uninstall) { Uninstall-Client }

    $logFile = Join-Path $env:TEMP "p2p-mesh-client-deploy.log"
    "=== P2P Mesh Client Deployment (Windows) - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ===" | Out-File $logFile

    Write-Banner

    Test-System
    Install-Rust
    Test-BuildTools
    Build-Client
    Install-Binary
    Set-ClientConfig
    Install-WindowsService
    New-DesktopShortcut
    Test-Connection

    Write-Host ""
    Write-Host "==============================================================" -ForegroundColor Green
    Write-Host "  Client deployment complete!" -ForegroundColor Green
    Write-Host "==============================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Quick commands:" -ForegroundColor White
    Write-Host "  Status:    Get-Service P2PMeshTunnel" -ForegroundColor Cyan
    Write-Host "  Logs:      Get-EventLog -LogName Application -Source P2PMeshTunnel -Newest 50" -ForegroundColor Cyan
    Write-Host "  Start:     Start-Service P2PMeshTunnel" -ForegroundColor Cyan
    Write-Host "  Stop:      Stop-Service P2PMeshTunnel" -ForegroundColor Cyan
    Write-Host "  Config:    notepad `"$configDir\client.toml`"" -ForegroundColor Cyan
    Write-Host "  Uninstall: .\scripts\deploy-client.ps1 -Uninstall" -ForegroundColor Cyan
    Write-Host ""
}

# Execute
Main
