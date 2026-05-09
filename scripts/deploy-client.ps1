# ╔══════════════════════════════════════════════════════════════════╗
# ║       P2P Mesh Network — 客户端一键部署脚本 (Windows)           ║
# ║       Client One-Click Deployment Script (PowerShell)           ║
# ╚══════════════════════════════════════════════════════════════════╝
#
# 功能:
#   1. 检测系统环境 (Windows 10+/Server 2019+)
#   2. 安装 Rust 工具链 (如未安装)
#   3. 编译 mesh-tunnel 客户端
#   4. 交互式配置客户端
#   5. 安装为 Windows 服务 (开机自启)
#
# 用法 (以管理员身份运行 PowerShell):
#   .\scripts\deploy-client.ps1
#   .\scripts\deploy-client.ps1 -Server "https://mesh.yourdomain.com" -Token "<auth_token>"
#   .\scripts\deploy-client.ps1 -Uninstall
#
# 要求:
#   - Windows 10 (1809+) 或 Windows Server 2019+
#   - PowerShell 5.1+ (以管理员身份运行)
#   - Visual Studio Build Tools (或单独安装)

param(
    [string]$Server = "",
    [string]$Token = "",
    [string]$Mode = "tunnel",
    [switch]$Uninstall = $false,
    [switch]$Help = $false
)

# ─── 函数定义 ────────────────────────────────────────────────────

function Write-Banner {
    Write-Host @"
    ╔══════════════════════════════════════════════════════════════╗
    ║     P2P Mesh Network — 客户端部署 (Windows)                 ║
    ║     Client Deployment v2.0.0                                ║
    ╚══════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan
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
        "SUCCESS" { "[✓]" }
        "WARN"    { "[!]" }
        "ERROR"   { "[✗]" }
        "INFO"    { "[i]" }
        default   { "   " }
    }
    Write-Host "$prefix $Message" -ForegroundColor $color
    Add-Content -Path "$env:TEMP\p2p-mesh-client-deploy.log" -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $Level $Message"
}

# ─── 检测系统 ────────────────────────────────────────────────────
function Test-System {
    Write-Log "检测系统环境..." "INFO"

    $os = Get-CimInstance Win32_OperatingSystem
    Write-Log "操作系统: $($os.Caption) ($($os.Version))" "INFO"
    Write-Log "CPU 架构: $env:PROCESSOR_ARCHITECTURE" "INFO"
    Write-Log "内存: $([math]::Round($os.TotalVisibleMemorySize / 1MB, 1)) GB" "INFO"

    # 检查是否管理员权限
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Log "建议以管理员身份运行此脚本 (部分功能需要管理员权限)" "WARN"
    }

    Write-Log "系统检测完成" "SUCCESS"
}

# ─── 安装 Rust ────────────────────────────────────────────────────
function Install-Rust {
    Write-Log "检查 Rust 工具链..." "INFO"

    $rustInstalled = $null
    try {
        $rustInstalled = Get-Command rustc -ErrorAction SilentlyContinue
    }
    catch { }

    if ($rustInstalled) {
        $version = & rustc --version 2>$null
        Write-Log "Rust 已安装: $version" "SUCCESS"
    }
    else {
        Write-Log "正在安装 Rust 工具链..." "INFO"
        Write-Log "下载 rustup-init.exe..." "INFO"

        $rustupUrl = "https://static.rust-lang.org/rustup/dist/x86_64-pc-windows-msvc/rustup-init.exe"
        $rustupPath = "$env:TEMP\rustup-init.exe"

        try {
            Invoke-WebRequest -Uri $rustupUrl -OutFile $rustupPath -UseBasicParsing
            Write-Log "正在安装 Rust (这可能需要几分钟)..." "INFO"
            & $rustupPath -y --default-toolchain stable 2>&1 | Out-Null
            Remove-Item $rustupPath -Force -ErrorAction SilentlyContinue

            # 刷新环境变量
            $env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"
            Write-Log "Rust 安装完成" "SUCCESS"
        }
        catch {
            Write-Log "Rust 安装失败: $_" "ERROR"
            Write-Log "请手动安装: https://rustup.rs" "INFO"
            exit 1
        }
    }

    # 确保 Rust 在 PATH 中
    $cargoPath = "$env:USERPROFILE\.cargo\bin\cargo.exe"
    if (-not (Test-Path $cargoPath)) {
        Write-Log "找不到 Cargo，请确保 Rust 已正确安装" "ERROR"
        exit 1
    }
}

# ─── 检查构建工具 ────────────────────────────────────────────────
function Test-BuildTools {
    Write-Log "检查 C++ 构建工具..." "INFO"

    # 检查 Visual Studio Build Tools
    $vsWhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vsWhere) {
        $vsPath = & $vsWhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2>$null
        if ($vsPath) {
            Write-Log "Visual Studio Build Tools 已安装: $vsPath" "SUCCESS"
            return
        }
    }

    # 检查 winget 方式安装
    $clangPath = Get-Command clang -ErrorAction SilentlyContinue
    if ($clangPath) {
        Write-Log "Clang/LLVM 已安裝" "SUCCESS"
        return
    }

    Write-Log "未找到 C++ 构建工具。" "WARN"
    Write-Log "Rust 在 Windows 上编译需要 Microsoft Visual C++ Build Tools 或 LLVM/Clang。" "INFO"
    Write-Log "推荐安装方式:" "INFO"
    Write-Log "  1. 运行: winget install Microsoft.VisualStudio.2022.BuildTools --silent --override '--wait --add Microsoft.VisualStudio.Workload.VCTools'" "INFO"
    Write-Log "  2. 或访问: https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2022" "INFO"
    Write-Log "  选择 'C++ 生成工具' 工作负载" "INFO"
    Write-Log "安装完成后重新运行此脚本。" "INFO"
    exit 1
}

# ─── 编译客户端 ──────────────────────────────────────────────────
function Build-Client {
    Write-Log "编译 mesh-tunnel 客户端..." "INFO"

    $projectDir = Split-Path -Parent $PSScriptRoot
    $dataPlaneDir = Join-Path $projectDir "data-plane"

    if (-not (Test-Path (Join-Path $dataPlaneDir "Cargo.toml"))) {
        Write-Log "未找到 Cargo.toml: $dataPlaneDir" "ERROR"
        exit 1
    }

    Push-Location $dataPlaneDir
    try {
        $buildResult = & cargo build --release --bin mesh-tunnel 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Log "编译失败:" "ERROR"
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
        Write-Log "编译成功! 二进制大小: $size" "SUCCESS"
    }
    else {
        Write-Log "编译失败，未找到 mesh-tunnel.exe" "ERROR"
        exit 1
    }
}

# ─── 安装二进制文件 ──────────────────────────────────────────────
function Install-Binary {
    Write-Log "安装 mesh-tunnel..." "INFO"

    $installDir = "$env:ProgramFiles\P2P-Mesh-Client"
    $projectDir = Split-Path -Parent $PSScriptRoot
    $binaryPath = Join-Path $projectDir "data-plane\target\release\mesh-tunnel.exe"

    New-Item -ItemType Directory -Force -Path "$installDir\bin" | Out-Null
    New-Item -ItemType Directory -Force -Path "$installDir\config" | Out-Null
    New-Item -ItemType Directory -Force -Path "$installDir\logs" | Out-Null

    Copy-Item $binaryPath -Destination "$installDir\bin\mesh-tunnel.exe" -Force

    # 添加到 PATH
    $currentPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
    if ($currentPath -notlike "*$installDir\bin*") {
        [Environment]::SetEnvironmentVariable("PATH", "$currentPath;$installDir\bin", "Machine")
        Write-Log "已添加到系统 PATH" "SUCCESS"
    }

    Write-Log "安装完成: $installDir" "SUCCESS"
}

# ─── 交互式配置 ──────────────────────────────────────────────────
function Set-ClientConfig {
    Write-Log "配置客户端参数" "INFO"

    $configDir = "$env:APPDATA\p2p-mesh"
    $configFile = Join-Path $configDir "client.toml"
    New-Item -ItemType Directory -Force -Path $configDir | Out-Null

    if ((Test-Path $configFile) -and -not $ForceConfig) {
        Write-Log "配置文件已存在: $configFile" "WARN"
        $overwrite = Read-Host "  是否覆盖? [y/N]"
        if ($overwrite -notmatch '^[Yy]$') {
            Write-Log "保留现有配置" "INFO"
            return
        }
    }

    # API 服务器
    $apiServer = $Server
    if (-not $apiServer) {
        $apiServer = Read-Host "  API 服务器地址 (例如 https://mesh.yourdomain.com)"
        if (-not $apiServer) { $apiServer = "http://localhost:8000" }
    }

    # 认证令牌
    $authToken = $Token
    if (-not $authToken) {
        $authToken = Read-Host "  认证令牌 (留空稍后配置)"
    }

    # 监听端口
    $listenPort = Read-Host "  本地监听端口 [51820]"
    if (-not $listenPort) { $listenPort = "51820" }

    # 日志级别
    $logLevel = Read-Host "  日志级别 (trace/debug/info/warn/error) [info]"
    if (-not $logLevel) { $logLevel = "info" }

    # 写入配置
@"
# P2P Mesh Network — 客户端配置 (Windows)
# 生成时间: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
# 模式: tunnel

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
"@ | Out-File -FilePath $configFile -Encoding utf8

    Write-Log "配置已保存: $configFile" "SUCCESS"

    $tokenDisplay = if ($authToken) { "$($authToken.Substring(0, [Math]::Min(8, $authToken.Length)))..." } else { "未设置" }
    Write-Host ""
    Write-Host "配置摘要:" -ForegroundColor White
    Write-Host "  服务器:     $apiServer" -ForegroundColor Cyan
    Write-Host "  本地端口:   $listenPort" -ForegroundColor Cyan
    Write-Host "  令牌:       $tokenDisplay" -ForegroundColor Cyan
    Write-Host ""
}

# ─── 安装 Windows 服务 ───────────────────────────────────────────
function Install-WindowsService {
    Write-Log "安装 Windows 服务..." "INFO"

    $installDir = "$env:ProgramFiles\P2P-Mesh-Client"
    $configDir = "$env:APPDATA\p2p-mesh"
    $serviceName = "P2PMeshTunnel"

    # 检查是否已存在
    $existingService = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($existingService) {
        Write-Log "服务已存在，正在停止..." "WARN"
        Stop-Service $serviceName -Force -ErrorAction SilentlyContinue
        sc.exe delete $serviceName 2>&1 | Out-Null
        Start-Sleep -Seconds 2
    }

    # 使用 nssm (Non-Sucking Service Manager) 或 sc.exe
    # 这里使用 sc.exe 创建 Windows 服务
    $binaryPath = "$installDir\bin\mesh-tunnel.exe"
    $configPath = "$configDir\client.toml"

    $result = sc.exe create $serviceName `
        binPath= "$binaryPath --config `"$configPath`"" `
        start= auto `
        DisplayName= "P2P Mesh Tunnel Client" `
        obj= LocalSystem 2>&1

    if ($LASTEXITCODE -eq 0) {
        # 配置服务恢复选项
        sc.exe failure $serviceName reset= 86400 actions= restart/5000/restart/10000/restart/30000 2>&1 | Out-Null
        sc.exe description $serviceName "P2P Mesh Network — Mesh Tunnel Client Service" 2>&1 | Out-Null

        # 启动服务
        Start-Service $serviceName -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 3

        $svc = Get-Service $serviceName -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq 'Running') {
            Write-Log "Windows 服务安装成功并运行中" "SUCCESS"
        }
        else {
            Write-Log "服务已安装但可能未成功启动，请检查日志" "WARN"
            Write-Log "  查看日志: Get-EventLog -LogName Application -Source P2PMeshTunnel" "INFO"
        }
    }
    else {
        Write-Log "创建 Windows 服务失败: $result" "ERROR"
        Write-Log "您也可以手动运行:" "INFO"
        Write-Log "  $binaryPath --config `"$configPath`"" "INFO"
    }
}

# ─── 创建快捷方式 ────────────────────────────────────────────────
function New-DesktopShortcut {
    Write-Log "创建桌面快捷方式..." "INFO"

    $installDir = "$env:ProgramFiles\P2P-Mesh-Client"
    $desktopPath = [Environment]::GetFolderPath("Desktop")

    # 创建启动脚本
    $startScript = @"
@echo off
echo Starting P2P Mesh Tunnel Client...
"$installDir\bin\mesh-tunnel.exe" --config "%APPDATA%\p2p-mesh\client.toml"
pause
"@

    $startScriptPath = "$installDir\bin\start-tunnel.bat"
    $startScript | Out-File -FilePath $startScriptPath -Encoding ASCII

    # 创建快捷方式
    $WshShell = New-Object -ComObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut("$desktopPath\P2P Mesh Tunnel.lnk")
    $Shortcut.TargetPath = $startScriptPath
    $Shortcut.WorkingDirectory = $installDir
    $Shortcut.Description = "启动 P2P Mesh Tunnel 客户端"
    $Shortcut.Save()

    Write-Log "桌面快捷方式已创建" "SUCCESS"
}

# ─── 连通性测试 ──────────────────────────────────────────────────
function Test-Connection {
    Write-Log "连通性测试" "INFO"

    $apiUrl = if ($Server) { $Server } else { "http://localhost:8000" }

    try {
        $response = Invoke-WebRequest -Uri "$apiUrl/health" -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
        Write-Log "API 连接测试通过: $apiUrl (状态码: $($response.StatusCode))" "SUCCESS"
    }
    catch {
        Write-Log "API 服务器不可达: $apiUrl" "WARN"
        Write-Log "请检查防火墙和网络配置" "INFO"
    }
}

# ─── 卸载 ────────────────────────────────────────────────────────
function Uninstall-Client {
    Write-Host "=== P2P Mesh 客户端卸载 ===" -ForegroundColor Yellow
    Write-Host ""

    $installDir = "$env:ProgramFiles\P2P-Mesh-Client"
    $configDir = "$env:APPDATA\p2p-mesh"
    $serviceName = "P2PMeshTunnel"

    # 停止并删除服务
    $existingService = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($existingService) {
        Stop-Service $serviceName -Force -ErrorAction SilentlyContinue
        sc.exe delete $serviceName 2>&1 | Out-Null
        Write-Log "Windows 服务已删除" "SUCCESS"
    }

    # 删除安装目录
    if (Test-Path $installDir) {
        Remove-Item $installDir -Recurse -Force -ErrorAction SilentlyContinue
        Write-Log "安装目录已删除: $installDir" "SUCCESS"
    }

    # 保留配置
    if (Test-Path $configDir) {
        Write-Log "配置文件保留在: $configDir" "WARN"
        $deleteConfig = Read-Host "  是否删除配置文件? [y/N]"
        if ($deleteConfig -match '^[Yy]$') {
            Remove-Item $configDir -Recurse -Force
            Write-Log "配置文件已删除" "SUCCESS"
        }
    }

    # 删除桌面快捷方式
    $desktopPath = [Environment]::GetFolderPath("Desktop")
    $shortcutPath = "$desktopPath\P2P Mesh Tunnel.lnk"
    if (Test-Path $shortcutPath) {
        Remove-Item $shortcutPath -Force
        Write-Log "桌面快捷方式已删除" "SUCCESS"
    }

    Write-Host ""
    Write-Log "卸载完成" "SUCCESS"
    exit 0
}

# ─── 帮助 ────────────────────────────────────────────────────────
function Show-Help {
    Write-Host @"

P2P Mesh Network — Windows 客户端部署脚本

用法:
  .\scripts\deploy-client.ps1 [参数]

参数:
  -Server <URL>     API 服务器地址
  -Token <TOKEN>    认证令牌
  -Uninstall        卸载客户端
  -Help             显示此帮助

示例:
  .\scripts\deploy-client.ps1 -Server "https://mesh.example.com" -Token "eyJ..."

"@
    exit 0
}

# ─── 主流程 ──────────────────────────────────────────────────────
function Main {
    if ($Help) { Show-Help }
    if ($Uninstall) { Uninstall-Client }

    $logFile = "$env:TEMP\p2p-mesh-client-deploy.log"
    "=== P2P Mesh 客户端部署 (Windows) — $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ===" | Out-File $logFile

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
    Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║         🎉 客户端部署完成！Client Deployed!                  ║" -ForegroundColor Green
    Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Green
    Write-Host ""

    Write-Host "📋 常用操作:" -ForegroundColor White
    Write-Host "  查看状态:   Get-Service P2PMeshTunnel" -ForegroundColor Cyan
    Write-Host "  查看日志:   Get-EventLog -LogName Application -Source P2PMeshTunnel -Newest 50" -ForegroundColor Cyan
    Write-Host "  启动服务:   Start-Service P2PMeshTunnel" -ForegroundColor Cyan
    Write-Host "  停止服务:   Stop-Service P2PMeshTunnel" -ForegroundColor Cyan
    Write-Host "  编辑配置:   notepad `"$env:APPDATA\p2p-mesh\client.toml`"" -ForegroundColor Cyan
    Write-Host "  卸载:       .\scripts\deploy-client.ps1 -Uninstall" -ForegroundColor Cyan
    Write-Host ""
}

# 执行
Main
