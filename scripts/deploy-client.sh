#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════╗
# ║       P2P Mesh Network — 客户端一键部署脚本                     ║
# ║       Client One-Click Deployment Script (Linux)                ║
# ╚══════════════════════════════════════════════════════════════════╝
#
# 功能:
#   1. 安装 Rust 工具链 (如未安装)
#   2. 编译 mesh-tunnel 客户端二进制文件
#   3. 交互式配置客户端参数
#   4. 安装为 systemd 服务 (开机自启)
#   5. 运行连通性测试
#
# 用法:
#   bash scripts/deploy-client.sh
#   bash scripts/deploy-client.sh --server https://mesh.yourdomain.com --token <auth_token>
#   bash scripts/deploy-client.sh --uninstall
#
set -euo pipefail

# ─── 颜色 ─────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ─── 默认配置 ────────────────────────────────────────────────────
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DATA_PLANE_DIR="${PROJECT_DIR}/data-plane"
INSTALL_DIR="${INSTALL_DIR:-/opt/p2p-mesh-client}"
CONFIG_DIR="${HOME}/.config/p2p-mesh"
SERVICE_NAME="p2p-mesh-tunnel"
LOG_FILE="/tmp/p2p-mesh-client-deploy.log"

# ─── 日志 ─────────────────────────────────────────────────────────
log()   { echo -e "${GREEN}[✓]${NC} $*" | tee -a "$LOG_FILE"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*" | tee -a "$LOG_FILE"; }
error() { echo -e "${RED}[✗]${NC} $*" | tee -a "$LOG_FILE"; }
info()  { echo -e "${BLUE}[i]${NC} $*" | tee -a "$LOG_FILE"; }

# ─── Banner ──────────────────────────────────────────────────────
banner() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║     P2P Mesh Network — 客户端部署 (Linux)                   ║"
    echo "║     Client Deployment v2.0.0                                ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# ─── 系统检测 ────────────────────────────────────────────────────
detect_os() {
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        info "操作系统: $NAME $VERSION_ID"
    fi
    info "CPU 架构: $(uname -m)"
    info "内核版本: $(uname -r)"

    # 检查 TUN 模块 (mesh-overlay 需要)
    if lsmod | grep -q "^tun "; then
        log "TUN 模块已加载"
    else
        warn "TUN 模块未加载 (仅 overlay 模式需要)"
        info "加载方法: sudo modprobe tun"
    fi
}

# ─── 安装 Rust ────────────────────────────────────────────────────
install_rust() {
    if command -v cargo &>/dev/null; then
        RUST_VERSION=$(rustc --version 2>/dev/null || echo "unknown")
        log "Rust 已安装: $RUST_VERSION"
    else
        info "安装 Rust 工具链..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
        source "$HOME/.cargo/env"
        log "Rust 安装完成"

        # 安装交叉编译目标 (可选)
        info "安装额外目标..."
        rustup target add x86_64-unknown-linux-musl 2>/dev/null || true
    fi
}

# ─── 编译客户端 ──────────────────────────────────────────────────
build_client() {
    info "编译 mesh-tunnel 客户端..."

    cd "$DATA_PLANE_DIR"

    # 检查 Cargo.toml
    if [[ ! -f Cargo.toml ]]; then
        error "未找到 $DATA_PLANE_DIR/Cargo.toml"
        exit 1
    fi

    # 编译发布版本
    cargo build --release --bin mesh-tunnel 2>&1 | tee -a "$LOG_FILE"

    if [[ -f "target/release/mesh-tunnel" ]]; then
        local size=$(du -h target/release/mesh-tunnel | cut -f1)
        log "编译成功! 二进制大小: $size"
    else
        error "编译失败，请检查日志"
        exit 1
    fi
}

# ─── 安装二进制文件 ──────────────────────────────────────────────
install_binary() {
    info "安装 mesh-tunnel 到 ${INSTALL_DIR}/bin"

    sudo mkdir -p "${INSTALL_DIR}/bin"
    sudo cp "${DATA_PLANE_DIR}/target/release/mesh-tunnel" "${INSTALL_DIR}/bin/mesh-tunnel"
    sudo chmod +x "${INSTALL_DIR}/bin/mesh-tunnel"

    # 创建符号链接以便全局访问
    sudo ln -sf "${INSTALL_DIR}/bin/mesh-tunnel" /usr/local/bin/mesh-tunnel 2>/dev/null || true
    log "二进制文件安装完成"
}

# ─── 交互式配置 ──────────────────────────────────────────────────
configure_client() {
    info "配置客户端参数"

    mkdir -p "$CONFIG_DIR"
    local config_file="${CONFIG_DIR}/client.toml"

    # 如果配置文件已存在
    if [[ -f "$config_file" ]]; then
        warn "配置文件已存在: $config_file"
        read -rp "  是否覆盖? [y/N]: " overwrite
        if [[ ! "$overwrite" =~ ^[Yy]$ ]]; then
            info "保留现有配置"
            return
        fi
    fi

    echo ""

    # API 服务器地址
    if [[ -n "${API_SERVER:-}" ]]; then
        SERVER="$API_SERVER"
        info "API 服务器 (来自参数): $SERVER"
    else
        read -rp "  API 服务器地址 (例如 https://mesh.yourdomain.com): " SERVER
        if [[ -z "$SERVER" ]]; then
            SERVER="http://localhost:8000"
        fi
    fi

    # 认证令牌
    if [[ -n "${AUTH_TOKEN:-}" ]]; then
        TOKEN="$AUTH_TOKEN"
        info "认证令牌 (来自参数): ****${TOKEN: -8}"
    else
        read -rp "  认证令牌 (留空稍后手动配置): " TOKEN
    fi

    # 监听端口
    read -rp "  本地监听端口 [51820]: " LISTEN_PORT
    LISTEN_PORT="${LISTEN_PORT:-51820}"

    # 运行模式
    echo ""
    echo "  运行模式:"
    echo "    1) tunnel — 基础 P2P 隧道 (推荐)"
    echo "    2) overlay — 完整 Overlay 网络 (需要 TUN 接口)"
    read -rp "  选择 [1]: " MODE_CHOICE
    MODE_CHOICE="${MODE_CHOICE:-1}"

    if [[ "$MODE_CHOICE" == "2" ]]; then
        MODE="overlay"
        read -rp "  Overlay 网络 CIDR [10.99.0.0/24]: " OVERLAY_CIDR
        OVERLAY_CIDR="${OVERLAY_CIDR:-10.99.0.0/24}"
    else
        MODE="tunnel"
        OVERLAY_CIDR=""
    fi

    # 日志级别
    read -rp "  日志级别 (trace/debug/info/warn/error) [info]: " LOG_LEVEL
    LOG_LEVEL="${LOG_LEVEL:-info}"

    # 写入配置
    cat > "$config_file" << EOF
# P2P Mesh Network — 客户端配置
# 生成时间: $(date '+%Y-%m-%d %H:%M:%S')
# 模式: $MODE

[client]
mode = "$MODE"
listen_port = $LISTEN_PORT

[server]
api_url = "$SERVER"
auth_token = "$TOKEN"

[network]
# 本地覆盖网络 CIDR (仅 overlay 模式使用)
overlay_cidr = "$OVERLAY_CIDR"

[logging]
level = "$LOG_LEVEL"

[advanced]
# 并发连接数
max_connections = 100

# 心跳间隔 (秒)
heartbeat_interval = 30

# 健康检查间隔 (秒)
health_check_interval = 10

# QUIC 空闲超时 (秒)
quic_idle_timeout = 30

# 启用 AI 路由优化
ai_routing_enabled = false
EOF

    chmod 600 "$config_file"
    log "配置已保存: $config_file"

    # 密码脱敏显示
    local token_display="未设置"
    if [[ -n "$TOKEN" ]]; then
        token_display="${TOKEN:0:8}...${TOKEN: -4}"
    fi

    echo ""
    echo -e "${BOLD}配置摘要:${NC}"
    echo -e "  模式:         ${CYAN}$MODE${NC}"
    echo -e "  服务器:       ${CYAN}$SERVER${NC}"
    echo -e "  本地端口:     ${CYAN}$LISTEN_PORT${NC}"
    echo -e "  令牌:         ${CYAN}$token_display${NC}"
    if [[ "$MODE" == "overlay" ]]; then
        echo -e "  Overlay CIDR: ${CYAN}$OVERLAY_CIDR${NC}"
    fi
    echo ""
}

# ─── 安装 systemd 服务 ───────────────────────────────────────────
install_systemd() {
    info "安装 systemd 服务 ($SERVICE_NAME)"

    local service_file="/etc/systemd/system/${SERVICE_NAME}.service"

    cat << EOF | sudo tee "$service_file" > /dev/null
[Unit]
Description=P2P Mesh Network — Mesh Tunnel Client
Documentation=https://github.com/p2p-mesh/p2p-mesh
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${USER}
Group=${USER}
Environment="RUST_LOG=${LOG_LEVEL:-info}"
ExecStart=${INSTALL_DIR}/bin/mesh-tunnel \\
    --config ${CONFIG_DIR}/client.toml
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

# 安全加固
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=${CONFIG_DIR}
ReadOnlyPaths=${INSTALL_DIR}

# 允许 TUN 设备创建 (overlay 模式需要)
# AmbientCapabilities=CAP_NET_ADMIN
# DeviceAllow=/dev/net/tun rw

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl daemon-reload
    log "systemd 服务已创建"

    read -rp "  是否启用开机自启? [Y/n]: " enable_autostart
    if [[ ! "$enable_autostart" =~ ^[Nn]$ ]]; then
        sudo systemctl enable "$SERVICE_NAME"
        log "已启用开机自启"
    fi

    read -rp "  是否立即启动服务? [Y/n]: " start_now
    if [[ ! "$start_now" =~ ^[Nn]$ ]]; then
        sudo systemctl start "$SERVICE_NAME"
        sleep 2
        if systemctl is-active --quiet "$SERVICE_NAME"; then
            log "服务已启动并运行正常"
        else
            warn "服务启动可能存在问题，请检查日志:"
            info "  sudo journalctl -u ${SERVICE_NAME} -f"
        fi
    fi
}

# ─── 测试连通性 ──────────────────────────────────────────────────
test_connection() {
    info "连通性测试"

    local api_url="${API_SERVER:-http://localhost:8000}"

    # 测试 API 可达性
    echo -n "  测试 API 连接... "
    if curl -sf -o /dev/null --connect-timeout 5 "${api_url}/health" 2>/dev/null; then
        echo -e "${GREEN}可达${NC}"
        log "API 连接测试通过: $api_url"
    else
        echo -e "${YELLOW}无法连接${NC}"
        warn "API 服务器不可达: $api_url"
        info "请检查防火墙和网络配置"
    fi

    # 测试 STUN
    echo -n "  测试 STUN 服务... "
    if nc -z -u -w 2 "${api_url#*://}" 3478 2>/dev/null; then
        echo -e "${GREEN}可达${NC}"
    else
        echo -e "${YELLOW}跳过${NC}"
    fi
}

# ─── 卸载 ────────────────────────────────────────────────────────
uninstall() {
    echo -e "${YELLOW}=== P2P Mesh 客户端卸载 ===${NC}"
    echo ""

    # 停止并禁用服务
    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        sudo systemctl stop "$SERVICE_NAME"
        log "服务已停止"
    fi
    if systemctl is-enabled --quiet "$SERVICE_NAME" 2>/dev/null; then
        sudo systemctl disable "$SERVICE_NAME"
        log "已禁用开机自启"
    fi

    # 删除 systemd 文件
    if [[ -f "/etc/systemd/system/${SERVICE_NAME}.service" ]]; then
        sudo rm "/etc/systemd/system/${SERVICE_NAME}.service"
        sudo systemctl daemon-reload
        log "已删除 systemd 服务文件"
    fi

    # 删除安装目录
    if [[ -d "$INSTALL_DIR" ]]; then
        sudo rm -rf "$INSTALL_DIR"
        log "已删除安装目录: $INSTALL_DIR"
    fi

    # 删除符号链接
    if [[ -L "/usr/local/bin/mesh-tunnel" ]]; then
        sudo rm /usr/local/bin/mesh-tunnel
        log "已删除符号链接"
    fi

    # 保留配置文件
    if [[ -d "$CONFIG_DIR" ]]; then
        warn "配置文件保留在: $CONFIG_DIR"
        read -rp "  是否删除配置文件? [y/N]: " delete_config
        if [[ "$delete_config" =~ ^[Yy]$ ]]; then
            rm -rf "$CONFIG_DIR"
            log "已删除配置文件"
        fi
    fi

    echo ""
    log "卸载完成"
    exit 0
}

# ─── 帮助 ────────────────────────────────────────────────────────
show_help() {
    echo "用法: bash scripts/deploy-client.sh [选项]"
    echo ""
    echo "选项:"
    echo "  --server <URL>     API 服务器地址"
    echo "  --token <TOKEN>    认证令牌"
    echo "  --mode <模式>      tunnel (默认) 或 overlay"
    echo "  --uninstall        卸载客户端"
    echo "  --help             显示此帮助"
    echo ""
}

# ─── 参数解析 ────────────────────────────────────────────────────
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --server)
                API_SERVER="$2"
                shift 2
                ;;
            --token)
                AUTH_TOKEN="$2"
                shift 2
                ;;
            --mode)
                CLIENT_MODE="$2"
                shift 2
                ;;
            --uninstall)
                uninstall
                ;;
            --help|-h)
                show_help
                exit 0
                ;;
            *)
                error "未知参数: $1 (使用 --help 查看帮助)"
                exit 1
                ;;
        esac
    done
}

# ─── 主函数 ──────────────────────────────────────────────────────
main() {
    echo "=== P2P Mesh 客户端部署 — $(date '+%Y-%m-%d %H:%M:%S') ===" > "$LOG_FILE"

    banner
    parse_args "$@"

    detect_os
    install_rust
    build_client
    install_binary
    configure_client
    install_systemd
    test_connection

    echo ""
    echo -e "${BOLD}${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${GREEN}║         🎉 客户端部署完成！Client Deployed!                  ║${NC}"
    echo -e "${BOLD}${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${BOLD}📋 常用命令:${NC}"
    echo -e "  查看状态:   ${CYAN}systemctl status ${SERVICE_NAME}${NC}"
    echo -e "  查看日志:   ${CYAN}journalctl -u ${SERVICE_NAME} -f${NC}"
    echo -e "  重启服务:   ${CYAN}sudo systemctl restart ${SERVICE_NAME}${NC}"
    echo -e "  编辑配置:   ${CYAN}nano ${CONFIG_DIR}/client.toml${NC}"
    echo -e "  卸载:       ${CYAN}bash scripts/deploy-client.sh --uninstall${NC}"
    echo ""
}

main "$@"
