#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════╗
# ║       P2P Mesh Network — 总控部署脚本                           ║
# ║       Master Deployment Orchestrator                            ║
# ╚══════════════════════════════════════════════════════════════════╝
#
# 统一入口，支持一键部署服务端和客户端。
#
# 用法:
#   # 服务端部署
#   sudo bash deploy.sh server [--domain mesh.example.com] [--arch microservices]
#
#   # 客户端部署 (Linux)
#   bash deploy.sh client [--server https://mesh.example.com] [--token <auth_token>]
#
#   # 客户端部署 (Windows)
#   powershell -File scripts/deploy-client.ps1 [-Server https://mesh.example.com]
#
#   # 完整部署 (交互式菜单)
#   bash deploy.sh
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

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ─── Banner ──────────────────────────────────────────────────────
banner() {
    clear 2>/dev/null || true
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║                                                                  ║"
    echo "║     ██████╗ ██████╗     ███╗   ███╗███████╗███████╗██╗  ██╗     ║"
    echo "║     ██╔══██╗╚════██╗    ████╗ ████║██╔════╝██╔════╝██║  ██║     ║"
    echo "║     ██████╔╝ █████╔╝    ██╔████╔██║█████╗  ███████╗███████║     ║"
    echo "║     ██╔═══╝ ██╔═══╝     ██║╚██╔╝██║██╔══╝  ╚════██║██╔══██║     ║"
    echo "║     ██║     ███████╗    ██║ ╚═╝ ██║███████╗███████║██║  ██║     ║"
    echo "║     ╚═╝     ╚══════╝    ╚═╝     ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝     ║"
    echo "║                                                                  ║"
    echo "║              一键部署平台 — Deployment Platform                  ║"
    echo "║                     v2.0.0 | $(date +%Y-%m-%d)                           ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# ─── 交互式菜单 ──────────────────────────────────────────────────
interactive_menu() {
    banner

    echo -e "${BOLD}请选择部署模式:${NC}"
    echo ""
    echo -e "  ${GREEN}1)${NC} ${BOLD}服务端部署${NC} — 在 VPS/服务器上部署全套后端服务"
    echo "      包括: Docker, PostgreSQL, Redis, 6 个微服务, Nginx, 监控"
    echo ""
    echo -e "  ${GREEN}2)${NC} ${BOLD}客户端部署 (Linux)${NC} — 在 Linux 设备上部署 P2P 客户端"
    echo "      编译 Rust 客户端二进制, 安装 systemd 服务"
    echo ""
    echo -e "  ${GREEN}3)${NC} ${BOLD}客户端部署 (Windows)${NC} — 在 Windows 设备上部署 P2P 客户端"
    echo "      编译 Rust 客户端, 安装 Windows 服务"
    echo ""
    echo -e "  ${GREEN}4)${NC} ${BOLD}快速体验${NC} — 本地开发环境一键启动"
    echo "      使用默认配置启动所有服务 (不推荐用于生产)"
    echo ""
    echo -e "  ${GREEN}5)${NC} ${BOLD}查看仪表盘${NC} — 在浏览器中打开可视化监控面板"
    echo ""
    echo -e "  ${GREEN}6)${NC} ${BOLD}运行验证${NC} — 运行部署后验证测试"
    echo ""
    echo -e "  ${GREEN}0)${NC} 退出"
    echo ""
    read -rp "请输入选项 [1-6]: " choice

    case "$choice" in
        1)
            deploy_server_interactive
            ;;
        2)
            deploy_client_linux_interactive
            ;;
        3)
            deploy_client_windows_guide
            ;;
        4)
            quick_start
            ;;
        5)
            open_dashboard
            ;;
        6)
            run_verification
            ;;
        0)
            echo "再见!"
            exit 0
            ;;
        *)
            echo -e "${RED}无效选项${NC}"
            sleep 1
            interactive_menu
            ;;
    esac
}

# ─── 服务端交互式部署 ────────────────────────────────────────────
deploy_server_interactive() {
    banner
    echo -e "${BOLD}服务端部署配置${NC}"
    echo ""

    if [[ "$EUID" -ne 0 ]]; then
        echo -e "${RED}服务端部署需要 root 权限。${NC}"
        echo -e "请运行: ${CYAN}sudo bash deploy.sh server${NC}"
        echo ""
        read -rp "按任意键返回..."
        interactive_menu
    fi

    # 域名
    read -rp "域名 (用于 SSL, 留空跳过): " domain

    # 架构
    echo ""
    echo "部署架构:"
    echo "  1) 微服务 (推荐) — 6 个独立服务, 适合生产环境"
    echo "  2) 单体 — 1 个 FastAPI 应用, 适合开发/小规模"
    read -rp "选择 [1]: " arch_choice
    arch_choice="${arch_choice:-1}"
    if [[ "$arch_choice" == "2" ]]; then
        arch="monolith"
    else
        arch="microservices"
    fi

    echo ""
    echo -e "${BOLD}确认配置:${NC}"
    echo -e "  域名:     ${CYAN}${domain:-无 (HTTP 模式)}${NC}"
    echo -e "  架构:     ${CYAN}${arch}${NC}"
    echo ""

    read -rp "确认部署? [Y/n]: " confirm
    if [[ "$confirm" =~ ^[Nn]$ ]]; then
        interactive_menu
    fi

    # 构建参数
    local args=""
    if [[ -n "$domain" ]]; then
        args="$args --domain $domain"
    fi
    args="$args --arch $arch"

    echo ""
    echo -e "${GREEN}开始服务端部署...${NC}"
    bash "${SCRIPT_DIR}/scripts/deploy-server.sh" $args

    echo ""
    read -rp "按任意键返回主菜单..."
    interactive_menu
}

# ─── 客户端 (Linux) 交互式部署 ────────────────────────────────────
deploy_client_linux_interactive() {
    banner
    echo -e "${BOLD}Linux 客户端部署${NC}"
    echo ""

    read -rp "API 服务器地址 (例如 https://mesh.yourdomain.com): " server
    read -rp "认证令牌 (留空稍后配置): " token

    echo ""
    read -rp "确认部署? [Y/n]: " confirm
    if [[ "$confirm" =~ ^[Nn]$ ]]; then
        interactive_menu
    fi

    local args=""
    if [[ -n "$server" ]]; then
        args="$args --server $server"
    fi
    if [[ -n "$token" ]]; then
        args="$args --token $token"
    fi

    echo ""
    echo -e "${GREEN}开始客户端部署...${NC}"
    bash "${SCRIPT_DIR}/scripts/deploy-client.sh" $args

    echo ""
    read -rp "按任意键返回主菜单..."
    interactive_menu
}

# ─── 客户端 (Windows) 说明 ────────────────────────────────────────
deploy_client_windows_guide() {
    banner
    echo -e "${BOLD}Windows 客户端部署指南${NC}"
    echo ""

    echo "在 Windows 设备上以管理员身份打开 PowerShell，然后运行:"
    echo ""
    echo -e "  ${CYAN}cd ${SCRIPT_DIR}${NC}"
    echo -e "  ${CYAN}.\\scripts\\deploy-client.ps1${NC}"
    echo ""
    echo "或指定服务器地址:"
    echo -e "  ${CYAN}.\\scripts\\deploy-client.ps1 -Server 'https://mesh.yourdomain.com' -Token '<token>'${NC}"
    echo ""
    echo "前置要求:"
    echo "  - Windows 10 (1809+) 或 Server 2019+"
    echo "  - Visual Studio Build Tools (C++ 生成工具)"
    echo "  - PowerShell 5.1+ (以管理员身份运行)"
    echo ""

    read -rp "按任意键返回主菜单..."
    interactive_menu
}

# ─── 快速体验 ────────────────────────────────────────────────────
quick_start() {
    banner
    echo -e "${BOLD}快速体验 (开发环境)${NC}"
    echo ""

    echo -e "${YELLOW}注意: 此模式仅用于本地开发和体验，不应用于生产环境。${NC}"
    echo ""

    # 检查 Docker
    if ! command -v docker &>/dev/null; then
        echo -e "${RED}需要 Docker。请先安装 Docker Desktop 或 Docker Engine。${NC}"
        read -rp "按任意键返回..."
        interactive_menu
    fi

    # 生成开发密钥
    echo -e "${BLUE}正在准备开发环境...${NC}"

    local dev_dir="${SCRIPT_DIR}/deployment"
    local env_file="${dev_dir}/.env"

    # 创建开发 .env (如果不存在或包含占位符)
    if [[ ! -f "$env_file" ]] || grep -q "CHANGE_ME" "$env_file" 2>/dev/null; then
        cat > "$env_file" << 'EOF'
# P2P Mesh — 开发环境 (自动生成)
POSTGRES_PASSWORD=dev_password_12345
REDIS_PASSWORD=dev_password_12345
JWT_SECRET=dev_jwt_secret_for_local_testing_only_do_not_use_in_production_64_chars
RELAY_AUTH_TOKEN=dev_relay_token_for_local_testing_only_64_chars
RELAY_HMAC_KEY=dev_hmac_key_32_chars_local
PUNCH_HMAC_KEY=dev_punch_key_32_chars_local
INTERNAL_API_KEY=dev_internal_api_key_32_chars
RELAY_ID=relay-dev
LOG_LEVEL=DEBUG
DEBUG=true
GRAFANA_USER=admin
GRAFANA_PASSWORD=admin
EOF
        echo -e "${GREEN}开发配置已生成${NC}"
    fi

    # 启动服务
    echo ""
    echo -e "${BLUE}启动服务...${NC}"
    cd "$dev_dir"

    docker compose -f docker-compose.microservices.yml --env-file .env up -d 2>&1

    echo ""
    echo -e "${GREEN}服务正在启动，等待就绪...${NC}"
    echo ""

    # 等待并显示状态
    sleep 30
    docker compose -f docker-compose.microservices.yml --env-file .env ps 2>&1

    echo ""
    echo -e "${BOLD}${GREEN}快速体验环境已就绪!${NC}"
    echo ""
    echo -e "  API:              ${CYAN}http://localhost${NC}"
    echo -e "  Grafana:          ${CYAN}http://localhost:3000${NC} (admin/admin)"
    echo -e "  Prometheus:       ${CYAN}http://localhost:9090${NC}"
    echo -e "  Jaeger:           ${CYAN}http://localhost:16686${NC}"
    echo ""
    echo -e "  停止服务: ${CYAN}cd deployment && docker compose down${NC}"
    echo ""

    read -rp "按任意键返回主菜单..."
    interactive_menu
}

# ─── 打开仪表盘 ──────────────────────────────────────────────────
open_dashboard() {
    banner
    echo -e "${BOLD}可视化监控面板${NC}"
    echo ""

    local dashboard_path="${SCRIPT_DIR}/dashboard/index.html"

    if [[ -f "$dashboard_path" ]]; then
        echo -e "仪表盘文件: ${CYAN}${dashboard_path}${NC}"
        echo ""

        # 尝试在浏览器中打开
        if command -v xdg-open &>/dev/null; then
            xdg-open "$dashboard_path" 2>/dev/null &
            echo -e "${GREEN}已在浏览器中打开仪表盘${NC}"
        elif command -v open &>/dev/null; then
            open "$dashboard_path" 2>/dev/null &
            echo -e "${GREEN}已在浏览器中打开仪表盘${NC}"
        elif [[ "$OS" == "Windows_NT" ]]; then
            start "$dashboard_path" 2>/dev/null &
            echo -e "${GREEN}已在浏览器中打开仪表盘${NC}"
        else
            echo -e "${YELLOW}无法自动打开浏览器。请手动打开:${NC}"
            echo -e "  ${CYAN}${dashboard_path}${NC}"
        fi
    else
        echo -e "${YELLOW}仪表盘文件不存在: ${dashboard_path}${NC}"
        echo "请确保已正常安装项目。"
    fi

    echo ""
    read -rp "按任意键返回主菜单..."
    interactive_menu
}

# ─── 运行验证 ────────────────────────────────────────────────────
run_verification() {
    banner
    echo -e "${BOLD}部署验证测试${NC}"
    echo ""

    read -rp "API 地址 [http://localhost:8000]: " api_url
    api_url="${api_url:-http://localhost:8000}"

    echo ""
    echo -e "${BLUE}运行验证测试...${NC}"
    bash "${SCRIPT_DIR}/scripts/verify.sh" "$api_url"

    echo ""
    read -rp "按任意键返回主菜单..."
    interactive_menu
}

# ─── 命令行模式 ──────────────────────────────────────────────────
cli_mode() {
    local subcommand="$1"
    shift

    case "$subcommand" in
        server|srv|s)
            if [[ "$EUID" -ne 0 ]]; then
                echo -e "${RED}服务端部署需要 root 权限: sudo bash deploy.sh server${NC}"
                exit 1
            fi
            bash "${SCRIPT_DIR}/scripts/deploy-server.sh" "$@"
            ;;
        client|cli|c)
            bash "${SCRIPT_DIR}/scripts/deploy-client.sh" "$@"
            ;;
        quick|dev|q)
            quick_start
            ;;
        dashboard|dash|d)
            open_dashboard
            ;;
        verify|check|v)
            run_verification
            ;;
        help|--help|-h)
            echo "用法: bash deploy.sh [命令] [参数]"
            echo ""
            echo "命令:"
            echo "  server    服务端部署 (需要 root)"
            echo "  client    Linux 客户端部署"
            echo "  quick     快速启动开发环境"
            echo "  dashboard 打开可视化监控面板"
            echo "  verify    运行部署验证测试"
            echo "  help      显示此帮助"
            echo ""
            echo "无参数运行则进入交互式菜单。"
            echo ""
            echo "示例:"
            echo "  sudo bash deploy.sh server --domain mesh.example.com"
            echo "  bash deploy.sh client --server https://mesh.example.com"
            ;;
        *)
            echo -e "${RED}未知命令: $subcommand${NC}"
            echo "运行 'bash deploy.sh help' 查看帮助"
            exit 1
            ;;
    esac
}

# ─── 主入口 ──────────────────────────────────────────────────────
main() {
    if [[ $# -eq 0 ]]; then
        interactive_menu
    else
        cli_mode "$@"
    fi
}

main "$@"
