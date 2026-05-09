#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════╗
# ║       P2P Mesh Network — 服务端一键部署脚本                      ║
# ║       Server One-Click Deployment Script                        ║
# ╚══════════════════════════════════════════════════════════════════╝
#
# 功能:
#   1. 自动检测操作系统并安装依赖 (Docker, Docker Compose)
#   2. 安全生成所有密钥和密码
#   3. 构建并启动全部服务 (微服务架构)
#   4. 配置防火墙规则
#   5. 健康检查和验证
#   6. 可选 Let's Encrypt SSL 证书配置
#
# 用法:
#   sudo bash scripts/deploy-server.sh
#   sudo bash scripts/deploy-server.sh --domain mesh.example.com
#   sudo bash scripts/deploy-server.sh --arch monolith   # 单体架构
#   sudo bash scripts/deploy-server.sh --arch microservices  # 微服务架构(默认)
#
set -euo pipefail

# ─── 颜色定义 ───────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ─── 默认配置 ───────────────────────────────────────────────────
DOMAIN="${DOMAIN:-}"
ARCH="${ARCH:-microservices}"
PROJECT_DIR="${PROJECT_DIR:-/opt/p2p-mesh}"
DEPLOY_DIR="${PROJECT_DIR}/deployment"
DATA_DIR="${PROJECT_DIR}/data"
LOG_FILE="${PROJECT_DIR}/deploy-server.log"

# ─── Banner ──────────────────────────────────────────────────────
banner() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                                                              ║"
    echo "║     ██████╗ ██████╗     ███╗   ███╗███████╗███████╗██╗  ██╗  ║"
    echo "║     ██╔══██╗╚════██╗    ████╗ ████║██╔════╝██╔════╝██║  ██║  ║"
    echo "║     ██████╔╝ █████╔╝    ██╔████╔██║█████╗  ███████╗███████║  ║"
    echo "║     ██╔═══╝ ██╔═══╝     ██║╚██╔╝██║██╔══╝  ╚════██║██╔══██║  ║"
    echo "║     ██║     ███████╗    ██║ ╚═╝ ██║███████╗███████║██║  ██║  ║"
    echo "║     ╚═╝     ╚══════╝    ╚═╝     ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝  ║"
    echo "║                                                              ║"
    echo "║              服务端一键部署 — Server Deployment               ║"
    echo "║                     v2.0.0 | $(date +%Y-%m-%d)                       ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# ─── 日志函数 ────────────────────────────────────────────────────
log()     { echo -e "${GREEN}[✓]${NC} $*" | tee -a "$LOG_FILE"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*" | tee -a "$LOG_FILE"; }
error()   { echo -e "${RED}[✗]${NC} $*" | tee -a "$LOG_FILE"; }
info()    { echo -e "${BLUE}[i]${NC} $*" | tee -a "$LOG_FILE"; }
section() { echo -e "\n${BOLD}${CYAN}━━━ $* ━━━${NC}" | tee -a "$LOG_FILE"; }

# ─── 参数解析 ────────────────────────────────────────────────────
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --domain)
                DOMAIN="$2"
                shift 2
                ;;
            --arch)
                ARCH="$2"
                if [[ ! "$ARCH" =~ ^(monolith|microservices)$ ]]; then
                    error "无效架构: $ARCH (可选: monolith, microservices)"
                    exit 1
                fi
                shift 2
                ;;
            --dir)
                PROJECT_DIR="$2"
                DEPLOY_DIR="${PROJECT_DIR}/deployment"
                shift 2
                ;;
            --help|-h)
                echo "用法: sudo bash scripts/deploy-server.sh [选项]"
                echo ""
                echo "选项:"
                echo "  --domain <域名>      配置 SSL 证书的域名 (自动启用 Let's Encrypt)"
                echo "  --arch <架构>        部署架构: monolith 或 microservices (默认: microservices)"
                echo "  --dir <目录>         项目目录 (默认: /opt/p2p-mesh)"
                echo "  --help, -h           显示此帮助信息"
                exit 0
                ;;
            *)
                error "未知参数: $1"
                exit 1
                ;;
        esac
    done
}

# ─── 系统检测 ────────────────────────────────────────────────────
detect_os() {
    section "系统环境检测"

    if [[ ! -f /etc/os-release ]]; then
        error "无法检测操作系统 (缺少 /etc/os-release)"
        exit 1
    fi

    source /etc/os-release

    case "$ID" in
        ubuntu|debian)
            info "检测到: $NAME $VERSION_ID"
            OS_FAMILY="debian"
            ;;
        centos|rhel|fedora|rocky|almalinux)
            info "检测到: $NAME $VERSION_ID"
            OS_FAMILY="redhat"
            ;;
        *)
            warn "未充分测试的操作系统: $ID。将尝试 Debian 系安装方式。"
            OS_FAMILY="debian"
            ;;
    esac

    ARCH_CPU=$(uname -m)
    info "CPU 架构: $ARCH_CPU"

    MEM_TOTAL=$(free -m 2>/dev/null | awk '/^Mem:/{print $2}' || echo "unknown")
    info "内存: ${MEM_TOTAL}MB"
    if [[ "$MEM_TOTAL" != "unknown" ]] && [[ "$MEM_TOTAL" -lt 1024 ]]; then
        warn "内存不足 1GB，建议至少 2GB 用于生产环境"
    fi
}

# ─── 安装 Docker ──────────────────────────────────────────────────
install_docker() {
    section "安装 Docker 引擎"

    if command -v docker &>/dev/null; then
        DOCKER_VERSION=$(docker --version 2>/dev/null || echo "unknown")
        log "Docker 已安装: $DOCKER_VERSION"
    else
        info "正在安装 Docker..."
        if [[ "$OS_FAMILY" == "debian" ]]; then
            # 卸载旧版本
            for pkg in docker.io docker-doc docker-compose docker-compose-v2 podman-docker containerd runc; do
                apt-get remove -y "$pkg" 2>/dev/null || true
            done

            # 安装依赖
            apt-get update -qq
            apt-get install -y -qq ca-certificates curl gnupg

            # 添加 Docker GPG 密钥
            install -m 0755 -d /etc/apt/keyrings
            curl -fsSL https://download.docker.com/linux/${ID}/gpg -o /etc/apt/keyrings/docker.asc
            chmod a+r /etc/apt/keyrings/docker.asc

            # 添加仓库
            echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/${ID} $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
                tee /etc/apt/sources.list.d/docker.list > /dev/null

            apt-get update -qq
            apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
            log "Docker 安装完成"
        elif [[ "$OS_FAMILY" == "redhat" ]]; then
            dnf remove -y docker docker-client docker-client-latest docker-common docker-latest \
                docker-latest-logrotate docker-logrotate docker-engine podman runc 2>/dev/null || true
            dnf -y install dnf-plugins-core
            dnf config-manager --add-repo https://download.docker.com/linux/${ID}/docker-ce.repo
            dnf install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
            systemctl enable --now docker
            log "Docker 安装完成"
        fi
    fi

    # 验证 Docker Compose 插件
    if ! docker compose version &>/dev/null; then
        error "Docker Compose 插件未正确安装"
        warn "请手动安装: apt-get install docker-compose-plugin"
        exit 1
    fi
    log "Docker Compose: $(docker compose version)"

    # 启动 Docker
    if ! docker info &>/dev/null; then
        systemctl enable --now docker
    fi

    # 添加当前用户到 docker 组 (如果以 root 运行且有 SUDO_USER)
    if [[ -n "${SUDO_USER:-}" ]] && [[ "$SUDO_USER" != "root" ]]; then
        usermod -aG docker "$SUDO_USER" 2>/dev/null || true
        info "已将 $SUDO_USER 加入 docker 组 (重新登录后生效)"
    fi
}

# ─── 安装工具 ────────────────────────────────────────────────────
install_tools() {
    section "安装必要工具"

    local tools="curl wget git openssl jq"
    if [[ "$OS_FAMILY" == "debian" ]]; then
        apt-get update -qq
        apt-get install -y -qq $tools ufw
    elif [[ "$OS_FAMILY" == "redhat" ]]; then
        dnf install -y $tools firewalld
    fi
    log "基础工具安装完成"
}

# ─── 生成密钥 ────────────────────────────────────────────────────
generate_secrets() {
    section "安全生成密钥"

    info "使用 openssl rand 生成加密安全随机值..."

    POSTGRES_PASSWORD=$(openssl rand -hex 32)
    REDIS_PASSWORD=$(openssl rand -hex 32)
    JWT_SECRET=$(openssl rand -hex 64)
    RELAY_AUTH_TOKEN=$(openssl rand -hex 64)
    RELAY_HMAC_KEY=$(openssl rand -hex 32)
    PUNCH_HMAC_KEY=$(openssl rand -hex 32)
    INTERNAL_API_KEY=$(openssl rand -hex 32)
    GRAFANA_PASSWORD=$(openssl rand -hex 16)

    log "全部密钥已安全生成"
}

# ─── 创建环境配置文件 ────────────────────────────────────────────
create_env_file() {
    section "创建环境配置"

    mkdir -p "$DEPLOY_DIR"

    local env_file="${DEPLOY_DIR}/.env"

    # 如果 .env 已存在，检测是否为占位符
    if [[ -f "$env_file" ]]; then
        if grep -q "CHANGE_ME" "$env_file" 2>/dev/null; then
            warn "检测到现有 .env 包含占位符，将覆盖"
            cp "$env_file" "${env_file}.backup.$(date +%s)"
        else
            warn ".env 已存在且已配置，跳过生成"
            info "如需重新生成，请删除: rm ${env_file}"
            return
        fi
    fi

    cat > "$env_file" << EOF
# ╔══════════════════════════════════════════════════════════════════╗
# ║  P2P Mesh Network — 环境变量 (自动生成)                        ║
# ║  生成时间: $(date '+%Y-%m-%d %H:%M:%S')                              ║
# ╚══════════════════════════════════════════════════════════════════╝

# PostgreSQL 数据库密码
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}

# Redis 密码
REDIS_PASSWORD=${REDIS_PASSWORD}

# JWT 签名密钥 (HS256)
JWT_SECRET=${JWT_SECRET}

# 中继节点认证令牌 (API ↔ 中继节点共享密钥)
RELAY_AUTH_TOKEN=${RELAY_AUTH_TOKEN}

# 中继 HMAC 密钥 (验证转发数据包源设备 ID)
RELAY_HMAC_KEY=${RELAY_HMAC_KEY}

# 打洞 HMAC 密钥 (验证 HELLO/HELLO_ACK 数据包)
PUNCH_HMAC_KEY=${PUNCH_HMAC_KEY}

# 微服务间认证密钥 (所有微服务共享)
INTERNAL_API_KEY=${INTERNAL_API_KEY}

# Grafana 管理员密码
GRAFANA_USER=admin
GRAFANA_PASSWORD=${GRAFANA_PASSWORD}

# 中继节点标识
RELAY_ID=relay-primary

# 日志级别
LOG_LEVEL=INFO
DEBUG=false

# 域名 (用于 SSL)
DOMAIN=${DOMAIN}

# 部署架构
ARCH=${ARCH}
EOF

    chmod 600 "$env_file"
    log "环境配置已保存到: $env_file"

    # 同步到项目根目录
    cp "$env_file" "${PROJECT_DIR}/.env.prod" 2>/dev/null || true
}

# ─── 选择 Docker Compose 文件 ─────────────────────────────────────
select_compose_file() {
    section "选择部署架构"

    if [[ "$ARCH" == "monolith" ]]; then
        COMPOSE_FILE="docker-compose.prod.yml"
        info "使用单体架构: $COMPOSE_FILE"
    else
        COMPOSE_FILE="docker-compose.microservices.prod.yml"
        # 如果生产微服务文件不存在，回退到普通版本
        if [[ ! -f "${DEPLOY_DIR}/${COMPOSE_FILE}" ]]; then
            warn "未找到 $COMPOSE_FILE，使用 docker-compose.microservices.yml"
            COMPOSE_FILE="docker-compose.microservices.yml"
        fi
        info "使用微服务架构: $COMPOSE_FILE"
    fi
}

# ─── 拉取/构建镜像 ────────────────────────────────────────────────
build_images() {
    section "构建 Docker 镜像"

    cd "$DEPLOY_DIR"

    info "拉取基础镜像..."
    docker compose -f "$COMPOSE_FILE" --env-file .env pull 2>&1 | tee -a "$LOG_FILE" || true

    info "构建项目镜像 (这可能需要几分钟)..."
    docker compose -f "$COMPOSE_FILE" --env-file .env build \
        --build-arg BUILDKIT_INLINE_CACHE=1 \
        2>&1 | tee -a "$LOG_FILE"

    log "镜像构建完成"
}

# ─── 创建数据目录 ─────────────────────────────────────────────────
setup_directories() {
    section "创建数据目录"

    mkdir -p "${DATA_DIR}/postgres"
    mkdir -p "${DATA_DIR}/redis"
    mkdir -p "${DATA_DIR}/prometheus"
    mkdir -p "${DATA_DIR}/grafana"
    mkdir -p "${DATA_DIR}/loki"
    mkdir -p "${DATA_DIR}/nginx/ssl"

    # 设置权限
    chown -R 1000:1000 "${DATA_DIR}/grafana" 2>/dev/null || true

    log "数据目录创建完成"
}

# ─── 配置防火墙 ────────────────────────────────────────────────────
setup_firewall() {
    section "配置防火墙"

    if [[ "$OS_FAMILY" == "debian" ]]; then
        if ! command -v ufw &>/dev/null; then
            apt-get install -y -qq ufw
        fi

        # 基础策略
        ufw default deny incoming
        ufw default allow outgoing

        # SSH
        ufw allow 22/tcp comment 'SSH'

        # Web
        ufw allow 80/tcp comment 'HTTP'
        ufw allow 443/tcp comment 'HTTPS'

        # P2P 端口
        ufw allow 51821/udp comment 'Relay'
        ufw allow 3478/udp comment 'STUN'
        ufw allow 51820/udp comment 'Tunnel'

        # 管理端口 (仅本地)
        ufw allow from 127.0.0.1 to any port 9090 comment 'Prometheus (local only)'
        ufw allow from 127.0.0.1 to any port 3000 comment 'Grafana (local only)'

        # 阻止出站垃圾邮件
        ufw deny out to any port 25 comment 'Block SMTP outbound'

        echo "y" | ufw enable 2>/dev/null || true
        log "UFW 防火墙规则配置完成"

    elif [[ "$OS_FAMILY" == "redhat" ]]; then
        systemctl enable --now firewalld 2>/dev/null || true
        firewall-cmd --permanent --add-service=ssh
        firewall-cmd --permanent --add-service=http
        firewall-cmd --permanent --add-service=https
        firewall-cmd --permanent --add-port=51821/udp
        firewall-cmd --permanent --add-port=3478/udp
        firewall-cmd --permanent --add-port=51820/udp
        firewall-cmd --reload
        log "Firewalld 防火墙规则配置完成"
    fi
}

# ─── 启动服务 ────────────────────────────────────────────────────
start_services() {
    section "启动 P2P Mesh 服务"

    cd "$DEPLOY_DIR"

    info "启动所有容器..."
    docker compose -f "$COMPOSE_FILE" --env-file .env up -d --remove-orphans 2>&1 | tee -a "$LOG_FILE"

    log "服务启动指令已发送"
}

# ─── 等待服务健康 ──────────────────────────────────────────────────
wait_for_healthy() {
    section "等待服务就绪"

    local max_wait=180
    local waited=0
    local interval=5

    info "等待所有服务健康就绪 (最长 ${max_wait}s)..."

    while [[ $waited -lt $max_wait ]]; do
        local unhealthy=$(docker compose -f "$COMPOSE_FILE" --env-file .env ps --format json 2>/dev/null | \
            jq -r 'select(.Health != "" and .Health != "healthy") | "\(.Name): \(.Health)"' 2>/dev/null || true)

        if [[ -z "$unhealthy" ]]; then
            log "所有服务健康就绪!"
            break
        fi

        if [[ $((waited % 15)) -eq 0 ]]; then
            info "等待中... (${waited}s/$max_wait)"
        fi

        sleep "$interval"
        waited=$((waited + interval))
    done

    if [[ $waited -ge $max_wait ]]; then
        warn "部分服务可能未完全就绪，请稍后检查"
    fi
}

# ─── 健康验证 ────────────────────────────────────────────────────
health_check() {
    section "健康检查"

    cd "$DEPLOY_DIR"

    # 显示所有容器状态
    info "容器状态:"
    docker compose -f "$COMPOSE_FILE" --env-file .env ps 2>&1 | tee -a "$LOG_FILE"

    # 检查 API 端点
    info "API 健康检查:"
    local api_host="localhost"
    local api_port="8000"

    # 尝试通过 nginx 检查
    if curl -sf http://localhost/health >/dev/null 2>&1; then
        HEALTH_RESP=$(curl -s http://localhost/health)
        echo "  Nginx → API: $HEALTH_RESP"
        log "Nginx 健康检查通过"
    elif curl -sf http://localhost:8000/health >/dev/null 2>&1; then
        HEALTH_RESP=$(curl -s http://localhost:8000/health)
        echo "  Direct API: $HEALTH_RESP"
        log "API 直连健康检查通过"
    else
        warn "API 健康检查未通过，服务可能仍在初始化中"
    fi

    # 检查关键端口
    info "端口监听:"
    for port in 80 443 5432 6379 3478 51821; do
        if ss -tuln 2>/dev/null | grep -q ":${port} "; then
            log "端口 ${port} — 监听中"
        else
            warn "端口 ${port} — 未监听 (可能不需要或仍在启动)"
        fi
    done
}

# ─── SSL 证书配置 ──────────────────────────────────────────────────
setup_ssl() {
    if [[ -z "$DOMAIN" ]]; then
        section "SSL 证书 (跳过)"
        info "未指定域名，跳过 SSL 配置"
        info "如需启用 SSL: sudo bash scripts/deploy-server.sh --domain mesh.yourdomain.com"
        return
    fi

    section "配置 Let's Encrypt SSL 证书"

    if ! command -v certbot &>/dev/null; then
        if [[ "$OS_FAMILY" == "debian" ]]; then
            apt-get install -y -qq certbot python3-certbot-nginx
        elif [[ "$OS_FAMILY" == "redhat" ]]; then
            dnf install -y certbot python3-certbot-nginx
        fi
    fi

    # 停止 nginx 以获取证书 (standalone 模式)
    docker compose -f "$COMPOSE_FILE" --env-file .env stop nginx 2>/dev/null || true

    # 获取证书
    if certbot certonly --standalone \
        -d "$DOMAIN" \
        --non-interactive \
        --agree-tos \
        --email "admin@${DOMAIN}" \
        --no-eff-email 2>&1 | tee -a "$LOG_FILE"; then

        # 复制证书到 nginx ssl 目录
        cp "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" "${DEPLOY_DIR}/nginx/ssl/server.crt" 2>/dev/null || true
        cp "/etc/letsencrypt/live/${DOMAIN}/privkey.pem" "${DEPLOY_DIR}/nginx/ssl/server.key" 2>/dev/null || true
        chmod 600 "${DEPLOY_DIR}/nginx/ssl/server.key" 2>/dev/null || true

        # 使用生产配置
        cp "${DEPLOY_DIR}/nginx/nginx.prod.conf" "${DEPLOY_DIR}/nginx/nginx.conf" 2>/dev/null || true

        log "SSL 证书获取成功: $DOMAIN"
    else
        warn "SSL 证书获取失败，将以 HTTP 模式运行"
        warn "请确保域名 DNS 已正确解析到本服务器 IP"
    fi

    # 重启 nginx
    docker compose -f "$COMPOSE_FILE" --env-file .env up -d nginx 2>/dev/null || true
}

# ─── 设置自动更新 (可选) ──────────────────────────────────────────
setup_cron() {
    section "设置定时任务"

    # SSL 证书自动续期 (如果有域名)
    if [[ -n "$DOMAIN" ]]; then
        local cron_job="0 3 * * * certbot renew --quiet --post-hook 'docker compose -f ${DEPLOY_DIR}/${COMPOSE_FILE} --env-file ${DEPLOY_DIR}/.env restart nginx'"
        if ! crontab -l 2>/dev/null | grep -q "certbot renew"; then
            (crontab -l 2>/dev/null; echo "$cron_job") | crontab -
            log "已添加 SSL 证书自动续期任务 (每天 3:00 AM)"
        fi
    fi

    # Docker 日志清理 (每周)
    local cleanup_job="0 2 * * 0 docker system prune -af --filter 'until=168h' >/dev/null 2>&1"
    if ! crontab -l 2>/dev/null | grep -q "docker system prune"; then
        (crontab -l 2>/dev/null; echo "$cleanup_job") | crontab -
        log "已添加 Docker 清理任务 (每周日 2:00 AM)"
    fi
}

# ─── 显示摘要 ────────────────────────────────────────────────────
print_summary() {
    section "部署完成 — 摘要"

    echo ""
    echo -e "${BOLD}${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${GREEN}║              🎉 部署成功！Deployment Complete!               ║${NC}"
    echo -e "${BOLD}${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    echo -e "${BOLD}📋 服务地址:${NC}"
    echo -e "  API Gateway:      ${CYAN}http://localhost${NC}"
    if [[ -n "$DOMAIN" ]]; then
        echo -e "  Public API:       ${CYAN}https://${DOMAIN}${NC}"
    fi
    echo -e "  Prometheus:       ${CYAN}http://localhost:9090${NC}"
    echo -e "  Grafana:          ${CYAN}http://localhost:3000${NC}"
    echo -e "  Jaeger (Tracing): ${CYAN}http://localhost:16686${NC}"
    echo ""

    echo -e "${BOLD}🔑 登录凭据:${NC}"
    echo -e "  Grafana:  admin / ${YELLOW}${GRAFANA_PASSWORD}${NC}"
    echo ""

    echo -e "${BOLD}📁 关键文件:${NC}"
    echo -e "  环境变量:     ${PROJECT_DIR}/deployment/.env"
    echo -e "  部署日志:     ${LOG_FILE}"
    echo -e "  Docker 配置:  ${DEPLOY_DIR}/${COMPOSE_FILE}"
    echo ""

    echo -e "${BOLD}🔧 常用命令:${NC}"
    echo -e "  查看日志:     ${CYAN}cd ${DEPLOY_DIR} && docker compose -f ${COMPOSE_FILE} logs -f${NC}"
    echo -e "  重启服务:     ${CYAN}cd ${DEPLOY_DIR} && docker compose -f ${COMPOSE_FILE} restart${NC}"
    echo -e "  停止服务:     ${CYAN}cd ${DEPLOY_DIR} && docker compose -f ${COMPOSE_FILE} down${NC}"
    echo -e "  运行验证:     ${CYAN}bash ${PROJECT_DIR}/scripts/verify.sh${NC}"
    echo ""

    echo -e "${BOLD}📊 监控面板:${NC}"
    echo -e "  打开浏览器访问: ${CYAN}${PROJECT_DIR}/dashboard/index.html${NC}"
    echo ""

    echo -e "${BOLD}⚠️  安全提醒:${NC}"
    echo -e "  - ${RED}请立即备份 .env 文件到安全位置${NC}"
    echo -e "  - 修改 Grafana 默认密码: 登录后 Settings → Password"
    echo -e "  - 生产环境建议配置 SSL 证书: 重新运行脚本并加 --domain 参数"
    echo -e "  - 定期更新 Docker 镜像: docker compose pull && docker compose up -d"
    echo ""
}

# ─── 主函数 ──────────────────────────────────────────────────────
main() {
    # 检查 root 权限
    if [[ "$EUID" -ne 0 ]]; then
        error "请使用 root 权限运行: sudo bash scripts/deploy-server.sh"
        exit 1
    fi

    # 初始化日志
    mkdir -p "$(dirname "$LOG_FILE")"
    echo "=== P2P Mesh 部署日志 — $(date '+%Y-%m-%d %H:%M:%S') ===" > "$LOG_FILE"

    banner
    parse_args "$@"

    # 检查项目目录
    if [[ ! -f "${PROJECT_DIR}/deployment/docker-compose.yml" ]]; then
        error "未找到项目文件。请确保脚本在项目根目录下运行。"
        error "期望路径: ${PROJECT_DIR}/deployment/docker-compose.yml"
        info "提示: 将项目克隆到 /opt/p2p-mesh 或使用 --dir 指定路径"
        exit 1
    fi

    # 执行部署步骤
    detect_os
    install_tools
    install_docker
    generate_secrets
    create_env_file
    select_compose_file
    setup_directories
    setup_firewall
    build_images
    start_services
    wait_for_healthy
    setup_ssl
    health_check
    setup_cron
    print_summary

    # 保存密钥备份提醒
    info "密钥备份: 请将以下文件安全保存 (例如密码管理器)"
    info "  ${DEPLOY_DIR}/.env"

    echo ""
    log "部署脚本执行完毕。$(date '+%Y-%m-%d %H:%M:%S')"
}

# 执行主函数
main "$@"
