#!/bin/bash
# P2P Mesh Network - Server Setup Script
# 在新 VPS 上一键初始化生产环境
# 用法: sudo bash setup-server.sh

set -e

echo "=== P2P Mesh Server Setup ==="

# 1. 系统更新
echo "[1/7] Updating system..."
apt-get update && apt-get upgrade -y

# 2. 安装 Docker
echo "[2/7] Installing Docker..."
if ! command -v docker &> /dev/null; then
    curl -fsSL https://get.docker.com | sh
    usermod -aG docker $SUDO_USER
fi

# 3. 安装 Docker Compose 插件
echo "[3/7] Installing Docker Compose..."
apt-get install -y docker-compose-plugin

# 4. 安装基础工具
echo "[4/7] Installing tools..."
apt-get install -y curl wget git ufw certbot python3-certbot-nginx htop

# 5. 配置防火墙
echo "[5/7] Configuring firewall..."
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp     # SSH
ufw allow 80/tcp     # HTTP
ufw allow 443/tcp    # HTTPS
ufw allow 51821/udp  # Relay
ufw --force enable

# 6. 生成 DH 参数（用于 SSL）
echo "[6/7] Generating DH parameters (this takes a few minutes)..."
openssl dhparam -out /etc/nginx/dhparam.pem 4096 2>/dev/null || \
    openssl dhparam -dsaparam -out /etc/nginx/dhparam.pem 4096

# 7. 创建项目目录
echo "[7/7] Creating project directory..."
mkdir -p /opt/p2p-mesh
chown -R $SUDO_USER:$SUDO_USER /opt/p2p-mesh

echo ""
echo "=== Setup Complete ==="
echo ""
echo "Next steps:"
echo "  1. Clone project:  git clone <repo> /opt/p2p-mesh"
echo "  2. Copy .env.prod:  cp /opt/p2p-mesh/.env.prod.example /opt/p2p-mesh/.env.prod"
echo "  3. Edit config:     nano /opt/p2p-mesh/.env.prod"
echo "  4. Get SSL cert:    certbot certonly --standalone -d mesh.yourdomain.com"
echo "  5. Start services:  cd /opt/p2p-mesh/deployment && docker compose -f docker-compose.prod.yml up -d"
