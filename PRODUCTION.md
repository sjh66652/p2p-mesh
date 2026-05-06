# P2P Mesh Network - 生产上线指南

本文档介绍如何将项目从本地 Docker Compose 部署到生产环境，提供三种方案按需选择。

---

## 方案对比

| 方案 | 适用场景 | 月成本（估算） | 运维复杂度 |
|------|----------|---------------|-----------|
| 单机 VPS + Docker | 小型团队、验证阶段 | $20-50 | 低 |
| 多 VPS + Docker Swarm | 中等规模、多地域 | $100-300 | 中 |
| Kubernetes 集群 | 大规模、高可用 | $300+ | 高 |

---

## 一、方案 A：单机 VPS + Docker（最快上线）

### 1.1 准备服务器

推荐配置：2 vCPU / 4GB RAM / 40GB SSD（如 AWS Lightsail $20/月、阿里云/腾讯云同等配置）

```bash
# SSH 登录后安装 Docker
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
newgrp docker

# 安装 docker-compose 插件
sudo apt install docker-compose-plugin
```

### 1.2 上传项目并配置

```bash
# 在服务器上
git clone https://github.com/your-org/p2p-mesh.git
cd p2p-mesh/deployment

# 生成安全密钥
openssl rand -hex 32  # 用作 JWT_SECRET
openssl rand -base64 32  # 用作数据库密码

# 创建生产环境配置
cat > ../.env.prod << 'EOF'
JWT_SECRET=<上面生成的hex密钥>
POSTGRES_PASSWORD=<上面生成的base64密码>
DEBUG=false
LOG_LEVEL=INFO
EOF
```

### 1.3 配置域名和 SSL

```bash
# 安装 certbot
sudo apt install certbot

# 获取证书（确保域名 DNS 指向本机 IP）
sudo certbot certonly --standalone -d mesh.yourdomain.com

# 证书路径
# /etc/letsencrypt/live/mesh.yourdomain.com/fullchain.pem
# /etc/letsencrypt/live/mesh.yourdomain.com/privkey.pem
```

### 1.4 启动服务

```bash
cd deployment

# 使用生产配置启动
docker compose -f docker-compose.prod.yml --env-file ../.env.prod up -d

# 检查状态
docker compose ps
curl https://mesh.yourdomain.com/health
```

---

## 二、方案 B：多机 + Docker Swarm

适合需要多地域 Relay 节点、API 高可用的场景。

### 2.1 架构

```
         ┌── DNS (mesh.yourdomain.com)
         │
    ┌────▼─────┐
    │  Nginx LB │  (节点1：负载均衡)
    └────┬─────┘
         │
    ┌────▼─────────┐
    │  API x 3      │  (节点1：API 集群)
    │  PostgreSQL   │  (节点1：主数据库)
    │  Redis        │  (节点1：缓存)
    └──────────────┘
         │
    ┌────▼─────┐  ┌────▼─────┐  ┌────▼─────┐
    │ Relay    │  │ Relay    │  │ Relay    │
    │ us-east  │  │ eu-west  │  │ ap-south │
    └──────────┘  └──────────┘  └──────────┘
```

### 2.2 初始化 Swarm

```bash
# 在管理节点（主服务器）
docker swarm init --advertise-addr <管理节点IP>

# 输出类似：
# docker swarm join --token SWMTKN-1-xxx <IP>:2377
# 在其他节点执行上面这条命令加入集群

# 创建网络
docker network create --driver overlay mesh-net

# 创建 secrets
echo "<jwt-secret>" | docker secret create jwt_secret -
echo "<db-password>" | docker secret create db_password -
```

### 2.3 部署服务栈

```bash
docker stack deploy -c docker-compose.swarm.yml p2p-mesh

# 查看服务
docker stack services p2p-mesh

# 扩展 API
docker service scale p2p-mesh_api=5

# 扩展 Relay（按地域标签部署）
docker service scale p2p-mesh_relay=10
```

---

## 三、方案 C：Kubernetes

项目已包含 K8s 清单文件（`deployment/k8s/`），可直接用于生产集群。

### 3.1 前置条件

- Kubernetes 集群（推荐 GKE/EKS/AKS 托管服务，或自建 k3s）
- `kubectl` 已配置
- Ingress Controller 已安装（nginx-ingress 或 traefik）
- cert-manager 已安装（自动 SSL）

### 3.2 部署步骤

```bash
# 1. 创建命名空间和密钥
kubectl apply -f deployment/k8s/namespace.yaml
kubectl create secret generic mesh-secrets \
  --namespace p2p-mesh \
  --from-literal=jwt-secret="$(openssl rand -hex 32)" \
  --from-literal=db-password="$(openssl rand -base64 32)"

# 2. 部署 PostgreSQL（建议用云厂商 RDS，这里以集群内部署为例）
kubectl apply -f deployment/k8s/postgres-statefulset.yaml

# 3. 部署 Redis
kubectl apply -f deployment/k8s/redis-statefulset.yaml

# 4. 部署 API（含 HPA 自动扩缩）
kubectl apply -f deployment/k8s/api-deployment.yaml

# 5. 部署 Relay DaemonSet（每节点一个）
kubectl label nodes --all mesh-relay=enabled
kubectl apply -f deployment/k8s/relay-daemonset.yaml

# 6. 配置 Ingress
kubectl apply -f deployment/k8s/ingress.yaml

# 7. 查看状态
kubectl get pods -n p2p-mesh
kubectl get svc -n p2p-mesh
kubectl get hpa -n p2p-mesh
```

### 3.3 多地域部署

```bash
# 为各地域 Relay 节点打标签
kubectl label node relay-us-1 region=us-east-1
kubectl label node relay-eu-1 region=eu-west-1
kubectl label node relay-ap-1 region=ap-southeast-1

# Relay DaemonSet 会自动按标签调度
```

---

## 四、镜像构建与推送

### 4.1 构建并推送到 Docker Hub

```bash
# 构建 API 镜像
cd control-plane
docker build -t yourorg/p2p-mesh-api:latest -f ../deployment/Dockerfile.api .
docker push yourorg/p2p-mesh-api:latest

# 构建 Relay 镜像
cd ../data-plane
docker build -t yourorg/p2p-mesh-relay:latest -f ../deployment/Dockerfile.relay .
docker push yourorg/p2p-mesh-relay:latest
```

### 4.2 推送到阿里云容器镜像（国内推荐）

```bash
# 登录阿里云
docker login --username=yourname registry.cn-hangzhou.aliyuncs.com

# 打标签
docker tag yourorg/p2p-mesh-api:latest \
  registry.cn-hangzhou.aliyuncs.com/yourname/p2p-mesh-api:v1.0.0

# 推送
docker push registry.cn-hangzhou.aliyuncs.com/yourname/p2p-mesh-api:v1.0.0
```

---

## 五、生产安全清单

上线前必须逐项确认：

| 检查项 | 说明 |
|--------|------|
| `JWT_SECRET` | 使用 `openssl rand -hex 32` 生成，绝对不用默认值 |
| 数据库密码 | 高强度随机密码，不同服务不同密码 |
| HTTPS | 强制 TLS 1.2+，HSTS 头部 |
| 防火墙 | 仅开放 80/443（API）和 51821/udp（Relay），其余关闭 |
| 数据库 | 不暴露公网端口，仅内网访问 |
| Redis | 设置密码，不暴露公网 |
| 限流 | Nginx 层 + API 层双重限流 |
| 日志 | 不记录密码、token 等敏感信息 |
| 备份 | 数据库每日自动备份 |
| 监控 | Prometheus + Grafana + 告警规则 |

---

## 六、监控告警

```bash
# 在 Grafana 中配置告警规则

# API 不可用
# p2p_mesh_health_check{status="ok"} == 0

# Relay 负载过高
# p2p_mesh_relay_load > 0.8

# P2P 成功率下降
# p2p_mesh_p2p_success_rate < 0.6

# 数据库连接池耗尽
# p2p_mesh_db_pool_available < 5
```

---

## 七、日常运维命令

```bash
# Docker Compose
docker compose ps                          # 查看服务状态
docker compose logs -f api                 # 查看 API 日志
docker compose restart api                 # 重启 API
docker compose up -d --scale api=3         # 扩展 API 实例

# 数据库备份
docker exec deployment-postgres-1 \
  pg_dump -U mesh p2p_mesh > backup_$(date +%Y%m%d).sql

# 数据库恢复
docker exec -i deployment-postgres-1 \
  psql -U mesh p2p_mesh < backup_20260506.sql

# 证书续期
sudo certbot renew
docker compose restart nginx

# K8s
kubectl get pods -n p2p-mesh
kubectl logs -f -n p2p-mesh deployment/mesh-api
kubectl scale deployment mesh-api -n p2p-mesh --replicas=5
```
