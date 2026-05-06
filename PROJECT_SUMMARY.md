# P2P Mesh Network — 项目成果总结

> 2026-05-06 | 共 2 个会话 | 文件修改 13 个 | 新增文件 5 个 | 修补漏洞 16 个

---

## 第一阶段：故障诊断与启动修复

**问题**：`deployment-api-1` 服务持续重启，无法正常启动。

**根因定位**（共 4 个）：
1. JWT 导入错误 — `python-jose` 包导出的是 `jose.jwt` 而非顶层 `jwt`，3 个文件中 `import jwt` 导致 `ModuleNotFoundError`
2. PostgreSQL ENUM 类型冲突 — `CREATE TYPE` 不支持 `IF NOT EXISTS`，容器重启时 SAEnum 重复建类型报错
3. ENUM 大小写不匹配 — SQLAlchemy SAEnum 使用成员名 `'FREE'`（大写），但初始脚本创建的是 `'free'`（小写）
4. 缺乏连接重试 — 数据库启动慢于 API 时直接崩溃，无指数退避重试

**修复**：
- 新增 `_ensure_enum_types()` 预检查逻辑，大写标签匹配 SAEnum
- 新增 `_connect_database_with_retry()` 和 `_connect_redis_with_retry()`（指数退避 2s → 128s）
- Docker Compose 健康检查调优：start_period 90s，retries 10，init:true

---

## 第二阶段：安全审计与加固（黑客视角）

按照攻击者思路（侦察 → 横向移动 → 提权 → 持久化）逐一审查，共发现并修补 16 个漏洞。

### 严重（4 个）
| 漏洞 | 文件 | 修复方案 |
|------|------|----------|
| JWT 黑名单在 WebSocket 被绕过 | `ws.py` | WebSocket 握手后检查 `jwt_blacklist:{jti}` |
| 配置文件中硬编码数据库密码 | `config.py` | `_require_env("DATABASE_URL")`，无默认值 |
| ENUM 类型冲突导致重启循环 | `main.py` | `_ensure_enum_types()` 预检查，大写标签 |
| JWT 模块导入错误 | `dependencies.py` 等 3 文件 | `from jose import jwt, JWTError` |

### 高危（4 个）
| 漏洞 | 文件 | 修复方案 |
|------|------|----------|
| 中继认证可被时序攻击 | `dependencies.py` | `hmac.compare_digest()` 常数时间比较 |
| 通过不同错误信息枚举用户 | `auth.py` | 注册/登录错误统一为通用消息 |
| Redis 无密码认证 | `docker-compose.yml` | `--requirepass` + `REDISCLI_AUTH` 环境变量 |
| 速率限制器 Redis 故障后全放行 | `rate_limit.py` | Redis 不可用时降至 20 rpm 硬预算 |

### 中危（8 个）
| 漏洞 | 文件 | 修复方案 |
|------|------|----------|
| WebSocket 连接可被耗尽 | `signaling_service.py` | `MAX_CONNECTIONS = 10_000` 硬上限 |
| Prometheus 指标端点未鉴权 | `main.py` | 限制为内网 IP（172/10/127） |
| API 端口直接暴露在 0.0.0.0 | `docker-compose.yml` × 2 | 绑定 `127.0.0.1:8000`，Nginx 做唯一入口 |
| Grafana 默认密码 admin/admin | `docker-compose.yml` | `GRAFANA_PASSWORD` 环境变量，无默认值 |
| Relay 心跳始终 404 | `relay.py` + `relay_service.py` | 新增按名称自动注册心跳端点 |
| 异常捕获混淆 UUID 解析与 DB 查询 | `relay.py` | 分离 `uuid.UUID()` 与 `update_heartbeat()` 的 try/except |
| JWT_SECRET 默认值带可预测前缀 | `config.py` | 纯随机 64 字符十六进制 |
| Redis 密码泄露在 /proc/*/cmdline | `docker-compose.yml` × 2 | `REDISCLI_AUTH` 替代 `-a` 标志 |

---

## 修改文件清单

### 后端代码（7 个）
| 文件 | 变更 |
|------|------|
| `control-plane/app/main.py` | 添加数据库重试、ENUM 预检、安全启动警告、metrics IP 限制 |
| `control-plane/app/config.py` | 移除硬编码密码、加固 JWT 密钥生成、新增 RS256 配置项 |
| `control-plane/app/dependencies.py` | 修复 JWT 导入、常数时间令牌比较、JWT 黑名单检查 |
| `control-plane/app/services/auth_service.py` | 修复 JWT 导入 |
| `control-plane/app/services/signaling_service.py` | 添加连接数上限 |
| `control-plane/app/services/relay_service.py` | 新增 `heartbeat_by_name` 自动注册 |
| `control-plane/app/api/ws.py` | 修复 JWT 导入、WebSocket JWT 黑名单、白名单消息类型 |
| `control-plane/app/api/auth.py` | 注册错误信息统一化 |
| `control-plane/app/api/relay.py` | 修复异常处理、支持按名称心跳 |
| `control-plane/app/middleware/rate_limit.py` | 故障关闭 fallback |

### 部署配置（3 个）
| 文件 | 变更 |
|------|------|
| `deployment/docker-compose.yml` | 环境变量密码、local 绑定、REDISCLI_AUTH、Grafana 安全 |
| `deployment/docker-compose.prod.yml` | local 绑定、REDISCLI_AUTH、API 端口安全 |
| `deployment/Dockerfile.api` | 非 root 用户、procps 依赖 |

### 新增文件（2 个）
| 文件 | 用途 |
|------|------|
| `deployment/.env` | 开发环境变量（已 .gitignore） |
| `deployment/.env.example` | 环境变量模板，供新开发者复制 |

---

## 当前系统状态

- **端口绑定**：API → 127.0.0.1:8000，Postgres → 127.0.0.1:5432，Redis → 127.0.0.1:6379，Grafana → 127.0.0.1:3000，Prometheus → 127.0.0.1:9090
- **认证链路**：注册/登录 → JWT（HS256，黑名单撤销）→ WebSocket（同机制验证 jti）→ Relay（共享令牌，常数时间比较）
- **纵深防御**：Nginx（边缘过滤）→ 请求大小限制 → 安全头 → CORS → 速率限制（Redis 滑动窗口）→ 业务鉴权
- **监控**：Prometheus（内网 IP 限制）+ Grafana（环境变量密码）+ 结构化日志
