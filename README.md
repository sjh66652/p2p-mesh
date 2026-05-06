# P2P Mesh Network

A production-grade P2P mesh networking system (similar in concept to Tailscale / ZeroTier), built with Python (control plane) and Rust (data plane). Microservices architecture with 5 independent services, distributed WebSocket signaling, usage-based quota system, and full observability stack.

## Architecture

```
                        ┌──────────────────────────────┐
                        │      Nginx API Gateway        │
                        │    (SSL, WAF, rate-limit)     │
                        └────────────┬─────────────────┘
                                     │
        ┌──────────┬──────────┬──────┴──────┬──────────┬──────────┐
        │          │          │             │          │          │
   ┌────▼────┐┌────▼────┐┌────▼─────┐┌──────▼───┐┌─────▼────┐┌────▼───┐
   │  Auth   ││  User   ││Signaling ││  Relay   ││  Usage   ││ Worker │
   │ Service ││ Service ││ Service  ││ Service  ││ Service  ││(bg job)│
   └────┬────┘└────┬────┘└────┬─────┘└──────┬───┘└─────┬────┘└────┬───┘
        │          │          │             │          │          │
        └──────────┴──────────┴──────┬──────┴──────────┴──────────┘
                                     │
                    ┌────────────────┼────────────────┐
              ┌─────▼─────┐   ┌─────▼─────┐   ┌──────▼──────┐
              │ PostgreSQL │   │   Redis   │   │ Rust Relay  │
              │   (16)     │   │   (7)     │   │ (UDP 51821) │
              └────────────┘   └───────────┘   └─────────────┘

        ┌──────────┬──────────┬──────────┬──────────┐
   ┌────▼────┐┌────▼────┐┌────▼────┐┌───▼────┐┌───▼────┐
   │Promethe.││ Grafana ││  Loki   ││Promtail││ Jaeger │
   │ :9090   ││ :3000   ││ :3100   ││  logs  ││ :16686 │
   └─────────┘└─────────┘└─────────┘└────────┘└────────┘
```

## Project Structure

```
p2p-mesh/
├── services/                           # Microservices (Python/FastAPI)
│   ├── shared/app/                     # Shared library (12 modules)
│   │   ├── config.py                   # Base configuration
│   │   ├── jwt_utils.py                # JWT create/verify/revoke
│   │   ├── database.py                 # SQLAlchemy async engine
│   │   ├── models_base.py              # Canonical SQLAlchemy Base
│   │   ├── schemas_base.py             # Base Pydantic schemas
│   │   ├── middleware.py               # Inter-service auth middleware
│   │   ├── metrics.py                  # Prometheus metrics helpers
│   │   ├── usage_middleware.py         # Quota enforcement middleware
│   │   ├── audit.py                    # Audit logging
│   │   └── tracing.py                  # OpenTelemetry setup
│   ├── auth-service/                   # Authentication & authorization
│   │   ├── app/main.py, config.py, database.py
│   │   ├── app/models.py, schemas.py
│   │   ├── app/service.py, dependencies.py, api.py
│   │   ├── requirements.txt, Dockerfile
│   ├── user-service/                   # User profiles & device management
│   │   └── (same structure as auth-service)
│   ├── signaling-service/              # WebSocket signaling (Redis Pub/Sub)
│   │   ├── app/pubsub.py               # Distributed signaling via Redis
│   │   └── (same structure)
│   ├── relay-service/                  # Relay node management & traffic
│   │   └── (same structure)
│   ├── usage-service/                  # Quota management & rate limiting
│   │   └── (same structure)
│   └── worker/                         # Background task worker
│       └── app/worker.py, config.py
├── control-plane/                      # Legacy monolith (kept for reference)
├── data-plane/                         # Rust high-performance core
│   ├── Cargo.toml
│   └── src/
│       ├── crypto/mod.rs               # ChaCha20-Poly1305 AEAD
│       ├── tunnel/mod.rs, main.rs      # mesh-tunnel binary
│       └── relay/mod.rs, main.rs       # mesh-relay binary
├── deployment/
│   ├── docker-compose.microservices.yml    # 12-container dev stack
│   ├── docker-compose.microservices.prod.yml # Production version
│   ├── docker-compose.yml              # Legacy monolith compose
│   ├── .env                            # Dev environment variables (gitignored)
│   ├── .env.example                    # Template — copy and fill in
│   ├── nginx/nginx.conf                # API gateway with microservice routing
│   ├── nginx/nginx.prod.conf           # Production nginx config
│   ├── init.sql                        # PostgreSQL init script
│   ├── Dockerfile.api, Dockerfile.relay
│   └── k8s/
│       ├── microservices/              # K8s manifests for microservices
│       │   ├── namespace.yaml, configmap.yaml
│       │   ├── postgres.yaml, redis.yaml
│       │   ├── services.yaml, ingress.yaml
│       │   ├── hpa.yaml, kustomization.yaml
│       ├── api-deployment.yaml         # Legacy monolith K8s
│       └── relay-daemonset.yaml
├── monitoring/
│   ├── prometheus.yml                  # Scrape targets for all services
│   ├── loki-config.yaml                # Log aggregation config
│   ├── promtail-config.yaml            # Log collector config
│   └── grafana/
│       ├── provisioning/               # Datasource provisioning
│       └── dashboards/p2p-mesh-overview.json
├── scripts/
│   ├── setup-server.sh                 # VPS one-click setup
│   └── verify.sh                       # Deployment verification
├── .github/workflows/deploy.yml        # CI/CD (matrix build for 6 services)
├── .env.prod.example                   # Production env template
├── PRODUCTION.md                       # Production deployment guide
├── SECURITY.md                         # Security policy & audit history
└── README.md                           # This file
```

## Quick Start (Docker Compose — Microservices)

### Prerequisites

- Docker 24+ with Docker Compose plugin
- 4 GB RAM free (the full stack runs ~3 GB)

### 1. Clone and configure

```bash
git clone <repo-url> p2p-mesh
cd p2p-mesh

# Copy and edit environment variables
cp deployment/.env.example deployment/.env
# Edit deployment/.env with your secrets (see checklist below)
```

### 2. Start the full stack

```bash
cd deployment
docker compose -f docker-compose.microservices.yml --env-file .env up -d --build
```

### 3. Wait for all services to be healthy

```bash
# Watch container status (Ctrl+C to exit)
docker compose -f docker-compose.microservices.yml ps --watch

# Or check with curl
curl http://localhost/health
```

### 4. Quick API test

```bash
# Register a user
curl -X POST http://localhost/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"SecurePass123!","name":"Test User"}'

# Login (returns JWT token)
curl -X POST http://localhost/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"SecurePass123!"}'

# Use the token for authenticated requests
export TOKEN="<token-from-login-response>"

# Register a device
curl -X POST http://localhost/api/v1/devices \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"my-laptop","public_key":"base64-public-key"}'
```

## Services at a Glance

| Service | Internal Port | Public Port | Endpoint Prefix | Purpose |
|---------|--------------|-------------|-----------------|---------|
| **Nginx** | — | 80, 443 | `/` | API gateway, SSL termination, rate limiting |
| **Auth Service** | 8000 | — | `/api/v1/auth/` | Registration, login, token management, JWT |
| **User Service** | 8000 | — | `/api/v1/users/`, `/api/v1/devices/` | User profiles, device CRUD, heartbeats |
| **Signaling Service** | 8000 | — | `/ws/signaling/` | WebSocket signaling hub (Redis Pub/Sub) |
| **Relay Service** | 8000 | — | `/api/v1/relay/`, `/api/v1/traffic/` | Relay management, traffic reports |
| **Usage Service** | 8000 | — | `/api/v1/usage/` | Quota checks, rate limiting, plan enforcement |
| **Worker** | — | — | — | Background jobs, cleanup, usage aggregation |
| **PostgreSQL** | 5432 | 127.0.0.1:5432 | — | Primary database (shared) |
| **Redis** | 6379 | 127.0.0.1:6379 | — | Cache, signaling Pub/Sub, rate limit counters |
| **Relay (Rust)** | 51821/udp | 51821/udp | — | High-performance UDP packet forwarder |
| **Prometheus** | 9090 | 127.0.0.1:9090 | — | Metrics collection |
| **Grafana** | 3000 | 127.0.0.1:3000 | — | Dashboards & alerting |
| **Loki** | 3100 | 127.0.0.1:3100 | — | Log aggregation |
| **Promtail** | — | — | — | Ships Docker logs to Loki |
| **Jaeger** | 16686 | 127.0.0.1:16686 | — | Distributed tracing UI |

## API Endpoints

### Auth Service (`/api/v1/auth/`)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/auth/register` | No | Register new user |
| POST | `/auth/login` | No | Login, returns JWT |
| POST | `/auth/logout` | JWT | Revoke current token |
| POST | `/auth/refresh` | JWT | Refresh access token |
| GET | `/auth/me` | JWT | Get current user info |

### User Service (`/api/v1/`)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/users/me` | JWT | Get own profile |
| PUT | `/users/me` | JWT | Update own profile |
| GET | `/devices` | JWT | List own devices |
| POST | `/devices` | JWT | Register new device |
| PUT | `/devices/{id}` | JWT | Update device |
| DELETE | `/devices/{id}` | JWT | Delete device |
| POST | `/devices/{id}/heartbeat` | JWT | Device heartbeat |

### Relay Service (`/api/v1/`)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/relay/register` | Admin | Register relay node |
| GET | `/relay` | JWT | List relay nodes |
| POST | `/relay/{id}/heartbeat` | Internal/Admin | Relay heartbeat |
| DELETE | `/relay/{id}` | Admin | Delete relay node |
| POST | `/traffic/report` | JWT | Submit traffic report |

### Signaling Service

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| WS | `/ws/signaling/{device_id}` | JWT | WebSocket signaling connection |

### Usage Service (`/api/v1/usage/`)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/usage/me` | JWT | Get current usage stats |
| POST | `/usage/check` | Internal | Check quota for action |

## Security

Defense-in-depth across every layer. 16 vulnerabilities patched as of May 2026.

- **Transport**: Nginx enforces TLS 1.2+, HSTS headers
- **Authentication**: JWT (HS256) with jti-based precise revocation, bcrypt (rounds=12)
- **Inter-service**: Shared `INTERNAL_API_KEY` header for service-to-service calls
- **Data plane**: ChaCha20-Poly1305 AEAD, keys never touch the server
- **Zero-trust relay**: Relay nodes forward encrypted packets without decryption
- **Rate limiting**: Nginx layer + Redis sliding window (multi-replica safe)
- **Input validation**: Pydantic schemas, SQLAlchemy ORM (no raw SQL), 1MB body limit
- **Container security**: Non-root user (`USER mesh`), minimal base images
- **Secrets**: All secrets via environment variables, never hardcoded

See [SECURITY.md](./SECURITY.md) for the full audit history and incident response procedures.

## Monitoring & Observability

### Access URLs

| Tool | URL | Default Credentials |
|------|-----|-------------------|
| Grafana | http://localhost:3000 | `admin` / (set in `.env`) |
| Prometheus | http://localhost:9090 | No auth (internal only) |
| Jaeger | http://localhost:16686 | No auth (internal only) |

### Logs

```bash
# View logs for a specific service
docker compose -f deployment/docker-compose.microservices.yml logs -f auth-service

# View all logs
docker compose -f deployment/docker-compose.microservices.yml logs -f

# Logs are also aggregated in Loki and viewable in Grafana
```

### Metrics

Every microservice exposes `/metrics` in Prometheus format. Key metrics:

- `p2p_mesh_http_requests_total` — Request count by service, method, path, status
- `p2p_mesh_http_request_duration_seconds` — Request latency histogram
- `p2p_mesh_ws_connections` — Active WebSocket connections
- `p2p_mesh_usage_quota_remaining` — User quota remaining by plan

## Building the Rust Data Plane

```bash
cd data-plane
cargo build --release

# Run tunnel client
./target/release/mesh-tunnel \
  --api-url http://localhost:8000 \
  --token "<jwt-token>" \
  --device-id "<device-uuid>"

# Run relay node
./target/release/mesh-relay \
  --api-url http://localhost:8000 \
  --relay-id "relay-us-east-1" \
  --region "us-east-1"
```

## Deployment Options

Three strategies, from simple to enterprise:

| Strategy | Scale | Monthly Cost | Guide |
|----------|-------|-------------|-------|
| Single VPS + Docker Compose | Small team (≤50 users) | $20-50 | [Quick Start](#quick-start-docker-compose--microservices) |
| Multi-VPS + Docker Swarm | Medium (≤500 users) | $100-300 | [PRODUCTION.md](./PRODUCTION.md) §方案B |
| Kubernetes Cluster | Large (500+ users) | $300+ | [PRODUCTION.md](./PRODUCTION.md) §方案C |

For Kubernetes, use the manifests in `deployment/k8s/microservices/`:

```bash
kubectl apply -k deployment/k8s/microservices/
```

## CI/CD

GitHub Actions workflow (`.github/workflows/deploy.yml`) builds all 6 services in matrix:

- auth-service, user-service, signaling-service, relay-service, usage-service, worker
- Runs `bandit` (Python SAST), `pip-audit` (dependency CVE scan)
- Runs `cargo audit` and `cargo clippy` on Rust data plane
- Manual approval gate before production deploy

---

## Post-Deployment Local Modifications Checklist

After running `docker compose up -d`, you **must** change the following before any production use. Open `deployment/.env` and replace every value.

### Critical — Must Change

| Variable | Current Dev Value | How to Generate | Used By |
|----------|-------------------|-----------------|---------|
| `JWT_SECRET` | `dev-jwt-secret-change-me-in-production...` | `openssl rand -hex 64` | All 5 microservices |
| `POSTGRES_PASSWORD` | `mesh_dev_password_change_me` | `openssl rand -base64 32` | All services + PostgreSQL |
| `REDIS_PASSWORD` | `redis_dev_password_change_me` | `openssl rand -hex 16` | All services + Redis |
| `RELAY_AUTH_TOKEN` | `dev-relay-auth-token-change-me...` | `openssl rand -hex 32` | relay-service + Rust relay |
| `INTERNAL_API_KEY` | `dev-internal-api-key-change-me...` | `openssl rand -hex 32` | All 5 microservices (inter-service auth) |

### Recommended — Should Change

| Variable | Current Dev Value | Notes |
|----------|-------------------|-------|
| `GRAFANA_PASSWORD` | `grafana_dev_password_change_me` | Change to a strong unique password |
| `GRAFANA_USER` | `admin` | Optional, but changing adds obscurity |
| `LOG_LEVEL` | `INFO` | Set to `WARNING` in production to reduce log volume |
| `DEBUG` | `false` | Must remain `false` in production |
| `RELAY_ID` | `relay-primary` | Set to a meaningful identifier for your deployment |

### Optional — Tune for Your Environment

| Setting | Location | Notes |
|---------|----------|-------|
| CORS origins | `deployment/nginx/nginx.conf` | Replace `*` with your domain whitelist |
| Rate limits | `deployment/nginx/nginx.conf` lines 44-45 | Adjust `rate=60r/m` for API, `rate=10r/m` for login |
| SSL certificates | `deployment/nginx/ssl/` | Place your `fullchain.pem` and `privkey.pem` here |
| Prometheus retention | `docker-compose.microservices.yml` prometheus command | Default 15 days; adjust `--storage.tsdb.retention.time` |
| Loki retention | `monitoring/loki-config.yaml` | Loki keeps no retention by default; add `retention_period: 720h` |
| Database port exposure | `docker-compose.microservices.yml` postgres/redis | Remove `ports:` section entirely in production (only expose via internal network) |
| OpenTelemetry | Each service's `OTEL_*` env vars | Uncomment `OTEL_ENABLED` and `OTEL_EXPORTER_OTLP_ENDPOINT` to enable tracing |

### Kubernetes Deployments — Additional Changes

| File | What to Change |
|------|---------------|
| `deployment/k8s/microservices/configmap.yaml` | All placeholder values |
| `deployment/k8s/microservices/services.yaml` | Image registry, resource limits per service |
| `deployment/k8s/microservices/ingress.yaml` | Domain name, TLS certificate ARN / secret name |
| `deployment/k8s/microservices/hpa.yaml` | Min/max replicas per service |
| `deployment/k8s/microservices/postgres.yaml` | Storage class, size; consider using cloud RDS instead |

### Docker Image Registry

If using a private registry or mirror (e.g., Aliyun for China):

```bash
# Edit each service's Dockerfile to change the pip mirror
# Currently: https://mirrors.aliyun.com/pypi/simple/

# For Docker Hub mirror, configure Docker daemon:
# /etc/docker/daemon.json:
# { "registry-mirrors": ["https://docker.1ms.run"] }
```

### Grafana Setup After First Login

1. Login at http://localhost:3000 with credentials from `.env`
2. Datasources (Prometheus, Loki) are auto-provisioned from `monitoring/grafana/provisioning/`
3. Import additional dashboards from `monitoring/grafana/dashboards/`
4. Configure alert notification channels (Slack, email, etc.)
5. Change the default password immediately

### Firewall Rules

```bash
# Public-facing ports (must be open):
#   80/tcp   — HTTP (redirects to 443)
#   443/tcp  — HTTPS API gateway
#   51821/udp — Relay node (if running relay)

# Internal-only ports (should NOT be exposed to internet):
#   5432, 6379, 8000, 9090, 3000, 3100, 16686

# UFW example:
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 51821/udp
sudo ufw enable
```

### Quick Verification Script

```bash
# Run this after deployment to verify everything works
bash scripts/verify.sh

# Or manually:
# 1. Check all containers healthy
docker compose -f deployment/docker-compose.microservices.yml ps

# 2. Test each service health endpoint
curl -s http://localhost/health | grep '"status":"healthy"'

# 3. Verify registration flow
curl -s -X POST http://localhost/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@verify.local","password":"Verify123!","name":"Verify"}'

# 4. Check Prometheus targets
curl -s http://localhost:9090/api/v1/targets | grep '"health":"up"'

# 5. Check Grafana is accessible
curl -s -o /dev/null -w "%{http_code}" http://localhost:3000
```

---

## Development

### Running a single service locally

```bash
cd services/auth-service
cp ../../deployment/.env .env
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8001
```

### Database migrations

Each service manages its own tables via SQLAlchemy `create_all()` on startup. For production, consider using Alembic migrations per service.

### Pre-commit checks

```bash
# Python
bandit -r services/ -ll
pip-audit -r services/auth-service/requirements.txt

# Rust
cd data-plane && cargo clippy --all-targets -- -D warnings && cargo audit
```
