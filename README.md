# P2P Mesh Network

A production-grade P2P mesh networking system, similar in concept to Tailscale / ZeroTier, built with Python (control plane) and Rust (data plane).

## Architecture

```
                    ┌──────────────────────────────┐
                    │        API Gateway (Nginx)     │
                    └────────────┬─────────────────┘
                                 │
        ┌────────────────────────▼────────────────────────┐
        │                 Control Plane (Python)           │
        │  FastAPI + Redis + PostgreSQL                    │
        │  - Auth (JWT/OAuth2)                             │
        │  - Device Management                             │
        │  - Network Scheduling (P2P path / Relay)         │
        │  - WebSocket Signaling                           │
        │  - Billing & Traffic QoS                         │
        └────────────┬───────────────┬───────────────────┘
                     │               │
        ┌────────────▼───────┐   ┌───▼────────────────┐
        │  Data Plane (Rust)  │   │  Data Plane (Rust)  │
        │  P2P Tunnel Client  │   │  Relay Forwarder    │
        │  NAT Hole Punch     │   │  Encrypted Passthru │
        └────────────┬───────┘   └───┬────────────────┘
                     │               │
            ┌────────▼────┐    ┌────▼────────┐
            │   Android    │    │   PC / IoT   │
            └─────────────┘    └─────────────┘
```

## Project Structure

```
p2p-mesh/
├── control-plane/                      # Python FastAPI backend
│   ├── app/
│   │   ├── main.py                     # FastAPI entry point
│   │   ├── config.py                   # Configuration management
│   │   ├── database.py                 # PostgreSQL + Redis connections
│   │   ├── dependencies.py             # Auth dependencies (JWT)
│   │   ├── models/                     # SQLAlchemy ORM models
│   │   │   ├── user.py                 # User (plan, role)
│   │   │   ├── device.py               # Device (NAT type, public key)
│   │   │   ├── relay.py                # Relay node
│   │   │   └── traffic.py              # Traffic/Subscription/Invoice
│   │   ├── schemas/                    # Pydantic request/response schemas
│   │   ├── services/                   # Business logic layer
│   │   │   ├── auth_service.py         # JWT, bcrypt password hashing
│   │   │   ├── device_service.py       # Device CRUD, heartbeats
│   │   │   ├── network_service.py      # P2P path selection, NAT matrix
│   │   │   ├── relay_service.py        # Relay management, health checks
│   │   │   ├── billing_service.py      # Traffic accounting, QoS, plans
│   │   │   └── signaling_service.py    # WebSocket signaling hub
│   │   ├── api/                        # REST API routes
│   │   │   ├── auth.py                 # Login / Register / Profile
│   │   │   ├── devices.py              # Device CRUD / Heartbeat
│   │   │   ├── network.py              # Path finding / NAT check
│   │   │   ├── relay.py                # Relay registration / heartbeat
│   │   │   ├── traffic.py              # Traffic report / QoS
│   │   │   ├── billing.py              # Subscriptions / Invoices
│   │   │   └── ws.py                   # WebSocket signaling endpoint
│   │   └── middleware/                 # Rate limiting, logging
│   ├── alembic/                        # Database migrations
│   ├── requirements.txt
│   └── tests/
├── data-plane/                         # Rust high-performance core
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs
│       ├── crypto/mod.rs               # ChaCha20-Poly1305 AEAD encrypt
│       ├── tunnel/mod.rs               # P2P tunnel management
│       ├── tunnel/main.rs              # mesh-tunnel binary
│       ├── relay/mod.rs                # Relay forwarding logic
│       └── relay/main.rs               # mesh-relay binary
├── deployment/
│   ├── docker-compose.yml              # Full stack (API + DB + Redis + Nginx + Relay)
│   ├── Dockerfile.api                  # Python API container
│   ├── Dockerfile.relay                # Rust relay multi-stage build
│   ├── nginx/nginx.conf                # API gateway (rate limit, WS proxy)
│   ├── init.sql                        # PostgreSQL init (extensions, indexes)
│   └── k8s/
│       ├── api-deployment.yaml         # Deployment + HPA + Service + Secrets
│       └── relay-daemonset.yaml        # DaemonSet with hostNetwork
├── monitoring/
│   ├── prometheus.yml
│   └── grafana/dashboards/
│       └── p2p-mesh-overview.json
├── .env.example
├── .gitignore
└── README.md
```

## Quick Start (Docker Compose)

```bash
cd p2p-mesh
cp .env.example .env
# Edit .env with your secrets (especially JWT_SECRET)

cd deployment
docker-compose up -d

# Check health
curl http://localhost:8000/health

# Register
curl -X POST http://localhost:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"securepass123","name":"Test User"}'

# Login (returns JWT token)
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"securepass123"}'

# Register device
curl -X POST http://localhost:8000/api/v1/devices \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"name":"my-laptop","public_key":"base64-public-key"}'
```

## Services

| Service     | URL                      | Purpose                    |
| ----------- | ------------------------ | -------------------------- |
| API         | http://localhost:8000    | Control plane REST API     |
| Nginx       | http://localhost:80      | API gateway                |
| PostgreSQL  | localhost:5432           | Primary database           |
| Redis       | localhost:6379           | Cache & signaling          |
| Prometheus  | http://localhost:9090    | Metrics collection         |
| Grafana     | http://localhost:3000    | Dashboards (admin/admin)   |

## Key Capabilities

- **User System**: JWT + bcrypt, plan-based access control
- **Device Management**: Public key registration, NAT type detection
- **P2P Path Selection**: NAT compatibility matrix for direct vs relay routing
- **WebSocket Signaling**: Real-time SDP/ICE relay for connection setup
- **Relay Orchestration**: Region-aware, load-balanced relay selection
- **Traffic Accounting**: Per-session byte tracking with batch reporting
- **Billing System**: Free/Pro/Enterprise plans with subscription lifecycle
- **Zero-Trust Security**: ChaCha20-Poly1305 AEAD, server never decrypts traffic
- **Production Deploy**: Docker Compose (dev) + Kubernetes HPA/DaemonSet (prod)
- **Monitoring**: Prometheus metrics + Grafana dashboards

## Building Rust Data Plane

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

## Development Roadmap

| Phase | Duration  | Deliverables                                     |
| ----- | --------- | ------------------------------------------------ |
| 1     | 1 week    | User system, device registration, WebSocket      |
| 2     | 2 weeks   | Rust tunnel, P2P connections, NAT hole punching  |
| 3     | 2 weeks   | Relay forwarding system, traffic statistics      |
| 4     | 2 weeks   | Billing, QoS, subscription management            |
| 5     | Launch    | K8s deployment, multi-region relay nodes         |

## Security

- Control plane: TLS at Nginx, JWT API auth
- Data plane: ChaCha20-Poly1305 AEAD, keys never touch server
- Zero-trust: Relay nodes forward without decryption
- Rate limiting: Per-IP sliding window on gateway

## Production Deployment

See [PRODUCTION.md](./PRODUCTION.md) for complete guides covering three deployment strategies:

| 方案 | 适用场景 | 月成本 |
|------|----------|--------|
| 单机 VPS + Docker | 小型团队 | $20-50 |
| 多机 Docker Swarm | 中型规模、多地域 | $100-300 |
| Kubernetes 集群 | 大规模、高可用 | $300+ |

Quick VPS setup:
```bash
sudo bash scripts/setup-server.sh
git clone <repo> /opt/p2p-mesh
cp .env.prod.example .env.prod && nano .env.prod
certbot certonly --standalone -d mesh.yourdomain.com
docker compose -f deployment/docker-compose.prod.yml up -d
```
