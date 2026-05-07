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
│   ├── user-service/                   # User profiles & device management
│   ├── signaling-service/              # WebSocket signaling (Redis Pub/Sub)
│   ├── relay-service/                  # Relay node management & traffic
│   ├── usage-service/                  # Quota management & rate limiting
│   └── worker/                         # Background task worker
├── control-plane/                      # Legacy monolith (FastAPI)
│   ├── app/
│   │   ├── api/candidates.py           # Candidate registration REST API
│   │   ├── api/ws.py                   # WebSocket signaling (6 msg types)
│   │   ├── schemas/candidate.py        # Pydantic candidate models
│   │   └── services/nat_utils.py       # NAT compatibility matrix
│   └── main.py
├── data-plane/                         # Rust high-performance core
│   ├── Cargo.toml
│   └── src/
│       ├── bin/
│       │   ├── mesh-overlay.rs         # Overlay mesh node (TUN + Noise IK + ICE)
│       │   ├── mesh-stun.rs            # STUN server (UDP 3478)
│       │   ├── mesh-tunnel.rs          # P2P tunnel client endpoint
│       │   └── mesh-relay.rs           # Relay forwarding node
│       ├── crypto/noise.rs             # Noise IK handshake (X25519 + ChaCha20-Poly1305)
│       ├── crypto/mod.rs               # ChaCha20-Poly1305 AEAD
│       ├── stun/mod.rs                 # STUN client + NAT classification (RFC 5780)
│       ├── ice/mod.rs                  # ICE agent (RFC 8445): connectivity checks, role conflict
│       ├── router/mod.rs               # LPM route table with Arc<Route> + ECMP
│       ├── overlay/mod.rs              # TUN device + IPAM + ACL + route integration
│       ├── ipam/mod.rs                 # 100.64.0.0/10 CGNAT address management
│       ├── acl/mod.rs                  # Per-peer access control rules
│       ├── dns/mod.rs                  # Split-horizon DNS resolver
│       ├── puncher/mod.rs              # UDP hole punching (HELLO/ACK)
│       ├── tunnel/mod.rs               # P2P tunnel management
│       ├── quic/mod.rs                 # QUIC transport (quinn + rustls)
│       ├── multipath/mod.rs            # Multi-path routing (Direct/Relay)
│       ├── metrics/mod.rs              # EWMA network quality metrics
│       ├── relay/mod.rs                # Zero-trust relay forwarding (HMAC key zeroized on drop)
│       └── lib.rs                      # Public module declarations
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
│       │   ├── network-policies.yaml   # NetworkPolicy resources (defense-in-depth)
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
│   ├── verify.sh                       # Deployment verification
│   └── verify-upgrade.sh               # Phase 1+2 upgrade verification (6 check sections)
├── .github/workflows/deploy.yml        # CI/CD (matrix build for 6 services)
├── .env.prod.example                   # Production env template
├── PRODUCTION.md                       # Production deployment guide
├── SECURITY.md                         # Security policy & audit history
├── AUDIT-2026-05-08.md                 # Full code audit report (~100 findings, all resolved)
├── VERIFICATION-2026-05-07.md          # Phase 3 security fixes verification
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
| **STUN (Rust)** | 3478/udp | 3478/udp | — | Public address discovery for NAT traversal |
| **Relay (Rust)** | 51821/udp | 51821/udp | — | High-performance UDP packet forwarder |
| **Tunnel (Rust)** | 51820/udp | dynamic | — | P2P client with QUIC + multi-path routing |
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
| GET | `/relay/best` | JWT | Get best relay for region (authenticated) |
| POST | `/relay/{id}/heartbeat` | Internal/Admin | Relay heartbeat |
| DELETE | `/relay/{id}` | Admin | Delete relay node |
| POST | `/traffic/report` | JWT | Submit traffic report |

### Signaling Service

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| WS | `/ws/signaling/{device_id}` | JWT | WebSocket signaling connection |
| WS Msg | `candidates` | JWT | Exchange peer candidate addresses |
| WS Msg | `stun_result` | JWT | Share STUN-probed public address |
| WS Msg | `punch_request/result` | JWT | Trigger/acknowledge hole punching |
| WS Msg | `path_quality` | JWT | Report multi-path quality metrics |

### Candidate Exchange (`/api/v1/candidates/`)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/candidates` | JWT | Register device candidates (host/srflx) |
| GET | `/candidates/{device_id}` | JWT | Get peer candidates for hole punching |

### Usage Service (`/api/v1/usage/`)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/usage/me` | JWT | Get current usage stats |
| POST | `/usage/check` | Internal | Check quota for action |

## Data Plane Features

### NAT Traversal (Phase 1)

The data plane implements a complete, security-hardened NAT traversal stack:

1. **STUN Discovery** — Client sends `ping` to STUN server (UDP 3478), receives its public `IP:PORT` mapping
2. **NAT Classification** — Multi-server STUN probes classify NAT type (Full Cone / Symmetric / etc.)
3. **Candidate Exchange** — ICE-style candidates exchanged via signaling WebSocket + REST API
4. **UDP Hole Punching** — Burst of HMAC-SHA256-authenticated HELLO packets to peer candidates (max 10), HELLO_ACK confirms connectivity. Enforced 500-packet budget and unsafe-address rejection prevent abuse.
5. **Relay Fallback** — When direct P2P fails (e.g., Symmetric NAT on both sides), traffic routes through relay

### Data Plane Transport (Phase 2)

| Feature | Implementation | Details |
|---------|---------------|---------|
| **Transport** | QUIC (RFC 9000) via quinn 0.11 | TLS 1.3, 0-RTT, multiplexed streams, connection migration, SHA-256 cert pinning |
| **Encryption** | ChaCha20-Poly1305 AEAD | Data plane traffic never decrypted by control plane |
| **Key Exchange** | Noise IK + X25519 ECDH | Noise Protocol Framework IK handshake (0-RTT, mutual auth, forward secrecy); HKDF domain-separated session key derivation |
| **Multi-Path** | Direct / Relay / Local | Auto-selects best path based on RTT, loss, bandwidth |
| **Quality Metrics** | EWMA-smoothed | RTT (microsecond precision), loss rate %, bandwidth bps |
| **Relay Auth** | HMAC-SHA256 | Source device ID authentication, per-device + per-IP rate limiting; HMAC key zeroized on drop |
| **Punch Auth** | HMAC-SHA256 | HELLO/HELLO_ACK packet authentication, 10-candidate limit, 500-packet budget |

### Overlay Network (Phase 3)

| Feature | Implementation | Details |
|---------|---------------|---------|
| **Handshake** | Noise IK (Noise Protocol Framework) | 0-RTT encryption, mutual X25519 auth, forward secrecy; full initiator+responder state machine |
| **ICE** | RFC 8445 Connectivity Checks | Candidate gathering (host/srflx/relay), pair prioritization, role conflict resolution, consent freshness (RFC 7675); lock-phased to avoid async hold |
| **NAT Classification** | RFC 3489 / RFC 5780 | Multi-server STUN probes; Symmetric/Full-Cone heuristics with documented limitations |
| **Routing** | LPM + ECMP via Arc<Route> | Longest Prefix Match with CIDR trie; Equal-Cost Multi-Path round-robin; zero-clone hot-path lookups |
| **Overlay** | TUN device + IPAM + ACL | WireGuard-like TUN interface, 100.64.0.0/10 CGNAT space, per-peer ACL rules |
| **DNS** | Split-horizon resolver | Mesh-local names via hosts table, upstream bypass for non-mesh domains |

### Path Selection Strategy

```
Direct P2P (preferred)  →  Relay (fallback)  →  None (unreachable)
         ↑                        ↑
  RTT < 300ms threshold    Automatic when
  loss < 10%               Direct path fails
```

## Security

Defense-in-depth across every layer. Two comprehensive audits (May 7–8, 2026): ~100 findings identified, **all Critical, High, Medium, and actionable Low issues resolved** (6C + 7H + 10M + 7L fixed).

- **Transport**: Nginx enforces TLS 1.2+, HSTS headers
- **Authentication**: JWT (HS256) with jti-based precise revocation, device-session isolation, bcrypt (rounds=12)
- **Session invalidation**: Password change invalidates all existing JWTs (iat vs. password_updated_at check)
- **Password policy**: 10+ characters, 3 of 4 character classes, bcrypt with work factor 12
- **Brute-force protection**: Redis-based login lockout after N failed attempts
- **Registration hardening**: IP-based rate limiting (5/hour), generic error messages to prevent user enumeration
- **Audit logging**: All auth events logged; email addresses SHA-256 hashed with JWT secret to prevent PII leakage
- **Inter-service**: Shared `INTERNAL_API_KEY` header for service-to-service calls
- **JWT error handling**: Narrow exception types (ExpiredSignatureError vs JWTError); unexpected errors propagate for monitoring
- **Data plane**: ChaCha20-Poly1305 AEAD, keys never touch the server; encrypt returns Result (no panics)
- **Noise IK handshake**: Full initiator+responder state machine with 0-RTT encryption, mutual X25519 auth, forward secrecy
- **ECDH key exchange**: X25519 elliptic-curve Diffie-Hellman with HKDF domain separation
- **Certificate pinning**: QUIC clients verify server certificates against SHA-256 fingerprints (prevents MITM)
- **Punch authentication**: HMAC-SHA256 on all HELLO/HELLO_ACK packets, prevents unauthorized NAT traversal
- **Candidate limits**: Max 10 peer candidates per punch session, 500 total punch packets (DoS prevention)
- **Address validation**: Rejects multicast, broadcast, unspecified, and loopback targets
- **Zero-trust relay**: Relay nodes forward encrypted packets without decryption; HMAC key zeroized on drop
- **Relay HMAC**: Enforced via `RELAY_HMAC_KEY` env var (no hardcoded fallbacks); graceful warning if missing
- **Rate limiting**: Nginx layer + Redis sliding window (multi-replica safe), per-device + per-IP relay limits
- **WebSocket limits**: Per-device connection cap (configurable via `SIGNALING_MAX_CONNS_PER_DEVICE`, default 3)
- **ICE lock safety**: No write locks held across await points (prevents deadlocks in connectivity checks)
- **ICE role resolution**: RFC 8445 §6.2 compliant (larger tiebreaker = controlling agent)
- **Route lookups**: Arc<Route> zero-copy returns on hot path; ECMP round-robin distribution
- **WebSocket hardening**: receive_bytes() with immediate size enforcement before UTF-8 decode
- **IPAM persistence**: Virtual IP assignments backed by PostgreSQL (survives restarts)
- **ACL persistence**: Access control policies versioned in PostgreSQL with history
- **TUN resilience**: Fallback device names mesh0..mesh9 if primary name is in use
- **DNS hardening**: Configurable upstream query timeout (`DNS_UPSTREAM_TIMEOUT_SECS`, default 5s)
- **Error sanitization**: All _require_env errors use generic messages (no config structure leakage)
- **Input validation**: Pydantic schemas, SQLAlchemy ORM (no raw SQL), 1MB body limit
- **Container security**: Non-root user (`USER mesh`), minimal base images, pinned image digests, .dockerignore files
- **Dependency scanning**: `bandit`, `pip-audit`, `cargo audit` in CI; Trivy image scanning step ready to enable
- **Secrets**: All secrets via environment variables, never hardcoded; all defaults are `CHANGE_ME_REQUIRED` placeholders
- **DH params**: 4096-bit for Nginx (upgraded from 2048-bit)
- **Trusted hosts**: All microservices enforce `TrustedHostMiddleware` (no wildcard `*`)
- **K8s policies**: NetworkPolicy resources with default-deny ingress + explicit service allow-rules
- **CI/CD**: Vulnerability scanning (Trivy) step documented and ready to enable before production

See [SECURITY.md](./SECURITY.md) for the full audit history and incident response procedures.

## Monitoring & Observability

### Access URLs

| Tool | URL | Default Credentials |
|------|-----|-------------------|
| Grafana | http://localhost:3000 | `admin` / (set in `.env`) |
| Prometheus | http://localhost:9090 | No auth (internal only — production should use HTTPS) |
| Jaeger | http://localhost:16686 | No auth (internal only) |
| Loki | http://localhost:3100 | No auth (production should enable auth — see loki-config.yaml) |

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

### mesh-stun — STUN Server (NAT Traversal)

# Start the STUN server (standard port 3478)
./target/release/mesh-stun --port 3478

# Test: client sends "ping", server responds with public IP:PORT
echo -n "ping" | nc -u 127.0.0.1 3478
# Response: 203.0.113.5:51820

### mesh-tunnel — P2P Client Endpoint

# Full-featured client with NAT traversal, QUIC transport, multi-path routing
export MESH_TOKEN="<jwt-token>"
./target/release/mesh-tunnel \
  --api-url http://localhost:8000 \
  --ws-url ws://localhost:8000/api/v1/ws \
  --device-id "<device-uuid>" \
  --stun-server "stun.local:3478" \
  --local-port 51820

# Steps performed automatically:
# 1. STUN public address discovery
# 2. Candidate registration via REST API
# 3. WebSocket signaling connection
# 4. UDP hole punching (HMAC-authenticated HELLO/ACK, 10s timeout → relay fallback)
# 5. QUIC connection establishment (TLS 1.3, ChaCha20-Poly1305 AEAD)
# 6. Multi-path management (Direct > Relay auto-selection)
# 7. Periodic traffic/quality metrics reporting

### mesh-relay — Relay Forwarding Node

# Zero-trust packet forwarder (never decrypts traffic)
export RELAY_AUTH_TOKEN="<relay-auth-token>"
export RELAY_ID="relay-us-east-1"
export REGION="us-east"
./target/release/mesh-relay \
  --port 51821 \
  --max-connections 1000 \
  --bandwidth-mbps 1000

# Security: HMAC-SHA256 source authentication, per-device + per-IP rate limiting

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
- Trivy container image vulnerability scanning step (commented, ready to enable)
- Manual approval gate before production deploy

## Recent Changes

### May 8, 2026 — Complete Code Audit (17 fixes)

Full codebase audit across 172 files with 100% resolution of all Critical, High, and Medium issues. See [AUDIT-2026-05-08.md](./AUDIT-2026-05-08.md) for the full report.

**Rust data-plane (5):**
- `crypto/mod.rs`: encrypt() returns Result instead of panicking (H1)
- `relay/mod.rs`: RELAY_HMAC_KEY graceful fallback with unwrap_or_default() (H2)
- `tun/mod.rs`: TUN device name fallback mesh0..mesh9 (M1)
- `dns/mod.rs`: Configurable upstream DNS timeout, default 5s (M2)
- ICE role conflict resolution corrected per RFC 8445 §6.2 (CRITICAL)

**Python microservices (8):**
- IPAM PostgreSQL persistence: virtual IP assignments survive restarts (H3)
- ACL PostgreSQL persistence: versioned policy storage with history (H4)
- Session invalidation on password change: all JWTs revoked via password_updated_at (M3)
- jwt_utils.py: narrow exception handling (ExpiredSignatureError vs generic JWTError) (M4)
- WebSocket per-device connection limits via SIGNALING_MAX_CONNS_PER_DEVICE (M5)
- Traffic summary endpoint completed (was empty stub)
- All IPAM/ACL endpoints now require authentication (CRITICAL)
- Removed unused imports per ruff F401 (CRITICAL)

**Deployment & monitoring (7):**
- `network-policies.yaml`: 6 K8s NetworkPolicies with default-deny ingress (M9)
- `prometheus.yml`: HTTPS defense-in-depth comments on all targets (M6)
- `loki-config.yaml`: Authentication documentation and options (M7)
- `.github/workflows/deploy.yml`: Trivy vulnerability scanning step (M8)
- `redis.yaml`: Password-in-/proc documentation and mitigations (M10)
- `docker-compose.microservices.yml`: healthcheck start_period for postgres/redis (H7)
- 6 `.dockerignore` files created for service directories (L4)

**Documentation fixes (3):**
- Dangling `docker-compose.swarm.yml` reference corrected (L5)
- Dangling ClickHouse init volume removed (L6)
- PRODUCTION.md and PRODUCTION.md references updated

### May 7, 2026 — Phase 3 Security Audit (18 fixes)

**Rust data-plane (5):**
- ForwardingTable HMAC key zeroized on drop (manual `Drop` impl)
- Full Noise IK handshake: responder-side flow + bidirectional integration test
- ICE lock restructuring: no write locks held across await points
- NAT classification improved per RFC 5780 (Symmetric/Unknown heuristics)
- RouteTable migrated to `Arc<Route>` for zero-clone hot-path lookups

**Python microservices (10):**
- CORS: explicit origins instead of wildcard+credentials (auth-service, user-service)
- TrustedHostMiddleware added to signaling-service and relay-service
- `/relay/best` endpoint now requires authentication
- WebSocket message size enforced at `receive_bytes()` level before UTF-8 decode
- `_require_env` error messages sanitized across all 5 config files
- Docker Compose deprecated `version` strings removed (3 yml files)

**Verification report:** [VERIFICATION-2026-05-07.md](./VERIFICATION-2026-05-07.md)

See [SECURITY.md](./SECURITY.md) for full audit history and [AUDIT-2026-05-08.md](./AUDIT-2026-05-08.md) for the complete code audit.

---

## Post-Deployment Local Modifications Checklist

After running `docker compose up -d`, you **must** change the following before any production use. Open `deployment/.env` and replace every value.

### Critical — Must Change

| Variable | Current Dev Value | How to Generate | Used By |
|----------|-------------------|-----------------|---------|
| `JWT_SECRET` | `CHANGE_ME_REQUIRED` | `openssl rand -hex 64` | All 5 microservices |
| `POSTGRES_PASSWORD` | `CHANGE_ME_REQUIRED` | `openssl rand -base64 32` | All services + PostgreSQL |
| `REDIS_PASSWORD` | `CHANGE_ME_REQUIRED` | `openssl rand -hex 16` | All services + Redis |
| `RELAY_AUTH_TOKEN` | `CHANGE_ME_REQUIRED` | `openssl rand -hex 32` | relay-service + Rust relay |
| `RELAY_HMAC_KEY` | `CHANGE_ME_REQUIRED` | `openssl rand -hex 32` | Rust relay (packet authentication) |
| `PUNCH_HMAC_KEY` | `CHANGE_ME_REQUIRED` | `openssl rand -hex 32` | Rust tunnel (punch packet auth) |
| `INTERNAL_API_KEY` | `CHANGE_ME_REQUIRED` | `openssl rand -hex 32` | All 5 microservices (inter-service auth) |

### Recommended — Should Change

| Variable | Current Dev Value | Notes |
|----------|-------------------|-------|
| `GRAFANA_PASSWORD` | `CHANGE_ME_REQUIRED` | Change to a strong unique password |
| `GRAFANA_USER` | `admin` | Optional, but changing adds obscurity |
| `LOG_LEVEL` | `INFO` | Set to `WARNING` in production to reduce log volume |
| `DEBUG` | `false` | Must remain `false` in production |
|