# P2P Mesh Network

Production-grade P2P mesh networking — Python control plane, Rust data plane, 5 microservices, distributed WebSocket signaling, 10-phase data plane roadmap (TUN routing through post-quantum crypto).

**Audited:** 3 rounds (May 2026). 60+ findings. Zero critical or high issues open.

---

## Architecture

```
                       ┌──────────────────────────────┐
                       │      Nginx API Gateway        │
                       │    (TLS, WAF, rate-limit)     │
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
```

---

## Security & Features

### Authentication & Access Control

| Feature | Implementation |
|---------|---------------|
| Token format | JWT (HS256) with `jti`-based precise revocation |
| Password hashing | bcrypt, work factor 12 |
| Password policy | 10+ chars, 3 of 4 character classes |
| Brute-force protection | Redis-based lockout after N failed attempts, generic error messages |
| Registration hardening | IP rate limiting (5/hour), no user enumeration |
| Session isolation | Per-device refresh tokens keyed by `{user_id}:{device_id}` |
| Session invalidation | Password change revokes all JWTs via `password_updated_at` check |
| Admin authorization | Role-based (`require_admin` dependency) on all privileged endpoints |
| Device ownership | Every IPAM/candidate/device endpoint verifies `Device.user_id == user.id` |
| Inter-service auth | Shared `INTERNAL_API_KEY` header |
| Audit logging | All auth events; email addresses SHA-256 hashed to prevent PII leakage |

### Transport & Encryption

| Feature | Implementation |
|---------|---------------|
| API gateway | Nginx with TLS 1.2+, HSTS, 1MB body limit |
| Data plane encryption | ChaCha20-Poly1305 AEAD — keys never touch control plane |
| Key exchange | Noise IK handshake (X25519 ECDH, 0-RTT, mutual auth, forward secrecy) |
| Certificate pinning | QUIC clients verify server certs against SHA-256 fingerprints (MITM prevention) |
| Zero-trust relay | Relay nodes forward encrypted packets without decryption |
| Punch authentication | HMAC-SHA256 on all HELLO/HELLO_ACK packets |
| CORS | Explicit origin whitelists, no wildcard with credentials |
| Trusted hosts | `TrustedHostMiddleware` on all microservices |

### NAT Traversal & Connectivity

| Feature | Implementation |
|---------|---------------|
| STUN discovery | UDP 3478, multi-server probes, NAT classification per RFC 5780 |
| ICE | RFC 8445 — candidate gathering, pair prioritization, role conflict resolution, consent freshness (RFC 7675) |
| Hole punching | HMAC-authenticated HELLO/ACK, max 10 candidates, 500-packet budget |
| TURN fallback | RFC 8656 relay allocations for symmetric NAT |
| Connectivity checks | Periodic STUN binding requests, dead peer detection, path quality probing |
| RTT measurement | `send_time.elapsed()`, EWMA-smoothed (α=0.125) |

### Routing & Overlay

| Feature | Implementation |
|---------|---------------|
| Overlay network | TUN device (mesh0–mesh9), 100.64.0.0/10 CGNAT space |
| Route table | LPM with `Arc<Route>` for zero-copy hot-path lookups |
| Load balancing | ECMP round-robin across equal-cost routes |
| IPAM | PostgreSQL-backed virtual IP allocation, device ownership enforced |
| ACL | Per-peer access control with group membership resolution |
| DNS | Split-horizon resolver, 4KB EDNS0 buffer, configurable upstream timeout |
| Mesh routing | Distance vector (split horizon + poison reverse) + Babel (RFC 8966) + SWIM gossip |

### Advanced Data Plane (Phases 4–10)

| Feature | Implementation |
|---------|---------------|
| QUIC transport | quinn 0.11, TLS 1.3, multiplexed streams, connection migration |
| QUIC multi-path | Concurrent paths with per-path congestion control |
| Multi-path routing | Direct → Relay → Local auto-selection by RTT/loss/bandwidth |
| Fast path | Buffer pool, pre-allocated crypto, <100μs encrypt latency |
| Smart relay | Load-based relay ranking, regional selection |
| Post-quantum | ML-KEM (Kyber) + ML-DSA (Dilithium) — PQC-ready |
| Decentralized | Kademlia DHT, 160-bit node IDs, XOR distance |
| AI routing | ML-powered path optimization with quality scoring |
| DPDK | Userspace networking for 10G+ line rate |
| eBPF | XDP/TC kernel packet filtering |
| io_uring | Submission queue polling for ultra-low latency |
| Mobile | Android JNI + iOS C FFI bindings |

### Rate Limiting & DoS Protection

| Feature | Implementation |
|---------|---------------|
| API gateway | Nginx connection/request limits |
| Application layer | Redis sliding window (multi-replica safe) |
| Relay | Per-device + per-IP rate limits |
| WebSocket | Per-device connection cap (`SIGNALING_MAX_CONNS_PER_DEVICE`, default 3) |
| Candidate limits | Max 10 peer candidates, 500 total punch packets |
| Address validation | Rejects multicast, broadcast, unspecified, loopback targets |

### Container & Infrastructure Security

| Feature | Implementation |
|---------|---------------|
| Container user | Non-root (`USER mesh`) |
| Base images | Minimal, pinned digests |
| Secrets | Environment variables only, no hardcoded values, `CHANGE_ME_REQUIRED` defaults |
| Redis password | Loaded from config file (not `/proc/*/cmdline` visible) |
| etcd | TLS enforced for client and peer communication |
| K8s NetworkPolicy | Default-deny ingress, explicit service allow-rules |
| DH params | 4096-bit for Nginx |
| Dependency scanning | `bandit`, `pip-audit`, `cargo audit --deny warnings` in CI |
| Image scanning | Trivy CVE scanning in CI pipeline |
| Nginx hardening | Body/header/send timeouts, sensitive path blocking |

---

## Secrets Checklist

After cloning, copy the env template and generate every secret. **Do not skip any item.**

```bash
cp deployment/.env.example deployment/.env
```

### Critical — Must Change

| Variable | Generate With | Used By |
|----------|--------------|---------|
| `JWT_SECRET` | `openssl rand -hex 64` | All 5 microservices |
| `POSTGRES_PASSWORD` | `openssl rand -base64 32` | All services + PostgreSQL |
| `REDIS_PASSWORD` | `openssl rand -hex 32` | All services + Redis |
| `RELAY_AUTH_TOKEN` | `openssl rand -hex 32` | relay-service + Rust relay |
| `RELAY_HMAC_KEY` | `openssl rand -hex 32` | Rust relay (packet auth) |
| `PUNCH_HMAC_KEY` | `openssl rand -hex 32` | Rust tunnel (punch auth) |
| `INTERNAL_API_KEY` | `openssl rand -hex 32` | All microservices (inter-service) |

### Recommended

| Variable | Action |
|----------|--------|
| `GRAFANA_PASSWORD` | Change to a strong unique password |
| `LOG_LEVEL` | Set to `WARNING` in production |
| `DEBUG` | Must remain `false` in production |
| `CORS_ORIGINS` | Set to your actual frontend domain |
| `ALLOWED_HOSTS` | Set to your actual domain, not wildcard |

---

## Quick Start

```bash
git clone <repo-url> p2p-mesh
cd p2p-mesh

# 1. Generate secrets (see checklist above)
cp deployment/.env.example deployment/.env
# Edit deployment/.env — replace every CHANGE_ME_REQUIRED value

# 2. Start
cd deployment
docker compose -f docker-compose.microservices.yml --env-file .env up -d --build

# 3. Verify
curl http://localhost/health

# 4. Register and test
curl -X POST http://localhost/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"SecurePass123!","name":"Test User"}'
```

---

## Services

| Service | Port | Prefix | Purpose |
|---------|------|--------|---------|
| Nginx | 80, 443 | `/` | API gateway, TLS, rate limiting |
| Auth Service | 8000 | `/api/v1/auth/` | Registration, login, JWT |
| User Service | 8000 | `/api/v1/users/`, `/devices/` | Profiles, device CRUD |
| Signaling Service | 8000 | `/ws/signaling/` | WebSocket hub (Redis Pub/Sub) |
| Relay Service | 8000 | `/api/v1/relay/`, `/traffic/` | Relay management, traffic reports |
| Usage Service | 8000 | `/api/v1/usage/` | Quota, rate limiting |
| PostgreSQL | 5432 | — | Primary database |
| Redis | 6379 | — | Cache, Pub/Sub, rate counters |
| STUN (Rust) | 3478/udp | — | NAT discovery |
| Relay (Rust) | 51821/udp | — | UDP packet forwarder |
| Tunnel (Rust) | 51820/udp | — | P2P client |
| Prometheus | 9090 | — | Metrics |
| Grafana | 3000 | — | Dashboards |
| Loki | 3100 | — | Log aggregation |
| Jaeger | 16686 | — | Distributed tracing |

---

## API

### Auth (`/api/v1/auth/`)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/register` | — | Register |
| POST | `/login` | — | Login, returns JWT |
| POST | `/logout` | JWT | Revoke token |
| POST | `/refresh` | JWT | Refresh access token |
| GET | `/me` | JWT | Current user info |

### Devices (`/api/v1/devices/`)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/` | JWT | List own devices |
| POST | `/` | JWT | Register device |
| PUT | `/{id}` | JWT | Update device |
| DELETE | `/{id}` | JWT | Delete device |
| POST | `/{id}/heartbeat` | JWT | Device heartbeat |

### Relays (`/api/v1/relay/`)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/register` | Admin | Register relay |
| GET | `/` | JWT | List relays |
| GET | `/best` | JWT | Best relay for region |
| DELETE | `/{id}` | Admin | Delete relay |
| POST | `/traffic/report` | JWT | Submit traffic report |

### Signaling (WebSocket)

| Message | Description |
|---------|-------------|
| `candidates` | Exchange peer addresses |
| `stun_result` | Share STUN-probed public addr |
| `punch_request` / `punch_result` | Trigger/ack hole punching |
| `path_quality` | Report path metrics |

---

## Building Rust Binaries

```bash
cd data-plane
cargo build --release

# STUN server
./target/release/mesh-stun --port 3478

# P2P client
export MESH_TOKEN="<jwt>"
./target/release/mesh-tunnel \
  --api-url http://localhost:8000 \
  --device-id "<uuid>" \
  --stun-server stun.local:3478

# Relay node
export RELAY_AUTH_TOKEN="<token>" RELAY_HMAC_KEY="<key>"
./target/release/mesh-relay --port 51821
```

---

## Project Structure

```
p2p-mesh/
├── services/                    # Python microservices (FastAPI)
│   ├── shared/app/              # Shared library (config, JWT, DB, middleware, metrics, audit)
│   ├── auth-service/            # Authentication & authorization
│   ├── user-service/            # User profiles & device management
│   ├── signaling-service/       # WebSocket signaling (Redis Pub/Sub)
│   ├── relay-service/           # Relay node management & traffic
│   ├── usage-service/           # Quota management & rate limiting
│   └── worker/                  # Background task worker
├── control-plane/               # Legacy monolith (FastAPI)
├── data-plane/                  # Rust core (~18,000 LOC)
│   └── src/
│       ├── crypto/              # Noise IK + ChaCha20-Poly1305 AEAD
│       ├── ice/                 # ICE agent (RFC 8445) + connectivity + path selection
│       ├── mesh_routing/        # Distance vector, Babel, gossip, topology
│       ├── stun, turn/          # NAT traversal protocols
│       ├── router, overlay/     # LPM route table + TUN pipeline
│       ├── ipam, acl, dns/      # Address management, access control, DNS
│       ├── puncher, tunnel/     # Hole punching, tunnel management
│       ├── quic, quic_multipath/# QUIC transport + multi-path
│       ├── multipath, relay, smart_relay/
│       ├── post_quantum/        # ML-KEM + ML-DSA (PQC)
│       ├── decentralized/       # Kademlia DHT
│       ├── ai_routing/          # ML-powered route optimization
│       ├── fastpath, dpdk, ebpf, io_uring/
│       ├── mobile/              # Android JNI + iOS FFI
│       ├── metrics/             # EWMA quality metrics
│       └── bin/                 # mesh-stun, mesh-tunnel, mesh-relay, mesh-overlay
├── deployment/                  # Docker Compose, K8s, Nginx, Dockerfiles
├── monitoring/                  # Prometheus, Grafana, Loki, Promtail, Jaeger
├── scripts/                     # setup-server.sh, verify.sh, verify-upgrade.sh
└── .github/workflows/           # CI/CD (matrix build, bandit, cargo audit, Trivy)
```

---

## Deployment

| Strategy | Scale | Guide |
|----------|-------|-------|
| Single VPS + Docker Compose | ≤50 users | [Quick Start](#quick-start) |
| Multi-VPS + Swarm | ≤500 users | [PRODUCTION.md](./PRODUCTION.md) |
| Kubernetes | 500+ users | `kubectl apply -k deployment/k8s/microservices/` |

---

## Audit History

| Date | Round | Scope | Outcome |
|------|-------|-------|---------|
| 2026-05-08 | Third | GitHub code-review re-audit — 24 issues | All resolved |
| 2026-05-08 | Second | Full codebase (172 files) — 17 issues | All resolved |
| 2026-05-07 | First | Phase 3 security audit — 18 issues | All resolved |

Full details: [SECURITY.md](./SECURITY.md) · [AUDIT-2026-05-08.md](./AUDIT-2026-05-08.md)
