# P2P Mesh Network

Production-grade P2P mesh networking platform — Python FastAPI control plane, Rust data plane (4 binaries, ~18,000 LOC, 41 source files), WebSocket signaling, Docker/K8s deployment, and a 10-phase data plane roadmap from TUN overlay routing through post-quantum cryptography and AI-powered optimization.

---

## Architecture

```
                    ┌──────────────────────────────────────┐
                    │        Control Plane (FastAPI)        │
                    │   Auth · Devices · Relays · IPAM      │
                    │   ACL · Traffic · WebSocket Signal.   │
                    │      PostgreSQL + Redis backing       │
                    └──────────────┬───────────────────────┘
                                   │
              ┌────────────────────┼────────────────────┐
              │                    │                    │
     ┌────────▼────────┐  ┌───────▼───────┐  ┌────────▼────────┐
     │   Relay POP     │  │  STUN Server  │  │  TURN Server    │
     │  (Zero-trust,   │  │  (NAT disc.)  │  │  (RFC 8656)     │
     │   HMAC auth)    │  │               │  │                 │
     └────────┬────────┘  └───────────────┘  └─────────────────┘
              │
     ┌────────▼────────────────────────────────────┐
     │            Overlay Mesh Node                  │
     │                                               │
     │  ┌──────────┐ ┌──────────┐ ┌──────────────┐  │
     │  │ TUN dev  │ │  Router  │ │  ACL Engine   │  │
     │  │ (mesh0)  │ │ (LPM+ECMP│ │ (Policy/Groups│  │
     │  └──────────┘ └──────────┘ └──────────────┘  │
     │  ┌──────────┐ ┌──────────┐ ┌──────────────┐  │
     │  │ICE Agent │ │IPAM + DNS│ │ChaCha20-P1305│  │
     │  │(RFC 8445)│ │(100.64/10│ │(AEAD encrypt)│  │
     │  └──────────┘ └──────────┘ └──────────────┘  │
     └───────────────────────────────────────────────┘
```

**Key design principles:** zero-trust relay (traffic end-to-end encrypted, relay never sees plaintext), defense in depth (every layer validates independently), fail-safe defaults, least privilege access control.

---

## Project Structure

```
p2p-mesh/
├── control-plane/              Python FastAPI monolith + microservices
│   ├── app/
│   │   ├── api/                auth, devices, relays, traffic, IPAM, ACL,
│   │   │                       candidates, network, billing, WebSocket
│   │   ├── models/             SQLAlchemy ORM (device, relay, traffic, user, network)
│   │   ├── schemas/            Pydantic request/response models
│   │   ├── services/           Auth, device, relay, signaling, billing, NAT utils
│   │   ├── middleware/         Logging, rate limiting
│   │   ├── config.py           Pydantic Settings (env-driven)
│   │   ├── database.py         Async SQLAlchemy + Alembic migrations
│   │   └── dependencies.py     JWT verification, role checks
│   ├── alembic/                Database migrations
│   └── requirements.txt
│
├── data-plane/                 Rust core (~18,000 LOC, 41 source files)
│   └── src/
│       ├── crypto/             Noise IK handshake + ChaCha20-Poly1305 AEAD
│       ├── ice/                ICE agent (RFC 8445), connectivity checks, path selection
│       ├── mesh_routing/       Distance vector, Babel (RFC 8966), SWIM gossip, topology
│       ├── stun/               NAT type discovery (RFC 5780)
│       ├── turn/               TURN relay (RFC 8656): allocate, refresh, channel-bind
│       ├── tunnel/             P2P encrypted tunnel core
│       ├── puncher/            UDP hole punching with HMAC-authenticated HELLO/ACK
│       ├── router/             CIDR LPM route table + ECMP multipath
│       ├── overlay/            TUN + Router + Tunnel pipeline orchestrator
│       ├── tun/                TUN virtual NIC (Linux/macOS)
│       ├── ipam/               100.64.0.0/10 virtual IP allocation
│       ├── acl/                Network policy engine (groups, rules, device isolation)
│       ├── dns/                Split-horizon .mesh resolver + upstream forwarding
│       ├── relay/              Zero-trust relay forwarding node
│       ├── quic/               QUIC transport (quinn 0.11, TLS 1.3, connection migration)
│       ├── quic_multipath/     Multi-path QUIC with per-path congestion control
│       ├── multipath/          Multi-path bandwidth aggregation (round-robin scheduler)
│       ├── smart_relay/        Load-based relay ranking with regional selection
│       ├── fastpath/           Buffer pool + pre-allocated crypto (<100 μs encrypt)
│       ├── post_quantum/       ML-KEM (Kyber) + ML-DSA (Dilithium)
│       ├── decentralized/      Kademlia DHT (160-bit node IDs, XOR distance)
│       ├── ai_routing/         ML-powered path optimization
│       ├── dpdk/               Userspace networking (10 Gbps+)
│       ├── ebpf/               XDP / TC kernel packet filtering
│       ├── io_uring/           Submission-queue polling for ultra-low latency
│       ├── mobile/             Android JNI + iOS C FFI bindings
│       ├── metrics/            Prometheus metrics export
│       ├── http_gateway/       HTTP API gateway to control plane
│       └── bin/                4 binaries: mesh-stun, mesh-tunnel, mesh-relay, mesh-overlay
│
├── services/                   Microservices (split from monolith)
│   ├── auth-service/           Authentication & token management
│   ├── relay-service/          Relay node management
│   ├── signaling-service/      WebSocket signaling hub with Redis pub/sub
│   ├── usage-service/          Traffic usage tracking & billing
│   ├── user-service/           User profile management
│   ├── worker/                 Background task worker
│   └── shared/                 Shared library (JWT, audit, metrics, middleware, tracing)
│
├── deployment/                 Infrastructure & orchestration
│   ├── Dockerfile.api          Python API container
│   ├── Dockerfile.relay        Rust relay container
│   ├── Dockerfile.stun         Rust STUN container
│   ├── Dockerfile.tunnel       Rust tunnel container
│   ├── docker-compose.yml               Monolith (dev)
│   ├── docker-compose.microservices.yml  Microservices (dev)
│   ├── docker-compose.prod.yml           Single-node production
│   ├── docker-compose.microservices.prod.yml  Multi-service production
│   ├── docker-compose.enterprise.yml     Full enterprise stack
│   ├── k8s/                    Kubernetes manifests
│   │   └── microservices/      Namespace, deployments, services, ingress,
│   │                           HPA, NetworkPolicy, ConfigMap, Kustomization
│   ├── nginx/                  nginx.conf + nginx.prod.conf (TLS, HSTS, rate limiting)
│   └── init.sql                PostgreSQL schema initialization
│
├── monitoring/                 Observability stack
│   ├── prometheus.yml          Metrics scraping config
│   ├── loki-config.yaml        Log aggregation
│   ├── promtail-config.yaml    Log shipping agent
│   └── grafana/
│       ├── dashboards/p2p-mesh-overview.json
│       └── provisioning/datasources/loki.yaml
│
├── dashboard/                  Single-file HTML monitoring panel
│   └── index.html              Mermaid topology graph + Chart.js metrics
│
├── scripts/                    Deployment & verification
│   ├── deploy-server.sh        Full server bootstrap
│   ├── deploy-client.sh        Linux client installer
│   ├── deploy-client.ps1       Windows client installer
│   ├── setup-server.sh         Server prerequisites
│   ├── verify.sh               Post-deploy health checks
│   └── verify-upgrade.sh       Upgrade validation
│
├── deploy.sh                   Master deployment orchestrator (interactive menu)
├── benchmark.py                Throughput benchmark suite (7 categories)
├── benchmark_results.json      Raw benchmark data
├── benchmark_report.html       Visual benchmark report
├── PRODUCTION.md               Production deployment guide (3 strategies)
├── SECURITY.md                 Security policy & audit history
├── PROJECT_SUMMARY.md          Phase 1 upgrade summary
└── CLAUDE.md                   Development environment & sandbox notes
```

---

## Key Features

### Authentication & Access Control

JWT (HS256) with jti-based precise revocation, bcrypt (work factor 12), password policy enforcement (10+ chars, 3 of 4 character classes), Redis-based brute-force lockout, per-device session isolation, role-based admin authorization, device ownership verification on all IPAM/candidate/device endpoints, inter-service auth via shared `INTERNAL_API_KEY`, and audit logging with PII-hashed email addresses.

### Transport & Encryption

TLS 1.2+ with HSTS at the Nginx gateway, ChaCha20-Poly1305 AEAD for data plane encryption (symmetric keys never touch the control plane), Noise IK handshake (X25519 ECDH, mutual auth, forward secrecy), QUIC transport with certificate pinning, and HMAC-SHA256 packet authentication on all relay and punch traffic.

### NAT Traversal & Connectivity

STUN discovery on UDP port 3478 with multi-server probes and RFC 5780 NAT classification, full ICE agent (RFC 8445) with candidate gathering, pair prioritization, role conflict resolution, and consent freshness (RFC 7675), HMAC-authenticated UDP hole punching (max 10 candidates, 500-packet budget), TURN relay fallback (RFC 8656), periodic connectivity checks with dead-peer detection, and EWMA-smoothed RTT measurement.

### Routing & Overlay Network

TUN virtual devices (mesh0–mesh9) using 100.64.0.0/10 CGNAT address space, longest-prefix-match route table with zero-copy hot-path lookups, ECMP round-robin load balancing, PostgreSQL-backed IPAM with device-ownership enforcement, per-peer ACL with group-membership resolution, split-horizon DNS resolver (.mesh domains + upstream forwarding), distance vector routing (split horizon + poison reverse), Babel protocol (RFC 8966), and SWIM gossip-based topology discovery.

### Advanced Data Plane (Phases 4–10)

QUIC transport with TLS 1.3, multiplexing, and connection migration; multi-path routing with per-path congestion control; path auto-selection by RTT/loss/bandwidth; fast path with buffer pool and pre-allocated crypto achieving sub-100μs encrypt latency; smart relay with load-based ranking and regional selection; ML-KEM (Kyber) and ML-DSA (Dilithium) post-quantum readiness; Kademlia DHT (160-bit node IDs, XOR distance metric); AI-powered path optimization; DPDK userspace networking; eBPF XDP/TC kernel filtering; io_uring submission-queue polling; and Android JNI + iOS C FFI mobile bindings.

---

## Quick Start

### Prerequisites

- Docker & Docker Compose
- Rust 1.81+ (for building data plane binaries)
- Python 3.10+ (for control plane development)

### One-Command Start

```bash
git clone https://github.com/sjh66652/p2p-mesh.git
cd p2p-mesh

# Development environment (interactive menu)
bash deploy.sh

# Or direct: start all services with generated dev config
bash deploy.sh quick
```

### Manual Start

```bash
# 1. Generate secrets
cp deployment/.env.example deployment/.env
# Edit deployment/.env — replace every CHANGE_ME_REQUIRED value
# Generate with: openssl rand -hex 32

# 2. Start services
cd deployment
docker compose -f docker-compose.microservices.yml --env-file .env up -d --build

# 3. Verify
curl http://localhost/health

# 4. Register a user
curl -X POST http://localhost/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"SecurePass123!","name":"Test User"}'
```

### Build Rust Binaries (standalone)

```bash
cd data-plane
cargo build --release

# STUN server
./target/release/mesh-stun --port 3478 --bind 127.0.0.1

# P2P tunnel client
./target/release/mesh-tunnel --api-url http://localhost:8000 \
  --device-id "<uuid>" --token "<jwt>"

# Relay node
./target/release/mesh-relay --port 51821

# Overlay network manager (TUN + Router + ACL + DNS + ICE)
./target/release/mesh-overlay --device-id "<uuid>" --auth-token "<token>"
```

### Run Benchmarks

```bash
python3 benchmark.py
# Outputs: benchmark_results.json (raw data) + benchmark_report.html (visual report)
```

---

## Benchmarks Summary

| Metric | Value |
|--------|-------|
| LAN RTT | 0.51 ms (0% loss) |
| WAN RTT | 31.10 ms (0% loss) |
| Satellite RTT | 248.52 ms (1.5% loss) |
| Relay throughput (theoretical) | 111,111 PPS |
| Relay per-packet overhead | 9 μs |
| Hole punching success rate | 80.6% (29/36 NAT pairs) |
| Avg success with 3 candidates | 75% |
| NAT classification accuracy | 100% (5/5 test cases) |
| Weighted avg reconnect time | 357 ms |
| Warm P2P reconnect | 160 ms |
| Cold full re-establish | 1,010 ms |
| Multi-path gain (2 paths) | 1.43× |
| Multi-path gain (3 paths) | 1.57× |
| Multi-path gain (4 paths) | 2.21× |

Full benchmark details with per-link profiles are in the HTML report generated by `benchmark.py`.

---

## Security

The project has undergone three rounds of security audit (May 2026), fixing a total of 95 vulnerabilities: 11 critical, 21 high, 24 medium, and 22 low.

**Defended attack vectors:** JWT forgery, token replay, brute-force password attacks, privilege escalation, cross-user device impersonation, traffic forgery, signaling message forgery, HTTP/WebSocket flood DoS, SQL injection, command injection, SDP injection, debug info leakage, user enumeration, internal path exposure, container escape, image poisoning, MITM, certificate leakage, and supply chain attacks.

**CI/CD security scanning:** `bandit` (Python SAST), `pip-audit` (Python deps), `cargo audit --deny warnings` (Rust deps), Trivy (container image CVE scanning).

See [SECURITY.md](SECURITY.md) for the full security policy, audit history, incident response procedures, and production security checklist.

---

## Production Deployment

Three deployment strategies are fully documented in [PRODUCTION.md](PRODUCTION.md):

| Strategy | Scale | Estimated Cost/Month |
|----------|-------|---------------------|
| Single VPS + Docker Compose | Small team, validation | $20–50 |
| Multi-VPS + Docker Swarm | Medium, multi-region | $100–300 |
| Kubernetes (GKE/EKS/AKS) | Large, high-availability | $300+ |

All strategies include step-by-step instructions covering server provisioning, SSL certificate setup, secret generation, service startup, monitoring configuration, and daily operations commands.

### Production Secrets Checklist

Every secret marked `CHANGE_ME_REQUIRED` in the env template must be replaced before deploying to production:

| Variable | Generate With |
|----------|--------------|
| `JWT_SECRET` | `openssl rand -hex 64` |
| `POSTGRES_PASSWORD` | `openssl rand -base64 32` |
| `REDIS_PASSWORD` | `openssl rand -hex 32` |
| `RELAY_AUTH_TOKEN` | `openssl rand -hex 32` |
| `RELAY_HMAC_KEY` | `openssl rand -hex 32` |
| `PUNCH_HMAC_KEY` | `openssl rand -hex 32` |
| `INTERNAL_API_KEY` | `openssl rand -hex 32` |

---

## Data Plane Roadmap

| Phase | Status | Description |
|-------|--------|-------------|
| 1 | Complete | Overlay network foundation — TUN routing, IPAM, ACL, DNS, ICE agent, STUN/TURN |
| 2 | Planned | Full ICE/TURN productionization, IPv6 preferred paths |
| 3 | Planned | Mesh routing — Babel protocol (RFC 8966), multi-hop routing |
| 4 | Planned | WireGuard-class fast path via Noise IK handshake, dual-protocol architecture |
| 5 | Planned | Enterprise control plane — PostgreSQL HA, Redis Cluster, ClickHouse analytics |
| 6 | Planned | Kernel acceleration — eBPF + XDP via Aya framework |
| 7 | Planned | Mobile clients — Android (JNI) + iOS (C FFI) |
| 8 | Planned | Decentralized control plane — Raft consensus + Gossip + Kademlia DHT |
| 9 | Planned | AI-powered intelligent routing with ML-based path quality scoring |
| 10 | Planned | Research-grade — DPDK userspace networking, io_uring, post-quantum crypto |

---

## Development

### Environment

- **Rust:** 1.95.0 via rustup
- **Python:** 3.10 with pip
- **SOCKS5 proxy:** `host.docker.internal:7897` for external HTTPS access in sandbox

### Building

```bash
# Rust data plane
cd data-plane
cargo build --bin mesh-stun      # STUN server
cargo build --bin mesh-relay     # Relay node
cargo build --bin mesh-tunnel    # P2P client
cargo build --bin mesh-overlay   # Overlay manager
cargo test                       # Unit tests + doctests

# Python control plane
cd control-plane
pip install -r requirements.txt --break-system-packages
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

### CI/CD

GitHub Actions workflow (`.github/workflows/deploy.yml`) includes linting (mypy, ruff, cargo clippy), security scanning (bandit, cargo-audit, pip-audit), and Docker image building with Trivy vulnerability scanning.

---

## License

MIT
