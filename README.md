# P2P Mesh Network

Production-grade P2P mesh networking — Python FastAPI control plane + Rust data plane (4 binaries, ~18,000 LOC), WebSocket signaling, 10-phase data plane roadmap from TUN routing through post-quantum crypto.

---

## Security & Features

### Authentication & Access Control

| Feature | Implementation |
|---------|---------------|
| Token format | JWT (HS256) with `jti`-based precise revocation |
| Password hashing | bcrypt, work factor 12 |
| Password policy | 10+ chars, 3 of 4 character classes (upper, lower, digit, special) |
| Brute-force protection | Redis-based lockout after N failed attempts, generic error responses (no user enumeration) |
| Registration hardening | IP rate limiting (5 requests per hour) |
| Session isolation | Per-device refresh tokens keyed by `{user_id}:{device_id}` |
| Session invalidation | Password change revokes all JWTs via `password_updated_at` timestamp check |
| Admin authorization | Role-based (`require_admin` dependency) on all privileged endpoints |
| Device ownership | Every IPAM / candidate / device endpoint verifies `Device.user_id == user.id` |
| Inter-service auth | Shared `INTERNAL_API_KEY` header between microservices |
| Audit logging | All auth events logged; email addresses SHA-256 hashed to prevent PII leakage |

### Transport & Encryption

| Feature | Implementation |
|---------|---------------|
| API gateway TLS | Nginx: TLS 1.2+, HSTS, 1 MB body limit, 4096-bit DH params |
| Data plane encryption | ChaCha20-Poly1305 AEAD — symmetric keys never touch the control plane |
| Key exchange | Noise IK handshake (X25519 ECDH, 0-RTT, mutual auth, forward secrecy) |
| Certificate pinning | QUIC clients verify server certs against SHA-256 fingerprints to prevent MITM |
| Zero-trust relay | Relay nodes forward encrypted packets; decryption happens only at endpoints |
| Punch authentication | HMAC-SHA256 on all HELLO / HELLO_ACK packets |
| CORS | Explicit origin whitelist; no wildcard when credentials are present |
| Trusted hosts | `TrustedHostMiddleware` on all microservices |

### NAT Traversal & Connectivity

| Feature | Implementation |
|---------|---------------|
| STUN discovery | UDP port 3478, multi-server probes, NAT classification per RFC 5780 |
| ICE | RFC 8445 — candidate gathering, pair prioritization, role conflict resolution, consent freshness (RFC 7675) |
| Hole punching | HMAC-authenticated HELLO / ACK, max 10 candidates, 500-packet budget |
| TURN fallback | RFC 8656 relay allocations for symmetric NAT |
| Connectivity checks | Periodic STUN binding requests, dead-peer detection, path quality probing |
| RTT measurement | EWMA-smoothed (`α = 0.125`) on `send_time.elapsed()` |

### Routing & Overlay

| Feature | Implementation |
|---------|---------------|
| Overlay network | TUN devices (mesh0–mesh9), 100.64.0.0/10 CGNAT address space |
| Route table | Longest-prefix-match with `Arc<Route>` for zero-copy hot-path lookups |
| Load balancing | ECMP round-robin across equal-cost routes |
| IPAM | PostgreSQL-backed virtual IP allocation with device-ownership enforcement |
| ACL | Per-peer access control with group-membership resolution |
| DNS | Split-horizon resolver, 4 KB EDNS0 buffer, configurable upstream timeout |
| Mesh routing | Distance vector (split horizon + poison reverse) + Babel (RFC 8966) + SWIM gossip |

### Advanced Data Plane (Phases 4–10)

| Feature | Implementation |
|---------|---------------|
| QUIC transport | quinn 0.11, TLS 1.3, multiplexed streams, connection migration |
| QUIC multi-path | Concurrent paths with per-path congestion control |
| Multi-path routing | Direct → Relay → Local auto-selection by RTT / loss / bandwidth |
| Fast path | Buffer pool + pre-allocated crypto, <100 μs encrypt latency |
| Smart relay | Load-based relay ranking with regional selection |
| Post-quantum crypto | ML-KEM (Kyber) + ML-DSA (Dilithium), PQC-ready |
| Decentralized | Kademlia DHT, 160-bit node IDs, XOR distance metric |
| AI routing | ML-powered path optimization with quality scoring |
| DPDK | Userspace networking for 10 Gbps+ line rate |
| eBPF | XDP / TC kernel packet filtering |
| io_uring | Submission-queue polling for ultra-low latency |
| Mobile | Android JNI + iOS C FFI bindings |

### Rate Limiting & DoS Protection

| Feature | Implementation |
|---------|---------------|
| API gateway | Nginx connection and request limits |
| Application layer | Redis sliding window (multi-replica safe) |
| Relay | Per-device and per-IP rate limits |
| WebSocket | Per-device connection cap (default 3) |
| Candidate limits | Max 10 peer candidates, 500 total punch packets |
| Address validation | Rejects multicast, broadcast, unspecified, and loopback targets |

### Container & Infrastructure Security

| Feature | Implementation |
|---------|---------------|
| Container user | Non-root (`USER mesh`) |
| Base images | Minimal, pinned by digest |
| Secrets | Environment variables only; no hardcoded values; `CHANGE_ME_REQUIRED` defaults |
| Redis password | Loaded from config file (not visible in `/proc/*/cmdline`) |
| K8s NetworkPolicy | Default-deny ingress, explicit per-service allow-rules |
| Dependency scanning | `bandit`, `pip-audit`, `cargo audit --deny warnings` in CI |
| Image scanning | Trivy CVE scanning in CI pipeline |
| Nginx hardening | Body / header / send timeouts, sensitive path blocking |

---

## Secrets Checklist

After cloning, copy the environment template and generate every secret. **Do not skip any item.**

```bash
cp deployment/.env.example deployment/.env
```

### Critical — Must Change

| Variable | Generate With | Used By |
|----------|--------------|---------|
| `JWT_SECRET` | `openssl rand -hex 64` | All microservices |
| `POSTGRES_PASSWORD` | `openssl rand -base64 32` | All services + PostgreSQL |
| `REDIS_PASSWORD` | `openssl rand -hex 32` | All services + Redis |
| `RELAY_AUTH_TOKEN` | `openssl rand -hex 32` | relay-service + Rust relay node |
| `RELAY_HMAC_KEY` | `openssl rand -hex 32` | Rust relay (packet authentication) |
| `PUNCH_HMAC_KEY` | `openssl rand -hex 32` | Rust tunnel (punch authentication) |
| `INTERNAL_API_KEY` | `openssl rand -hex 32` | All microservices (inter-service auth) |

### Recommended

| Variable | Action |
|----------|--------|
| `GRAFANA_PASSWORD` | Change to a strong, unique password |
| `LOG_LEVEL` | Set to `WARNING` in production |
| `DEBUG` | Must remain `false` in production |
| `CORS_ORIGINS` | Set to your actual frontend domain |
| `ALLOWED_HOSTS` | Set to your actual domain, not a wildcard |

---

## Throughput Benchmarks

Run `python3 benchmark.py` to reproduce all measurements. Outputs go to `benchmark_results.json` (raw data) and `benchmark_report.html` (visual report).

### 1. Latency — PING / PONG RTT

EWMA smoothing (`α = 0.125`), 200 samples per profile.

| Link Profile | Avg RTT | Packet Loss | Quality Score |
|-------------|---------|-------------|:---:|
| LAN | **0.51 ms** | 0.00 % | 1.000 |
| WAN | **31.10 ms** | 0.00 % | 0.969 |
| Satellite | **248.52 ms** | 1.50 % | 0.747 |

### 2. Relay PPS — Forwarding Throughput

| Metric | Value |
|--------|-------|
| Per-packet overhead | 9 μs (HMAC verify + rate-limit + route lookup + UDP send) |
| Single-core theoretical max | **111,111 PPS** |
| Protocol overhead | 4.4 % (64 B header on 1464 B payload) |
| Throughput at 1400 B | 5.86 Mbps (IP rate-limited); 1.3 Gbps (limit removed) |

Current bottleneck is `MAX_IP_PACKETS_PER_SEC = 500` — raise to 10,000+ in production for multi-device relay scenarios.

### 3. Hole Punching Success Rate

| Metric | Value |
|--------|-------|
| NAT pairs with P2P possible | **80.6 %** (29 / 36) |
| Avg success — 1 STUN candidate | 0.69 |
| Avg success — 3 STUN candidates | **0.75** |
| Multi-candidate improvement | +8.6 % |

Seven impossible combinations all involve symmetric NAT — relay fallback is required.

### 4. NAT Coverage — Classification Accuracy

Based on RFC 3489 / 5780 multi-server STUN probe methodology.

| Metric | Value |
|--------|-------|
| Classification accuracy | **100.0 %** (5 / 5 cases) |
| Directly detectable types | Full Cone, Symmetric |
| Needs phase-2 connectivity test | Restricted Cone, Port Restricted Cone |

### 5. Reconnect Time

| Scenario | Time | Probability |
|----------|------|:-----------:|
| Warm P2P (cached address) | **160 ms** | 65 % |
| Cold full re-establish | 1,010 ms | 25 % |
| Relay fallback (pre-established) | **5 ms** | 10 % |
| **Weighted average** | **357 ms** | — |
| Worst case (dual timeout) | 13,000 ms | — |

### 6. Multipath Gain — Bandwidth Aggregation

Round-robin scheduler with 5 % reordering penalty per extra path (max 15 %).

| Configuration | Single Path | Aggregate | Gain |
|---------------|------------|-----------|:----:|
| WiFi + LTE (2 paths) | 50 Mbps | 71 Mbps | **1.43×** |
| WiFi + LTE + 5G (3 paths) | 100 Mbps | 158 Mbps | **1.57×** |
| 4-path multi-WAN | 100 Mbps | 221 Mbps | **2.21×** |

### 7. QUIC Connection Migration

| Metric | Value |
|--------|-------|
| Migration success rate | **75.0 %** (3 / 4) |
| Average disruption | **6.0 ms** |
| Max paths per connection | 8 |
| Relay fallback RTT penalty | +65 ms |

Single-path failure is the only unrecoverable scenario — deploy ≥ 2 active paths for production high availability.

---

## Project Structure

```
p2p-mesh/
├── control-plane/          # Python FastAPI (auth, devices, relays, traffic, IPAM, ACL, WebSocket)
├── data-plane/             # Rust core (~18,000 LOC, 41 source files)
│   └── src/
│       ├── crypto/         # Noise IK + ChaCha20-Poly1305 AEAD
│       ├── ice/            # ICE agent (RFC 8445) + connectivity checks
│       ├── mesh_routing/   # Distance vector, Babel (RFC 8966), SWIM gossip
│       ├── stun/, turn/    # NAT traversal
│       ├── router/, overlay/  # LPM route table + TUN pipeline
│       ├── ipam/, acl/, dns/  # Address management, access control, DNS
│       ├── quic/, quic_multipath/  # QUIC transport + multi-path
│       ├── post_quantum/   # ML-KEM + ML-DSA
│       ├── decentralized/  # Kademlia DHT
│       ├── ai_routing/     # ML-powered route optimization
│       ├── fastpath/, dpdk/, ebpf/, io_uring/  # Hardware acceleration
│       ├── mobile/         # Android JNI + iOS FFI
│       └── bin/            # mesh-stun, mesh-tunnel, mesh-relay, mesh-overlay
├── deployment/             # Docker Compose, K8s, Nginx, Dockerfiles
├── monitoring/             # Prometheus, Grafana, Loki, Promtail
├── dashboard/              # Single-file HTML monitoring panel (Mermaid + Chart.js)
├── scripts/                # deploy-server.sh, deploy-client.sh, deploy-client.ps1
├── deploy.sh               # Master deployment orchestrator (interactive menu)
├── benchmark.py            # Throughput benchmark suite
├── benchmark_results.json  # Raw benchmark data
└── benchmark_report.html   # Visual benchmark report
```

---

## Quick Start

```bash
git clone https://github.com/sjh66652/p2p-mesh.git
cd p2p-mesh

# Generate secrets
cp deployment/.env.example deployment/.env
# → Edit deployment/.env, replace every CHANGE_ME_REQUIRED value

# Start (Docker Compose)
cd deployment
docker compose -f docker-compose.microservices.yml --env-file .env up -d --build

# Verify
curl http://localhost/health

# Register and test
curl -X POST http://localhost/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"SecurePass123!","name":"Test User"}'
```

### Build Rust Binaries (standalone)

```bash
cd data-plane
cargo build --release

./target/release/mesh-stun --port 3478                        # STUN server
./target/release/mesh-tunnel --api-url http://localhost:8000 \  # P2P client
  --device-id "<uuid>" --token "<jwt>"
./target/release/mesh-relay --port 51821                      # Relay node
./target/release/mesh-overlay --device-id "<uuid>" \          # Overlay manager
  --auth-token "<token>"
```

### Run Benchmarks

```bash
cd p2p-mesh
python3 benchmark.py
# Outputs benchmark_results.json + benchmark_report.html
```
