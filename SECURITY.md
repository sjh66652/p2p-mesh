# Security Policy

## Security Architecture

P2P Mesh Network employs defense-in-depth, protecting every layer from network to application:

```
Internet -> Nginx (TLS/WAF/Rate Limit) -> API (JWT/Input Validation) -> DB (Least Privilege)
                                        |          |
                                   Redis (Session/Rate Limit/Signaling Pub-Sub)
                                        |          |
                              Rust Relay (Zero-Trust, HMAC Verified, Never Decrypts)
```

**Key design principles:**
- Zero-trust relay: traffic is end-to-end encrypted; the relay never sees plaintext
- Defense in depth: every layer validates independently
- Fail-safe defaults: missing env vars crash with clear errors, never fall back to insecure defaults
- Least privilege: relay nodes use shared tokens, users use JWT, admins use role checks

---

## Vulnerability Reporting

Report security vulnerabilities to `security@yourdomain.com`. Do NOT publicly disclose. We respond within 48 hours.

---

## Defended Attack Vectors (Phase 1 + Phase 2 Audit)

### 1. Authentication Attacks

| Attack | Defense |
|--------|---------|
| JWT forgery (key leak) | No hardcoded key; production forces env var; dev uses per-restart random key |
| Token replay | JWT contains `jti` unique ID; logout blacklists by jti precisely |
| Refresh token abuse | Refresh tokens in Redis, independently revocable |
| Brute-force password | bcrypt(rounds=12); Redis login failure count; 5 attempts = 15min lockout |
| Privilege escalation | `update_user` field whitelist; `plan`/`role` NOT modifiable via API |
| Weak passwords | Enforced 10+ chars, 3 of 4 categories (upper/lower/digit/special) |

### 2. Authorization Attacks

| Attack | Defense |
|--------|---------|
| Cross-user device impersonation | WebSocket verifies device_id belongs to authenticated user |
| Traffic forgery/inflation | Single report cap 10GB; batch cap 100 entries |
| Signaling message forgery | WS message type whitelist (6 types); unknown types rejected |
| Relay node self-registration | `POST /relay/register` requires `require_admin` role (Phase 2) |
| Relay heartbeat spoofing | `POST /relay/{id}/heartbeat` requires `get_relay_auth` token (Phase 2) |
| Relay deletion by non-admin | `DELETE /relay/{id}` requires `require_admin` role (Phase 2) |
| Admin interface access | `require_admin` dependency injection with role check |
| CORS arbitrary origins | Production restricts `CORS_ORIGINS` whitelist |
| Signaling sender spoofing | `relay_signal()` verifies sender; cross-user signaling blocked (Phase 2) |

### 3. DoS Attacks

| Attack | Defense |
|--------|---------|
| HTTP flood | Nginx `limit_req` + API Redis sliding window (multi-replica safe) |
| WebSocket flood | Per-connection 20 msg/s limit; over-limit = disconnect |
| Oversized requests | Global 1MB request body limit |
| Oversized WS messages | 64KB single message cap |
| Login endpoint brute force | Independent rate limit zone (10 req/min) |
| Relay registration flood | Redis rate limit per admin IP (5/min) (Phase 2) |
| Relay packet amplification | Per-device rate limit (100 pkt/s); HMAC verification before forward (Phase 2) |

### 4. Injection Attacks

| Attack | Defense |
|--------|---------|
| SQL injection | All queries use SQLAlchemy ORM parameterized; zero raw SQL |
| Command injection | No `os.system`; Docker CMD uses exec form |
| SDP injection | SDP string max 32KB with format validation |
| Relay device ID injection | HMAC-SHA256 tag verifies device ID authenticity before forwarding (Phase 2) |

### 5. Information Leakage

| Attack | Defense |
|--------|---------|
| Debug info leak | Production `DEBUG=false`; `/docs` disabled |
| User enumeration | Login returns unified "Invalid credentials" |
| Internal path leak | Error messages exclude stack traces |
| Online device enumeration | `get_peers` returns same-user devices only (Phase 2) |
| Network topology leak | Relay list hides IPs from non-admins; path find requires both devices belong to user (Phase 2) |
| JWT in URL query string | WebSocket auth uses `Authorization` header, NOT URL (Phase 2) |
| JWT in CLI args (/proc exposure) | Token via `MESH_TOKEN` env var; `hide_env_values=true` in clap (Phase 2) |
| Database password in repo | `alembic.ini` uses placeholder; `env.py` reads from environment |

### 6. Infrastructure Attacks

| Attack | Defense |
|--------|---------|
| Container escape | Non-root user (`USER mesh`); `--cap-drop=ALL` in K8s |
| Image poisoning | Multi-stage builds; pinned Rust version (`1.81-slim-bookworm`); minimal base images |
| MITM | Nginx forces TLS 1.2+; HSTS header |
| Certificate leak | Private keys via volume mount, never in images |
| Redis password in /proc | Healthcheck uses `REDISCLI_AUTH` env var, not `-a` flag (Phase 2) |
| Supply chain / reproducible builds | `Cargo.lock` committed (was gitignored); pinned Docker base images (Phase 2) |
| K8s hardcoded secrets | Manifests reference `Secret` objects; secrets created via `kubectl create secret` (Phase 2) |
| K8s DATABASE_URL construction | URL assembled from individual ConfigMap + Secret parts (Phase 2) |

### 7. CI/CD Pipeline

| Issue | Fix |
|-------|-----|
| No security scanning | Added `bandit` (Python SAST), `cargo-audit` (Rust deps), `pip-audit` (Python deps) |
| Linting errors silently ignored | Removed `|| true` from `mypy` and `cargo clippy` steps |
| No manual approval gate | GitHub environment protection rules recommended for `deploy` job |
| No image vulnerability scanning | Add Trivy/Grype scan step before push |

---

## Production Security Checklist

Verify every item before deploying:

```bash
# 1. JWT secret (must NOT be default)
[ -z "$JWT_SECRET" ] && echo "MISSING!" || echo "OK"

# 2. Relay auth token (must NOT be default)
[ -z "$RELAY_AUTH_TOKEN" ] && echo "MISSING!" || echo "OK"

# 3. Database password strength
[ ${#POSTGRES_PASSWORD} -lt 16 ] && echo "WEAK!" || echo "OK"

# 4. Redis password
[ -z "$REDIS_PASSWORD" ] && echo "MISSING!" || echo "OK"

# 5. DEBUG disabled
[ "$DEBUG" = "true" ] && echo "DANGER!" || echo "OK"

# 6. CORS whitelist configured
[ "$CORS_ORIGINS" = "*" ] && echo "DANGER!" || echo "OK"

# 7. TLS enabled
[ "$TLS_ENABLED" != "true" ] && echo "WARNING!" || echo "OK"

# 8. Non-root container
docker inspect p2p-mesh-api | jq '.[].Config.User' | grep -v root || echo "OK"

# 9. Token NOT in URL (check nginx logs for JWT patterns)
grep -r "Bearer\|eyJ" /var/log/nginx/access.log && echo "WARNING: Token in URL!" || echo "OK"
```

---

## Dependency Security

```bash
# Python: audit dependencies for known CVEs
pip-audit -r requirements.txt

# Python: static analysis for common security issues
bandit -r app/ -ll

# Rust: audit dependencies
cargo audit

# Rust: lint with security lints
cargo clippy --all-targets -- -D warnings

# Docker: scan built images
docker scout quickview yourorg/p2p-mesh-api:latest
docker scout quickview yourorg/p2p-mesh-relay:latest
```

**Version policy:**
- Python: `pip-audit` on every CI run
- Rust: `cargo-audit` on every CI run; `Cargo.lock` committed for reproducibility
- Docker: base images pinned to specific digests in production
- PostgreSQL: 16+, apply security patches promptly

---

## Incident Response

### 1. Active attack detected
Immediately block attacker IP in Nginx:
```bash
docker exec deployment-nginx-1 sh -c "echo 'deny ATTACKER_IP;' >> /etc/nginx/conf.d/block.conf && nginx -s reload"
```

### 2. JWT secret compromised
Rotate the secret and invalidate all tokens:
```bash
# Generate new secret
openssl rand -hex 32 > new_jwt_secret

# Flush all JWT blacklists in Redis (forces re-login)
docker exec deployment-redis-1 redis-cli KEYS "jwt_blacklist:*" | xargs docker exec deployment-redis-1 redis-cli DEL

# Update JWT_SECRET and restart API
docker compose restart api
```

### 3. Relay auth token compromised
```bash
# Generate new token
openssl rand -hex 32 > new_relay_token

# Update RELAY_AUTH_TOKEN env var and restart API + all relay nodes
docker compose restart api relay
```

### 4. Token leaked (individual user)
Revoke all of a user's tokens:
```bash
docker exec deployment-redis-1 redis-cli KEYS "refresh_token:USER_ID:*" | xargs docker exec deployment-redis-1 redis-cli DEL
```

### 5. Database anomaly
Switch to read-only mode and restore from backup:
```bash
docker exec deployment-postgres-1 psql -U mesh -c "ALTER DATABASE p2p_mesh SET default_transaction_read_only = on;"
```

### 6. Signaling hub under attack
If cross-user signaling is being abused, the signaling hub already blocks it. Verify:
```bash
docker compose logs api | grep "Cross-user signaling blocked"
```

---

## Audit History

| Date | Scope | CRITICAL | HIGH | MEDIUM | LOW |
|------|-------|----------|------|--------|-----|
| 2026-05-06 (Phase 1) | auth, ws, main, config | 4 | 7 | 0 | 0 |
| 2026-05-06 (Phase 2) | Full codebase (50+ files) | 4 | 7 | 6 | 6 |

### Phase 2 Vulnerabilities Discovered and Fixed

**CRITICAL:**
1. Relay API routes (register/heartbeat/delete) had no admin role checks — any authenticated user could manage relay infrastructure
2. JWT token passed in WebSocket URL query string — logged by Nginx, proxies, and application logs
3. K8s manifest had hardcoded placeholder secrets with empty Redis password and broken DATABASE_URL construction
4. Relay self-registration endpoint had no authentication at all

**HIGH:**
1. Relay packets had no source device authentication — any device could spoof sender identity in relayed UDP packets
2. Relay auto-registered any device sending a UDP packet — amplification attack vector
3. Signaling hub lacked sender identity verification — connected device could relay messages posing as any device
4. Signaling hub exposed full network topology (all online peers with user IDs) to every connected client
5. Redis password exposed in process listing via healthcheck command (`redis-cli -a $PASSWORD ping`)
6. Cargo.lock was gitignored — dependency versions not reproducible; supply chain risk
7. In-memory rate limiting with memory leak — single-replica only; Redis-backed replacement implemented

**MEDIUM:**
1. CI pipeline had no security scanning (bandit, cargo-audit, pip-audit missing)
2. Linter/type errors silently ignored in CI with `|| true`
3. JWT token via CLI args visible in `/proc/*/cmdline` on Linux
4. `UserUpdate` schema allowed `plan` field (privilege escalation vector)
5. JWT had insecure `change-this-in-production` default fallback in dev docker-compose
6. PostgreSQL and Redis ports exposed to all interfaces in dev docker-compose

**LOW:**
1. Network path finder leaked other users' routing info (IP, region) via "at least one device" policy
2. Relay list endpoint exposed internal IPs to all authenticated users
3. Signaling hub in-memory only — breaks with multiple API replicas (Redis pub/sub planned)
4. Hole punch packet had static `"P2P_MESH_PUNCH"` payload (easily fingerprintable by DPI)
5. Grafana defaulted to admin/admin credentials when env var unset
6. K8s relay DaemonSet used hostNetwork with NET_ADMIN+NET_RAW capabilities
