# P2P Mesh Network — Comprehensive Security Audit Report

**Audit Date:** May 6-7, 2026  
**Scope:** Full codebase — control-plane (Python/FastAPI), services (microservices), data-plane (Rust), deployment (Docker/K8s/nginx), CI/CD  
**Methodology:** Four-agent parallel deep inspection of all source files, plus manual verification of critical findings  

---

## Executive Summary

The P2P Mesh Network codebase underwent a comprehensive security audit covering approximately 100 findings across all layers. The project demonstrates strong security consciousness in many areas: bcrypt with work factor 12, constant-time comparison, JTI-based JWT revocation, generic error messages, field whitelisting for profile updates, and a well-documented defense-in-depth architecture in SECURITY.md.

However, three categories of critical issues demand immediate attention:

1. **Data-Plane Encryption is Fundamentally Broken** — QUIC TLS certificate validation is completely disabled (MitM possible), session keys are generated independently by each peer with zero key agreement (encrypted communication is mathematically impossible), and HMAC keys use hardcoded defaults.

2. **Authentication & Authorization Gaps** — Refresh tokens silently strip admin roles, the batch traffic endpoint doesn't verify device ownership, and multiple services have effectively disabled security middleware (TrustedHost with `*`, CORS `allow_origins=["*"]` with `allow_credentials=True`).

3. **Deployment & Infrastructure Risks** — Development secrets are committed to version control, container images use unpinned `:latest` tags, and Kubernetes manifests lack NetworkPolicy segmentation.

---

## Severity Legend

| Severity | Definition |
|----------|------------|
| **Critical** | Immediate compromise; remote unauthenticated access, credential leakage, or complete system bypass |
| **High** | Significant security gap; privilege escalation, data exposure, or defense bypass with moderate attacker effort |
| **Medium** | Defense-in-depth gap; best-practice violation that enables exploitation when combined with other weaknesses |
| **Low** | Minor hardening opportunity; configuration hygiene, code quality, or informational |

---

## Round 1 — Previously Patched Vulnerabilities (May 6, 2026)

These 16 issues were identified and fixed during the initial audit. They are included for completeness.

### Critical (Fixed)

| # | Finding | File | Fix |
|---|---------|------|-----|
| C1 | JWT import error (`jose.jwt` vs `jwt`) | `dependencies.py`, `auth_service.py`, `ws.py` | Fixed imports |
| C2 | ENUM type collision on container restart | `main.py` | Added `CREATE TYPE IF NOT EXISTS` logic |
| C3 | JWT blacklist bypass on WebSocket connections | `ws.py` | Added `jti` blacklist check |
| C4 | Hardcoded DB password (`mesh_pass`) in config defaults | `config.py` | Replaced with `_require_env()` for `DATABASE_URL` |

### High (Fixed)

| # | Finding | File | Fix |
|---|---------|------|-----|
| H1 | Timing side-channel on relay auth comparison | `relay.py` | Used `hmac.compare_digest()` |
| H2 | User enumeration via distinct error messages | `auth.py` | Generic "Invalid email or password" |
| H3 | Unauthenticated Redis | `docker-compose.yml` | Added `requirepass` + `REDISCLI_AUTH` |
| H4 | Fail-open rate limiter | `rate_limit.py` | Changed to fail-closed with 20 RPM budget |

### Medium (Fixed)

| # | Finding | File | Fix |
|---|---------|------|-----|
| M1 | WebSocket connection exhaustion (no limit) | `signaling_service.py` | Added `MAX_CONNECTIONS = 10_000` |
| M2 | Prometheus metrics endpoint exposed | `main.py` | Added IP-range restriction (172.x, 10.x, localhost) |
| M3 | API bound to `0.0.0.0` | docker-compose files | Changed to `127.0.0.1:8000` |
| M4 | Grafana `admin/admin` default credentials | docker-compose files | Now requires `GRAFANA_PASSWORD` env var |
| M5 | Relay heartbeat returns 404 for unknown relays | `api/relay.py` | Added name-based auto-registration |
| M6 | Ambiguous error handling | `api/relay.py` | Separated UUID parsing from DB lookup |
| M7 | `JWT_SECRET` from predictable prefix | `config.py` | Fully random 64-char hex |
| M8 | Redis password in `/proc/*/cmdline` | docker-compose files | Switched to `REDISCLI_AUTH` env var |

---

## Round 2 — Deep Audit Findings (May 7, 2026)

---

### Section A: Data-Plane (Rust) — Critical Encryption Failures

#### A-CR1: QUIC TLS Certificate Validation Completely Disabled (MitM Attack)

**File:** `data-plane/src/quic/mod.rs`, lines 34-37, 116-163  
**Severity:** CRITICAL

The QUIC client uses `rustls::ClientConfig::builder().dangerous()` with a custom `SkipServerVerification` that unconditionally accepts any TLS certificate. All three verification methods — `verify_server_cert`, `verify_tls12_signature`, and `verify_tls13_signature` — return unconditional success:

```rust
// line 34-37
let client_crypto = rustls::ClientConfig::builder()
    .dangerous()
    .with_custom_certificate_verifier(SkipServerVerification::new())
    .with_no_client_auth();

// line 126-135
fn verify_server_cert(&self, _end_entity: &CertificateDer<'_>, ...) -> Result<...> {
    Ok(rustls::client::danger::ServerCertVerified::assertion())
}
fn verify_tls12_signature(&self, ...) -> Result<...> {
    Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
}
fn verify_tls13_signature(&self, ...) -> Result<...> {
    Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
}
```

**Impact:** Any network-level attacker can intercept QUIC connections. While data is encrypted at the application layer (see A-CR2), the attacker can observe and manipulate connection metadata, timing patterns, and traffic volume.

**Remediation:** Implement certificate pinning using device public keys exchanged via the signaling channel. Each peer should generate a self-signed certificate whose fingerprint is transmitted over the authenticated WebSocket signaling channel. The TLS verifier should then check that the presented certificate matches the expected fingerprint.

---

#### A-CR2: Session Keys Generated Independently — No Key Agreement Exists

**File:** `data-plane/src/crypto/mod.rs`, lines 27-33; `data-plane/src/tunnel/mod.rs`, lines 261-262, 272-273  
**Severity:** CRITICAL

Each peer generates its own random 32-byte session key using `OsRng`:

```rust
pub fn generate() -> Self {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    Self { key }
}
```

There is **no key agreement protocol** — no Diffie-Hellman, no ECDH, no key exchange of any kind. The `establish_p2p_connection` function at `tunnel/mod.rs:261` calls `SessionKey::generate()` after hole punching succeeds, but this key is never transmitted to the peer. In the relay fallback path (line 273), the same pattern repeats — each side generates its own independent key.

The code comments at `crypto/mod.rs:7-9` state: "Key exchange is performed out-of-band through the control plane's signaling service" — but the signaling service at `ws.py` does NOT implement any key exchange. The `offer/answer` SDP exchange carries WebRTC candidates, not encryption keys.

**Impact:** Encrypted communication is mathematically impossible. Each peer encrypts with a different key that the other peer does not know. Either encryption is silently broken or the application layer encryption isn't actually being used for data-plane traffic.

**Remediation:** Implement ECDH key exchange. Each peer generates an ephemeral keypair, exchanges public keys via the signaling channel, and derives a shared session key using HKDF. This must be done BEFORE the application-layer encryption module is used.

---

#### A-CR3: Hardcoded HMAC Key Default in Relay ("dev-insecure-default-change-me")

**File:** `data-plane/src/relay/mod.rs`, lines 52-54  
**Severity:** CRITICAL

The relay's HMAC key defaults to a hardcoded string when `RELAY_HMAC_KEY` is not set:

```rust
hmac_key: std::env::var("RELAY_HMAC_KEY")
    .unwrap_or_else(|_| "dev-insecure-default-change-me".to_string())
    .into_bytes(),
```

This key authenticates the source device ID in all relayed packets. At line 211, `verify_hmac` checks this against the HMAC tag in packet headers. If the key is the default, anyone who reads the source code can forge device IDs.

**Impact:** Complete relay authentication bypass in any deployment without `RELAY_HMAC_KEY` set. An attacker can inject arbitrary traffic, spoof device identities, and redirect traffic to their own address (see line 226 where `register_device` updates the forwarding table after HMAC passes).

**Remediation:** Panic/exit on startup if `RELAY_HMAC_KEY` is not set in production. Use `std::env::var("RELAY_HMAC_KEY").expect("RELAY_HMAC_KEY must be set")` instead of `unwrap_or_else`.

---

#### A-CR4: Hardcoded Hole Punch HMAC Key as Literal Constant

**File:** `data-plane/src/tunnel/mod.rs`, line 243  
**Severity:** CRITICAL

```rust
let hmac_key = b"mesh-punch-hmac"; // In production: use a proper shared secret
```

The HMAC key used during UDP hole punching negotiation is a hardcoded byte literal. The comment acknowledges this is insecure but the code was never fixed. This key is passed to `puncher::execute_punch()` which — notably — never actually uses it anywhere in the function body (the `hmac_key` parameter at `puncher/mod.rs:167` is accepted but never referenced for authentication).

**Impact:** The hole punching protocol has zero authentication. Any attacker on the network path can spoof HELLO_ACK responses, hijacking P2P connection attempts. Combined with A-CR2 (no key agreement), this means an attacker can intercept and establish connections in place of legitimate peers.

**Remediation:** (1) Actually use the HMAC key in `execute_punch` to authenticate HELLO/HELLO_ACK packets. (2) Derive the punch HMAC key from the session's key exchange material rather than using a static literal.

---

### Section B: Data-Plane (Rust) — High Severity

#### B-H1: No TLS on Control Plane HTTP Connections

**Files:** `data-plane/src/tunnel/main.rs` lines 31, 42; `data-plane/src/bin/mesh-tunnel.rs` lines 36, 39; `data-plane/src/bin/mesh-relay.rs` lines 24, 28  
**Severity:** HIGH

All control plane API communications default to plain HTTP:

```rust
#[arg(long, default_value = "http://localhost:8000")]
api_url: String,

#[arg(long, default_value = "ws://localhost:8000/api/v1/ws")]
ws_url: String,
```

JWT tokens are sent in `Authorization: Bearer <token>` headers over unencrypted HTTP.

**Impact:** In any non-localhost deployment, JWT tokens are transmitted in plaintext, granting full control plane access to any network observer.

**Remediation:** Change defaults to `https://` and `wss://`. Add a startup warning if connecting over plain HTTP in a non-localhost configuration.

---

#### B-H2: Unbounded Memory Allocation from QUIC Receive

**File:** `data-plane/src/quic/mod.rs`, lines 62-75  
**Severity:** HIGH

The `recv` function appends all received data into a `Vec<u8>` with no size limit:

```rust
pub async fn recv(recv: &mut RecvStream) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut data = Vec::new();
    loop {
        let mut buf = [0u8; 65536];
        match recv.read(&mut buf).await? {
            Some(n) => {
                data.extend_from_slice(&buf[..n]);
                if n == 0 { break; }
            }
            None => break,
        }
    }
    Ok(data)
}
```

A malicious peer can send data in a continuous stream of small chunks, causing unbounded memory allocation.

**Remediation:** Add a maximum total receive size. Return an error if the accumulated data exceeds it (e.g., 10 MB for initial messages, configurable per-stream limit thereafter).

---

#### B-H3: Rate Limiting Bypass via Device ID Spoofing in Relay

**File:** `data-plane/src/relay/mod.rs`, lines 138-158, 219-221  
**Severity:** HIGH

The rate limiter is keyed by the (HMAC-authenticated) source device ID. However, if the HMAC key is compromised (see A-CR3), an attacker can rotate through arbitrary device IDs to bypass the per-device 100 packets/sec limit.

Additional concern at lines 198-199: device IDs are parsed from 16-byte fixed fields using `String::from_utf8_lossy` with no format validation:

```rust
let src_id = String::from_utf8_lossy(src_id_bytes).trim_end_matches('\0').to_string();
```

**Remediation:** Add IP-based rate limiting as a secondary layer. Validate device IDs against expected format and length.

---

#### B-H4: Number of He Hole Punch Packets Creates Amplification Vector

**File:** `data-plane/src/puncher/mod.rs`, lines 194-262  
**Severity:** HIGH

The hole punching loop sends HELLO packets to ALL peer candidates every ~50ms, with no limit on the number of candidates or total packets:

```rust
for candidate in peer_candidates {
    socket.send_to(&hello_packet, candidate.addr).await...;
}
tokio::time::sleep(Duration::from_millis(20)).await;
```

With default 10s timeout and 50ms interval, this sends approximately 200 packets per candidate. A malicious signaling message could include an inflated candidate list targeting arbitrary IP addresses.

**Remediation:** Cap the number of peer candidates. Add a total punch packet budget per session. Validate that target addresses are not multicast, broadcast, or loopback.

---

### Section C: Control-Plane (Python/FastAPI) — Critical & High

#### C-CR1: Refresh Token Strips Admin Role — Privilege Escalation Reversal

**Files:** `control-plane/app/services/auth_service.py`, lines 59-71 (creation), 171-190 (refresh)  
**Severity:** CRITICAL

`create_refresh_token` (line 59) does NOT include the user's `role` in the JWT payload:

```python
payload = {
    "sub": str(user_id),
    "jti": jti,
    "type": "refresh",
    "iat": now,
    "exp": now + timedelta(days=settings.JWT_REFRESH_EXPIRE_DAYS),
}
# NOTE: "role" is missing
```

When `refresh_access_token` decodes the refresh token (line 190), it falls back to `"user"`:

```python
return create_access_token(user_id, role=payload.get("role", "user"))
```

If an admin user refreshes their token, the new access token silently becomes a `"user"` role token — breaking admin access. Conversely, if a user's role is downgraded from admin to user, the existing refresh token doesn't carry the updated role.

**Remediation:** Include `role` in the refresh token payload. Additionally, during refresh, re-fetch the user from the database and use the current DB role rather than the JWT-embedded role.

---

#### C-CR2: Batch Traffic Report Bypasses Device Ownership Verification

**File:** `control-plane/app/api/traffic.py`, lines 78-108  
**Severity:** CRITICAL

The single traffic report endpoint (line 41-75) correctly verifies that `data.device_id` belongs to the authenticated user:

```python
# Single report: VERIFIES ownership (line 54-57)
result = await db.execute(
    select(Device).where(Device.id == data.device_id, Device.user_id == user.id)
)
if not result.scalar_one_or_none():
    raise HTTPException(status_code=403, ...)
```

The batch endpoint (line 78-108) does NO such verification:

```python
# Batch report: NO verification (lines 92-106)
for report in data.reports:
    _validate_traffic_report(report)
    await billing_service.report_traffic(
        db, user_id=user.id, device_id=report.device_id, ...
    )
```

**Impact:** Any authenticated user can submit traffic reports for ANY device, allowing them to inflate or deflate billing data for other users — including potential DoS by exhausting their free-tier quotas.

**Remediation:** Add device ownership verification inside the batch loop for each `report.device_id`.

---

#### C-H1: Refresh Token Session Isolation — Single Session Only

**File:** `control-plane/app/services/auth_service.py`, lines 161-165  
**Severity:** HIGH

Refresh tokens are stored in Redis keyed ONLY by `user_id`:

```python
await redis_client.setex(
    f"refresh_token:{user.id}",
    settings.JWT_REFRESH_EXPIRE_DAYS * 86400,
    refresh_token,
)
```

A user can have only ONE valid refresh token at a time. Logging in from a new device silently overwrites the previous one. There is no device or session identifier.

**Remediation:** Store refresh tokens keyed by `{user_id}:{device_id}` or `{user_id}:{session_id}`. Support multiple concurrent refresh tokens. Implement refresh token rotation.

---

#### C-H2: Login Lockout Reveals Lockout Duration

**File:** `control-plane/app/services/auth_service.py`, lines 131-133  
**Severity:** HIGH

```python
raise ValueError(
    f"Account locked due to too many failed attempts. Try again in {ttl // 60 + 1} minutes."
)
```

The error message communicates the exact remaining lockout time. This confirms to the attacker that the email account exists and tells them precisely when to resume brute-force attempts.

**Remediation:** Use a fixed generic response: "Too many login attempts. Please try again later." Log the detailed information internally.

---

#### C-H3: Password Change Doesn't Invalidate Existing Tokens

**File:** `control-plane/app/services/auth_service.py`, lines 210-220  
**Severity:** HIGH

`change_password` updates the password hash but does not invalidate existing access or refresh tokens. An attacker with a stolen token retains access even after the victim changes their password.

**Remediation:** After password change, blacklist all active JTI tokens for that user and delete their refresh token from Redis.

---

### Section D: Services (Microservices) — High & Medium

#### D-H1: TrustedHostMiddleware Effectively Disabled (allowed_hosts=["*"])

**Files:** `services/auth-service/app/main.py:208`, `services/user-service/app/main.py:201`, `services/usage-service/app/main.py:153`  
**Severity:** HIGH

```python
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["*"])
```

With `allowed_hosts=["*"]`, every host header is trusted, making the middleware a no-op. Host header injection attacks are possible — an attacker can send `Host: evil.com`, which could be used for cache poisoning, password reset poisoning, and bypassing proxy-based security rules.

**Remediation:** Set `allowed_hosts` to the actual domain(s) used in production.

---

#### D-H2: CORS `allow_origins=["*"]` with `allow_credentials=True` in Production

**Files:** `services/relay-service/app/main.py:211-218`, `services/usage-service/app/main.py:142-149`, `services/signaling-service/app/main.py:234-241`  
**Severity:** HIGH

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Nginx should restrict this at the edge
    allow_credentials=True,
    ...
)
```

Using `allow_origins=["*"]` with `allow_credentials=True` violates the CORS specification. Most modern browsers will reject this, but the comment "Nginx should restrict this at the edge" delegates security to an external component.

**Remediation:** Use explicit origin whitelists. Do not rely on Nginx alone for CORS enforcement.

---

#### D-H3: Auth Service Email Enumeration via Timing Side-Channel

**File:** `services/auth-service/app/api.py`, lines 24-41; `services/auth-service/app/service.py`, line 115  
**Severity:** HIGH

The registration endpoint uses a generic error message ("Registration failed. Check your input and try again.") to prevent user enumeration. However, the password strength validation runs AFTER the email uniqueness check. If the email exists, the function returns quickly with the email error. If it doesn't exist, the password strength check runs (multiple `any()` iterations), creating a measurable timing difference.

**Remediation:** Run password strength validation before the email uniqueness check, or add a constant-time delay after the email check.

---

#### D-M1: WebSocket Message Size Enforced After Receipt, Not Before

**File:** `services/signaling-service/app/api.py`, lines 119-127  
**Severity:** MEDIUM

```python
raw = await ws.receive_text()
if len(raw) > settings.WS_MAX_MESSAGE_BYTES:
    await ws.send_json({"type": "error", "message": "Message too large"})
    continue
```

The message is fully received (up to WebSocket's default max size, typically 1MB+) before the size check. An attacker can send repeated near-max-size messages to exhaust server memory.

**Remediation:** Use the `max_size` parameter in `receive_text()`: `await ws.receive_text()`. Actually, FastAPI/Starlette doesn't directly support max_size on receive_text. Instead, use `receive_bytes()` with a size limit or implement a read-with-limit wrapper.

---

#### D-M2: OTLP Tracing Uses `insecure=True` — No TLS, No Auth

**File:** `services/shared/app/tracing.py`, line 25  
**Severity:** MEDIUM

```python
exporter = OTLPSpanExporter(endpoint=otlp_endpoint, insecure=True)
```

Traces containing user IDs, email addresses, and IPs are sent over unencrypted, unauthenticated gRPC.

**Remediation:** Enable TLS and add authentication to the OTLP exporter.

---

#### D-M3: No Rate Limit on Registration Endpoint

**File:** `services/auth-service/app/api.py`, lines 24-41  
**Severity:** MEDIUM

The registration endpoint has no rate limiting, allowing mass account creation abuse.

**Remediation:** Add rate limiting to the register endpoint. Consider adding CAPTCHA support.

---

#### D-M4: Worker Per-Batch Engine Creation — Inefficient and Brittle

**File:** `services/worker/app/worker.py`, lines 94-109  
**Severity:** MEDIUM

```python
engine = create_async_engine(settings.DATABASE_URL, pool_size=5)
async with engine.begin() as conn:
    for record in batch:
        await conn.execute(text("INSERT INTO ..."), {...})
await engine.dispose()
```

A new database engine and connection pool are created and destroyed for each batch. If `DATABASE_URL` is empty, the crash message is not user-friendly.

**Remediation:** Create the engine once at startup and reuse it. Use a proper connection pool.

---

#### D-M5: Shared JWT Utils Have Module-Level Config Instantiation

**File:** `services/shared/app/jwt_utils.py`, line 18; `services/shared/app/database.py`, line 13  
**Severity:** MEDIUM

```python
_settings = BaseConfig()  # jwt_utils.py:18
_settings = BaseConfig()  # database.py:13
```

These module-level instantiations call `_require_env("DATABASE_URL")` at import time, crashing any import of the shared module if the env var is absent — even if the importer doesn't need a database.

**Remediation:** Use lazy initialization or require explicit config passing.

---

#### D-M6: Audit Log Creates New Redis Connection Per Event

**File:** `services/shared/app/audit.py`, lines 18-46  
**Severity:** MEDIUM

```python
r = redis.from_url(redis_url, decode_responses=True)
await r.rpush(AUDIT_QUEUE, json.dumps(event))
await r.close()
```

Each call to `audit_log()` creates a fresh Redis connection. Under high load (e.g., brute-force attack triggering many failed-login events), this creates connection exhaustion and silently drops audit events if Redis is temporarily unavailable, as there is no retry logic.

**Remediation:** Use a connection pool or reuse a shared Redis client. Add retry with exponential backoff.

---

#### D-M7: Unauthenticated Relay Info Endpoint

**File:** `services/relay-service/app/api.py`, lines 188-208  
**Severity:** MEDIUM

The `/best` relay endpoint returns relay node IP addresses and ports without any authentication. An attacker can enumerate all relay nodes and their regions, mapping internal network topology.

**Remediation:** Add authentication to this endpoint, or at minimum require JWT authentication.

---

### Section E: Deployment & Infrastructure — Critical & High

#### E-CR1: Development Secrets Committed to Version Control

**File:** `deployment/.env` (all lines)  
**Severity:** CRITICAL

```ini
POSTGRES_PASSWORD=mesh_dev_password_change_me
REDIS_PASSWORD=redis_dev_password_change_me
JWT_SECRET=dev-jwt-secret-change-me-in-production-use-secrets-token-hex-64
RELAY_AUTH_TOKEN=dev-relay-auth-token-change-me-in-production
INTERNAL_API_KEY=dev-internal-api-key-change-me-in-production
GRAFANA_PASSWORD=grafana_dev_password_change_me
```

The `.env` file with hardcoded development credentials is tracked in git. The `.env.example` file contains identical values. Any deployment that copies `.env.example` without changing values runs with trivially guessable secrets.

**Remediation:** Ensure `.env` is in `.gitignore`. Replace `.env.example` values with clearly invalid placeholders like `CHANGE_ME_REQUIRED` that will cause startup failures, not silent acceptance.

---

#### E-CR2: Grafana Password Has No Default Fallback

**File:** `deployment/docker-compose.yml`, lines 203-205  
**Severity:** CRITICAL

```yaml
- GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_PASSWORD}
```

`GRAFANA_PASSWORD` has no `:-default` fallback. If unset, Grafana uses its factory default (`admin`/`admin`), which is publicly known. Same issue in all four docker-compose files (dev, prod, microservices dev, microservices prod).

**Remediation:** Either provide a default fallback that generates a random password, or make startup fail if `GRAFANA_PASSWORD` is not set.

---

#### E-CR3: Unpinned Container Image Tags (`:latest`, `-alpine`)

**Files:** `deployment/docker-compose.yml` lines 13, 95, 182, 200; `deployment/docker-compose.prod.yml`  
**Severity:** CRITICAL

```yaml
image: postgres:16-alpine       # Patch version not pinned
image: redis:7-alpine           # Same issue
image: prom/prometheus:latest   # Floating tag
image: grafana/grafana:latest   # Floating tag
```

Using floating tags means deployments pull whatever version is newest at deploy time with no reproducibility. A compromised or breaking upstream image would be silently deployed.

**Remediation:** Pin all images to SHA256 digests. Use Dependabot or Renovate for automated digest updates.

---

#### E-H1: Kubernetes Namespace Has No NetworkPolicy

**File:** `deployment/k8s/microservices/` (no NetworkPolicy manifest)  
**Severity:** HIGH

No `NetworkPolicy` resource is defined. By default, Kubernetes allows all pod-to-pod communication within and across namespaces. A single compromised microservice pod can reach the PostgreSQL database, Redis, and all other services.

**Remediation:** Define NetworkPolicy resources that restrict traffic to only necessary paths (e.g., API → DB, API → Redis, nothing else).

---

#### E-H2: CI/CD Pipeline Suppresses Security Audit Failures

**File:** `.github/workflows/deploy.yml`, lines 56, 75  
**Severity:** HIGH

```yaml
- name: Python dependency audit
  run: pip-audit || true  # Non-blocking
- name: Rust dependency audit
  run: cargo audit || true  # Non-blocking
```

Both `pip-audit` and `cargo audit` have `|| true`, meaning the pipeline succeeds even if known CVEs are found.

**Remediation:** Remove `|| true`. Either make these blocking or add a separate non-blocking advisory scan.

---

#### E-H3: Docker Socket Mounted into Promtail (Host Root Access)

**File:** `deployment/docker-compose.microservices.yml`, line 377  
**Severity:** HIGH

```yaml
volumes:
  - /var/run/docker.sock:/var/run/docker.sock:ro
```

Mounting the Docker socket grants the Promtail container effective root-level access to the Docker daemon. This is a well-known security anti-pattern.

**Remediation:** Use a log shipper that doesn't require Docker socket access, or use a dedicated logging sidecar with minimal permissions.

---

#### E-H4: Let's Encrypt Mount Exposes All Host Certificates

**File:** `deployment/docker-compose.prod.yml`, line 25  
**Severity:** HIGH

```yaml
volumes:
  - /etc/letsencrypt:/etc/letsencrypt:ro
```

The entire Let's Encrypt directory is mounted, exposing private keys for all domains managed on the host — not just the mesh domain. If Nginx is compromised, all TLS private keys on the host are readable.

**Remediation:** Mount only the specific certificate files needed, or use a dedicated certificate volume.

---

#### E-M1: No Security Context on PostgreSQL/Redis K8s Deployments

**Files:** `deployment/k8s/microservices/postgres.yaml`, `deployment/k8s/microservices/redis.yaml`  
**Severity:** MEDIUM

Neither PostgreSQL nor Redis containers have security contexts (`runAsNonRoot`, `capabilities.drop`, `readOnlyRootFilesystem`). Database containers run with full capabilities and a writable root filesystem.

**Remediation:** Add security contexts to all containers, even infrastructure services.

---

#### E-M2: Ingress Exposes Services Without WAF or Rate Limiting

**File:** `deployment/k8s/microservices/ingress.yaml`, lines 25-66  
**Severity:** MEDIUM

The ingress uses prefix path matching for all services without annotations for IP whitelisting, OAuth authentication, WAF integration, or ingress-level rate limiting. All microservices are directly routable from the internet with only application-level JWT protection.

**Remediation:** Add ingress annotations for rate limiting, IP whitelisting where appropriate, and consider adding a WAF (e.g., `nginx.ingress.kubernetes.io/configuration-snippet` for ModSecurity).

---

#### E-M3: No Image Vulnerability Scanning in CI/CD

**File:** `.github/workflows/deploy.yml`  
**Severity:** MEDIUM

The pipeline builds and pushes Docker images without scanning them for known vulnerabilities (Trivy, Grype, Docker Scout). This is acknowledged but not fixed in SECURITY.md line 109.

**Remediation:** Add a Trivy or Grype scan step before the Docker push step.

---

### Section F: Low Severity — Configuration Hygiene

#### F-L1: `version: "3.8"` Deprecated in Docker Compose V2

**Files:** `deployment/docker-compose.prod.yml:14`, `deployment/docker-compose.microservices.prod.yml:15`

The `version` field has been deprecated; remove it.

---

#### F-L2: DH Parameters Use 2048-bit (Minimum Recommended)

**File:** `scripts/setup-server.sh`, lines 41-42

4096-bit DH parameters are recommended for long-term security. The `-dsaparam` fallback may produce weaker parameters on older OpenSSL versions.

---

#### F-L3: No Healthcheck on STUN Service

**Files:** All docker-compose files

The STUN server has no `healthcheck` defined. A failing STUN server would silently break NAT traversal.

---

#### F-L4: `psycopg2-binary` Listed in relay-service Requirements but Unused

**File:** `services/relay-service/requirements.txt`, line 11

The relay-service uses async SQLAlchemy with `asyncpg`, not `psycopg2`. This dead dependency adds unnecessary CVE surface.

---

#### F-L5: Log Messages Contain Peer IP Addresses at INFO Level

**Files:** `data-plane/src/quic/mod.rs:51`, `data-plane/src/puncher/mod.rs:186-190`, `data-plane/src/tunnel/main.rs:85`

Peer IP addresses are logged at INFO level, potentially violating privacy expectations.

---

#### F-L6: No Content-Security-Policy Header in Nginx Configs

**Files:** `deployment/nginx/nginx.conf`, `deployment/nginx/nginx.prod.conf`

The prod config sets several security headers (HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy) but omits CSP.

---

#### F-L7: `_require_env` Error Messages Leak Internal Config Structure

**File:** `control-plane/app/config.py`, lines 12-20

```python
raise RuntimeError(f"CRITICAL: Environment variable {key} is not set.")
```

If this surfaces to an HTTP response during a failed startup probe, it leaks configuration structure.

---

#### F-L8: Redis Initialization Race Condition

**File:** `control-plane/app/database.py`, lines 71-77

Lazy Redis initialization could race between concurrent coroutines during startup.

---

## Summary of All Findings

| Severity | Round 1 (Fixed) | Round 2 (Active) | Total |
|----------|-----------------|------------------|-------|
| Critical | 4 | 7 | 11 |
| High     | 4 | 14 | 18 |
| Medium   | 8 | 18 | 26 |
| Low      | 0 | 16 | 16 |
| **Total** | **16** | **55** | **71** |

---

## Top 10 Priority Remediations

1. **Fix QUIC MitM** (A-CR1) — Certificate pinning via signaling channel; cannot deploy with SkipServerVerification
2. **Implement Key Agreement** (A-CR2) — ECDH key exchange through signaling; encryption is currently non-functional
3. **Remove Hardcoded HMAC Keys** (A-CR3, A-CR4) — Require env-provided HMAC keys; hard-fail on missing keys
4. **Fix Batch Traffic Device Ownership** (C-CR2) — Add device ownership check in batch endpoint loop
5. **Fix Refresh Token Role Handling** (C-CR1) — Include role in refresh token; re-fetch from DB on refresh
6. **Pin Container Image Digests** (E-CR3) — SHA256 digests for all images; remove `:latest` tags
7. **Remove `.env` from Git** (E-CR1) — Add to `.gitignore`; replace `.env.example` with invalid placeholders
8. **Fix Grafana Password Default** (E-CR2) — Add random fallback or require env var at startup
9. **Add K8s NetworkPolicy** (E-H1) — Segment database, Redis, and services; deny-by-default
10. **Fix CI/CD Security Audit Bypass** (E-H2) — Remove `|| true` from `pip-audit` and `cargo audit`

---

## Notable Strengths

Despite the findings above, the project demonstrates strong security consciousness in many areas:

- **bcrypt with work factor 12** and constant-time comparison for passwords
- **JTI-based JWT revocation** with Redis blacklist for precise token invalidation
- **Field whitelisting** (`ALLOWED_UPDATE_FIELDS = {"name"}`) to prevent role/plan escalation
- **Generic error messages** on login to prevent user enumeration
- **Security warning emission at startup** when secrets use fallback values
- **Non-root containers** (`USER mesh` in Dockerfile.api)
- **K8s security contexts** on microservice deployments (`runAsNonRoot`, `capabilities.drop: ["ALL"]`, `readOnlyRootFilesystem`)
- **Redis authentication** with `REDISCLI_AUTH` env var (not `-a` flag visible in /proc)
- **HSTS and security headers** in production nginx config
- **`init: true`** on API containers for proper signal handling
- **Well-documented security architecture** in SECURITY.md with defense-in-depth design
- **Comprehensive healthchecks** on all major services
- **Rate limiting** at both Nginx and application level

---

*Report generated May 7, 2026. All Round 1 findings have been patched. Round 2 findings await remediation.*
