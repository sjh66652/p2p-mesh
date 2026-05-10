# P2P Mesh Network v2.0.0 — Build & Release Guide

## Overview

This package contains the P2P Mesh Network data-plane binaries and build tools.

```
release-package/
├── README.md              # This file
├── linux/                  # Pre-built Linux x86_64 binaries
│   ├── mesh-tunnel         # P2P client endpoint
│   ├── mesh-relay          # Relay forwarding node (server)
│   ├── mesh-stun           # STUN server (NAT traversal)
│   └── mesh-overlay        # Overlay network manager (TUN + routing)
├── configs/                # Configuration templates
│   ├── client.toml         # mesh-tunnel config
│   ├── relay.toml          # mesh-relay config
│   ├── stun.toml           # mesh-stun config
│   └── .env.example        # Environment variables
└── scripts/                # Build & deploy scripts
    ├── build-all.ps1       # Windows one-click build
    ├── build-windows.ps1   # Windows build script
    ├── build-windows.bat   # Windows batch build
    ├── deploy-server.sh    # Linux server deployment
    └── deploy-client.sh    # Linux client deployment
```

## Binary Roles

| Binary | Role | Platform | Category |
|--------|------|----------|----------|
| **mesh-tunnel** | P2P client endpoint — connects to mesh, NAT traversal, QUIC transport | Windows, Linux, macOS | **Client** |
| **mesh-relay** | Relay forwarding node — zero-trust UDP packet forwarding for symmetric NAT fallback | Windows, Linux | **Server** |
| **mesh-stun** | STUN server — public address discovery for NAT traversal | Windows, Linux | **Server** |
| **mesh-overlay** | Full overlay network node — TUN interface, routing, ACL, DNS, ICE | **Linux/macOS only** | **Server** |

> **Note:** `mesh-overlay` requires a TUN/TAP virtual network interface and is Linux/macOS only. Use `mesh-tunnel` for Windows client endpoints.

---

## Building from Source

### Prerequisites (all platforms)

- Rust 1.80+ (install via https://rustup.rs)
- Git

### Windows Build

**Option A: Native build (recommended)**

1. Install Visual Studio 2022 Build Tools with "Desktop development with C++" workload
2. Open **Developer Command Prompt for VS 2022**
3. Run:
```
cd data-plane
cargo build --release --bin mesh-tunnel --bin mesh-relay --bin mesh-stun
```
4. Find EXEs in `target\release\`

**Option B: One-click script**
```
cd data-plane
powershell -ExecutionPolicy Bypass -File .\scripts\build-all.ps1
```

**Option C: GitHub Actions (CI)**

Push to GitHub and use the workflow at `.github\workflows\windows-build.yml`. Artifacts are downloadable from the Actions tab.

### Linux Build

```
cd data-plane
cargo build --release --bin mesh-tunnel --bin mesh-relay --bin mesh-stun --bin mesh-overlay
```

Output: `target/release/mesh-tunnel`, `mesh-relay`, `mesh-stun`, `mesh-overlay`

---

## Deployment

### Client (mesh-tunnel)

**Windows:**
```powershell
# Set environment variables
setx MESH_TOKEN "your_jwt_token"
setx API_URL "https://your-server.example.com"

# Run
.\mesh-tunnel.exe --device-id "my-device-001"

# Or install as Windows service (Admin)
sc.exe create P2PMeshTunnel binPath= "C:\p2p-mesh\mesh-tunnel.exe --device-id my-device-001" start= auto
sc.exe start P2PMeshTunnel
```

**Linux:**
```bash
export MESH_TOKEN="your_jwt_token"
export API_URL="https://your-server.example.com"
./mesh-tunnel --device-id "my-device-001"
```

### Relay Server (mesh-relay)

```bash
export RELAY_AUTH_TOKEN="your_relay_token"
export RELAY_ID="relay-us-east-1"
export REGION="us-east"
./mesh-relay
```

### STUN Server (mesh-stun)

```bash
./mesh-stun --port 3478 --bind 0.0.0.0
```

### Overlay Node (mesh-overlay) — Linux only

```bash
export MESH_AUTH_TOKEN="your_token"
export MESH_DEVICE_ID="your_device_uuid"
./mesh-overlay
```

---

## Configuration Reference

See `configs/` directory for template files:
- `client.toml` — mesh-tunnel settings (API URL, ports, advanced options)
- `relay.toml` — mesh-relay settings (region, capacity, heartbeat)
- `stun.toml` — mesh-stun settings (bind address, port)
- `.env.example` — all environment variables

---

## Security Notes

- JWT tokens are read from MESH_TOKEN env var, never CLI args
- RELAY_AUTH_TOKEN is read from environment, never config files
- PUNCH_HMAC_KEY should be a 64-char hex string for hole-punch authentication
- Generate HMAC key: `openssl rand -hex 32`
- Always use HTTPS/WSS in production (plaintext HTTP is logged as a warning)

---

## Technical Details

- **Language:** Rust (edition 2021)
- **Async runtime:** Tokio
- **Transport:** QUIC (quinn) + ChaCha20-Poly1305 AEAD
- **NAT traversal:** STUN + UDP hole punching + relay fallback
- **Crypto:** Noise IK (snow), X25519 ECDH, SHA-256, HMAC
- **TUN:** Linux `/dev/net/tun` / macOS utun (overlay node only)
- **Features:** dpdk, io-uring, pqc (post-quantum crypto), jni (Android)

---

## Troubleshooting

**"TUN read not supported on Windows"** — mesh-overlay is Linux/macOS only. Use mesh-tunnel for Windows.

**"PUNCH_HMAC_KEY not set"** — Generate with `openssl rand -hex 32` and set the env var.

**"Build failed: linker not found"** — Install Visual Studio Build Tools or use LLVM/Clang.

**"STUN query failed"** — Ensure STUN server is reachable and port 3478 is open.
