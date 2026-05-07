"""
WebSocket signaling API - real-time communication for P2P connection setup.

Security:
  - JWT token authentication with device ownership verification
  - Per-connection rate limiting (prevents signaling DoS)
  - Max message size enforcement
  - Audit logging for connection events
  - Generic error messages (no internal info leak)
  - Per-device connection limit (configurable via SIGNALING_MAX_CONNS_PER_DEVICE)
"""

import os
import time
import uuid
import logging
from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from jose import jwt, JWTError

from app.config import settings
from app.database import get_redis, async_session_factory
from app.services.signaling_service import signaling_hub

logger = logging.getLogger("p2p-mesh.ws")
router = APIRouter()

# Per-device connection tracking: device_id -> set of WebSocket objects
_active_device_connections: dict[str, set[WebSocket]] = {}
# Configurable limit on concurrent connections per device
MAX_CONNS_PER_DEVICE: int = int(os.getenv("SIGNALING_MAX_CONNS_PER_DEVICE", "3"))


@router.websocket("/{device_id}")
async def websocket_endpoint(
    ws: WebSocket,
    device_id: str,
) -> None:
    # ---- Phase 1: Accept connection first ----
    await ws.accept()

    # ---- Phase 2: JWT authentication via Authorization header ----
    # Token is passed in the WebSocket upgrade request's Authorization header,
    # NOT in the URL query string (which would leak into Nginx/proxy logs).
    auth_header = ws.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        await ws.send_json({"type": "error", "message": "Authentication required"})
        await ws.close(code=4001)
        return

    token = auth_header[7:]  # strip "Bearer "

    try:
        payload = jwt.decode(
            token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM],
            options={"require": ["exp", "sub", "type", "jti"]},
        )
    except JWTError:
        await ws.send_json({"type": "error", "message": "Authentication failed"})
        await ws.close(code=4001)
        return

    if payload.get("type") != "access":
        await ws.send_json({"type": "error", "message": "Invalid token type"})
        await ws.close(code=4001)
        return

    user_id_str = payload.get("sub")
    jti = payload.get("jti")
    if not user_id_str or not jti:
        await ws.send_json({"type": "error", "message": "Invalid token"})
        await ws.close(code=4001)
        return

    # Check JWT blacklist (logout revocation) — same as REST endpoints
    redis_conn = await get_redis()
    is_blacklisted = await redis_conn.exists(f"jwt_blacklist:{jti}")
    if is_blacklisted:
        await ws.send_json({"type": "error", "message": "Token has been revoked"})
        await ws.close(code=4001)
        return

    try:
        user_id = uuid.UUID(user_id_str)
    except ValueError:
        await ws.send_json({"type": "error", "message": "Invalid token"})
        await ws.close(code=4001)
        return

    # ---- Phase 3: Verify device ownership ----
    # This prevents attackers from connecting as another user's device
    async with async_session_factory() as db:
        from app.models.device import Device
        from sqlalchemy import select

        try:
            dev_uuid = uuid.UUID(device_id)
        except ValueError:
            await ws.send_json({"type": "error", "message": "Invalid device ID"})
            await ws.close(code=4002)
            return

        result = await db.execute(
            select(Device).where(Device.id == dev_uuid, Device.user_id == user_id)
        )
        device = result.scalar_one_or_none()

        if device is None:
            logger.warning(
                "WS auth failed: device %s does not belong to user %s",
                device_id, user_id,
            )
            await ws.send_json({"type": "error", "message": "Device not authorized"})
            await ws.close(code=4003)
            return

        # Invalidate tokens issued before the user's last password change
        token_iat = payload.get("iat")
        if token_iat is not None:
            from app.models.user import User as UserModel
            user_result = await db.execute(select(UserModel).where(UserModel.id == user_id))
            db_user = user_result.scalar_one_or_none()
            if db_user is not None and db_user.password_updated_at is not None:
                if token_iat < db_user.password_updated_at.timestamp():
                    await ws.send_json({"type": "error", "message": "Token has been revoked"})
                    await ws.close(code=4001)
                    return

    # ---- Phase 4: Per-device connection limit ----
    # Prevents resource exhaustion from a single device opening too many connections
    if device_id not in _active_device_connections:
        _active_device_connections[device_id] = set()

    conns = _active_device_connections[device_id]
    if len(conns) >= MAX_CONNS_PER_DEVICE:
        # Close the oldest connection for this device
        oldest = conns.pop()
        logger.warning(
            "WS per-device limit hit for device %s: closing oldest connection",
            device_id,
        )
        try:
            await oldest.close(code=4004, reason="Connection limit reached")
        except Exception:
            pass

    _active_device_connections[device_id].add(ws)

    # ---- Phase 5: Register in signaling hub ----
    dev_uuid = uuid.UUID(device_id)
    await signaling_hub.connect(dev_uuid, user_id, ws)
    logger.info("WS connected: device=%s user=%s", device_id, user_id)

    # Per-connection rate limiting state
    msg_timestamps: list[float] = []

    try:
        await ws.send_json({
            "type": "authenticated",
            "device_id": device_id,
        })

        while True:
            # Receive with max size enforcement
            try:
                raw = await ws.receive_text()
            except WebSocketDisconnect:
                break

            # Enforce max message size
            if len(raw) > settings.WS_MAX_MESSAGE_BYTES:
                await ws.send_json({"type": "error", "message": "Message too large"})
                continue

            # Parse JSON
            try:
                import json as _json
                msg = _json.loads(raw)
            except Exception:
                await ws.send_json({"type": "error", "message": "Invalid message format"})
                continue

            # Rate limiting: sliding window
            now = time.time()
            msg_timestamps = [t for t in msg_timestamps if now - t < 1.0]
            msg_timestamps.append(now)
            if len(msg_timestamps) > settings.WS_MAX_MESSAGES_PER_SECOND:
                await ws.send_json({"type": "error", "message": "Rate limit exceeded"})
                logger.warning("WS rate limit hit: device=%s", device_id)
                continue

            # Process message
            await handle_signal(ws, dev_uuid, user_id, msg)

    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.error("WS error device=%s: %s", device_id, e)
    finally:
        await signaling_hub.disconnect(dev_uuid)
        # Clean up per-device connection tracking
        if device_id in _active_device_connections:
            _active_device_connections[device_id].discard(ws)
            if not _active_device_connections[device_id]:
                del _active_device_connections[device_id]
        logger.info("WS disconnected: device=%s user=%s", device_id, user_id)


async def handle_signal(
    ws: WebSocket,
    device_id: uuid.UUID,
    user_id: uuid.UUID,
    msg: dict[str, Any],
) -> None:
    """Process an incoming signaling message with validation."""
    msg_type = msg.get("type", "")

    # Whitelist of allowed message types
    # Phase 1 additions: candidates (NAT traversal), stun_result, punch_request
    ALLOWED_TYPES = {
        "ping", "offer", "answer", "ice_candidate", "get_peers",
        "candidates", "candidates_request", "stun_result",
        "punch_request", "punch_result", "path_quality",
    }
    if msg_type not in ALLOWED_TYPES:
        await ws.send_json({"type": "error", "message": "Unknown message type"})
        return

    if msg_type == "ping":
        await ws.send_json({"type": "pong"})
        return

    if msg_type == "get_peers":
        # Only expose devices belonging to the same user
        peers = await signaling_hub.get_online_peers(device_id)
        # Filter: only return peer's device_id, no user info leakage
        safe_peers = [
            {"device_id": p["device_id"]}
            for p in peers
        ]
        await ws.send_json({"type": "peers_list", "peers": safe_peers})
        return

    # ---- Phase 1: NAT Traversal Messages ----

    if msg_type == "stun_result":
        # Peer reports its STUN-discovered public address
        public_addr = msg.get("public_addr", "")
        nat_type = msg.get("nat_type", "unknown")
        await signaling_hub.update_device_nat(device_id, nat_type, public_addr)
        logger.info(
            "STUN result from device %s: addr=%s, nat=%s",
            device_id, public_addr, nat_type,
        )
        await ws.send_json({"type": "stun_ack"})
        return

    if msg_type == "candidates":
        # Peer shares its candidates (local + STUN addresses)
        candidates = msg.get("candidates", [])
        if not isinstance(candidates, list) or len(candidates) > 20:
            await ws.send_json({"type": "error", "message": "Invalid candidates"})
            return
        await signaling_hub.store_candidates(device_id, candidates)
        await ws.send_json({"type": "candidates_ack", "count": len(candidates)})
        logger.info("Candidates stored for device %s: %d entries", device_id, len(candidates))
        return

    if msg_type == "candidates_request":
        # Request a specific peer's candidates
        target_str = msg.get("peer_id", "")
        if not target_str:
            await ws.send_json({"type": "error", "message": "Missing peer_id"})
            return
        try:
            target_id = uuid.UUID(target_str)
        except ValueError:
            await ws.send_json({"type": "error", "message": "Invalid peer ID"})
            return

        peer_candidates = await signaling_hub.get_peer_candidates(device_id, target_id)
        if peer_candidates is None:
            await ws.send_json({
                "type": "candidates_response",
                "peer_id": target_str,
                "candidates": [],
                "error": "Peer not authorized or no candidates",
            })
        else:
            await ws.send_json({
                "type": "candidates_response",
                "peer_id": target_str,
                "candidates": peer_candidates,
            })

    if msg_type == "punch_request":
        # Initiate hole punching with a peer
        target_str = msg.get("peer_id", "")
        if not target_str:
            await ws.send_json({"type": "error", "message": "Missing peer_id"})
            return
        try:
            target_id = uuid.UUID(target_str)
        except ValueError:
            await ws.send_json({"type": "error", "message": "Invalid peer ID"})
            return

        # Forward punch request to target peer
        delivered = await signaling_hub.relay_signal(
            device_id, target_id, "punch_offer",
            {"from_device": str(device_id), "candidates": msg.get("our_candidates", [])},
        )
        if not delivered:
            await ws.send_json({"type": "error", "message": "Peer not available"})
        else:
            await ws.send_json({"type": "punch_ack", "peer_id": target_str})

    if msg_type == "punch_result":
        # Report hole punch result (success/failure)
        target_str = msg.get("peer_id", "")
        success = msg.get("success", False)
        path_type = msg.get("path_type", "relay")
        logger.info(
            "Punch result: device=%s -> peer=%s success=%s path=%s",
            device_id, target_str, success, path_type,
        )
        await ws.send_json({"type": "punch_result_ack"})

    if msg_type == "path_quality":
        # Report path quality metrics for active connections
        metrics = msg.get("metrics", {})
        logger.debug("Path quality from device %s: %s", device_id, metrics)
        await ws.send_json({"type": "path_quality_ack"})
        return

    # For offer/answer/ice_candidate: validate target
    target_str = msg.get("to", "")
    if not target_str:
        await ws.send_json({"type": "error", "message": "Missing target device"})
        return

    try:
        target_id = uuid.UUID(target_str)
    except ValueError:
        await ws.send_json({"type": "error", "message": "Invalid target device ID"})
        return

    # Prevent self-messaging (potential abuse)
    if target_id == device_id:
        await ws.send_json({"type": "error", "message": "Cannot signal yourself"})
        return

    # Relay the signal
    payload = {}
    if msg_type in ("offer", "answer"):
        sdp = msg.get("sdp")
        if not sdp or not isinstance(sdp, str) or len(sdp) > 32768:
            await ws.send_json({"type": "error", "message": "Invalid SDP"})
            return
        payload["sdp"] = sdp

    elif msg_type == "ice_candidate":
        candidate = msg.get("candidate", "")
        if not isinstance(candidate, str) or len(candidate) > 4096:
            await ws.send_json({"type": "error", "message": "Invalid ICE candidate"})
            return
        payload["candidate"] = candidate
        payload["sdp_mid"] = msg.get("sdp_mid", "")
        payload["sdp_mline_index"] = msg.get("sdp_mline_index", 0)

    delivered = await signaling_hub.relay_signal(
        device_id, target_id, msg_type, payload,
    )

    if not delivered:
        await ws.send_json({"type": "error", "message": "Target device not available"})
