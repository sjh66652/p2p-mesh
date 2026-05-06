"""
WebSocket signaling API - real-time communication for P2P connection setup.
REST API for polling peers and connection stats.

Security:
  - JWT token authentication with device ownership verification
  - Per-connection rate limiting (prevents signaling DoS)
  - Max message size enforcement
  - Audit logging for connection events
  - Generic error messages (no internal info leak)
"""

import json
import time
import uuid
import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, HTTPException, status, Query, Request, Depends
from jose import jwt, JWTError
from starlette.responses import Response

from app.config import settings
from app.service import signaling_hub, distributed_hub
from shared.app.usage_middleware import check_usage_quota

logger = logging.getLogger("signaling-service.api")
router = APIRouter(dependencies=[Depends(check_usage_quota)])


# ---- WebSocket Endpoint ----

@router.websocket("/{device_id}")
async def websocket_endpoint(
    ws: WebSocket,
    device_id: str,
):
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

    # Check JWT blacklist (logout revocation) via Redis
    from app.main import get_redis_client
    redis_conn = get_redis_client()
    if redis_conn:
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

    # ---- Phase 3: Verify device_id format ----
    try:
        dev_uuid = uuid.UUID(device_id)
    except ValueError:
        await ws.send_json({"type": "error", "message": "Invalid device ID"})
        await ws.close(code=4002)
        return

    # ---- Phase 4: Register in distributed signaling hub ----
    try:
        await distributed_hub.connect(dev_uuid, user_id, ws)
    except RuntimeError as e:
        await ws.send_json({"type": "error", "message": str(e)})
        await ws.close(code=4003)
        return

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
                msg = json.loads(raw)
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
        await distributed_hub.disconnect(dev_uuid)
        logger.info("WS disconnected: device=%s user=%s", device_id, user_id)


async def handle_signal(
    ws: WebSocket,
    device_id: uuid.UUID,
    user_id: uuid.UUID,
    msg: dict,
):
    """Process an incoming signaling message with validation."""
    msg_type = msg.get("type", "")

    # Whitelist of allowed message types
    ALLOWED_TYPES = {"ping", "offer", "answer", "ice_candidate", "get_peers"}
    if msg_type not in ALLOWED_TYPES:
        await ws.send_json({"type": "error", "message": "Unknown message type"})
        return

    if msg_type == "ping":
        await ws.send_json({"type": "pong"})
        return

    if msg_type == "get_peers":
        # Only expose devices belonging to the same user
        peers = await distributed_hub.get_online_peers(device_id)
        # Filter: only return peer's device_id, no user info leakage
        safe_peers = [
            {"device_id": p["device_id"]}
            for p in peers
        ]
        await ws.send_json({"type": "peers_list", "peers": safe_peers})
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

    # SDP validation: max 32KB
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
        payload["sdp_mid"] = msg.get("sdp_mid")
        payload["sdp_mline_index"] = msg.get("sdp_mline_index")

    delivered = await distributed_hub.relay_signal(
        device_id, target_id, msg_type, payload,
    )

    if not delivered:
        await ws.send_json({"type": "error", "message": "Target device not available"})


# ---- REST Endpoints ----

@router.get("/api/signaling/peers/{device_id}")
async def get_peers_rest(
    device_id: str,
    request: Request,
):
    """REST endpoint for polling peers of a device.
    Authenticated via Authorization header (Bearer JWT).
    """
    # Validate JWT from header
    auth_header = request.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )

    token = auth_header[7:]
    try:
        payload = jwt.decode(
            token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM],
            options={"require": ["exp", "sub", "type"]},
        )
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )

    if payload.get("type") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type",
        )

    user_id_str = payload.get("sub")
    if not user_id_str:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        )

    try:
        dev_uuid = uuid.UUID(device_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid device ID",
        )

    peers = await distributed_hub.get_online_peers(dev_uuid)
    return {"peers": peers}


@router.get("/api/signaling/stats")
async def get_signaling_stats(
    request: Request,
):
    """Get signaling connection statistics (admin only).
    Protected by internal API key.
    """
    # Require internal API key for admin-level stats
    from app.dependencies import verify_internal_service
    await verify_internal_service(request)

    from app.service import signaling_hub, distributed_hub
    # Count connections per user
    user_counts = {
        str(uid): len(devices)
        for uid, devices in signaling_hub._user_devices.items()
    }

    return {
        "total_connections": distributed_hub.online_count,
        "total_users": len(signaling_hub._user_devices),
        "max_connections": signaling_hub.MAX_CONNECTIONS,
        "connections_per_user": user_counts,
    }

