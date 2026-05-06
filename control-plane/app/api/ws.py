"""
WebSocket signaling API - real-time communication for P2P connection setup.

Protocol:
  Client -> Server:
    {"type": "authenticate", "token": "<jwt>"}
    {"type": "offer", "to": "<device_id>", "sdp": "<sdp>"}
    {"type": "answer", "to": "<device_id>", "sdp": "<sdp>"}
    {"type": "ice_candidate", "to": "<device_id>", "candidate": "<candidate>"}
    {"type": "ping"}

  Server -> Client:
    {"type": "authenticated", "device_id": "<id>"}
    {"type": "offer", "from": "<device_id>", "sdp": "<sdp>"}
    {"type": "answer", "from": "<device_id>", "sdp": "<sdp>"}
    {"type": "ice_candidate", "from": "<device_id>", "candidate": "<candidate>"}
    {"type": "device_status", "device_id": "<id>", "online": true/false}
    {"type": "error", "message": "<error>"}
    {"type": "pong"}
"""

import uuid
import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query
import jwt

from app.config import settings
from app.services.signaling_service import signaling_hub

logger = logging.getLogger(__name__)
router = APIRouter()


@router.websocket("/{device_id}")
async def websocket_endpoint(
    ws: WebSocket,
    device_id: str,
    token: str = Query(...),
):
    """
    WebSocket endpoint for real-time P2P signaling.

    Authentication is done via JWT token in query parameter.
    The device must be registered under the authenticated user.
    """
    await ws.accept()

    # Authenticate via JWT
    try:
        payload = jwt.decode(
            token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM]
        )
        user_id_str = payload.get("sub")
        if not user_id_str:
            await ws.send_json({"type": "error", "message": "Invalid token"})
            await ws.close(code=4001)
            return
        user_id = uuid.UUID(user_id_str)
    except (jwt.InvalidTokenError, ValueError) as e:
        await ws.send_json({"type": "error", "message": f"Authentication failed: {e}"})
        await ws.close(code=4001)
        return

    # Register in signaling hub
    dev_id = uuid.UUID(device_id)
    await signaling_hub.connect(dev_id, user_id, ws)

    try:
        await ws.send_json({
            "type": "authenticated",
            "device_id": device_id,
            "user_id": str(user_id),
        })

        # Main message loop
        while True:
            try:
                msg = await ws.receive_json()
                await handle_signal(ws, dev_id, user_id, msg)
            except WebSocketDisconnect:
                break
            except Exception as e:
                logger.error(f"Error processing message from {device_id}: {e}")
                try:
                    await ws.send_json({"type": "error", "message": str(e)})
                except Exception:
                    break

    except WebSocketDisconnect:
        pass
    finally:
        await signaling_hub.disconnect(dev_id)


async def handle_signal(ws: WebSocket, device_id: uuid.UUID, user_id: uuid.UUID, msg: dict):
    """Process an incoming signaling message."""
    msg_type = msg.get("type")

    if msg_type == "ping":
        await ws.send_json({"type": "pong"})

    elif msg_type == "offer":
        # Relay SDP offer to target device
        target_id = uuid.UUID(msg["to"])
        delivered = await signaling_hub.relay_signal(
            device_id, target_id, "offer",
            {"sdp": msg.get("sdp")},
        )
        if not delivered:
            await ws.send_json({
                "type": "error",
                "message": f"Target device {msg['to']} is not online",
            })

    elif msg_type == "answer":
        # Relay SDP answer to target device
        target_id = uuid.UUID(msg["to"])
        delivered = await signaling_hub.relay_signal(
            device_id, target_id, "answer",
            {"sdp": msg.get("sdp")},
        )
        if not delivered:
            await ws.send_json({
                "type": "error",
                "message": f"Target device {msg['to']} is not online",
            })

    elif msg_type == "ice_candidate":
        # Relay ICE candidate to target device
        target_id = uuid.UUID(msg["to"])
        delivered = await signaling_hub.relay_signal(
            device_id, target_id, "ice_candidate",
            {
                "candidate": msg.get("candidate"),
                "sdp_mid": msg.get("sdp_mid"),
                "sdp_mline_index": msg.get("sdp_mline_index"),
            },
        )
        if not delivered:
            await ws.send_json({
                "type": "error",
                "message": f"Target device {msg['to']} is not online",
            })

    elif msg_type == "get_peers":
        # Return list of online peers
        peers = await signaling_hub.get_online_peers(device_id)
        await ws.send_json({"type": "peers_list", "peers": peers})

    else:
        await ws.send_json({
            "type": "error",
            "message": f"Unknown message type: {msg_type}",
        })
