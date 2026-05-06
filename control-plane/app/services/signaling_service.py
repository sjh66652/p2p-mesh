"""
Signaling service - WebSocket-based real-time signaling for P2P connection establishment.
Manages device presence, SDP/ICE relay, and connection state.
"""

import asyncio
import json
import logging
import uuid
from dataclasses import dataclass, field
from typing import Dict, Set

logger = logging.getLogger(__name__)


@dataclass
class DeviceConnection:
    """Represents an active WebSocket connection from a device."""
    device_id: uuid.UUID
    user_id: uuid.UUID
    ws: "WebSocket"
    online_since: float = field(default_factory=lambda: asyncio.get_event_loop().time())


class SignalingHub:
    """
    Central signaling hub for the P2P mesh network.

    Responsibilities:
    - Track online devices and their WebSocket connections
    - Relay SDP offers/answers between peers
    - Relay ICE candidates
    - Handle connection state notifications
    - Broadcast device online/offline events
    """

    def __init__(self):
        # device_id -> DeviceConnection
        self._connections: Dict[uuid.UUID, DeviceConnection] = {}
        # user_id -> set of device_ids
        self._user_devices: Dict[uuid.UUID, Set[uuid.UUID]] = {}
        self._lock = asyncio.Lock()

    async def connect(
        self, device_id: uuid.UUID, user_id: uuid.UUID, ws
    ):
        """Register a new device WebSocket connection."""
        async with self._lock:
            connection = DeviceConnection(
                device_id=device_id,
                user_id=user_id,
                ws=ws,
            )
            self._connections[device_id] = connection

            if user_id not in self._user_devices:
                self._user_devices[user_id] = set()
            self._user_devices[user_id].add(device_id)

            logger.info(
                f"Device {device_id} (user {user_id}) connected. "
                f"Total online: {len(self._connections)}"
            )

        # Notify peers
        await self._notify_device_status(device_id, user_id, online=True)

    async def disconnect(self, device_id: uuid.UUID):
        """Unregister a device WebSocket connection."""
        async with self._lock:
            conn = self._connections.pop(device_id, None)
            if conn:
                user_devices = self._user_devices.get(conn.user_id, set())
                user_devices.discard(device_id)
                if not user_devices:
                    self._user_devices.pop(conn.user_id, None)

                logger.info(
                    f"Device {device_id} disconnected. "
                    f"Total online: {len(self._connections)}"
                )

                # Notify peers
                await self._notify_device_status(
                    device_id, conn.user_id, online=False
                )

    async def relay_signal(
        self,
        from_device_id: uuid.UUID,
        to_device_id: uuid.UUID,
        signal_type: str,
        payload: dict,
    ) -> bool:
        """
        Relays a signaling message from one device to another.
        Used for SDP exchange and ICE candidates during P2P setup.

        Returns True if the target device received the message.
        """
        target = self._connections.get(to_device_id)
        if not target:
            logger.warning(f"Target device {to_device_id} not online")
            return False

        message = {
            "type": signal_type,
            "from": str(from_device_id),
            "to": str(to_device_id),
            "payload": payload,
        }

        try:
            await target.ws.send_json(message)
            return True
        except Exception as e:
            logger.error(f"Failed to relay to {to_device_id}: {e}")
            await self.disconnect(to_device_id)
            return False

    async def broadcast_to_user(
        self, user_id: uuid.UUID, message: dict
    ):
        """Send a message to all devices belonging to a user."""
        device_ids = self._user_devices.get(user_id, set())
        for device_id in list(device_ids):
            conn = self._connections.get(device_id)
            if conn:
                try:
                    await conn.ws.send_json(message)
                except Exception as e:
                    logger.error(f"Failed to send to {device_id}: {e}")

    async def get_online_peers(
        self, device_id: uuid.UUID
    ) -> list[dict]:
        """Get a list of all other online devices."""
        conn = self._connections.get(device_id)
        if not conn:
            return []

        peers = []
        for other_id, other_conn in self._connections.items():
            if other_id != device_id:
                peers.append({
                    "device_id": str(other_id),
                    "user_id": str(other_conn.user_id),
                    "online_since": other_conn.online_since,
                })
        return peers

    async def _notify_device_status(
        self,
        device_id: uuid.UUID,
        user_id: uuid.UUID,
        online: bool,
    ):
        """Notify related peers about a device going online or offline."""
        message = {
            "type": "device_status",
            "device_id": str(device_id),
            "user_id": str(user_id),
            "online": online,
        }
        # Notify other devices of the same user
        await self.broadcast_to_user(user_id, message)

    @property
    def online_count(self) -> int:
        """Number of currently connected devices."""
        return len(self._connections)


# Global singleton
signaling_hub = SignalingHub()
