"""
Signaling service - WebSocket-based real-time signaling for P2P connection establishment.
Manages device presence, SDP/ICE relay, and connection state.

Security:
- Sender identity is verified on relay_signal (no device ID spoofing)
- Peers list is restricted to same-user devices only (no topology leak)
- Signaling messages are validated before forwarding
"""

import asyncio
import logging
import uuid
from dataclasses import dataclass, field
from typing import Dict, Set

from fastapi import WebSocket

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
    - Relay SDP offers/answers between peers (with sender verification)
    - Relay ICE candidates (with sender verification)
    - Handle connection state notifications
    - Broadcast device online/offline events to same-user devices only
    """

    MAX_CONNECTIONS = 10_000

    def __init__(self):
        # device_id -> DeviceConnection
        self._connections: Dict[uuid.UUID, DeviceConnection] = {}
        # user_id -> set of device_ids
        self._user_devices: Dict[uuid.UUID, Set[uuid.UUID]] = {}
        # device_id -> list of candidates (for NAT traversal)
        self._candidates: Dict[uuid.UUID, list] = {}
        # device_id -> nat_type
        self._nat_types: Dict[uuid.UUID, str] = {}
        # device_id -> public_addr
        self._public_addrs: Dict[uuid.UUID, str] = {}
        self._lock = asyncio.Lock()

    async def connect(
        self, device_id: uuid.UUID, user_id: uuid.UUID, ws
    ):
        """Register a new device WebSocket connection.
        Raises RuntimeError if the hub is at capacity."""
        async with self._lock:
            # Hard limit to prevent connection exhaustion DoS
            if len(self._connections) >= self.MAX_CONNECTIONS:
                raise RuntimeError(
                    f"Signaling hub at capacity ({self.MAX_CONNECTIONS} connections)"
                )

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

        # Notify other devices of the same user
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

                # Notify same-user peers
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
        Relay a signaling message from one device to another.

        The from_device_id MUST match the authenticated sender — this is
        enforced by the caller (ws.py) which already verified device ownership
        via JWT + database lookup. We do NOT trust the from_device_id in the
        message body; we use the authenticated sender's identity.

        Returns True if the target device received the message.
        """
        # Verify sender is connected as the claimed device
        sender = self._connections.get(from_device_id)
        if sender is None:
            logger.warning(
                f"Sender {from_device_id} not connected — rejecting relay"
            )
            return False

        target = self._connections.get(to_device_id)
        if not target:
            logger.warning(f"Target device {to_device_id} not online")
            return False

        # Enforce that sender and target belong to the same user
        # (In production, inter-user signaling may be allowed but requires
        # explicit authorization — for now, only same-user devices can signal)
        if sender.user_id != target.user_id:
            logger.warning(
                f"Cross-user signaling blocked: sender_user={sender.user_id} "
                f"target_user={target.user_id}"
            )
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
        """
        Get a list of other online devices belonging to the SAME user.
        Only returns device_id — no user_id or IP leakage.
        """
        conn = self._connections.get(device_id)
        if not conn:
            return []

        peers = []
        same_user_devices = self._user_devices.get(conn.user_id, set())
        for other_id in same_user_devices:
            if other_id != device_id and other_id in self._connections:
                peers.append({
                    "device_id": str(other_id),
                })
        return peers

    async def _notify_device_status(
        self,
        device_id: uuid.UUID,
        user_id: uuid.UUID,
        online: bool,
    ):
        """Notify same-user peers about a device going online or offline."""
        message = {
            "type": "device_status",
            "device_id": str(device_id),
            "online": online,
        }
        # Only notify devices of the same user
        await self.broadcast_to_user(user_id, message)

    async def store_candidates(self, device_id: uuid.UUID, candidates: list):
        """Store network candidates for a device (for NAT hole punching)."""
        async with self._lock:
            self._candidates[device_id] = candidates
        logger.info(f"Stored {len(candidates)} candidates for device {device_id}")

    async def get_peer_candidates(
        self, requesting_device: uuid.UUID, peer_device: uuid.UUID
    ) -> list | None:
        """
        Get a peer's candidates, verifying same-user authorization.

        Returns the peer's candidate list or None if not authorized/found.
        """
        requesting_conn = self._connections.get(requesting_device)
        peer_conn = self._connections.get(peer_device)

        if not requesting_conn or not peer_conn:
            return None

        # Only devices belonging to the same user can see each other's candidates
        if requesting_conn.user_id != peer_conn.user_id:
            logger.warning(
                f"Candidate access denied: device {requesting_device} "
                f"(user {requesting_conn.user_id}) requesting candidates "
                f"from device {peer_device} (user {peer_conn.user_id})"
            )
            return None

        return self._candidates.get(peer_device, [])

    async def update_device_nat(
        self, device_id: uuid.UUID, nat_type: str, public_addr: str
    ):
        """Update a device's NAT type and public address from STUN results."""
        async with self._lock:
            self._nat_types[device_id] = nat_type
            self._public_addrs[device_id] = public_addr
        logger.debug(
            f"NAT updated for device {device_id}: type={nat_type}, addr={public_addr}"
        )

    def get_candidate_count(self, device_id: uuid.UUID) -> int:
        """Get the number of stored candidates for a device."""
        return len(self._candidates.get(device_id, []))

    @property
    def online_count(self) -> int:
        """Number of currently connected devices."""
        return len(self._connections)


# Global singleton
signaling_hub = SignalingHub()
