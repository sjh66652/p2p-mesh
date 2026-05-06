"""
Redis Pub/Sub layer for distributed WebSocket signaling.
Enables cross-node message delivery when multiple signaling-service replicas run.
"""

import asyncio
import json
import logging
import uuid
from typing import Optional, Callable, Awaitable

import redis.asyncio as redis

logger = logging.getLogger("signaling.pubsub")


class PubSubHub:
    """
    Redis Pub/Sub hub for cross-node signaling.

    Architecture:
    - Each node subscribes to: signaling:msg:{own_node_id}
    - When a device connects: register ws:user:{user_id}:{device_id} -> node_id in Redis
    - When relaying to a device on another node: publish to signaling:msg:{target_node_id}
    - Connection limits are enforced globally via Redis counters
    """

    CHANNEL_PREFIX = "signaling:msg:"
    CONNECT_CHANNEL = "signaling:connect"
    DISCONNECT_CHANNEL = "signaling:disconnect"
    GLOBAL_CONN_COUNT_KEY = "signaling:global_connections"
    MAX_GLOBAL_CONNECTIONS = 10000
    MAX_CONNECTIONS_PER_USER = 5

    def __init__(self, node_id: str, redis_url: str):
        self.node_id = node_id
        self.redis_url = redis_url
        self.redis: Optional[redis.Redis] = None
        self.pubsub: Optional[redis.client.PubSub] = None
        self._channel = f"{self.CHANNEL_PREFIX}{self.node_id}"
        self._listener_task: Optional[asyncio.Task] = None
        # Callback for delivering messages to local WebSocket connections
        self._message_handler: Optional[Callable[[dict], Awaitable[None]]] = None

    def set_message_handler(self, handler: Callable[[dict], Awaitable[None]]):
        """Set the callback for delivering messages to local WebSocket connections."""
        self._message_handler = handler

    async def connect(self):
        """Connect to Redis and start the pubsub listener."""
        self.redis = redis.from_url(self.redis_url, decode_responses=True)
        await self.redis.ping()
        self.pubsub = self.redis.pubsub()

        # Subscribe to own message channel and global channels
        await self.pubsub.subscribe(self._channel, self.CONNECT_CHANNEL, self.DISCONNECT_CHANNEL)

        self._listener_task = asyncio.create_task(self._listen())
        logger.info("PubSub connected on node=%s channel=%s", self.node_id, self._channel)

    async def disconnect(self):
        """Disconnect from Redis."""
        if self._listener_task:
            self._listener_task.cancel()
            try:
                await self._listener_task
            except asyncio.CancelledError:
                pass

        if self.pubsub:
            await self.pubsub.unsubscribe()
            await self.pubsub.close()

        if self.redis:
            await self.redis.close()

        logger.info("PubSub disconnected")

    async def register_device(self, device_id: uuid.UUID, user_id: uuid.UUID):
        """Register a device connection in Redis."""
        key = f"ws:user:{user_id}:{device_id}"
        await self.redis.set(key, self.node_id)

        # Increment global counter
        await self.redis.incr(self.GLOBAL_CONN_COUNT_KEY)

        # Increment per-user counter
        user_key = f"ws:user_count:{user_id}"
        await self.redis.incr(user_key)
        await self.redis.expire(user_key, 86400)

        # Publish connect event
        await self.redis.publish(self.CONNECT_CHANNEL, json.dumps({
            "device_id": str(device_id),
            "user_id": str(user_id),
            "node_id": self.node_id,
        }))

        logger.debug("Device registered: device=%s user=%s node=%s", device_id, user_id, self.node_id)

    async def unregister_device(self, device_id: uuid.UUID, user_id: uuid.UUID):
        """Unregister a device connection from Redis."""
        key = f"ws:user:{user_id}:{device_id}"
        await self.redis.delete(key)

        # Decrement global counter
        await self.redis.decr(self.GLOBAL_CONN_COUNT_KEY)

        # Decrement per-user counter
        user_key = f"ws:user_count:{user_id}"
        await self.redis.decr(user_key)

        # Publish disconnect event
        await self.redis.publish(self.DISCONNECT_CHANNEL, json.dumps({
            "device_id": str(device_id),
            "user_id": str(user_id),
            "node_id": self.node_id,
        }))

        logger.debug("Device unregistered: device=%s user=%s", device_id, user_id)

    async def get_device_node(self, device_id: uuid.UUID, user_id: uuid.UUID) -> Optional[str]:
        """Get the node_id where a device is connected."""
        key = f"ws:user:{user_id}:{device_id}"
        return await self.redis.get(key)

    async def check_global_connection_limit(self) -> bool:
        """Check if global connection limit is exceeded. Returns True if ok."""
        count = await self.redis.get(self.GLOBAL_CONN_COUNT_KEY)
        if count and int(count) >= self.MAX_GLOBAL_CONNECTIONS:
            return False
        return True

    async def check_user_connection_limit(self, user_id: uuid.UUID) -> bool:
        """Check if a user has exceeded their connection limit. Returns True if ok."""
        count = await self.redis.get(f"ws:user_count:{user_id}")
        if count and int(count) >= self.MAX_CONNECTIONS_PER_USER:
            return False
        return True

    async def publish_to_node(self, target_node: str, message: dict):
        """Publish a message to a specific node's channel."""
        channel = f"{self.CHANNEL_PREFIX}{target_node}"
        await self.redis.publish(channel, json.dumps(message))

    async def _listen(self):
        """Listen for incoming PubSub messages."""
        try:
            async for msg in self.pubsub.listen():
                if msg["type"] != "message":
                    continue

                channel = msg["channel"]
                try:
                    data = json.loads(msg["data"])
                except json.JSONDecodeError:
                    logger.warning("Invalid JSON on channel %s: %s", channel, msg["data"][:200])
                    continue

                if channel == self._channel:
                    # Message destined for this node - deliver to local WebSocket
                    if self._message_handler:
                        await self._message_handler(data)
                elif channel == self.CONNECT_CHANNEL:
                    logger.debug("Remote connect: device=%s node=%s",
                               data.get("device_id"), data.get("node_id"))
                elif channel == self.DISCONNECT_CHANNEL:
                    logger.debug("Remote disconnect: device=%s node=%s",
                               data.get("device_id"), data.get("node_id"))
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error("PubSub listener error: %s", e)


pubsub_hub: Optional[PubSubHub] = None


async def init_pubsub(node_id: str, redis_url: str) -> PubSubHub:
    """Initialize the global PubSubHub instance and connect to Redis."""
    global pubsub_hub
    pubsub_hub = PubSubHub(node_id, redis_url)
    await pubsub_hub.connect()
    return pubsub_hub


async def close_pubsub():
    """Disconnect and clean up the global PubSubHub instance."""
    global pubsub_hub
    if pubsub_hub:
        await pubsub_hub.disconnect()
        pubsub_hub = None
