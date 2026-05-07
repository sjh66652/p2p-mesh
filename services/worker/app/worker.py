"""
Background task worker for P2P Mesh Network.
Processes usage records, log aggregation, and periodic cleanup.

Uses Redis lists as lightweight task queues (no external dependencies like Celery).
"""

import asyncio
import json
import logging
import os
import signal
import time
from datetime import datetime, timezone

import redis.asyncio as redis

from app.config import settings

logging.basicConfig(
    level=getattr(logging, getattr(settings, 'LOG_LEVEL', logging.INFO)),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("p2p-worker")


class TaskWorker:
    """Processes tasks from Redis queues."""

    def __init__(self):
        self.redis: redis.Redis = None
        self._running = False
        self._tasks: list[asyncio.Task] = []
        self._db_engine = None

    async def start(self):
        """Connect to Redis and start processing."""
        self.redis = redis.from_url(settings.REDIS_URL, decode_responses=True)
        await self.redis.ping()
        log.info("Connected to Redis at %s", settings.REDIS_URL)

        self._running = True

        # Start queue processors
        self._tasks.append(asyncio.create_task(self._process_usage_queue()))
        self._tasks.append(asyncio.create_task(self._process_log_queue()))
        self._tasks.append(asyncio.create_task(self._run_periodic_cleanup()))

        log.info("Worker started — processing queues: usage, logs, cleanup")

    async def stop(self):
        """Graceful shutdown."""
        self._running = False
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        if self.redis:
            await self.redis.close()
        await self._dispose_db_engine()
        log.info("Worker stopped")

    async def _process_usage_queue(self):
        """Process usage records in batches for efficient DB writes."""
        while self._running:
            try:
                batch = []
                # Collect batch from queue
                for _ in range(100):
                    item = await self.redis.lpop(settings.USAGE_QUEUE)
                    if item:
                        batch.append(json.loads(item))
                    else:
                        break

                if batch:
                    await self._write_usage_batch(batch)
                    log.debug("Processed usage batch: %d records", len(batch))
                else:
                    await asyncio.sleep(settings.USAGE_BATCH_INTERVAL)
            except asyncio.CancelledError:
                break
            except Exception as e:
                log.error("Usage queue processor error: %s", e)
                await asyncio.sleep(5)

    async def _get_db_engine(self):
        """Get or create the shared database engine."""
        if self._db_engine is None and settings.DATABASE_URL:
            from sqlalchemy.ext.asyncio import create_async_engine
            self._db_engine = create_async_engine(
                settings.DATABASE_URL, pool_size=5
            )
        return self._db_engine

    async def _dispose_db_engine(self):
        """Dispose the shared database engine on shutdown."""
        if self._db_engine is not None:
            await self._db_engine.dispose()
            self._db_engine = None

    async def _write_usage_batch(self, batch: list[dict]):
        """Write a batch of usage records to the database."""
        if not settings.DATABASE_URL:
            log.debug("No DATABASE_URL configured — skipping DB write for %d records", len(batch))
            return

        try:
            from sqlalchemy import text

            engine = await self._get_db_engine()
            if engine is None:
                return
            async with engine.begin() as conn:
                for record in batch:
                    await conn.execute(
                        text(
                            "INSERT INTO usage_records (user_id, metric_type, value, timestamp) "
                            "VALUES (:user_id, :metric_type, :value, :timestamp)"
                        ),
                        {
                            "user_id": record.get("user_id"),
                            "metric_type": record.get("metric_type", "unknown"),
                            "value": record.get("value", 1),
                            "timestamp": record.get("timestamp", datetime.now(timezone.utc).isoformat()),
                        },
                    )
        except Exception as e:
            log.error("Failed to write usage batch to DB: %s", e)
            # Re-queue on failure (with dead-letter after 3 retries)
            for record in batch:
                retries = record.get("_retries", 0)
                if retries < 3:
                    record["_retries"] = retries + 1
                    await self.redis.rpush(settings.USAGE_QUEUE, json.dumps(record))

    async def _process_log_queue(self):
        """Process log aggregation tasks."""
        while self._running:
            try:
                item = await self.redis.lpop(settings.LOG_QUEUE)
                if item:
                    log_entry = json.loads(item)
                    # Aggregate and emit structured logs
                    log.info(
                        "AUDIT: action=%s user=%s ip=%s",
                        log_entry.get("action", "unknown"),
                        log_entry.get("user_id", "anonymous"),
                        log_entry.get("ip", "unknown"),
                    )
                else:
                    await asyncio.sleep(10)
            except asyncio.CancelledError:
                break
            except Exception as e:
                log.error("Log queue processor error: %s", e)
                await asyncio.sleep(5)

    async def _run_periodic_cleanup(self):
        """Run periodic cleanup tasks."""
        while self._running:
            try:
                await asyncio.sleep(settings.CLEANUP_INTERVAL)

                # Clean up expired Redis keys
                if self.redis:
                    # Clean up stale ws:user keys (devices that disconnected without cleanup)
                    cursor = 0
                    cleaned = 0
                    while True:
                        cursor, keys = await self.redis.scan(cursor, match="ws:user:*", count=100)
                        for key in keys:
                            ttl = await self.redis.ttl(key)
                            if ttl == -1:  # No expiry set
                                await self.redis.expire(key, 86400)  # Set 24h expiry
                                cleaned += 1
                        if cursor == 0:
                            break
                    if cleaned:
                        log.info("Cleanup: set expiry on %d stale keys", cleaned)

                # Log queue depths
                usage_depth = await self.redis.llen(settings.USAGE_QUEUE)
                log_depth = await self.redis.llen(settings.LOG_QUEUE)
                log.info("Queue depths: usage=%d logs=%d", usage_depth, log_depth)

            except asyncio.CancelledError:
                break
            except Exception as e:
                log.error("Cleanup task error: %s", e)


async def main():
    worker = TaskWorker()

    # Handle graceful shutdown
    loop = asyncio.get_event_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, lambda: asyncio.create_task(worker.stop()))
        except NotImplementedError:
            # Windows doesn't support add_signal_handler
            pass

    await worker.start()

    # Keep running until stopped
    while worker._running:
        await asyncio.sleep(1)


if __name__ == "__main__":
    asyncio.run(main())
