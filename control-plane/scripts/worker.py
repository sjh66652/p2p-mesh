"""
Background worker — relay health check loop.
Runs as a separate container alongside the API.
"""

import asyncio
import logging

from app.database import async_session_factory
from app.services.relay_service import cleanup_stale_relays

logger = logging.getLogger("p2p-mesh.worker")


async def health_loop():
    """Periodically clean up stale relay nodes."""
    from app.config import settings

    interval = settings.RELAY_CLEANUP_INTERVAL
    logger.info("Worker started: relay health check every %d seconds", interval)

    while True:
        await asyncio.sleep(interval)
        try:
            async with async_session_factory() as session:
                await cleanup_stale_relays(session)
                logger.debug("Relay health check completed")
        except Exception as e:
            logger.error("Relay health check failed: %s", e, exc_info=True)


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    asyncio.run(health_loop())


if __name__ == "__main__":
    main()
