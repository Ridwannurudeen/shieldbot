"""ShieldBot's background work as a service of its own, for BACKGROUND_WORKERS=external.

With that setting the API starts no background work, and this process runs what the API lifespan
otherwise starts, in the same order: the mempool monitor, the Robinhood Chain verdict drain, the
hunter sweep and the launch watch. It builds the same service container as the API, so it reads the
same settings and database. Like the API and the bot, it also runs its own deployer indexer, which
indexes the contracts this process scans.

The drain signs verdict transactions, so this process is the one on-chain sender and the recorder key
belongs in its unit's environment, not the API's (docs/DEPLOYMENT.md). Run exactly one copy of it.

    python workers.py

SIGTERM or SIGINT stops the work in reverse order and closes the container.
"""

import asyncio
import logging
import signal
import sys

from core.config import Settings
from core.container import ServiceContainer

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)


async def run(container: ServiceContainer, stop: asyncio.Event) -> None:
    """Start the background work, wait for `stop`, then stop it and close the container."""
    await container.startup()
    await container.start_mempool_monitor()
    container.verdict_publisher.start()
    await container.hunter.start()
    await container.launch_watch.start()
    logger.info("ShieldBot workers started")
    await stop.wait()
    logger.info("ShieldBot workers stopping")
    await container.launch_watch.stop()
    await container.hunter.stop()
    await container.verdict_publisher.stop()
    await container.shutdown()


async def main() -> None:
    settings = Settings()
    if settings.background_workers != "external":
        # With the default setting the API runs this work itself; a second copy would poll every
        # mempool twice and race the API for the recorder's nonces.
        sys.exit(
            "workers.py runs only with BACKGROUND_WORKERS=external, set where the API reads it too"
        )
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, lambda *_: loop.call_soon_threadsafe(stop.set))
    await run(ServiceContainer(settings), stop)


if __name__ == "__main__":
    asyncio.run(main())
