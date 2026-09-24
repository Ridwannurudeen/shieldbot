"""ShieldBot's background work as a service of its own, for BACKGROUND_WORKERS=external.

With that setting the API starts no background work, and this process runs what the API lifespan
otherwise starts, in the same order: the mempool monitor, the Robinhood Chain verdict drain, the
hunter sweep and the launch watch. It builds the same service container as the API, so it reads the
same settings and database. Like the API and the bot, it also runs its own deployer indexer, which
indexes the contracts this process scans.

The drain signs verdict transactions, so this process is the one on-chain sender and the recorder key
belongs in its unit's environment, not the API's (docs/DEPLOYMENT.md). Run exactly one copy of it.

    python workers.py

SIGTERM or SIGINT stops the work in reverse order, closes the container and exits 0. If any of the work ends on
its own, which only a failure does, the rest is stopped the same way and the exit status is 1, so systemd's
Restart=always starts it again (if that failure is raised again while its loop is stopped, the process exits with
the traceback, also non-zero). A setting that does not allow it to run exits MISCONFIGURED, which the unit example
tells systemd not to restart.
"""

import asyncio
import logging
import signal
import sys

import pydantic

from core.config import Settings
from core.container import ServiceContainer

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)

# Exit status for a setting that does not allow workers.py to run; systemd must not restart it.
MISCONFIGURED = 3


async def run(container: ServiceContainer, stop: asyncio.Event) -> int:
    """Start the background work and wait for `stop` or for any of it to end, then stop it all and close the
    container. Returns the exit status: 0 after `stop`, 1 when background work ended on its own."""
    await container.startup()
    await container.start_mempool_monitor()
    container.verdict_publisher.start()
    await container.hunter.start()
    await container.launch_watch.start()
    logger.info("ShieldBot workers started")
    # The services keep their loops' tasks private; each is None when that work did not start (no mempool to
    # watch, or no registry or recorder key for the drain).
    work = {
        name: task
        for name, task in (
            ("deployer indexer", container.indexer._task),
            ("mempool monitor", container.mempool_monitor._task),
            ("verdict drain", container.verdict_publisher._drain_task),
            ("hunter", container.hunter._task),
            ("launch watch", container.launch_watch._task),
        )
        if task is not None
    }
    stopped = asyncio.create_task(stop.wait())
    done, _ = await asyncio.wait({stopped, *work.values()}, return_when=asyncio.FIRST_COMPLETED)
    stopped.cancel()
    ended = [name for name, task in work.items() if task in done]
    for name in ended:
        task = work[name]
        error = None if task.cancelled() else task.exception()
        logger.error(
            "ShieldBot workers: the %s ended on its own (%s)",
            name,
            "cancelled" if task.cancelled() else type(error).__name__ if error else "returned",
        )
    logger.info("ShieldBot workers stopping")
    await container.launch_watch.stop()
    await container.hunter.stop()
    await container.verdict_publisher.stop()
    await container.shutdown()
    return 1 if ended else 0


async def main() -> int:
    try:
        settings = Settings()
    except pydantic.ValidationError as e:
        logger.error("ShieldBot workers: invalid settings, not starting:\n%s", e)
        return MISCONFIGURED
    if settings.background_workers != "external":
        # With the default setting the API runs this work itself; a second copy would poll every
        # mempool twice and run a second verdict drain.
        logger.error(
            "ShieldBot workers: not starting, BACKGROUND_WORKERS is %r. workers.py runs only with "
            "BACKGROUND_WORKERS=external, set where the API reads it too",
            settings.background_workers,
        )
        return MISCONFIGURED
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, lambda *_: loop.call_soon_threadsafe(stop.set))
    return await run(ServiceContainer(settings), stop)


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
