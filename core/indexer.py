"""Deployer/funder indexer — background async queue worker."""

import asyncio
import logging
import time
from typing import Optional

logger = logging.getLogger(__name__)


class DeployerIndexer:
    """Indexes deployer and funder data for scanned contracts.

    Non-blocking: enqueue() returns immediately, worker processes in background.
    """

    def __init__(self, web3_client, db):
        self._web3 = web3_client
        self._db = db
        self._queue: asyncio.Queue = asyncio.Queue()
        self._task: Optional[asyncio.Task] = None
        self._running = False

    async def start(self):
        """Start the background worker."""
        self._running = True
        self._task = asyncio.create_task(self._worker())
        logger.info("DeployerIndexer started")

    async def stop(self):
        """Stop the background worker gracefully."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("DeployerIndexer stopped")

    def enqueue(self, address: str, chain_id: int = 56):
        """Add a contract to the indexing queue (non-blocking)."""
        try:
            self._queue.put_nowait((address, chain_id))
        except asyncio.QueueFull:
            logger.warning(f"Indexer queue full, dropping {address}")

    async def _worker(self):
        """Process queue items."""
        while self._running:
            try:
                address, chain_id = await asyncio.wait_for(
                    self._queue.get(), timeout=5.0
                )
                await self._index_contract(address, chain_id)
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Indexer worker error: {e}")

    async def _index_contract(self, address: str, chain_id: int):
        """Fetch deployer and funder info for a contract."""
        try:
            creation_info = await self._web3.get_contract_creation_info(address)
            if not creation_info:
                return

            deployer = creation_info.get('creator')
            tx_hash = creation_info.get('tx_hash')

            if not deployer:
                return

            # Store deployer
            now = time.time()
            await self._db._db.execute("""
                INSERT OR IGNORE INTO deployers
                    (contract_address, chain_id, deployer_address, deploy_tx_hash, indexed_at)
                VALUES (?, ?, ?, ?, ?)
            """, (address.lower(), chain_id, deployer.lower(), tx_hash, now))

            # Try to find funder (first incoming tx to deployer)
            funder_info = await self._fetch_funder(deployer, chain_id)
            if funder_info:
                await self._db._db.execute("""
                    INSERT OR IGNORE INTO funder_links
                        (deployer_address, chain_id, funder_address, funding_value_wei, indexed_at)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    deployer.lower(), chain_id,
                    funder_info['funder'].lower(),
                    funder_info.get('value', 0),
                    now,
                ))

            await self._db._db.commit()
            logger.info(f"Indexed deployer for {address}: {deployer}")

        except Exception as e:
            logger.error(f"Error indexing {address}: {e}")

    async def _fetch_funder(self, deployer_address: str, chain_id: int) -> Optional[dict]:
        """Fetch the first funding transaction to a deployer address."""
        try:
            import aiohttp
            # Use Etherscan API to get first normal tx
            api_key = self._web3._bsc_adapter.bscscan_api_key if hasattr(self._web3, '_bsc_adapter') else ''
            params = {
                'chainid': chain_id,
                'module': 'account',
                'action': 'txlist',
                'address': deployer_address,
                'startblock': 0,
                'endblock': 99999999,
                'page': 1,
                'offset': 5,
                'sort': 'asc',
                'apikey': api_key,
            }
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    'https://api.etherscan.io/v2/api',
                    params=params,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    data = await resp.json()
                    if data.get('status') == '1' and data.get('result'):
                        # Find first incoming tx (to == deployer)
                        for tx in data['result']:
                            if tx.get('to', '').lower() == deployer_address.lower():
                                return {
                                    'funder': tx['from'],
                                    'value': int(tx.get('value', 0)),
                                }
            return None
        except Exception as e:
            logger.error(f"Error fetching funder for {deployer_address}: {e}")
            return None
