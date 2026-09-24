"""Deployer/funder indexer — background async queue worker."""

import asyncio
import logging
import re
import time
from typing import Optional

from adapters.evm_base import _get_explorer_backend
from core.telegram_formatter import escape_markdown
from services.explorer_service import _is_address, explorer_service
from utils.web3_client import UnsupportedChainError

logger = logging.getLogger(__name__)


class DeployerIndexer:
    """Indexes deployer and funder data for scanned contracts.

    Non-blocking: enqueue() returns immediately, worker processes in background.
    """

    def __init__(self, web3_client, db, settings=None):
        self._web3 = web3_client
        self._db = db
        self._settings = settings
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
            except UnsupportedChainError:
                logger.error("Skipping %s: unsupported chain %s", address, chain_id)
            except Exception as e:
                logger.error("Indexer worker error: %s", type(e).__name__)

    async def _index_contract(self, address: str, chain_id: int):
        """Fetch deployer and funder info for a contract."""
        adapter = self._web3._get_adapter(chain_id)
        if adapter is None or adapter.chain_id != chain_id:
            raise UnsupportedChainError(f"No matching adapter registered for chain {chain_id}")
        backend = _get_explorer_backend(chain_id)
        try:
            if backend == 'sourcify_blockscout':
                result = await explorer_service.get_contract_creation_info(address, chain_id)
                if result.status == 'unknown':
                    logger.warning(f"Unknown creator for {address} on chain {chain_id}: {result.reason}")
                    return
                creation_info = result.data
            else:
                creation_info = await self._web3.get_contract_creation_info(address, chain_id=chain_id)
            if not creation_info:
                return

            deployer = creation_info.get('creator')
            tx_hash = creation_info.get('tx_hash')

            if not deployer:
                return

            # Resolve routed data before recording the item.
            funder_info = await self._fetch_funder(deployer, chain_id)

            # Store deployer
            now = time.time()
            async with self._db.transaction() as connection:
                await connection.execute("""
                    INSERT OR IGNORE INTO deployers
                        (contract_address, chain_id, deployer_address, deploy_tx_hash, indexed_at)
                    VALUES (?, ?, ?, ?, ?)
                """, (address.lower(), chain_id, deployer.lower(), tx_hash, now))

                # Try to find funder (first incoming tx to deployer)
                if funder_info:
                    await connection.execute("""
                        INSERT OR IGNORE INTO funder_links
                            (deployer_address, chain_id, funder_address, funding_value_wei, indexed_at)
                        VALUES (?, ?, ?, ?, ?)
                    """, (
                        deployer.lower(), chain_id,
                        funder_info['funder'].lower(),
                        str(funder_info['value']),
                        now,
                    ))

            logger.info(f"Indexed deployer for {address}: {deployer}")

            # Check if this deployer is watched — send alert if so
            try:
                watch_record = await self._db.is_watched_deployer(deployer.lower(), chain_id)
                if watch_record:
                    alert_id = await self._db.log_deployment_alert(
                        deployer.lower(), chain_id, address.lower(),
                        watch_record.get("watch_reason"), telegram_sent=0,
                    )
                    sent = await self._send_watch_alert(deployer, chain_id, address, watch_record)
                    if sent and alert_id:
                        await self._db._db.execute(
                            "UPDATE deployment_alerts SET telegram_sent=1 WHERE id=?", (alert_id,)
                        )
                        await self._db._db.commit()
            except UnsupportedChainError:
                raise
            except Exception as e:
                logger.error("Watch-deployer check failed for %s: %s", deployer, type(e).__name__)

        except UnsupportedChainError:
            raise
        except Exception as e:
            logger.error(f"Error indexing {address}: {type(e).__name__}")

    async def _send_watch_alert(self, deployer: str, chain_id: int, new_contract: str, watch_record: dict) -> bool:
        """Send a Telegram notification when a watched deployer creates a new contract."""
        if not self._settings:
            return False
        bot_token = getattr(self._settings, "telegram_bot_token", "")
        chat_id = getattr(self._settings, "telegram_alert_chat_id", "")
        if not bot_token or not chat_id:
            logger.warning("Watch alert not sent — Telegram not configured")
            return False

        chain_names = {56: "BNB Chain", 1: "Ethereum", 8453: "Base", 42161: "Arbitrum",
                       137: "Polygon", 10: "Optimism", 204: "opBNB"}
        chain_name = chain_names.get(chain_id, f"Chain {chain_id}")
        reason = watch_record.get("watch_reason", "MANUAL")
        severity = watch_record.get("risk_severity", "HIGH")
        msg = (
            f"\U0001f6a8 *Watched Deployer Alert*\n"
            f"Deployer `{deployer[:10]}...{deployer[-6:]}` deployed a new contract on {chain_name}.\n"
            f"Contract: `{new_contract}`\n"
            f"Watch reason: {escape_markdown(reason)} | Severity: {escape_markdown(severity)}"
        )
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"https://api.telegram.org/bot{bot_token}/sendMessage",
                    json={"chat_id": chat_id, "text": msg, "parse_mode": "Markdown"},
                    timeout=aiohttp.ClientTimeout(total=5),
                ) as resp:
                    return resp.status == 200
        except UnsupportedChainError:
            raise
        except Exception as e:
            logger.error("Telegram watch alert failed: %s", type(e).__name__)
            return False

    async def _fetch_funder(self, deployer_address: str, chain_id: int) -> Optional[dict]:
        """Fetch the first funding transaction to a deployer address."""
        adapter = self._web3._get_adapter(chain_id)
        if adapter is None or adapter.chain_id != chain_id:
            raise UnsupportedChainError(f"No matching adapter registered for chain {chain_id}")
        backend = _get_explorer_backend(chain_id)
        try:
            if backend == 'sourcify_blockscout':
                result = await explorer_service.get_first_funder(deployer_address, chain_id)
                if result.status == 'unknown':
                    logger.warning(f"Unknown funder for {deployer_address} on chain {chain_id}: {result.reason}")
                    return None
                return result.data
            import aiohttp
            # Use Etherscan API to get first normal tx
            api_key = adapter.etherscan_api_key
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
                    if resp.status != 200:
                        logger.warning(f"Unknown funder for {deployer_address} on chain {chain_id}: HTTP {resp.status}")
                        return None
                    data = await resp.json()
                    if data.get('status') == '1' and data.get('result'):
                        # Find first incoming tx (to == deployer)
                        for tx in data['result']:
                            if (
                                not isinstance(tx, dict)
                                or not _is_address(tx.get('to'))
                                or not _is_address(tx.get('from'))
                            ):
                                continue
                            value = tx.get('value')
                            if (
                                tx.get('isError') != '0'
                                or not isinstance(value, str)
                                or re.fullmatch(r'[0-9]{1,78}', value) is None
                                or not 0 < int(value) < 2**256
                            ):
                                continue
                            if tx.get('to', '').lower() == deployer_address.lower():
                                return {
                                    'funder': tx['from'],
                                    'value': int(value),
                                }
            return None
        except UnsupportedChainError:
            raise
        except Exception as e:
            logger.error(f"Error fetching funder for {deployer_address}: {type(e).__name__}")
            return None
