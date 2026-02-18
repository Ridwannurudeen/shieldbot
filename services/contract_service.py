import asyncio
import logging

logger = logging.getLogger(__name__)

# Bytecode signatures for dangerous patterns
BYTECODE_PATTERNS = {
    '40c10f19': 'mint',
    'a0712d68': 'mint',
    '8456cb59': 'pause',
    '44337ea1': 'blacklist',
    '3659cfe6': 'proxy_upgrade',
    '4f1ef286': 'proxy_upgrade',
    '7a9e5410': 'backdoor',
    '1694505e': 'selfdestruct',
    '83197ef0': 'delegatecall',
}

# Small delay between BscScan API calls to avoid free-tier rate limit (5/sec)
BSCSCAN_DELAY = 0.25


class ContractService:
    """Wraps existing scanner + web3_client contract checks."""

    def __init__(self, web3_client, scam_db):
        self.web3_client = web3_client
        self.scam_db = scam_db

    async def fetch_contract_data(self, address: str, chain_id: int = 56) -> dict:
        defaults = {
            'is_contract': False,
            'is_verified': False,
            'contract_age_days': None,
            'scam_matches': [],
            'ownership_renounced': None,
            'has_proxy': False,
            'has_mint': False,
            'has_pause': False,
            'has_blacklist': False,
            'source_code_patterns': [],
            'bytecode_warnings': [],
        }

        try:
            is_contract = await self.web3_client.is_contract(address, chain_id=chain_id)
            if not is_contract:
                return defaults

            results = {'is_contract': True}

            # Verification + source code
            verified, source_code = await self.web3_client.is_verified_contract(address, chain_id=chain_id)
            results['is_verified'] = verified

            await asyncio.sleep(BSCSCAN_DELAY)

            # Contract age
            creation_info = await self.web3_client.get_contract_creation_info(address, chain_id=chain_id)
            if creation_info:
                results['contract_age_days'] = creation_info.get('age_days')

            # Scam DB (external APIs, not BscScan — no delay needed)
            scam_matches = await self.scam_db.check_address(address)
            results['scam_matches'] = scam_matches or []

            # Ownership (RPC call, not BscScan)
            ownership = await self.web3_client.get_ownership_info(address, chain_id=chain_id)
            if ownership:
                results['ownership_renounced'] = ownership.get('is_renounced')

            # Bytecode pattern scan (RPC call)
            bytecode_warnings = []
            has_proxy = False
            has_mint = False
            has_pause = False
            has_blacklist = False

            try:
                bytecode = await self.web3_client.get_bytecode(address, chain_id=chain_id)
                if bytecode:
                    bytecode_hex = bytecode.hex() if isinstance(bytecode, bytes) else str(bytecode)
                    for sig, pattern_name in BYTECODE_PATTERNS.items():
                        if sig in bytecode_hex:
                            bytecode_warnings.append(pattern_name)
                            if pattern_name == 'mint':
                                has_mint = True
                            elif pattern_name == 'pause':
                                has_pause = True
                            elif pattern_name == 'blacklist':
                                has_blacklist = True
                            elif pattern_name in ('proxy_upgrade', 'delegatecall'):
                                has_proxy = True
            except Exception as e:
                logger.warning("Bytecode scan failed for %s: %s", address, e)

            results['bytecode_warnings'] = bytecode_warnings
            results['has_proxy'] = has_proxy
            results['has_mint'] = has_mint
            results['has_pause'] = has_pause
            results['has_blacklist'] = has_blacklist

            # Source code patterns
            source_patterns = []
            if source_code:
                patterns_to_check = [
                    'onlyOwner', 'blacklist', 'addBlacklist', 'setMaxTx',
                    'setMaxWallet', 'setFee', 'setTax', 'selfdestruct',
                    'delegatecall', 'mint', 'pause', 'proxy',
                ]
                for pat in patterns_to_check:
                    if pat.lower() in source_code.lower():
                        source_patterns.append(pat)

            results['source_code_patterns'] = source_patterns

            return {**defaults, **results}

        except Exception as e:
            logger.error("Contract data fetch failed for %s: %s", address, e)
            return defaults
