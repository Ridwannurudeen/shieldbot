"""Behavioral analyzer — wraps EthosService."""

import logging
from core.analyzer import Analyzer, AnalysisContext, AnalyzerResult
from services.ethos_service import neutral_reputation
from utils.calldata_decoder import CalldataDecoder

logger = logging.getLogger(__name__)

_decoder = CalldataDecoder()

# Where the spender sits in each approval-family call: approve, increaseAllowance and
# setApprovalForAll name it first; both permits name the owner first.
_SPENDER_PARAM = {
    '095ea7b3': 'param_0',
    '39509351': 'param_0',
    'a22cb465': 'param_0',
    'd505accf': 'param_1',
    '8fcbaf0c': 'param_1',
}


async def counterparty_reputation(ethos_service, decoded: dict, recipient: str) -> dict:
    """Ethos reputation of the counterparty whose reputation is evidence about this call.

    Only the spender of an approval (approval verdicts are never cached) and the recipient of a
    native send (the recipient is the cache key) are scored, so no address's reputation leaks
    into another address's cached verdict; any other call is neutral and covered. The sender is
    never scored: its reputation is not evidence about the transaction.
    """
    selector = decoded.get('selector')
    if not selector:
        address = recipient
    elif selector in _SPENDER_PARAM:
        address = (decoded.get('params') or {}).get(_SPENDER_PARAM[selector])
    else:
        address = None
    if not address:
        return {**neutral_reputation(), 'counterparty': None, 'status': 'ok'}
    data = await ethos_service.fetch_wallet_reputation(address)
    data['counterparty'] = address
    return data


class BehavioralAnalyzer(Analyzer):
    """Analyzes wallet reputation via Ethos Network."""

    def __init__(self, ethos_service):
        self._service = ethos_service

    @property
    def name(self) -> str:
        return "behavioral"

    @property
    def weight(self) -> float:
        return 0.20

    async def analyze(self, ctx: AnalysisContext) -> AnalyzerResult:
        decoded = _decoder.decode(ctx.extra.get('calldata', '0x'))
        data = await counterparty_reputation(self._service, decoded, ctx.address)
        score, flags = self._compute(data)
        return AnalyzerResult(
            name=self.name, weight=self.weight,
            score=score, flags=flags, data=data,
        )

    def _compute(self, d: dict) -> tuple:
        score = 0
        flags = []
        if d.get('status') == 'unknown':
            flags.append(f"Behavioral data unknown: {d.get('reason') or 'provider data unavailable'}")
        if d.get('severe_reputation_flag'):
            score += 50
            flags.append('Severe reputation warning')
        elif d.get('low_reputation_flag'):
            score += 30
            flags.append('Low wallet reputation')
        if d.get('scam_flags'):
            score += 40
            flags.append('Ethos scam flags present')
        return min(score, 100), flags
