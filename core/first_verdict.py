"""The streamed firewall's interim ("first") verdict.

POST /api/firewall with Accept: text/event-stream sends a first event while the scan still runs and
then the final verdict, which is exactly the plain response. Every required check is an external call,
so an interim answer can honestly be only a hard floor already known (a local admin blacklist entry,
an analyzer's declared floor, a scam match) or Unknown. Its status is always 'unknown' and it is never
SAFE.
"""

import asyncio
from typing import Callable, Dict, Iterable, Optional

from core import verdicts
from core.analyzer import AnalyzerResult
from core.extension_formatter import format_extension_alert
from core.risk_engine import RiskEngine, scam_match_floor

IN_PROGRESS = 'Unknown (analysis in progress)'


def _result_floor(result: AnalyzerResult) -> float:
    """The hard floor a returned analyzer's result sets, as RiskEngine.compute_from_results applies it:
    its declared floor and its scam matches' floor. A result carrying an error sets none."""
    if result.error:
        return 0
    return max(result.data.get('floor') or 0, scam_match_floor(result.data.get('scam_matches')))


class FirstVerdictProgress:
    """What one streamed scan knows so far: the results of the analyzers that have returned
    (AnalyzerRegistry.run_all's on_result), the local blacklist's match for the target, and the
    registry analyzers still pending. block_known is set as soon as a floor reaches BLOCK_MIN.

    describe is set once the request is decoded: it returns the response fields that describe the
    request. A request that never sets it (a signature request) gets no interim verdict."""

    def __init__(self, pending: Iterable[str], policy_mode: str):
        self.results = []
        self.local_matches = []
        self.pending = set(pending)
        self.policy_mode = policy_mode
        self.block_known = asyncio.Event()
        self.describe: Optional[Callable[[], Dict]] = None

    def add_result(self, result: AnalyzerResult):
        self.results.append(result)
        self.pending.discard(result.name)
        if _result_floor(result) >= verdicts.BLOCK_MIN:
            self.block_known.set()

    def add_local_match(self, match: Optional[dict]):
        if not match:
            return
        self.local_matches.append(match)
        if scam_match_floor([match]) >= verdicts.BLOCK_MIN:
            self.block_known.set()


def build_first_verdict(progress: FirstVerdictProgress, transaction: Dict, elapsed_ms: int) -> Dict:
    """The interim verdict: the plain response's shape, with status 'unknown', never SAFE, and
    scored by the hard floors known so far. `transaction` holds the fields that describe the request
    (decoded_action, calldata_details, transaction_impact, chain_id, network).

    Floors only, never a partial weighted mean. The engine applies every floor to the final score
    with max(), so while the same evidence holds the interim's band is never above the final's. A
    partial mean has no such bound: a structural 60 alone reads HIGH_RISK, and the clean results
    still to come can dilute it to SAFE.
    """
    floor = max(
        [_result_floor(result) for result in progress.results] + [scam_match_floor(progress.local_matches)]
    )
    flags = [flag for result in progress.results if _result_floor(result) for flag in result.flags]
    flags += [match['reason'] for match in progress.local_matches]
    pending = sorted(progress.pending)
    alert = format_extension_alert({
        'rug_probability': floor,
        'risk_level': verdicts.UNKNOWN,
        'status': 'unknown',
        # Each returned analyzer's coverage as the engine measures it; the pending ones have none.
        'coverage': RiskEngine().compute_from_results(progress.results)['coverage'],
        'coverage_reasons': {
            'pending': 'Full analysis in progress' + (': ' + ', '.join(pending) if pending else ''),
        },
        'critical_flags': list(dict.fromkeys(flags)),
    })
    classification = alert['risk_classification']
    return {
        'status': alert['status'],
        'coverage': alert['coverage'],
        'coverage_reasons': alert['coverage_reasons'],
        'risk_display': IN_PROGRESS,
        'classification': classification,
        'risk_score': floor,
        **transaction,
        'danger_signals': alert['top_flags'],
        'plain_english': alert['recommended_action'],
        'verdict': f'{classification} — {IN_PROGRESS}',
        'partial': True,
        'failed_sources': [],
        'policy_mode': progress.policy_mode,
        'final': False,
        'pending_sources': pending,
        'elapsed_ms': elapsed_ms,
    }
