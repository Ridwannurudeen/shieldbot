"""Policy modes — deterministic behavior on timeout/error."""

import logging
from enum import Enum
from typing import Dict, List, Optional

from core.analyzer import AnalyzerResult

logger = logging.getLogger(__name__)


class PolicyMode(Enum):
    STRICT = "STRICT"
    BALANCED = "BALANCED"


class PolicyEngine:
    """Applies policy rules to analysis results."""

    def __init__(self, mode: str = "BALANCED"):
        self.mode = PolicyMode(mode.upper())

    def apply(
        self,
        results: List[AnalyzerResult],
        risk_output: Dict,
        mode_override: Optional[str] = None,
    ) -> Dict:
        """
        Apply policy rules. May override classification based on failures.

        Args:
            mode_override: Per-request policy mode (e.g. from X-Policy-Mode header).

        Returns modified risk_output dict with added fields:
          - partial: bool (whether some analyzers failed or reported incomplete coverage)
          - failed_sources: list of failed or incomplete analyzer names
          - policy_mode: current mode string
          - policy_override: str or None (if policy changed the result)
        """
        active_mode = self.mode
        if mode_override:
            try:
                active_mode = PolicyMode(mode_override.upper())
            except ValueError:
                pass

        # Providers swallow their failures into unknown results, so an analyzer whose coverage is
        # below 1 has failed as surely as one that raised. Skipped analyzers are covered.
        failed_names = [r.name for r in results if r.error is not None]
        failed_names += [
            name for name, fraction in risk_output.get('coverage', {}).items()
            if fraction < 1 and name not in failed_names
        ]
        is_partial = len(failed_names) > 0

        output = dict(risk_output)
        output['partial'] = is_partial
        output['failed_sources'] = failed_names
        output['policy_mode'] = active_mode.value
        output['policy_override'] = None

        if not is_partial:
            return output

        if active_mode == PolicyMode.STRICT:
            # Any failure → BLOCK
            logger.warning(f"STRICT policy: analyzers failed ({failed_names}), overriding to BLOCK")
            output['risk_level'] = 'HIGH'
            output['rug_probability'] = max(output.get('rug_probability', 0), 80)
            output['policy_override'] = 'BLOCK_RECOMMENDED'
            if 'critical_flags' not in output:
                output['critical_flags'] = []
            output['critical_flags'].insert(
                0, f"Policy override: {len(failed_names)} analyzer(s) unavailable or incomplete ({', '.join(failed_names)})"
            )
        else:
            # BALANCED: warn with partial data
            logger.info(f"BALANCED policy: analyzers failed ({failed_names}), partial results")
            if 'critical_flags' not in output:
                output['critical_flags'] = []
            output['critical_flags'].append(
                f"Partial analysis: {', '.join(failed_names)} unavailable or incomplete"
            )

        return output
