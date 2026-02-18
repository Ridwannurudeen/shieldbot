"""RPC Proxy — intercepts eth_sendTransaction, runs firewall, forwards or blocks."""

import logging
from typing import Any, Dict, Optional

import aiohttp

logger = logging.getLogger(__name__)

# Methods that should be intercepted for security analysis
INTERCEPTED_METHODS = {"eth_sendTransaction"}


class RPCProxy:
    """JSON-RPC proxy that intercepts transactions for firewall analysis.

    All non-intercepted methods are transparently forwarded to the upstream RPC.
    For eth_sendTransaction, the firewall pipeline runs first and blocks
    HIGH-risk transactions.
    """

    def __init__(self, container):
        self._container = container

    def get_upstream_rpc(self, chain_id: int) -> Optional[str]:
        """Get the upstream RPC URL for a chain."""
        adapter = self._container.web3_client._get_adapter(chain_id)
        if adapter:
            return adapter.w3.provider.endpoint_uri
        return None

    async def handle_request(self, chain_id: int, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Handle a single JSON-RPC request.

        Returns the JSON-RPC response dict.
        """
        method = payload.get("method", "")
        params = payload.get("params", [])
        rpc_id = payload.get("id", 1)

        upstream_rpc = self.get_upstream_rpc(chain_id)
        if not upstream_rpc:
            return self._error_response(rpc_id, -32000, f"Unsupported chain_id: {chain_id}")

        # Non-intercepted methods: forward transparently
        if method not in INTERCEPTED_METHODS:
            return await self._forward(upstream_rpc, payload)

        # eth_sendTransaction: run firewall analysis
        try:
            tx_params = params[0] if params else {}
            to_addr = tx_params.get("to", "")
            from_addr = tx_params.get("from", "")
            value = tx_params.get("value", "0x0")
            data = tx_params.get("data", "0x")

            if not to_addr:
                # Contract creation — forward without analysis
                return await self._forward(upstream_rpc, payload)

            # Run the analyzer pipeline
            from core.analyzer import AnalysisContext

            ctx = AnalysisContext(
                address=to_addr,
                chain_id=chain_id,
                from_address=from_addr,
                extra={'calldata': data, 'value': value},
            )

            analyzer_results = await self._container.registry.run_all(ctx)
            risk_output = self._container.risk_engine.compute_from_results(analyzer_results)

            risk_level = risk_output.get("risk_level", "LOW")
            risk_score = risk_output.get("rug_probability", 0)

            if risk_level == "HIGH":
                logger.warning(
                    f"RPC Proxy BLOCKED tx to {to_addr} "
                    f"(risk={risk_score}, chain={chain_id})"
                )
                return self._error_response(
                    rpc_id, -32003,
                    f"Transaction blocked by ShieldBot firewall — "
                    f"risk score {risk_score}/100 ({risk_level})"
                )

            # MEDIUM or LOW: forward to upstream
            if risk_level == "MEDIUM":
                logger.info(f"RPC Proxy WARN tx to {to_addr} (risk={risk_score})")

            return await self._forward(upstream_rpc, payload)

        except Exception as e:
            logger.error(f"RPC Proxy analysis error: {e}")
            # On analysis failure, forward the transaction (fail-open)
            return await self._forward(upstream_rpc, payload)

    async def handle_batch(self, chain_id: int, payloads: list) -> list:
        """Handle a batch of JSON-RPC requests."""
        import asyncio
        tasks = [self.handle_request(chain_id, p) for p in payloads]
        return await asyncio.gather(*tasks)

    async def _forward(self, upstream_rpc: str, payload: Dict) -> Dict:
        """Forward a JSON-RPC request to the upstream RPC."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    upstream_rpc,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as resp:
                    return await resp.json()
        except Exception as e:
            logger.error(f"RPC forward error: {e}")
            return self._error_response(
                payload.get("id", 1), -32000,
                f"Upstream RPC error: {str(e)}"
            )

    @staticmethod
    def _error_response(rpc_id, code: int, message: str) -> Dict:
        return {
            "jsonrpc": "2.0",
            "id": rpc_id,
            "error": {"code": code, "message": message},
        }
