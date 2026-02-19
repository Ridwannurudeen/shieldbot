"""RPC Proxy — intercepts eth_sendTransaction and eth_sendRawTransaction, runs firewall, forwards or blocks."""

import logging
from typing import Any, Dict, Optional

import aiohttp
import rlp
from eth_account import Account

logger = logging.getLogger(__name__)

# Methods that should be intercepted for security analysis
INTERCEPTED_METHODS = {"eth_sendTransaction", "eth_sendRawTransaction"}


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

        # Extract tx fields depending on method
        try:
            if method == "eth_sendRawTransaction":
                raw_hex = params[0] if params else ""
                tx_fields = self._decode_raw_tx(raw_hex)
                if tx_fields is None:
                    # Decode failed — block transaction (fail-closed)
                    logger.warning(f"RPC Proxy: failed to decode raw tx, blocking (fail-closed)")
                    return self._error_response(
                        rpc_id, -32003,
                        "Transaction blocked: unable to decode for security analysis",
                    )
                to_addr = tx_fields.get("to", "") or ""
                from_addr = tx_fields.get("from", "")
                value = tx_fields.get("value", "0x0")
                data = tx_fields.get("data", "0x")
            else:
                tx_params = params[0] if params else {}
                to_addr = tx_params.get("to", "")
                from_addr = tx_params.get("from", "")
                value = tx_params.get("value", "0x0")
                data = tx_params.get("data", "0x")

            if not to_addr:
                # Contract creation — forward without analysis
                return await self._forward(upstream_rpc, payload)

            # Detect token vs non-token for accurate risk assessment
            is_token = True
            is_verified = False
            try:
                is_token = await self._container.web3_client.is_token_contract(to_addr, chain_id=chain_id)
            except Exception:
                pass
            try:
                verified_result = await self._container.web3_client.is_verified_contract(to_addr, chain_id=chain_id)
                is_verified = verified_result[0] if isinstance(verified_result, tuple) else bool(verified_result)
            except Exception:
                pass

            # Run the analyzer pipeline
            from core.analyzer import AnalysisContext

            ctx = AnalysisContext(
                address=to_addr,
                chain_id=chain_id,
                from_address=from_addr,
                is_token=is_token,
                extra={'calldata': data, 'value': value, 'is_verified': is_verified},
            )

            analyzer_results = await self._container.registry.run_all(ctx)
            risk_output = self._container.risk_engine.compute_from_results(analyzer_results, is_token=is_token)

            risk_level = risk_output.get("risk_level", "LOW")
            risk_score = risk_output.get("rug_probability", 0)

            logger.info(
                f"RPC Proxy analyzed tx to {to_addr} — "
                f"risk={risk_score}, level={risk_level}, chain={chain_id}"
            )

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
            # On analysis failure, block the transaction (fail-closed)
            return self._error_response(
                rpc_id, -32003,
                "Transaction blocked: security analysis failed — please retry",
            )

    async def handle_batch(self, chain_id: int, payloads: list) -> list:
        """Handle a batch of JSON-RPC requests."""
        import asyncio
        tasks = [self.handle_request(chain_id, p) for p in payloads]
        return await asyncio.gather(*tasks)

    @staticmethod
    def _decode_raw_tx(raw_hex: str) -> Optional[Dict[str, Any]]:
        """Decode an RLP-encoded signed transaction into its fields.

        Handles legacy (type 0), EIP-2930 (type 1), and EIP-1559 (type 2) txs.
        Returns a dict with to, from, value, data — or None on failure.
        """
        try:
            raw = bytes.fromhex(raw_hex.replace("0x", ""))

            # Determine tx type from first byte
            if raw[0] < 0x80:
                # Typed transaction (EIP-2718): first byte is the type
                tx_type = raw[0]
                decoded = rlp.decode(raw[1:])
            else:
                # Legacy transaction
                tx_type = 0
                decoded = rlp.decode(raw)

            if tx_type == 0:
                # Legacy: [nonce, gasPrice, gas, to, value, data, v, r, s]
                to_bytes, value_bytes, data_bytes = decoded[3], decoded[4], decoded[5]
            elif tx_type == 1:
                # EIP-2930: [chainId, nonce, gasPrice, gas, to, value, data, accessList, v, r, s]
                to_bytes, value_bytes, data_bytes = decoded[4], decoded[5], decoded[6]
            elif tx_type == 2:
                # EIP-1559: [chainId, nonce, maxPriorityFee, maxFee, gas, to, value, data, accessList, v, r, s]
                to_bytes, value_bytes, data_bytes = decoded[5], decoded[6], decoded[7]
            else:
                logger.warning(f"Unknown tx type {tx_type}")
                return None

            to_addr = ("0x" + to_bytes.hex()) if to_bytes else None
            value_int = int.from_bytes(value_bytes, "big") if value_bytes else 0

            # Recover sender
            from_addr = Account.recover_transaction(raw_hex)

            return {
                "to": to_addr,
                "from": from_addr,
                "value": hex(value_int),
                "data": ("0x" + data_bytes.hex()) if data_bytes else "0x",
            }
        except Exception as e:
            logger.warning(f"Failed to decode raw transaction: {e}")
            return None

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
