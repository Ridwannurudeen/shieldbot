#!/usr/bin/env bash
# One-shot Base mainnet deploy for ShieldBotAttestor.
#
# Signs with the Foundry keystore account base-deployer (DEPLOY_BASE.md step 1);
# cast and forge ask for its password. The deployer key is never passed on the
# command line or held in an environment variable. Generates a fresh verifier
# wallet, registers schema, deploys + verifies the contract, prints the VPS env
# block, and optionally writes it to the VPS over SSH.
#
# Usage (run from your terminal):
#   export BASESCAN_API_KEY=<from https://basescan.org/myapikey>
#   export BASE_RPC_URL=https://mainnet.base.org      # or paid endpoint
#   export VPS_HOST=root@75.119.153.252               # optional — enables auto-VPS update
#   bash contracts/base/deploy.sh
#
# Prereqs:
#   - Foundry installed (forge, cast)
#   - Submodules pulled: cd contracts/base && forge install (no-op if already done)
#   - Deployer keystore imported: cast wallet import base-deployer --interactive
#   - Deployer wallet 0xfE3f3cEAb7266b5de5Ae8738727b6cf82F7Be76c funded with
#     ~0.005 ETH on Base mainnet

set -euo pipefail

DEPLOYER_ACCOUNT="base-deployer"
EXPECTED_DEPLOYER="0xfE3f3cEAb7266b5de5Ae8738727b6cf82F7Be76c"
EAS="0x4200000000000000000000000000000000000021"
SCHEMA_REGISTRY="0x4200000000000000000000000000000000000020"

# ─── Validate env ────────────────────────────────────────────────────────────
# Etherscan v2 unified API: any explorer key works (BscScan/BaseScan/Etherscan).
# Fall back to BSCSCAN_API_KEY if ETHERSCAN_V2_API_KEY / BASESCAN_API_KEY aren't set.
ETHERSCAN_V2_API_KEY="${ETHERSCAN_V2_API_KEY:-${BASESCAN_API_KEY:-${BSCSCAN_API_KEY:-}}}"
export ETHERSCAN_V2_API_KEY
[[ -z "$ETHERSCAN_V2_API_KEY" ]] && { echo "ERROR: no Etherscan-family API key (set BSCSCAN_API_KEY or BASESCAN_API_KEY)"; exit 1; }
BASE_RPC_URL="${BASE_RPC_URL:-https://mainnet.base.org}"

cd "$(dirname "$0")"
[[ ! -f foundry.toml ]] && { echo "ERROR: must run from contracts/base/"; exit 1; }

# Confirm the deployer keystore holds the expected owner wallet.
DEPLOYER_ADDR=$(cast wallet address --account "$DEPLOYER_ACCOUNT")
if [[ "${DEPLOYER_ADDR,,}" != "${EXPECTED_DEPLOYER,,}" ]]; then
  echo "ERROR: keystore $DEPLOYER_ACCOUNT resolves to $DEPLOYER_ADDR"
  echo "       expected $EXPECTED_DEPLOYER (attestor owner)"
  echo "       refusing to deploy from a different wallet"
  exit 1
fi

# Check deployer balance.
BALANCE_WEI=$(cast balance --rpc-url "$BASE_RPC_URL" "$DEPLOYER_ADDR")
BALANCE_ETH=$(cast --to-unit "$BALANCE_WEI" ether)
echo "Deployer:        $DEPLOYER_ADDR"
echo "Deployer balance: $BALANCE_ETH ETH"
if (( $(echo "$BALANCE_ETH < 0.003" | bc -l 2>/dev/null || echo 0) )); then
  echo "WARN: balance below 0.003 ETH — deploy may fail. Fund the wallet and retry."
fi

# ─── 1. Build ────────────────────────────────────────────────────────────────
echo
echo "── 1. Build ──"
forge build --silent

# ─── 2. Register schema (one-time) ───────────────────────────────────────────
echo
echo "── 2. Register schema ──"
SCHEMA_STR="address scannedAddress,uint8 riskLevel,string scanType,uint64 sourceChainId,bytes32 evidenceHash,string evidenceURI"

# The schema UID is deterministic (matches EAS): keccak256(abi.encodePacked(schema, resolver=0, revocable=true)).
# For this schema it is 0xdc6d6de6…852e9e, the UID the live attestor uses.
SCHEMA_PACKED=$(cast abi-encode --packed "f(string,address,bool)" "$SCHEMA_STR" 0x0000000000000000000000000000000000000000 true)
SCHEMA_UID=$(cast keccak "$SCHEMA_PACKED")

# Try registering — revert means schema already exists, which is fine.
set +e
REG_OUT=$(forge script script/RegisterSchema.s.sol \
  --rpc-url "$BASE_RPC_URL" \
  --broadcast \
  --account "$DEPLOYER_ACCOUNT" --sender "$DEPLOYER_ADDR" \
  --json 2>&1)
set -e

# Either way the registry must now hold the schema under the computed UID.
REGISTERED=$(cast call "$SCHEMA_REGISTRY" "getSchema(bytes32)((bytes32,address,bool,string))" "$SCHEMA_UID" --rpc-url "$BASE_RPC_URL")
if [[ "${REGISTERED,,}" != "(${SCHEMA_UID,,},"* ]]; then
  echo "ERROR: schema $SCHEMA_UID is not registered"
  echo "$REG_OUT" | tail -20
  exit 1
fi
echo "Schema UID: $SCHEMA_UID"

# ─── 3. Generate verifier wallet ─────────────────────────────────────────────
echo
echo "── 3. Generate verifier wallet ──"
VERIFIER_OUT=$(cast wallet new)
VERIFIER_ADDR=$(grep -oE "0x[a-fA-F0-9]{40}" <<<"$VERIFIER_OUT" | head -1)
VERIFIER_KEY=$(grep -oE "0x[a-fA-F0-9]{64}" <<<"$VERIFIER_OUT" | head -1)

if [[ -z "$VERIFIER_ADDR" || -z "$VERIFIER_KEY" ]]; then
  echo "ERROR: failed to parse generated verifier wallet"
  exit 1
fi
echo "Verifier address: $VERIFIER_ADDR"
echo "Verifier key:     [REDACTED — written only to .deploy-output below]"

# ─── 4. Deploy attestor ──────────────────────────────────────────────────────
echo
echo "── 4. Deploy attestor ──"
DEPLOY_OUT=$(SCHEMA_UID="$SCHEMA_UID" INITIAL_VERIFIER="$VERIFIER_ADDR" \
  forge script script/DeployAttestor.s.sol \
  --rpc-url "$BASE_RPC_URL" \
  --broadcast \
  --account "$DEPLOYER_ACCOUNT" --sender "$DEPLOYER_ADDR" \
  --verify \
  --etherscan-api-key "$ETHERSCAN_V2_API_KEY" \
  2>&1)

ATTESTOR_ADDR=$(grep -oE "Deployed at: 0x[a-fA-F0-9]{40}" <<<"$DEPLOY_OUT" | grep -oE "0x[a-fA-F0-9]{40}" | head -1)
if [[ -z "$ATTESTOR_ADDR" ]]; then
  echo "ERROR: failed to extract attestor address from deploy output"
  echo "$DEPLOY_OUT" | tail -30
  exit 1
fi
echo "Attestor: $ATTESTOR_ADDR"

# ─── 5. Sanity check ─────────────────────────────────────────────────────────
echo
echo "── 5. Sanity check ──"
TOTAL=$(cast call "$ATTESTOR_ADDR" "totalAttestations()(uint256)" --rpc-url "$BASE_RPC_URL")
OWNER=$(cast call "$ATTESTOR_ADDR" "owner()(address)" --rpc-url "$BASE_RPC_URL")
SCHEMA_ON_CHAIN=$(cast call "$ATTESTOR_ADDR" "schemaUID()(bytes32)" --rpc-url "$BASE_RPC_URL")
EAS_ON_CHAIN=$(cast call "$ATTESTOR_ADDR" "eas()(address)" --rpc-url "$BASE_RPC_URL")
echo "  totalAttestations: $TOTAL"
echo "  owner:             $OWNER"
echo "  schemaUID:         $SCHEMA_ON_CHAIN"
echo "  eas:               $EAS_ON_CHAIN"

[[ "$TOTAL" != "0" ]]                                    && { echo "WARN: totalAttestations != 0"; }
[[ "${OWNER,,}" != "${EXPECTED_DEPLOYER,,}" ]]            && { echo "ERROR: owner mismatch"; exit 1; }
[[ "${SCHEMA_ON_CHAIN,,}" != "${SCHEMA_UID,,}" ]]         && { echo "ERROR: schemaUID mismatch"; exit 1; }
[[ "${EAS_ON_CHAIN,,}" != "${EAS,,}" ]]                   && { echo "ERROR: eas mismatch"; exit 1; }

# ─── 6. Write deploy output (sensitive — gitignored) ─────────────────────────
echo
echo "── 6. Write deploy output ──"
OUTPUT_FILE=".deploy-output"
cat > "$OUTPUT_FILE" <<EOF
# ShieldBot Base deploy output — generated $(date -u +%Y-%m-%dT%H:%M:%SZ)
# DO NOT COMMIT THIS FILE.
BASE_ATTESTOR_ADDRESS=$ATTESTOR_ADDR
BASE_ATTESTOR_SCHEMA_UID=$SCHEMA_UID
BASE_VERIFIER_PRIVATE_KEY=$VERIFIER_KEY
# Verifier address (informational): $VERIFIER_ADDR
# Owner (deployer):                 $OWNER
# Explorer:                         https://basescan.org/address/$ATTESTOR_ADDR
EOF
chmod 600 "$OUTPUT_FILE"
echo "Wrote $OUTPUT_FILE (mode 0600). It contains the verifier private key — keep it offline."

# ─── 7. Optional: update VPS ─────────────────────────────────────────────────
if [[ -n "${VPS_HOST:-}" ]]; then
  echo
  echo "── 7. Update VPS .env at $VPS_HOST ──"
  # The verifier key travels on ssh's stdin and is appended by cat, never placed on a command line.
  printf 'BASE_VERIFIER_PRIVATE_KEY=%s\n' "$VERIFIER_KEY" | ssh "$VPS_HOST" "set -e; cd /opt/shieldbot; \
    sed -i.bak \
      -e '/^BASE_ATTESTOR_ADDRESS=/d' \
      -e '/^BASE_ATTESTOR_SCHEMA_UID=/d' \
      -e '/^BASE_VERIFIER_PRIVATE_KEY=/d' \
      .env; \
    echo 'BASE_ATTESTOR_ADDRESS=$ATTESTOR_ADDR' >> .env; \
    echo 'BASE_ATTESTOR_SCHEMA_UID=$SCHEMA_UID' >> .env; \
    cat >> .env; \
    chmod 600 .env; \
    systemctl restart shieldbot.service; \
    sleep 3; \
    journalctl -u shieldbot.service -n 30 --no-pager | grep -E 'Base EAS Attestor|started'"
  echo "VPS updated and service restarted."
else
  echo
  echo "── 7. VPS update skipped (set VPS_HOST=root@75.119.153.252 to enable) ──"
fi

# ─── 8. Fund the verifier ────────────────────────────────────────────────────
echo
echo "── 8. Fund the verifier wallet ──"
echo "Send ~0.001 ETH on Base to: $VERIFIER_ADDR"
echo "(the one attestation posted so far used about 520k gas)"

# ─── Summary ─────────────────────────────────────────────────────────────────
echo
echo "═══════════════════════════════════════════════════════════════════"
echo "DONE"
echo "  Attestor:   https://basescan.org/address/$ATTESTOR_ADDR"
echo "  EAS Scan:   https://base.easscan.org/address/$ATTESTOR_ADDR"
echo "  Schema:     $SCHEMA_UID"
echo "  Output:     $(pwd)/$OUTPUT_FILE"
echo "═══════════════════════════════════════════════════════════════════"
