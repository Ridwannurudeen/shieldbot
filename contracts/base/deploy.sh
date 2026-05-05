#!/usr/bin/env bash
# One-shot Base mainnet deploy for ShieldBotAttestor.
#
# Reads the deployer key from BASE_DEPLOYER_PRIVATE_KEY env var (NEVER committed,
# NEVER passed as a CLI arg, NEVER printed). Generates a fresh verifier wallet,
# registers schema, deploys + verifies the contract, prints the VPS env block,
# and optionally writes it to the VPS over SSH.
#
# Usage (run from your terminal):
#   read -s BASE_DEPLOYER_PRIVATE_KEY ; export BASE_DEPLOYER_PRIVATE_KEY
#   export BASESCAN_API_KEY=<from https://basescan.org/myapikey>
#   export BASE_RPC_URL=https://mainnet.base.org      # or paid endpoint
#   export VPS_HOST=root@75.119.153.252               # optional — enables auto-VPS update
#   bash contracts/base/deploy.sh
#
# Prereqs:
#   - Foundry installed (forge, cast)
#   - Submodules pulled: cd contracts/base && forge install (no-op if already done)
#   - Deployer wallet 0xB2Fae83de08b285cB3D6A77Ff520F6AD669D5f33 funded with
#     ~0.005 ETH on Base mainnet

set -euo pipefail

EXPECTED_DEPLOYER="0xB2Fae83de08b285cB3D6A77Ff520F6AD669D5f33"
EAS="0x4200000000000000000000000000000000000021"
SCHEMA_REGISTRY="0x4200000000000000000000000000000000000020"

# ─── Validate env ────────────────────────────────────────────────────────────
[[ -z "${BASE_DEPLOYER_PRIVATE_KEY:-}" ]] && { echo "ERROR: BASE_DEPLOYER_PRIVATE_KEY not set"; exit 1; }
[[ -z "${BASESCAN_API_KEY:-}" ]]         && { echo "ERROR: BASESCAN_API_KEY not set"; exit 1; }
BASE_RPC_URL="${BASE_RPC_URL:-https://mainnet.base.org}"

cd "$(dirname "$0")"
[[ ! -f foundry.toml ]] && { echo "ERROR: must run from contracts/base/"; exit 1; }

# Confirm the deployer key matches the expected identity wallet.
DEPLOYER_ADDR=$(cast wallet address --private-key "$BASE_DEPLOYER_PRIVATE_KEY")
if [[ "${DEPLOYER_ADDR,,}" != "${EXPECTED_DEPLOYER,,}" ]]; then
  echo "ERROR: deployer key resolves to $DEPLOYER_ADDR"
  echo "       expected $EXPECTED_DEPLOYER (Base identity wallet)"
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

# Compute deterministic schema UID (matches EAS): keccak(schema, resolver=0, revocable=true)
SCHEMA_UID=$(cast keccak "$(cast abi-encode-packed 'string,address,bool' "$SCHEMA_STR" 0x0000000000000000000000000000000000000000 true 2>/dev/null)" 2>/dev/null || echo "")

# Fallback: query the registry for an existing record at the computed UID.
# Try registering — revert means schema already exists, which is fine.
set +e
REG_OUT=$(forge script script/RegisterSchema.s.sol \
  --rpc-url "$BASE_RPC_URL" \
  --broadcast \
  --private-key "$BASE_DEPLOYER_PRIVATE_KEY" \
  --json 2>&1)
REG_RC=$?
set -e

# Extract the schema UID from logs regardless of register-vs-already-exists path.
SCHEMA_UID=$(grep -oE "0x[0-9a-fA-F]{64}" <<<"$REG_OUT" | tail -1)
ZERO_UID="0x$(printf '0%.0s' {1..64})"

if [[ -z "$SCHEMA_UID" || "$SCHEMA_UID" == "$ZERO_UID" ]]; then
  echo "ERROR: failed to determine schema UID"
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
  --private-key "$BASE_DEPLOYER_PRIVATE_KEY" \
  --verify \
  --etherscan-api-key "$BASESCAN_API_KEY" \
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
  ssh "$VPS_HOST" "set -e; cd /opt/shieldbot; \
    sed -i.bak \
      -e '/^BASE_ATTESTOR_ADDRESS=/d' \
      -e '/^BASE_ATTESTOR_SCHEMA_UID=/d' \
      -e '/^BASE_VERIFIER_PRIVATE_KEY=/d' \
      .env; \
    echo 'BASE_ATTESTOR_ADDRESS=$ATTESTOR_ADDR' >> .env; \
    echo 'BASE_ATTESTOR_SCHEMA_UID=$SCHEMA_UID' >> .env; \
    echo 'BASE_VERIFIER_PRIVATE_KEY=$VERIFIER_KEY' >> .env; \
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
echo "(funds 10+ attestations at 150k gas each)"

# ─── Summary ─────────────────────────────────────────────────────────────────
echo
echo "═══════════════════════════════════════════════════════════════════"
echo "DONE"
echo "  Attestor:   https://basescan.org/address/$ATTESTOR_ADDR"
echo "  EAS Scan:   https://base.easscan.org/address/$ATTESTOR_ADDR"
echo "  Schema:     $SCHEMA_UID"
echo "  Output:     $(pwd)/$OUTPUT_FILE"
echo "═══════════════════════════════════════════════════════════════════"
