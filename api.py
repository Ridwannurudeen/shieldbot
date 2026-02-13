"""
ShieldAI Firewall API
FastAPI backend for the Chrome extension transaction firewall
Runs alongside bot.py on the VPS
"""

import os
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any
from dotenv import load_dotenv

from scanner.transaction_scanner import TransactionScanner
from scanner.token_scanner import TokenScanner
from utils.web3_client import Web3Client
from utils.ai_analyzer import AIAnalyzer
from utils.calldata_decoder import CalldataDecoder

load_dotenv()

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)

# Shared instances (initialized on startup)
web3_client: Optional[Web3Client] = None
ai_analyzer: Optional[AIAnalyzer] = None
tx_scanner: Optional[TransactionScanner] = None
token_scanner: Optional[TokenScanner] = None
calldata_decoder: Optional[CalldataDecoder] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global web3_client, ai_analyzer, tx_scanner, token_scanner, calldata_decoder
    web3_client = Web3Client()
    ai_analyzer = AIAnalyzer()
    tx_scanner = TransactionScanner(web3_client, ai_analyzer)
    token_scanner = TokenScanner(web3_client, ai_analyzer)
    calldata_decoder = CalldataDecoder()
    logger.info("ShieldAI Firewall API started")
    logger.info(f"AI Analysis: {'enabled' if ai_analyzer.is_available() else 'disabled'}")
    yield
    logger.info("ShieldAI Firewall API shutting down")


app = FastAPI(
    title="ShieldAI Firewall API",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Chrome extension uses chrome-extension:// origin
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --- Request / Response Models ---

class FirewallRequest(BaseModel):
    to: str
    sender: str = Field(alias="from")
    value: str = "0"
    data: str = "0x"
    chainId: int = 56

    class Config:
        populate_by_name = True


class ScanRequest(BaseModel):
    address: str


# --- Endpoints ---

@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "service": "shieldai-firewall",
        "ai_available": ai_analyzer.is_available() if ai_analyzer else False,
    }


@app.post("/api/firewall")
async def firewall(req: FirewallRequest):
    """
    Main firewall endpoint — intercepts a pending transaction,
    analyzes calldata + target contract, and returns a security verdict.
    """
    try:
        to_addr = req.to
        from_addr = req.sender

        if not web3_client.is_valid_address(to_addr):
            raise HTTPException(status_code=400, detail="Invalid 'to' address")

        to_addr = web3_client.to_checksum_address(to_addr)

        # 1. Decode calldata
        decoded = calldata_decoder.decode(req.data)
        whitelisted = calldata_decoder.is_whitelisted_target(to_addr)

        # 2. Scan the target contract
        is_token = False
        contract_scan = {}
        try:
            is_token = await web3_client.is_token_contract(to_addr)
        except Exception:
            pass

        if is_token:
            contract_scan = await token_scanner.check_token(to_addr)
        else:
            contract_scan = await tx_scanner.scan_address(to_addr)

        # Remove the forensic_report key (Telegram-formatted, not needed here)
        contract_scan.pop("forensic_report", None)
        contract_scan.pop("source_code", None)

        # 3. Build tx data context for AI
        tx_data = {
            "to": to_addr,
            "from": from_addr,
            "value": req.value,
            "data": req.data,
            "chainId": req.chainId,
            "decoded_calldata": decoded,
            "whitelisted_router": whitelisted,
        }

        # 4. Generate AI firewall report
        firewall_result = None
        if ai_analyzer and ai_analyzer.is_available():
            firewall_result = await ai_analyzer.generate_firewall_report(tx_data, contract_scan)

        if firewall_result:
            # Attach raw checks for the extension
            firewall_result["raw_checks"] = _extract_raw_checks(contract_scan)
            return firewall_result
        else:
            # Fallback: build response from heuristic data
            return _build_fallback_response(decoded, contract_scan, whitelisted)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Firewall error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/scan")
async def scan(req: ScanRequest):
    """Quick contract scan — reuses TransactionScanner.scan_address."""
    try:
        address = req.address
        if not web3_client.is_valid_address(address):
            raise HTTPException(status_code=400, detail="Invalid address")

        address = web3_client.to_checksum_address(address)
        result = await tx_scanner.scan_address(address)

        # Strip large fields
        result.pop("source_code", None)
        result.pop("forensic_report", None)

        return result

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Scan error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


# --- Helpers ---

def _extract_raw_checks(scan: Dict) -> Dict:
    """Extract key raw check values for the extension."""
    return {
        "is_verified": scan.get("is_verified", False),
        "scam_matches": len(scan.get("scam_matches", [])),
        "contract_age_days": scan.get("contract_age_days"),
        "is_honeypot": scan.get("is_honeypot", False),
        "ownership_renounced": scan.get("checks", {}).get("ownership_renounced", False),
        "risk_score_heuristic": scan.get("risk_score", 0),
    }


def _build_fallback_response(decoded: Dict, scan: Dict, whitelisted: Optional[str]) -> Dict:
    """Build a firewall response when AI is unavailable."""
    risk_score = scan.get("risk_score", 50)
    scam_matches = len(scan.get("scam_matches", []))
    is_honeypot = scan.get("is_honeypot", False)
    is_verified = scan.get("is_verified", False)
    is_unlimited_approval = decoded.get("is_unlimited_approval", False)

    danger_signals = []

    if scam_matches > 0:
        danger_signals.append(f"Found {scam_matches} scam database match(es)")
        risk_score = max(risk_score, 80)

    if is_honeypot:
        danger_signals.append("Honeypot detected — cannot sell after buying")
        risk_score = max(risk_score, 90)

    if is_unlimited_approval and not is_verified:
        danger_signals.append("Unlimited approval to unverified contract")
        risk_score = max(risk_score, 85)

    if not is_verified:
        danger_signals.append("Contract source code is not verified")

    if whitelisted:
        risk_score = max(0, risk_score - 20)

    # Classify
    if risk_score >= 80:
        classification = "BLOCK_RECOMMENDED"
    elif risk_score >= 60:
        classification = "HIGH_RISK"
    elif risk_score >= 30:
        classification = "CAUTION"
    else:
        classification = "SAFE"

    return {
        "classification": classification,
        "risk_score": min(100, risk_score),
        "danger_signals": danger_signals,
        "transaction_impact": {
            "sending": "Unknown (AI unavailable)",
            "granting_access": "Unknown" if not decoded.get("is_approval") else (
                "UNLIMITED" if is_unlimited_approval else "Limited approval"
            ),
            "recipient": scan.get("address", "Unknown"),
            "post_tx_state": "AI analysis unavailable — review manually",
        },
        "analysis": "AI analysis unavailable. Showing heuristic results only.",
        "plain_english": "Could not generate AI analysis. Review the danger signals above carefully.",
        "verdict": f"{classification} — Risk score {risk_score}/100",
        "raw_checks": _extract_raw_checks(scan),
    }
