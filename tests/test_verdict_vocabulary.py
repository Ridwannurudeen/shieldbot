"""One verdict vocabulary and band table, owned by core/verdicts.py.

No Python verdict producer outside that module restates a band number or writes a classification,
risk level or agent decision as a literal, and the extension and the SDKs use the words GET
/api/verdicts publishes.
"""

import re
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from agent.policy_engine import AgentPolicyEngine
from core import verdicts
from core.registry import FIRST_VERDICT_SECONDS

ROOT = Path(__file__).resolve().parents[1]
# Tests restate bands on purpose; the SDKs are separate packages checked below; the rest is not Python
# that serves a verdict.
SKIPPED = {
    "tests",
    "sdk",
    "node_modules",
    ".git",
    "venv",
    ".venv",
    "__pycache__",
    "landing",
    "landing-src",
    "dashboard",
    "extension",
    "contracts",
}
SCORE_COMPARISON = re.compile(
    r"(?:score|\brs\b|rug_prob\w*|probability|composite|floor)['\"]?(?:\]|,[^)]*\))?\s*(?:>=|<=|>|<)\s*\d"
)
CLASSIFICATION_LITERAL = re.compile(r"['\"](?:SAFE|CAUTION|HIGH_RISK|BLOCK_RECOMMENDED)['\"]")
LEVEL_LITERAL = re.compile(r"risk_level['\"]?\]?\s*(?:=|:)\s*['\"](?:LOW|MEDIUM|HIGH)['\"]")
AGENT_LITERAL = re.compile(r"verdict\s*=\s*['\"](?:ALLOW|WARN|BLOCK)['\"]")

# Lines the scan matches that are not a verdict producer restating the table, and why.
ALLOWED = {
    (
        "agent/advisor.py",
        "if score >= 70:",
    ): "wording tiers of the rule-based explanation when AI is off, not a verdict (owner decision to align)",
    (
        "agent/advisor.py",
        "if score >= 40:",
    ): "wording tiers of the rule-based explanation when AI is off, not a verdict (owner decision to align)",
    (
        "agent/policy_engine.py",
        "if math.isnan(risk_score) or risk_score < 0:",
    ): "rejects an invalid score, not a band",
    ("analyzers/structural.py", "if ts_score <= 30:"): "TokenSniffer's own score scale",
    ("analyzers/structural.py", "elif ts_score <= 60:"): "TokenSniffer's own score scale",
    (
        "core/risk_engine.py",
        "elif not result.error and (fraction == 1 or result.score > 0):",
    ): "any positive analyzer score is known adverse evidence, not a band",
    (
        "services/base_attestation_service.py",
        'RISK_LABELS = {0: "LOW", 1: "MEDIUM", 2: "HIGH", 3: "SAFE", 4: "WARNING", 5: "DANGER"}',
    ): "labels of the deployed contract's record format, which is not changed",
    (
        "utils/onchain_recorder.py",
        "risk_names = {0: 'LOW', 1: 'MEDIUM', 2: 'HIGH', 3: 'SAFE', 4: 'WARNING', 5: 'DANGER'}",
    ): "labels of the deployed contract's record format, which is not changed",
    ("services/ethos_service.py", "if raw_score >= 1800:"): "Ethos's own reputation scale",
    ("services/ethos_service.py", "elif raw_score >= 1000:"): "Ethos's own reputation scale",
    ("services/ethos_service.py", "elif raw_score >= 500:"): "Ethos's own reputation scale",
    (
        "services/greenfield_service.py",
        "Uploads forensic reports as immutable JSON objects when risk score >= 50.",
    ): "module docstring; the caller compares with verdicts.HIGH_RISK_MIN",
    ("services/guardian.py", "if rs >= 70:"): (
        "approval spender tiers of wallet health, a separate surface with its own words (owner decision to align)"
    ),
    ("services/guardian.py", 'elif rs >= 50 and risk_level not in ("critical",):'): (
        "approval spender tiers of wallet health, a separate surface with its own words (owner decision to align)"
    ),
    (
        "services/guardian.py",
        "elif composite >= 80:",
    ): "wallet health score tiers, not a transaction verdict",
    (
        "services/guardian.py",
        "elif composite >= 60:",
    ): "wallet health score tiers, not a transaction verdict",
    (
        "services/guardian.py",
        "elif composite >= 40:",
    ): "wallet health score tiers, not a transaction verdict",
    (
        "services/guardian.py",
        "elif composite >= 20:",
    ): "wallet health score tiers, not a transaction verdict",
    (
        "services/guardian.py",
        'if score_data and score_data.get("risk_score", 0) >= 70:',
    ): "wallet health risk points for a held token (owner decision to align with BLOCK_MIN)",
    (
        "services/injection_scanner.py",
        "if switch_score > 0.6:",
    ): "prompt-injection heuristic, not a risk score",
}


def _python_sources():
    for path in sorted(ROOT.rglob("*.py")):
        relative = path.relative_to(ROOT)
        if not SKIPPED.intersection(relative.parts) and relative.as_posix() != "core/verdicts.py":
            yield relative.as_posix(), path.read_text(encoding="utf-8")


def _matches():
    found = set()
    for relative, source in _python_sources():
        for line in source.splitlines():
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if any(
                pattern.search(line)
                for pattern in (
                    SCORE_COMPARISON,
                    CLASSIFICATION_LITERAL,
                    LEVEL_LITERAL,
                    AGENT_LITERAL,
                )
            ):
                found.add((relative, stripped))
    return found


def test_no_python_producer_restates_a_band_or_a_verdict_word():
    unexplained = sorted(_matches() - set(ALLOWED))
    assert not unexplained, (
        "read these from core/verdicts.py, or allow them here with a reason: " + repr(unexplained)
    )


def test_every_allowed_line_still_exists():
    assert not set(ALLOWED) - _matches()


def test_the_scan_catches_a_restated_band():
    for line in (
        "if rug_prob >= 71:",
        "if rs >= 70:",
        "risk_score = data.get('risk_score', 0) >= 50",
        'classification = "SAFE"',
        "result['risk_level'] = 'HIGH'",
        'return PolicyVerdict(verdict="BLOCK")',
    ):
        assert any(
            pattern.search(line)
            for pattern in (SCORE_COMPARISON, CLASSIFICATION_LITERAL, LEVEL_LITERAL, AGENT_LITERAL)
        ), line


def _js_object_keys(source: str, name: str) -> set:
    body = re.search(r"const " + name + r" = \{(.*?)\};", source, re.S).group(1)
    return set(re.findall(r"^\s*(\w+):", body, re.M))


def test_extension_badges_cover_exactly_the_published_classifications():
    content = (ROOT / "extension" / "content.js").read_text(encoding="utf-8")
    popup = (ROOT / "extension" / "popup.js").read_text(encoding="utf-8")
    # The overlay adds its own Unknown badge for an incomplete scan.
    for name in ("badgeClasses", "classLabels"):
        assert _js_object_keys(content, name) == set(verdicts.CLASSIFICATIONS) | {
            verdicts.UNKNOWN
        }, name
    for name in ("MAP", "FEED_MAP", "FEED_LABELS", "CLS"):
        assert _js_object_keys(popup, name) == set(verdicts.CLASSIFICATIONS), name
    for source in (content, (ROOT / "extension" / "background.js").read_text(encoding="utf-8")):
        for listed in re.findall(
            r'\[("[A-Z_]+"(?:, "[A-Z_]+")*)\]\.includes\(result\.classification\)', source
        ):
            assert set(re.findall(r'"([A-Z_]+)"', listed)) <= set(verdicts.CLASSIFICATIONS)


def _ts_union(source: str, field: str) -> set:
    union = re.search(r"\b" + field + r": ('[A-Z_]+'(?: \| '[A-Z_]+')*);", source).group(1)
    return set(re.findall(r"'([A-Z_]+)'", union))


def test_sdk_vocabularies_match_the_published_ones():
    typescript = (ROOT / "sdk" / "src" / "index.ts").read_text(encoding="utf-8")
    assert _ts_union(typescript, "risk_level") == set(verdicts.RISK_LEVELS)
    assert _ts_union(typescript, "verdict") == set(verdicts.AGENT_VERDICTS)
    assert _ts_union(typescript, "classification") == set(verdicts.CLASSIFICATIONS)
    assert "classification: string" not in typescript
    interim = re.search(r"const FIRST_CLASSIFICATIONS[^=]*= \[([^\]]*)\]", typescript).group(1)
    assert set(re.findall(r"'([A-Z_]+)'", interim)) == set(verdicts.CLASSIFICATIONS) - {verdicts.SAFE}
    assert set(re.findall(r"verdict: '([A-Z_]+)'", typescript)) <= set(verdicts.AGENT_VERDICTS)
    models = (ROOT / "sdk" / "python" / "shieldbot" / "models.py").read_text(encoding="utf-8")
    documented = re.search(r'verdict: str  # ("[A-Z]+"(?: \| "[A-Z]+")*)', models).group(1)
    assert set(re.findall(r'"([A-Z]+)"', documented)) == set(verdicts.AGENT_VERDICTS)
    client = (ROOT / "sdk" / "python" / "shieldbot" / "client.py").read_text(encoding="utf-8")
    assert set(re.findall(r'verdict="([A-Z]+)"', client)) <= set(verdicts.AGENT_VERDICTS)


def test_agent_firewall_defaults_meet_the_written_down_mapping():
    engine = AgentPolicyEngine()
    reached = {classification: set() for classification in verdicts.CLASSIFICATIONS}
    for tenth in range(1001):
        score = tenth / 10
        decision = engine.evaluate(
            policy={},
            risk_score=score,
            target_address="0x" + "a" * 40,
            status="ok",
            coverage={"honeypot": 1},
        ).verdict
        classification = verdicts.classify(score)
        assert decision in verdicts.AGENT_DECISIONS_BY_CLASSIFICATION[classification], score
        reached[classification].add(decision)
    assert reached == {
        key: set(value) for key, value in verdicts.AGENT_DECISIONS_BY_CLASSIFICATION.items()
    }


@pytest.mark.asyncio
async def test_the_vocabulary_endpoint_publishes_the_module(monkeypatch):
    import api
    from core.calibration import CalibrationConfig

    monkeypatch.setattr(
        api,
        "container",
        SimpleNamespace(
            calibration=CalibrationConfig(high_threshold=81.0, medium_threshold=21.0),
            auth_manager=None,
            settings=SimpleNamespace(trusted_proxies=[]),
        ),
    )
    monkeypatch.setattr(api, "rate_limiter", api.RateLimiter(1000, 1000))
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=api.app), base_url="http://testserver"
    ) as client:
        body = (await client.get("/api/verdicts")).json()

    assert body["classifications"] == list(verdicts.CLASSIFICATIONS)
    assert body["risk_levels"] == list(verdicts.RISK_LEVELS)
    assert body["agent_verdicts"] == list(verdicts.AGENT_VERDICTS)
    assert body["bands"] == [
        {"classification": name, "min_score": low} for name, low in verdicts.BANDS
    ]
    assert body["signature_bands"] == [
        {"classification": name, "min_score": low} for name, low in verdicts.SIGNATURE_BANDS
    ]
    # The eth_sign floor is in the Block band of both tables.
    assert body["blind_sign_min"] == verdicts.BLIND_SIGN_MIN
    for bands in (verdicts.BANDS, verdicts.SIGNATURE_BANDS):
        assert verdicts.classify(body["blind_sign_min"], bands) == verdicts.BLOCK_RECOMMENDED
    # The stored level is raised to the band table's, so a calibrated threshold above it does not apply.
    assert body["risk_level_thresholds"] == {"HIGH": 71, "MEDIUM": 21.0}
    assert body["agent_firewall"]["decisions_by_classification"] == {
        key: list(value) for key, value in verdicts.AGENT_DECISIONS_BY_CLASSIFICATION.items()
    }
    assert body["strict_block_score"] == verdicts.STRICT_BLOCK_SCORE
    # The streamed firewall's interim verdict: Unknown, never SAFE, and never sent under STRICT.
    assert body["first_verdict"] == {
        "seconds": FIRST_VERDICT_SECONDS,
        "status": "unknown",
        "never": [verdicts.SAFE],
        "policy_modes": ["BALANCED"],
    }
