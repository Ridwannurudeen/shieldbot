"""scripts/check_botchain_registry_code passes only when both chains run the built code and Sourcify
holds the Robinhood Chain copy as an exact match; the site and the deployment record name that check."""

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from scripts import check_botchain_registry_code as check

ROOT = Path(__file__).resolve().parent.parent
BUILT = "6080604052"
EXACT = {"creationMatch": "exact_match", "runtimeMatch": "exact_match"}


@pytest.fixture
def run(monkeypatch, tmp_path, capsys):
    artifact = tmp_path / "ShieldBotVerdictRegistry.json"
    artifact.write_text(
        json.dumps({"deployedBytecode": {"object": "0x" + BUILT}}), encoding="utf-8"
    )
    monkeypatch.setattr(check, "ARTIFACT", artifact)

    def run(codes, sourcify, rpc_chain_ids=(677, 4663)):
        for adapter_class, code, rpc_chain_id in zip(
            (check.BotChainAdapter, check.RobinhoodAdapter), codes, rpc_chain_ids
        ):
            adapter = MagicMock(chain_id=adapter_class().chain_id)
            adapter.w3.eth.get_code.return_value = bytes.fromhex(code)
            adapter.w3.eth.chain_id = rpc_chain_id
            monkeypatch.setattr(
                check, adapter_class.__name__, lambda adapter=adapter: adapter
            )
        monkeypatch.setattr(
            check.requests, "get", lambda url, timeout: MagicMock(json=lambda: sourcify)
        )
        status = check.main()
        return status, json.loads(capsys.readouterr().out)

    return run


def test_both_chains_running_the_build_and_an_exact_sourcify_match_pass(run):
    status, report = run((BUILT, BUILT), EXACT)
    assert status == 0
    assert [chain["chain_id"] for chain in report["chains"]] == [677, 4663]
    assert all(chain["matches_build"] for chain in report["chains"])


@pytest.mark.parametrize(
    "codes, sourcify",
    [
        ((BUILT + "00", BUILT), EXACT),
        ((BUILT, ""), EXACT),
        ((BUILT, BUILT), {"creationMatch": "match", "runtimeMatch": "exact_match"}),
        ((BUILT, BUILT), {"error": "not found"}),
    ],
    ids=[
        "other-code-on-677",
        "no-code-on-4663",
        "partial-sourcify-match",
        "not-on-sourcify",
    ],
)
def test_any_difference_fails(run, codes, sourcify):
    assert run(codes, sourcify)[0] == 1


def test_an_rpc_answering_for_another_chain_fails(run):
    assert run((BUILT, BUILT), EXACT, rpc_chain_ids=(4663, 4663))[0] == 1


def test_the_site_and_the_deployment_record_name_the_check():
    sourcify = f"https://sourcify.dev/server/v2/contract/4663/{check.REGISTRY}"
    assert check.SOURCIFY_URL == sourcify
    for path in (ROOT / "landing-src/public/about.html", ROOT / "docs/DEPLOYMENTS.md"):
        text = path.read_text(encoding="utf-8")
        assert (
            sourcify in text
            and "python -m scripts.check_botchain_registry_code" in text
        ), path.name
    assert (ROOT / "landing/about.html").read_bytes() == (
        ROOT / "landing-src/public/about.html"
    ).read_bytes()
