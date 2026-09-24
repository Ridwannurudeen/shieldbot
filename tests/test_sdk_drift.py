"""The SDKs must not drift from the chain registry or from their own package metadata.

utils/chain_info.py is the chain registry the rest of the repository describes, and it must match the
chain adapters core/container.py registers, which decide the chains the API accepts. The TypeScript
SDK's SUPPORTED_CHAIN_IDS and the chain tables in both SDK READMEs must list exactly those chains, so
a chain added or removed there fails here until the SDKs follow.
"""

import re
import socket
from pathlib import Path

import pytest

from utils.chain_info import CHAIN_INFO

SDK = Path(__file__).resolve().parent.parent / "sdk"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_chain_registry_matches_the_adapters_the_api_registers(monkeypatch):
    from core.config import Settings
    from core.container import ServiceContainer

    def no_network(*args):
        raise AssertionError("building the container must not touch the network")

    monkeypatch.setattr(socket.socket, "connect", no_network)
    container = ServiceContainer(Settings(_env_file=None))
    assert set(container.web3_client.get_supported_chain_ids()) == set(CHAIN_INFO)


def test_typescript_sdk_chain_list_matches_the_registry():
    match = re.search(
        r"SUPPORTED_CHAIN_IDS = \[([\d,\s]+)\] as const;", read(SDK / "src" / "index.ts")
    )
    assert match, "sdk/src/index.ts should export SUPPORTED_CHAIN_IDS"
    chain_ids = [int(chain_id) for chain_id in match.group(1).split(",")]
    assert len(chain_ids) == len(set(chain_ids))
    assert set(chain_ids) == set(CHAIN_INFO)


@pytest.mark.parametrize(
    "readme", [SDK / "README.md", SDK / "python" / "README.md"], ids=["typescript", "python"]
)
def test_sdk_readme_chain_table_matches_the_registry(readme):
    rows = re.findall(r"^\| [^|\n]+ \| (\d+) \|$", read(readme), re.MULTILINE)
    assert len(rows) == len(set(rows))
    assert {int(chain_id) for chain_id in rows} == set(CHAIN_INFO)


def test_python_sdk_version_matches_its_package_metadata():
    from shieldbot import __version__

    assert f'version="{__version__}"' in read(SDK / "python" / "setup.py")
