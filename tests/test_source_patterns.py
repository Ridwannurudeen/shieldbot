"""The source line names functions of the deployed contract, not words found anywhere in the published bundle."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from eth_utils import keccak

from services.contract_service import ContractService, canonical_type, live_source_patterns, source_files

# The shape of Interfold FOLD's verification bundle on Ethereum: a standard JSON input, every file
# the compiler read, wrapped in one more pair of braces as Etherscan's getsourcecode returns it. The
# token has no blacklist and no fee setter; "blacklist" is a comment in another contract's file and
# "setFee" is the prefix of an interface another contract implements.
OWNABLE = """
abstract contract Ownable is Context {
    /**
     * `onlyOwner`, which can be applied to your functions to restrict their use to the owner.
     */
    modifier onlyOwner() {
        _checkOwner();
        _;
    }

    function renounceOwnership() public virtual onlyOwner {
        _transferOwnership(address(0));
    }

    function transferOwnership(address newOwner) public virtual onlyOwner {
        _transferOwnership(newOwner);
    }
}
"""

ERC20 = """
abstract contract ERC20 is Context, IERC20 {
    /**
     * @dev Transfers a `value` amount of tokens from `from` to `to`, or alternatively mints (or burns).
     */
    function _mint(address account, uint256 value) internal {
        _update(address(0), account, value);
    }

    function totalSupply() public view virtual returns (uint256) {
        return _totalSupply;
    }
}
"""

INTERFOLD_INTERFACE = """
interface IInterfold {
    function setFeeToken(IERC20 _feeToken) external;

    function setFeeTokenAllowed(IERC20 token, bool allowed) external;
}
"""

TICKET_TOKEN = """
/**
 * @dev Risks:
 *      Underlying-blacklist risk: if the wrapped stablecoin (e.g. USDC, USDT) blacklists this
 *      contract, deposits and withdrawals that move the underlying will revert until the blacklist is cleared.
 */
contract InterfoldTicketToken is ERC20, Ownable2Step {
    function setRegistry(address newRegistry) external onlyOwner {
        registry = newRegistry;
    }
}
"""

TOKEN = """
contract InterfoldToken is ERC20, Ownable2Step, AccessControl {
    struct MintAllocation {
        address recipient;
        uint256 amount;
    }

    string private constant NOTICE = "function blacklist(address) is not part of this token";

    /// @notice Plain vanilla admin mint: FOLD with no lock attached.
    function mint(
        address recipient,
        uint256 amount,
        bytes32 label
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _mintTokens(recipient, amount);
    }

    function mintAllocations(
        MintAllocation[] calldata allocations
    ) external onlyRole(MINTER_ROLE) {
        _mintAllocation(allocations[0]);
    }

    /// @notice Sets the CCA auction/claim source exactly once.
    function setClaimSource(address claimSource) external onlyOwner {
        CLAIM_SOURCE = claimSource;
    }

    function renounceOwnership() public view override onlyOwner {
        revert RenounceOwnershipDisabled();
    }
}
"""

FOLD_FILES = {
    "npm/@openzeppelin/contracts@5.3.0/access/Ownable.sol": OWNABLE,
    "npm/@openzeppelin/contracts@5.3.0/token/ERC20/ERC20.sol": ERC20,
    "project/contracts/interfaces/IInterfold.sol": INTERFOLD_INTERFACE,
    "project/contracts/token/InterfoldTicketToken.sol": TICKET_TOKEN,
    "project/contracts/token/InterfoldToken.sol": TOKEN,
}

FOLD_LIVE = (
    "mint(address,uint256,bytes32)", "setClaimSource(address)", "totalSupply()",
    "renounceOwnership()", "transferOwnership(address)",
)


def _standard_json(files):
    sources = {path: {"content": text} for path, text in files.items()}
    return "{" + json.dumps({"language": "Solidity", "sources": sources, "settings": {}}) + "}"


def _selector(signature):
    return keccak(text=signature)[:4].hex()


def _bytecode(*signatures):
    return "0x60806040" + "".join("63" + _selector(signature) for signature in signatures)


async def _contract_data(source, *signatures, bytecode=None):
    web3_client = MagicMock()
    web3_client.is_contract = AsyncMock(return_value=True)
    web3_client.is_verified_contract = AsyncMock(return_value=(True, source))
    web3_client.get_contract_creation_info = AsyncMock(return_value={"age_days": 730})
    web3_client.get_ownership_info = AsyncMock(
        return_value={"owner": "0x" + "1" * 40, "is_renounced": False}
    )
    web3_client.get_bytecode = AsyncMock(return_value=bytecode or _bytecode(*signatures))
    scam_db = MagicMock()
    scam_db.check_address = AsyncMock(return_value=[])
    with patch("services.contract_service.BSCSCAN_DELAY", 0):
        return await ContractService(web3_client, scam_db).fetch_contract_data("0x" + "ab" * 20)


@pytest.mark.asyncio
async def test_fold_bundle_reports_the_deployed_token_only():
    data = await _contract_data(_standard_json(FOLD_FILES), *FOLD_LIVE)
    assert data["source_code_patterns"] == ["onlyOwner", "mint"]


def test_the_old_substring_scan_would_have_reported_the_other_files():
    bundle = _standard_json(FOLD_FILES)
    assert "blacklist" in bundle.lower() and "setfee" in bundle.lower()
    assert "blacklist" not in live_source_patterns(bundle, {_selector(s) for s in FOLD_LIVE})
    assert "setFee" not in live_source_patterns(bundle, {_selector(s) for s in FOLD_LIVE})


def test_another_contracts_function_counts_only_when_the_bytecode_dispatches_to_it():
    bundle = _standard_json(FOLD_FILES)
    assert live_source_patterns(bundle, {_selector("setRegistry(address)")}) == ["onlyOwner"]
    assert live_source_patterns(bundle, {_selector("setFeeToken(address)")}) == []


@pytest.mark.asyncio
async def test_a_genuine_pause_behind_only_owner_is_still_reported():
    source = OWNABLE + """
contract Token is ERC20, Ownable, Pausable {
    function pause() external onlyOwner {
        _pause();
    }

    function setFees(uint256 buy, uint256 sell) external onlyOwner {
        buyFee = buy;
        sellFee = sell;
    }
}
"""
    data = await _contract_data(source, "pause()", "setFees(uint256,uint256)", "renounceOwnership()")
    assert data["source_code_patterns"] == ["onlyOwner", "setFee", "pause"]
    assert data["has_pause"] is True


@pytest.mark.asyncio
async def test_a_declaration_in_a_comment_or_a_string_is_not_read():
    source = """
contract Token {
    // function pause() external onlyOwner { _pause(); }
    /* function setFee(uint256 fee) external onlyOwner { } */
    string constant HINT = "function mint(address to, uint256 amount) external onlyOwner";
    function totalSupply() public view returns (uint256) { return 0; }
}
"""
    data = await _contract_data(source, "pause()", "setFee(uint256)", "mint(address,uint256)", "totalSupply()")
    assert data["source_code_patterns"] == []
    assert data["bytecode_warnings"] == ["mint", "pause"]


@pytest.mark.parametrize(
    "signature,expected",
    [
        ("minTicketBalance()", []),
        ("isBlacklisted(address)", ["blacklist"]),
        ("setMaxTxAmount(uint256)", ["setMaxTx"]),
        ("mintAllocations(uint256)", ["mint"]),
        ("addBlacklist(address[])", ["blacklist", "addBlacklist"]),
    ],
)
def test_a_name_pattern_matches_as_written_or_capitalised_inside_the_name(signature, expected):
    name, _, types = signature.partition("(")
    params = ", ".join(f"{kind} p{i}" for i, kind in enumerate(types.rstrip(")").split(",")) if kind)
    source = f"contract Token {{ function {name}({params}) external {{ }} }}"
    assert live_source_patterns(source, {_selector(signature)}) == expected


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", [None, RuntimeError("rpc down")])
async def test_without_bytecode_nothing_is_attributed(failure):
    web3_client = MagicMock()
    web3_client.is_contract = AsyncMock(return_value=True)
    web3_client.is_verified_contract = AsyncMock(return_value=(True, OWNABLE))
    web3_client.get_contract_creation_info = AsyncMock(return_value={"age_days": 730})
    web3_client.get_ownership_info = AsyncMock(return_value={"owner": "0x" + "1" * 40, "is_renounced": False})
    web3_client.get_bytecode = AsyncMock(return_value=None, side_effect=failure)
    scam_db = MagicMock()
    scam_db.check_address = AsyncMock(return_value=[])
    with patch("services.contract_service.BSCSCAN_DELAY", 0):
        data = await ContractService(web3_client, scam_db).fetch_contract_data("0x" + "ab" * 20)
    assert data["source_code_patterns"] == []
    assert data["coverage"] == {"bytecode": False}


@pytest.mark.asyncio
async def test_an_unverified_contract_has_no_source_line():
    web3_client = MagicMock()
    web3_client.is_contract = AsyncMock(return_value=True)
    web3_client.is_verified_contract = AsyncMock(return_value=(False, None))
    web3_client.get_contract_creation_info = AsyncMock(return_value={"age_days": 730})
    web3_client.get_ownership_info = AsyncMock(return_value={"owner": "0x" + "1" * 40, "is_renounced": False})
    web3_client.get_bytecode = AsyncMock(return_value=_bytecode("pause()"))
    scam_db = MagicMock()
    scam_db.check_address = AsyncMock(return_value=[])
    with patch("services.contract_service.BSCSCAN_DELAY", 0):
        data = await ContractService(web3_client, scam_db).fetch_contract_data("0x" + "ab" * 20)
    assert data["source_code_patterns"] == []


def test_every_explorer_source_shape_yields_its_files():
    files = {"a.sol": "contract A {}", "b.sol": "contract B {}"}
    assert source_files(_standard_json(files)) == ["contract A {}", "contract B {}"]
    assert source_files(json.dumps({path: {"content": text} for path, text in files.items()})) == [
        "contract A {}", "contract B {}",
    ]
    assert source_files("contract A {}") == ["contract A {}"]
    assert source_files("{{not json") == ["{{not json"]
    assert source_files('{"a.sol": "no content key"}') == []


@pytest.mark.parametrize(
    "param,expected",
    [
        ("uint", "uint256"),
        ("int", "int256"),
        ("uint8 decimals_", "uint8"),
        ("address payable to", "address"),
        ("uint256[] calldata amounts", "uint256[]"),
        ("bytes32[2] memory pair", "bytes32[2]"),
        ("string memory label", "string"),
        ("bytes calldata data", "bytes"),
        ("bool allowed", "bool"),
        ("MintAllocation[] calldata allocations", None),
        ("IERC20 token", None),
        ("Phase phase", None),
        ("uint7 odd", None),
        ("uint264 wide", None),
        ("bytes33 long", None),
        ("bytes0 none", None),
        ("function(uint256) external f", None),
    ],
)
def test_only_elementary_parameter_types_are_resolved(param, expected):
    assert canonical_type(param) == expected
