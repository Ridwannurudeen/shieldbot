// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {IEAS, AttestationRequest, AttestationRequestData, RevocationRequest, RevocationRequestData} from "@eas/IEAS.sol";

/// @title ShieldBotAttestor
/// @notice Posts ShieldBot threat-scan attestations to the Ethereum Attestation Service on Base.
/// @dev Schema UID and EAS contract are immutable after deploy. Only authorized verifier wallets can attest or revoke.
contract ShieldBotAttestor is Ownable {
    IEAS public immutable eas;
    bytes32 public immutable schemaUID;

    mapping(address verifier => bool authorized) public verifiers;
    mapping(address scannedAddress => uint256 count) public attestationCount;

    uint256 public totalAttestations;
    uint256 public uniqueAddressCount;

    error InvalidAddress();
    error InvalidRiskLevel();
    error NotVerifier();
    error LengthMismatch();
    error EmptyBatch();

    event AttestationPosted(
        address indexed scannedAddress,
        uint8 riskLevel,
        string scanType,
        uint64 sourceChainId,
        bytes32 attestationUID,
        address indexed attester
    );
    event AttestationRevoked(bytes32 indexed attestationUID, address indexed revoker);
    event VerifierUpdated(address indexed verifier, bool authorized);

    modifier onlyVerifier() {
        if (!verifiers[msg.sender]) revert NotVerifier();
        _;
    }

    constructor(address _eas, bytes32 _schemaUID, address _initialVerifier) Ownable(msg.sender) {
        if (_eas == address(0) || _initialVerifier == address(0)) revert InvalidAddress();
        if (_schemaUID == bytes32(0)) revert InvalidAddress();
        eas = IEAS(_eas);
        schemaUID = _schemaUID;
        verifiers[_initialVerifier] = true;
        emit VerifierUpdated(_initialVerifier, true);
    }

    /// @notice Post a single threat attestation to EAS.
    /// @param scannedAddress The address being attested about (recipient on EAS).
    /// @param riskLevel 0=LOW, 1=MEDIUM, 2=HIGH, 3=SAFE, 4=WARNING, 5=DANGER.
    /// @param scanType e.g. "contract", "token", "approval", "deployer".
    /// @param sourceChainId Chain ID where the scanned address lives (cross-chain attestations).
    /// @param evidenceHash keccak256 of the off-chain detailed report.
    /// @param evidenceURI Pointer to the off-chain detailed report (ipfs:// or https://).
    /// @return uid The EAS attestation UID.
    function attest(
        address scannedAddress,
        uint8 riskLevel,
        string calldata scanType,
        uint64 sourceChainId,
        bytes32 evidenceHash,
        string calldata evidenceURI
    ) external onlyVerifier returns (bytes32 uid) {
        if (scannedAddress == address(0)) revert InvalidAddress();
        if (riskLevel > 5) revert InvalidRiskLevel();

        uid = eas.attest(
            AttestationRequest({
                schema: schemaUID,
                data: AttestationRequestData({
                    recipient: scannedAddress,
                    expirationTime: 0,
                    revocable: true,
                    refUID: bytes32(0),
                    data: abi.encode(scannedAddress, riskLevel, scanType, sourceChainId, evidenceHash, evidenceURI),
                    value: 0
                })
            })
        );

        if (attestationCount[scannedAddress] == 0) {
            unchecked {
                ++uniqueAddressCount;
            }
        }
        unchecked {
            ++attestationCount[scannedAddress];
            ++totalAttestations;
        }

        emit AttestationPosted(scannedAddress, riskLevel, scanType, sourceChainId, uid, msg.sender);
    }

    /// @notice Revoke a previously-posted attestation. Used for false-positive correction.
    function revoke(bytes32 attestationUID) external onlyVerifier {
        eas.revoke(
            RevocationRequest({
                schema: schemaUID,
                data: RevocationRequestData({uid: attestationUID, value: 0})
            })
        );
        emit AttestationRevoked(attestationUID, msg.sender);
    }

    function setVerifier(address verifier, bool authorized) external onlyOwner {
        if (verifier == address(0)) revert InvalidAddress();
        verifiers[verifier] = authorized;
        emit VerifierUpdated(verifier, authorized);
    }

    function getStats() external view returns (uint256 total, uint256 uniqueAddresses) {
        return (totalAttestations, uniqueAddressCount);
    }
}
