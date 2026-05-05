// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {ShieldBotAttestor} from "../src/ShieldBotAttestor.sol";
import {EAS} from "@eas/EAS.sol";
import {SchemaRegistry} from "@eas/SchemaRegistry.sol";
import {ISchemaRegistry} from "@eas/ISchemaRegistry.sol";
import {ISchemaResolver} from "@eas/resolver/ISchemaResolver.sol";

contract ShieldBotAttestorTest is Test {
    string constant SCHEMA =
        "address scannedAddress,uint8 riskLevel,string scanType,uint64 sourceChainId,bytes32 evidenceHash,string evidenceURI";

    SchemaRegistry registry;
    EAS eas;
    ShieldBotAttestor attestor;
    bytes32 schemaUID;

    address owner = makeAddr("owner");
    address verifier = makeAddr("verifier");
    address otherVerifier = makeAddr("otherVerifier");
    address scanned = makeAddr("scanned");
    address attacker = makeAddr("attacker");

    function setUp() public {
        registry = new SchemaRegistry();
        eas = new EAS(ISchemaRegistry(address(registry)));
        schemaUID = registry.register(SCHEMA, ISchemaResolver(address(0)), true);

        vm.prank(owner);
        attestor = new ShieldBotAttestor(address(eas), schemaUID, verifier);
    }

    function test_Constructor_SetsImmutables() public view {
        assertEq(address(attestor.eas()), address(eas));
        assertEq(attestor.schemaUID(), schemaUID);
        assertEq(attestor.owner(), owner);
        assertTrue(attestor.verifiers(verifier));
    }

    function test_Constructor_RevertsOnZeroEAS() public {
        vm.expectRevert(ShieldBotAttestor.InvalidAddress.selector);
        new ShieldBotAttestor(address(0), schemaUID, verifier);
    }

    function test_Constructor_RevertsOnZeroSchema() public {
        vm.expectRevert(ShieldBotAttestor.InvalidAddress.selector);
        new ShieldBotAttestor(address(eas), bytes32(0), verifier);
    }

    function test_Constructor_RevertsOnZeroVerifier() public {
        vm.expectRevert(ShieldBotAttestor.InvalidAddress.selector);
        new ShieldBotAttestor(address(eas), schemaUID, address(0));
    }

    function test_Attest_PostsToEAS() public {
        vm.prank(verifier);
        bytes32 uid = attestor.attest(scanned, 5, "contract", 56, keccak256("evidence"), "ipfs://Qm...");

        assertTrue(uid != bytes32(0));
        assertEq(attestor.totalAttestations(), 1);
        assertEq(attestor.uniqueAddressCount(), 1);
        assertEq(attestor.attestationCount(scanned), 1);

        // EAS should hold the attestation
        assertEq(eas.getAttestation(uid).recipient, scanned);
        assertEq(eas.getAttestation(uid).attester, address(attestor));
        assertEq(eas.getAttestation(uid).schema, schemaUID);
    }

    function test_Attest_RevertsForNonVerifier() public {
        vm.prank(attacker);
        vm.expectRevert(ShieldBotAttestor.NotVerifier.selector);
        attestor.attest(scanned, 5, "contract", 56, keccak256("evidence"), "ipfs://Qm...");
    }

    function test_Attest_RevertsForZeroAddress() public {
        vm.prank(verifier);
        vm.expectRevert(ShieldBotAttestor.InvalidAddress.selector);
        attestor.attest(address(0), 5, "contract", 56, keccak256("evidence"), "ipfs://Qm...");
    }

    function test_Attest_RevertsForInvalidRiskLevel() public {
        vm.prank(verifier);
        vm.expectRevert(ShieldBotAttestor.InvalidRiskLevel.selector);
        attestor.attest(scanned, 6, "contract", 56, keccak256("evidence"), "ipfs://Qm...");
    }

    function test_Attest_DecodesDataRoundtrip() public {
        vm.prank(verifier);
        bytes32 uid = attestor.attest(scanned, 2, "token", 8453, keccak256("evidence"), "https://shieldbot.io/r/1");

        bytes memory data = eas.getAttestation(uid).data;
        (address dScanned, uint8 dRisk, string memory dType, uint64 dChain, bytes32 dHash, string memory dURI) =
            abi.decode(data, (address, uint8, string, uint64, bytes32, string));

        assertEq(dScanned, scanned);
        assertEq(dRisk, 2);
        assertEq(dType, "token");
        assertEq(dChain, 8453);
        assertEq(dHash, keccak256("evidence"));
        assertEq(dURI, "https://shieldbot.io/r/1");
    }

    function test_Attest_UniqueCountTracksDistinct() public {
        vm.startPrank(verifier);
        attestor.attest(scanned, 5, "contract", 56, keccak256("e1"), "u1");
        attestor.attest(scanned, 4, "contract", 56, keccak256("e2"), "u2");
        attestor.attest(makeAddr("scanned2"), 3, "token", 8453, keccak256("e3"), "u3");
        vm.stopPrank();

        assertEq(attestor.totalAttestations(), 3);
        assertEq(attestor.uniqueAddressCount(), 2);
        assertEq(attestor.attestationCount(scanned), 2);
    }

    function test_Revoke_OnlyVerifier() public {
        vm.prank(verifier);
        bytes32 uid = attestor.attest(scanned, 5, "contract", 56, keccak256("e"), "u");

        vm.prank(attacker);
        vm.expectRevert(ShieldBotAttestor.NotVerifier.selector);
        attestor.revoke(uid);
    }

    function test_Revoke_Succeeds() public {
        vm.prank(verifier);
        bytes32 uid = attestor.attest(scanned, 5, "contract", 56, keccak256("e"), "u");

        assertEq(eas.getAttestation(uid).revocationTime, 0);

        vm.prank(verifier);
        attestor.revoke(uid);

        assertGt(eas.getAttestation(uid).revocationTime, 0);
    }

    function test_SetVerifier_OnlyOwner() public {
        vm.prank(attacker);
        vm.expectRevert();
        attestor.setVerifier(otherVerifier, true);
    }

    function test_SetVerifier_AddsAndRemoves() public {
        vm.prank(owner);
        attestor.setVerifier(otherVerifier, true);
        assertTrue(attestor.verifiers(otherVerifier));

        vm.prank(otherVerifier);
        bytes32 uid = attestor.attest(scanned, 5, "contract", 56, keccak256("e"), "u");
        assertTrue(uid != bytes32(0));

        vm.prank(owner);
        attestor.setVerifier(otherVerifier, false);
        assertFalse(attestor.verifiers(otherVerifier));

        vm.prank(otherVerifier);
        vm.expectRevert(ShieldBotAttestor.NotVerifier.selector);
        attestor.attest(scanned, 5, "contract", 56, keccak256("e"), "u");
    }

    function test_SetVerifier_RevertsZeroAddress() public {
        vm.prank(owner);
        vm.expectRevert(ShieldBotAttestor.InvalidAddress.selector);
        attestor.setVerifier(address(0), true);
    }

    function test_GetStats() public {
        vm.startPrank(verifier);
        attestor.attest(scanned, 5, "contract", 56, keccak256("e1"), "u1");
        attestor.attest(makeAddr("a2"), 3, "token", 8453, keccak256("e2"), "u2");
        vm.stopPrank();

        (uint256 total, uint256 unique) = attestor.getStats();
        assertEq(total, 2);
        assertEq(unique, 2);
    }

    function testFuzz_Attest_AcceptsAllValidRiskLevels(uint8 risk) public {
        risk = uint8(bound(uint256(risk), 0, 5));
        vm.prank(verifier);
        bytes32 uid = attestor.attest(scanned, risk, "contract", 56, keccak256("e"), "u");
        assertTrue(uid != bytes32(0));
    }

    function testFuzz_Attest_RejectsInvalidRiskLevels(uint8 risk) public {
        vm.assume(risk > 5);
        vm.prank(verifier);
        vm.expectRevert(ShieldBotAttestor.InvalidRiskLevel.selector);
        attestor.attest(scanned, risk, "contract", 56, keccak256("e"), "u");
    }

    function test_Attest_RevertsOnLongScanType() public {
        bytes memory tooLong = new bytes(33);
        for (uint256 i; i < tooLong.length; ++i) {
            tooLong[i] = "a";
        }
        vm.prank(verifier);
        vm.expectRevert(ShieldBotAttestor.ScanTypeTooLong.selector);
        attestor.attest(scanned, 5, string(tooLong), 56, keccak256("e"), "u");
    }

    function test_Attest_RevertsOnLongEvidenceURI() public {
        bytes memory tooLong = new bytes(257);
        for (uint256 i; i < tooLong.length; ++i) {
            tooLong[i] = "a";
        }
        vm.prank(verifier);
        vm.expectRevert(ShieldBotAttestor.EvidenceURITooLong.selector);
        attestor.attest(scanned, 5, "contract", 56, keccak256("e"), string(tooLong));
    }

    function test_Attest_AcceptsBoundaryLengths() public {
        bytes memory scan32 = new bytes(32);
        bytes memory uri256 = new bytes(256);
        for (uint256 i; i < 32; ++i) {
            scan32[i] = "x";
        }
        for (uint256 i; i < 256; ++i) {
            uri256[i] = "y";
        }
        vm.prank(verifier);
        bytes32 uid = attestor.attest(scanned, 5, string(scan32), 56, keccak256("e"), string(uri256));
        assertTrue(uid != bytes32(0));
    }

    function test_Ownable2Step_TransferRequiresAcceptance() public {
        address newOwner = makeAddr("newOwner");
        vm.prank(owner);
        attestor.transferOwnership(newOwner);

        // Ownership has NOT changed yet — pending acceptance.
        assertEq(attestor.owner(), owner);
        assertEq(attestor.pendingOwner(), newOwner);

        vm.prank(newOwner);
        attestor.acceptOwnership();
        assertEq(attestor.owner(), newOwner);
        assertEq(attestor.pendingOwner(), address(0));
    }
}
