// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {ShieldBotVerdictRegistry} from "../src/ShieldBotVerdictRegistry.sol";

contract VerdictRegistryHandler is Test {
    ShieldBotVerdictRegistry public registry;
    address recorder = address(0x100);
    mapping(address subject => uint256 count) public expectedCount;
    mapping(address subject => bytes32 evidenceHash) public expectedHash;

    constructor() {
        registry = new ShieldBotVerdictRegistry(recorder);
    }

    function record(uint8 subjectSeed, uint8 rawVerdict, bytes32 seed, uint64 observedBlock) external {
        address subject = address(uint160(subjectSeed % 8) + 1);
        bytes32 evidenceHash = bytes32(uint256(seed) | 1);
        vm.prank(recorder);
        registry.record(subject, ShieldBotVerdictRegistry.Verdict(rawVerdict % 5), evidenceHash, observedBlock);
        ++expectedCount[subject];
        expectedHash[subject] = evidenceHash;
    }

    function recordBatch(uint8 rawLength, bytes32 seed) external {
        uint256 length = bound(rawLength, 1, registry.MAX_BATCH());
        ShieldBotVerdictRegistry.Entry[] memory entries = new ShieldBotVerdictRegistry.Entry[](length);
        for (uint64 i; i < length; ++i) {
            bytes32 h = keccak256(abi.encode(seed, i));
            entries[i] = ShieldBotVerdictRegistry.Entry({
                subject: address(uint160(uint256(h) % 8) + 1),
                verdict: ShieldBotVerdictRegistry.Verdict(uint8(h[0]) % 5),
                evidenceHash: bytes32(uint256(h) | 1),
                observedBlock: i
            });
        }
        vm.prank(recorder);
        registry.recordBatch(entries);
        for (uint256 i; i < length; ++i) {
            ++expectedCount[entries[i].subject];
            expectedHash[entries[i].subject] = entries[i].evidenceHash;
        }
    }

    function rejectBatch(uint8 subjectSeed, bytes32 seed, bool zeroSubject) external {
        address subject = address(uint160(subjectSeed % 8) + 1);
        ShieldBotVerdictRegistry.Entry[] memory entries = new ShieldBotVerdictRegistry.Entry[](2);
        entries[0] = ShieldBotVerdictRegistry.Entry({
            subject: subject,
            verdict: ShieldBotVerdictRegistry.Verdict.HIGH,
            evidenceHash: bytes32(uint256(seed) | 1),
            observedBlock: 1
        });
        entries[1] = ShieldBotVerdictRegistry.Entry({
            subject: zeroSubject ? address(0) : subject,
            verdict: ShieldBotVerdictRegistry.Verdict.UNKNOWN,
            evidenceHash: zeroSubject ? bytes32(uint256(1)) : bytes32(0),
            observedBlock: 2
        });
        vm.prank(recorder);
        vm.expectRevert(
            zeroSubject
                ? ShieldBotVerdictRegistry.ZeroAddress.selector
                : ShieldBotVerdictRegistry.ZeroEvidenceHash.selector
        );
        registry.recordBatch(entries);
    }

    function rotateRecorder() external {
        address previousRecorder = recorder;
        recorder = recorder == address(0x100) ? address(0x101) : address(0x100);
        registry.setRecorder(recorder);
        vm.prank(previousRecorder);
        vm.expectRevert(ShieldBotVerdictRegistry.NotRecorder.selector);
        registry.record(address(1), ShieldBotVerdictRegistry.Verdict.LOW, bytes32(uint256(1)), 1);
    }
}

contract ShieldBotVerdictRegistryInvariantTest is Test {
    ShieldBotVerdictRegistry registry;
    VerdictRegistryHandler handler;

    function setUp() public {
        handler = new VerdictRegistryHandler();
        registry = handler.registry();
        bytes4[] memory selectors = new bytes4[](4);
        selectors[0] = VerdictRegistryHandler.record.selector;
        selectors[1] = VerdictRegistryHandler.recordBatch.selector;
        selectors[2] = VerdictRegistryHandler.rejectBatch.selector;
        selectors[3] = VerdictRegistryHandler.rotateRecorder.selector;
        targetContract(address(handler));
        targetSelector(FuzzSelector({addr: address(handler), selectors: selectors}));
    }

    /// forge-config: default.invariant.fail-on-revert = true
    function invariant_TotalRecordsEqualsSumOfSubjectCounts() public view {
        uint256 sum;
        for (uint160 i = 1; i <= 8; ++i) {
            uint256 count = registry.recordCount(address(i));
            assertEq(count, handler.expectedCount(address(i)));
            sum += count;
        }
        assertEq(registry.totalRecords(), sum);
    }

    /// forge-config: default.invariant.fail-on-revert = true
    function invariant_EvidenceExistsIfAndOnlyIfSubjectWasRecorded() public view {
        // Zero and address(9) are never recorded; both directions include untouched subjects.
        for (uint160 i; i <= 9; ++i) {
            bytes32 evidenceHash = registry.latestRecord(address(i)).evidenceHash;
            assertEq(evidenceHash != bytes32(0), registry.recordCount(address(i)) > 0);
            assertEq(evidenceHash, handler.expectedHash(address(i)));
        }
    }
}
