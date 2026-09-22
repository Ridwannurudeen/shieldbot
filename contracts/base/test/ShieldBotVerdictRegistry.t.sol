// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test, Vm} from "forge-std/Test.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ShieldBotVerdictRegistry} from "../src/ShieldBotVerdictRegistry.sol";

contract ShieldBotVerdictRegistryTest is Test {
    ShieldBotVerdictRegistry registry;

    address owner = makeAddr("owner");
    address recorder = makeAddr("recorder");
    address newRecorder = makeAddr("newRecorder");
    address attacker = makeAddr("attacker");
    address subject = makeAddr("subject");
    bytes32 constant HASH = keccak256("evidence");

    event VerdictRecorded(
        address indexed subject,
        ShieldBotVerdictRegistry.Verdict indexed verdict,
        bytes32 indexed evidenceHash,
        uint64 observedBlock,
        uint64 timestamp
    );
    event RecorderUpdated(address indexed previousRecorder, address indexed newRecorder);

    function setUp() public {
        vm.prank(owner);
        registry = new ShieldBotVerdictRegistry(recorder);
    }

    function _entry(address s, ShieldBotVerdictRegistry.Verdict v, bytes32 h, uint64 b)
        internal
        pure
        returns (ShieldBotVerdictRegistry.Entry memory)
    {
        return ShieldBotVerdictRegistry.Entry({subject: s, verdict: v, evidenceHash: h, observedBlock: b});
    }

    function _entries(uint256 n) internal pure returns (ShieldBotVerdictRegistry.Entry[] memory entries) {
        entries = new ShieldBotVerdictRegistry.Entry[](n);
        for (uint64 i; i < n; ++i) {
            entries[i] =
                _entry(address(uint160(i + 1)), ShieldBotVerdictRegistry.Verdict.LOW, keccak256(abi.encode(i)), i);
        }
    }

    // ------------------------------------------------------------------
    // Construction and roles
    // ------------------------------------------------------------------

    function test_Constructor_SetsOwnerRecorderAndEmptyState() public view {
        assertEq(registry.owner(), owner);
        assertEq(registry.pendingOwner(), address(0));
        assertEq(registry.recorder(), recorder);
        assertEq(registry.totalRecords(), 0);
        assertEq(registry.MAX_BATCH(), 50);
    }

    function test_Constructor_EmitsRecorderUpdated() public {
        vm.expectEmit(true, true, false, false);
        emit RecorderUpdated(address(0), recorder);
        new ShieldBotVerdictRegistry(recorder);
    }

    function test_Constructor_RevertsOnZeroRecorder() public {
        vm.expectRevert(ShieldBotVerdictRegistry.ZeroAddress.selector);
        new ShieldBotVerdictRegistry(address(0));
    }

    function test_UnrecordedSubject_ReadsAsUnknownNeverLow() public view {
        ShieldBotVerdictRegistry.Record memory latest = registry.latestRecord(subject);
        assertEq(uint8(latest.verdict), uint8(ShieldBotVerdictRegistry.Verdict.UNKNOWN));
        assertEq(latest.evidenceHash, bytes32(0));
        assertEq(latest.observedBlock, 0);
        assertEq(latest.timestamp, 0);
        assertEq(registry.recordCount(subject), 0);
    }

    function test_SetRecorder_RotatesAccess() public {
        vm.expectEmit(true, true, false, false);
        emit RecorderUpdated(recorder, newRecorder);
        vm.prank(owner);
        registry.setRecorder(newRecorder);
        assertEq(registry.recorder(), newRecorder);

        vm.prank(recorder);
        vm.expectRevert(ShieldBotVerdictRegistry.NotRecorder.selector);
        registry.record(subject, ShieldBotVerdictRegistry.Verdict.LOW, HASH, 1);

        vm.prank(newRecorder);
        registry.record(subject, ShieldBotVerdictRegistry.Verdict.LOW, HASH, 1);
        assertEq(registry.totalRecords(), 1);
    }

    function test_SetRecorder_OnlyOwner() public {
        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, attacker));
        registry.setRecorder(attacker);
    }

    function test_SetRecorder_RecorderCannotRotateItself() public {
        vm.prank(recorder);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, recorder));
        registry.setRecorder(newRecorder);
    }

    function test_SetRecorder_RevertsOnZeroAddress() public {
        vm.prank(owner);
        vm.expectRevert(ShieldBotVerdictRegistry.ZeroAddress.selector);
        registry.setRecorder(address(0));
    }

    function test_OwnerIsNotARecorder() public {
        vm.prank(owner);
        vm.expectRevert(ShieldBotVerdictRegistry.NotRecorder.selector);
        registry.record(subject, ShieldBotVerdictRegistry.Verdict.LOW, HASH, 1);
    }

    function test_Ownable2Step_HandoverRequiresAcceptance() public {
        address newOwner = makeAddr("newOwner");
        vm.prank(owner);
        registry.transferOwnership(newOwner);

        // Nothing changes until the pending owner accepts.
        assertEq(registry.owner(), owner);
        assertEq(registry.pendingOwner(), newOwner);
        vm.prank(newOwner);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, newOwner));
        registry.setRecorder(newRecorder);

        // Only the pending owner can accept.
        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, attacker));
        registry.acceptOwnership();

        vm.prank(newOwner);
        registry.acceptOwnership();
        assertEq(registry.owner(), newOwner);
        assertEq(registry.pendingOwner(), address(0));

        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, owner));
        registry.setRecorder(newRecorder);

        vm.prank(newOwner);
        registry.setRecorder(newRecorder);
        assertEq(registry.recorder(), newRecorder);
    }

    function test_Ownable2Step_PendingTransferCanBeCancelled() public {
        address newOwner = makeAddr("newOwner");
        vm.startPrank(owner);
        registry.transferOwnership(newOwner);
        registry.transferOwnership(address(0));
        vm.stopPrank();

        vm.prank(newOwner);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, newOwner));
        registry.acceptOwnership();
        assertEq(registry.owner(), owner);
    }

    function test_RenounceOwnership_RevertsAndPreservesRecovery() public {
        address newOwner = makeAddr("newOwner");
        vm.startPrank(owner);
        registry.transferOwnership(newOwner);
        vm.expectRevert(ShieldBotVerdictRegistry.OwnershipRenunciationDisabled.selector);
        registry.renounceOwnership();
        assertEq(registry.owner(), owner);
        assertEq(registry.pendingOwner(), newOwner);
        registry.setRecorder(newRecorder);
        vm.stopPrank();
        assertEq(registry.recorder(), newRecorder);

        vm.startPrank(newOwner);
        registry.acceptOwnership();
        vm.expectRevert(ShieldBotVerdictRegistry.OwnershipRenunciationDisabled.selector);
        registry.renounceOwnership();
        registry.setRecorder(recorder);
        vm.stopPrank();
        assertEq(registry.owner(), newOwner);
        assertEq(registry.recorder(), recorder);
    }

    // ------------------------------------------------------------------
    // record()
    // ------------------------------------------------------------------

    function test_Record_StoresLatestAndCounts() public {
        vm.warp(1_800_000_000);
        vm.prank(recorder);
        registry.record(subject, ShieldBotVerdictRegistry.Verdict.HONEYPOT, HASH, 65_704_949);

        ShieldBotVerdictRegistry.Record memory latest = registry.latestRecord(subject);
        assertEq(uint8(latest.verdict), uint8(ShieldBotVerdictRegistry.Verdict.HONEYPOT));
        assertEq(latest.evidenceHash, HASH);
        assertEq(latest.observedBlock, 65_704_949);
        assertEq(latest.timestamp, 1_800_000_000);
        assertEq(registry.recordCount(subject), 1);
        assertEq(registry.totalRecords(), 1);
    }

    function test_Record_LatestIsOverwrittenAndCountsAccumulate() public {
        address other = makeAddr("other");
        vm.startPrank(recorder);
        registry.record(subject, ShieldBotVerdictRegistry.Verdict.UNKNOWN, keccak256("first"), 10);
        registry.record(subject, ShieldBotVerdictRegistry.Verdict.HIGH, keccak256("second"), 20);
        registry.record(other, ShieldBotVerdictRegistry.Verdict.LOW, keccak256("third"), 30);
        vm.stopPrank();

        ShieldBotVerdictRegistry.Record memory latest = registry.latestRecord(subject);
        assertEq(uint8(latest.verdict), uint8(ShieldBotVerdictRegistry.Verdict.HIGH));
        assertEq(latest.evidenceHash, keccak256("second"));
        assertEq(latest.observedBlock, 20);
        assertEq(registry.recordCount(subject), 2);
        assertEq(registry.recordCount(other), 1);
        assertEq(registry.totalRecords(), 3);
    }

    function test_Record_AcceptsEveryVerdictIncludingUnknown() public {
        vm.startPrank(recorder);
        for (uint8 v; v <= uint8(type(ShieldBotVerdictRegistry.Verdict).max); ++v) {
            registry.record(subject, ShieldBotVerdictRegistry.Verdict(v), HASH, v);
            assertEq(uint8(registry.latestRecord(subject).verdict), v);
        }
        vm.stopPrank();
        assertEq(registry.recordCount(subject), 5);
    }

    function test_Record_EmitsVerdictRecorded() public {
        vm.warp(1_800_000_123);
        vm.expectEmit(true, true, true, true, address(registry));
        emit VerdictRecorded(subject, ShieldBotVerdictRegistry.Verdict.MEDIUM, HASH, 42, 1_800_000_123);
        vm.prank(recorder);
        registry.record(subject, ShieldBotVerdictRegistry.Verdict.MEDIUM, HASH, 42);
    }

    /// Pins the raw log layout that off-chain verifiers and the Python publisher decode.
    function test_Record_EventLayout() public {
        vm.warp(1_800_000_456);
        vm.recordLogs();
        vm.prank(recorder);
        registry.record(subject, ShieldBotVerdictRegistry.Verdict.HONEYPOT, HASH, 7);

        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(logs.length, 1);
        assertEq(logs[0].emitter, address(registry));
        assertEq(logs[0].topics.length, 4);
        assertEq(logs[0].topics[0], keccak256("VerdictRecorded(address,uint8,bytes32,uint64,uint64)"));
        assertEq(logs[0].topics[1], bytes32(uint256(uint160(subject))));
        assertEq(logs[0].topics[2], bytes32(uint256(4)));
        assertEq(logs[0].topics[3], HASH);
        assertEq(logs[0].data, abi.encode(uint64(7), uint64(1_800_000_456)));
    }

    /// On Arbitrum chains block.number is the parent-chain block, so the recorder-supplied
    /// Robinhood Chain block is deliberately not compared with it.
    function test_Record_ObservedBlockIsNotBoundToBlockNumber() public {
        vm.roll(26_002_636);
        vm.prank(recorder);
        registry.record(subject, ShieldBotVerdictRegistry.Verdict.LOW, HASH, 65_704_949);
        assertEq(registry.latestRecord(subject).observedBlock, 65_704_949);
    }

    function test_Record_RevertsForNonRecorder() public {
        vm.prank(attacker);
        vm.expectRevert(ShieldBotVerdictRegistry.NotRecorder.selector);
        registry.record(subject, ShieldBotVerdictRegistry.Verdict.LOW, HASH, 1);
    }

    function test_Record_RevertsOnZeroSubject() public {
        vm.prank(recorder);
        vm.expectRevert(ShieldBotVerdictRegistry.ZeroAddress.selector);
        registry.record(address(0), ShieldBotVerdictRegistry.Verdict.LOW, HASH, 1);
    }

    function test_Record_RevertsOnZeroEvidenceHash() public {
        vm.prank(recorder);
        vm.expectRevert(ShieldBotVerdictRegistry.ZeroEvidenceHash.selector);
        registry.record(subject, ShieldBotVerdictRegistry.Verdict.LOW, bytes32(0), 1);
    }

    /// The ABI decoder rejects an out-of-range enum before the function body runs, with empty revert data.
    function test_Record_RejectsOutOfRangeVerdict() public {
        vm.startPrank(recorder);
        (bool ok, bytes memory ret) =
            address(registry).call(abi.encodeWithSelector(registry.record.selector, subject, uint8(5), HASH, uint64(1)));
        assertFalse(ok);
        assertEq(ret.length, 0);

        (ok,) = address(registry)
            .call(abi.encodeWithSelector(registry.record.selector, subject, uint8(4), HASH, uint64(1)));
        assertTrue(ok);
        vm.stopPrank();
        assertEq(registry.totalRecords(), 1);
    }

    function test_NoPayableEntryPoints() public {
        vm.deal(recorder, 1 ether);
        vm.startPrank(recorder);
        (bool ok,) = address(registry).call{value: 1}("");
        assertFalse(ok);
        (ok,) = address(registry).call{value: 1}(
            abi.encodeWithSelector(registry.record.selector, subject, uint8(1), HASH, uint64(1))
        );
        assertFalse(ok);
        vm.stopPrank();
        assertEq(address(registry).balance, 0);
        assertEq(registry.totalRecords(), 0);
    }

    function test_Runtime_HasNoExternalCallOrCreationOpcodes() public view {
        bytes memory code = address(registry).code;
        assertGt(code.length, 2);
        // Solidity appends CBOR metadata and its two-byte big-endian length after INVALID.
        uint256 metadataLength = (uint256(uint8(code[code.length - 2])) << 8) | uint8(code[code.length - 1]);
        assertGt(metadataLength, 0);
        assertLt(metadataLength + 2, code.length);
        uint256 executableLength = code.length - metadataLength - 2;
        assertEq(uint8(code[executableLength - 1]), 0xfe);
        assertEq(uint8(code[executableLength]), 0xa2);

        for (uint256 pc; pc < executableLength; ++pc) {
            uint8 opcode = uint8(code[pc]);
            // CALL, CALLCODE, DELEGATECALL, STATICCALL, CREATE, CREATE2 and SELFDESTRUCT.
            assertFalse(
                opcode == 0xf1 || opcode == 0xf2 || opcode == 0xf4 || opcode == 0xfa || opcode == 0xf0 || opcode == 0xf5
                    || opcode == 0xff,
                "Runtime contains an external-call, creation or selfdestruct opcode"
            );
            // PUSH1..PUSH32 operands are data, not instructions. PUSH0 has no operand.
            if (opcode >= 0x60 && opcode <= 0x7f) {
                pc += opcode - 0x5f;
                assertLt(pc, executableLength);
            }
        }
    }

    // ------------------------------------------------------------------
    // recordBatch()
    // ------------------------------------------------------------------

    function test_RecordBatch_RecordsEveryEntryInOrder() public {
        ShieldBotVerdictRegistry.Entry[] memory entries = new ShieldBotVerdictRegistry.Entry[](3);
        entries[0] = _entry(subject, ShieldBotVerdictRegistry.Verdict.UNKNOWN, keccak256("a"), 1);
        entries[1] = _entry(makeAddr("b"), ShieldBotVerdictRegistry.Verdict.HONEYPOT, keccak256("b"), 2);
        entries[2] = _entry(subject, ShieldBotVerdictRegistry.Verdict.MEDIUM, keccak256("c"), 3);

        vm.recordLogs();
        vm.prank(recorder);
        registry.recordBatch(entries);

        assertEq(vm.getRecordedLogs().length, 3);
        assertEq(registry.totalRecords(), 3);
        assertEq(registry.recordCount(subject), 2);
        assertEq(registry.recordCount(makeAddr("b")), 1);
        ShieldBotVerdictRegistry.Record memory latest = registry.latestRecord(subject);
        assertEq(uint8(latest.verdict), uint8(ShieldBotVerdictRegistry.Verdict.MEDIUM));
        assertEq(latest.evidenceHash, keccak256("c"));
    }

    function test_RecordBatch_EmitsOneEventPerEntry() public {
        vm.warp(1_800_000_789);
        ShieldBotVerdictRegistry.Entry[] memory entries = new ShieldBotVerdictRegistry.Entry[](2);
        entries[0] = _entry(subject, ShieldBotVerdictRegistry.Verdict.LOW, keccak256("a"), 11);
        entries[1] = _entry(makeAddr("b"), ShieldBotVerdictRegistry.Verdict.HIGH, keccak256("b"), 12);

        vm.expectEmit(true, true, true, true, address(registry));
        emit VerdictRecorded(subject, ShieldBotVerdictRegistry.Verdict.LOW, keccak256("a"), 11, 1_800_000_789);
        vm.expectEmit(true, true, true, true, address(registry));
        emit VerdictRecorded(makeAddr("b"), ShieldBotVerdictRegistry.Verdict.HIGH, keccak256("b"), 12, 1_800_000_789);
        vm.prank(recorder);
        registry.recordBatch(entries);
    }

    function test_RecordBatch_AcceptsMaxBatch() public {
        uint256 max = registry.MAX_BATCH();
        vm.prank(recorder);
        registry.recordBatch(_entries(max));
        assertEq(registry.totalRecords(), max);
    }

    function test_RecordBatch_RevertsAboveMaxBatch() public {
        uint256 max = registry.MAX_BATCH();
        vm.prank(recorder);
        vm.expectRevert(abi.encodeWithSelector(ShieldBotVerdictRegistry.BatchTooLarge.selector, max + 1, max));
        registry.recordBatch(_entries(max + 1));
    }

    function test_RecordBatch_RevertsOnEmptyBatch() public {
        vm.prank(recorder);
        vm.expectRevert(ShieldBotVerdictRegistry.EmptyBatch.selector);
        registry.recordBatch(new ShieldBotVerdictRegistry.Entry[](0));
    }

    function test_RecordBatch_RevertsForNonRecorder() public {
        ShieldBotVerdictRegistry.Entry[] memory entries = _entries(1);
        vm.prank(attacker);
        vm.expectRevert(ShieldBotVerdictRegistry.NotRecorder.selector);
        registry.recordBatch(entries);
    }

    function test_RecordBatch_RevertsAtomicallyOnZeroSubject() public {
        ShieldBotVerdictRegistry.Entry[] memory entries = _entries(3);
        entries[2].subject = address(0);
        vm.prank(recorder);
        vm.expectRevert(ShieldBotVerdictRegistry.ZeroAddress.selector);
        registry.recordBatch(entries);
        assertEq(registry.totalRecords(), 0);
        assertEq(registry.recordCount(entries[0].subject), 0);
    }

    function test_RecordBatch_RevertsAtomicallyOnZeroEvidenceHash() public {
        ShieldBotVerdictRegistry.Entry[] memory entries = _entries(3);
        entries[1].evidenceHash = bytes32(0);
        vm.prank(recorder);
        vm.expectRevert(ShieldBotVerdictRegistry.ZeroEvidenceHash.selector);
        registry.recordBatch(entries);
        assertEq(registry.totalRecords(), 0);
    }

    function test_RecordBatch_RejectsOutOfRangeVerdict() public {
        // recordBatch((address,uint8,bytes32,uint64)[]) with one entry whose verdict is 5.
        bytes memory data = abi.encodePacked(
            registry.recordBatch.selector, abi.encode(uint256(32), uint256(1), subject, uint256(5), HASH, uint256(1))
        );
        vm.prank(recorder);
        (bool ok, bytes memory ret) = address(registry).call(data);
        assertFalse(ok);
        assertEq(ret.length, 0);
        assertEq(registry.totalRecords(), 0);
    }

    // ------------------------------------------------------------------
    // Fuzz
    // ------------------------------------------------------------------

    function testFuzz_Record_StoresAnySubjectAndHash(
        address fuzzSubject,
        bytes32 evidenceHash,
        uint8 rawVerdict,
        uint64 observedBlock
    ) public {
        vm.assume(fuzzSubject != address(0) && evidenceHash != bytes32(0));
        ShieldBotVerdictRegistry.Verdict verdict = ShieldBotVerdictRegistry.Verdict(bound(rawVerdict, 0, 4));

        vm.expectEmit(true, true, true, true, address(registry));
        emit VerdictRecorded(fuzzSubject, verdict, evidenceHash, observedBlock, uint64(block.timestamp));
        vm.prank(recorder);
        registry.record(fuzzSubject, verdict, evidenceHash, observedBlock);

        ShieldBotVerdictRegistry.Record memory latest = registry.latestRecord(fuzzSubject);
        assertEq(uint8(latest.verdict), uint8(verdict));
        assertEq(latest.evidenceHash, evidenceHash);
        assertEq(latest.observedBlock, observedBlock);
        assertEq(registry.recordCount(fuzzSubject), 1);
        assertEq(registry.totalRecords(), 1);
    }

    function testFuzz_Record_RejectsZeroHashForAnySubject(address fuzzSubject) public {
        vm.assume(fuzzSubject != address(0));
        vm.prank(recorder);
        vm.expectRevert(ShieldBotVerdictRegistry.ZeroEvidenceHash.selector);
        registry.record(fuzzSubject, ShieldBotVerdictRegistry.Verdict.LOW, bytes32(0), 1);
    }

    function testFuzz_Record_RejectsZeroSubjectForAnyHash(bytes32 evidenceHash) public {
        vm.prank(recorder);
        vm.expectRevert(ShieldBotVerdictRegistry.ZeroAddress.selector);
        registry.record(address(0), ShieldBotVerdictRegistry.Verdict.LOW, evidenceHash, 1);
    }

    function testFuzz_Record_RejectsOutOfRangeVerdict(uint8 rawVerdict) public {
        rawVerdict = uint8(bound(rawVerdict, 5, type(uint8).max));
        vm.prank(recorder);
        (bool ok, bytes memory ret) = address(registry)
            .call(abi.encodeWithSelector(registry.record.selector, subject, rawVerdict, HASH, uint64(1)));
        assertFalse(ok);
        assertEq(ret.length, 0);
    }

    function testFuzz_Record_OnlyRecorder(address caller) public {
        vm.assume(caller != recorder);
        vm.prank(caller);
        vm.expectRevert(ShieldBotVerdictRegistry.NotRecorder.selector);
        registry.record(subject, ShieldBotVerdictRegistry.Verdict.LOW, HASH, 1);
    }

    function testFuzz_RecordBatch_CountsEveryEntry(uint8 rawLength, bytes32 seed) public {
        uint256 length = bound(rawLength, 1, registry.MAX_BATCH());
        ShieldBotVerdictRegistry.Entry[] memory entries = new ShieldBotVerdictRegistry.Entry[](length);
        for (uint64 i; i < length; ++i) {
            bytes32 h = keccak256(abi.encode(seed, i));
            // At most four distinct subjects, so repeats within a batch are exercised.
            entries[i] =
                _entry(address(uint160(uint256(h) % 4) + 1), ShieldBotVerdictRegistry.Verdict(uint8(h[0]) % 5), h, i);
        }
        vm.prank(recorder);
        registry.recordBatch(entries);

        assertEq(registry.totalRecords(), length);
        uint256 sum;
        for (uint160 s = 1; s <= 4; ++s) {
            sum += registry.recordCount(address(s));
        }
        assertEq(sum, length);
        ShieldBotVerdictRegistry.Entry memory last = entries[length - 1];
        assertEq(registry.latestRecord(last.subject).evidenceHash, last.evidenceHash);
    }
}
