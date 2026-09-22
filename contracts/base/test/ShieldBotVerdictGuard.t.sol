// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {ShieldBotVerdictGuard} from "../src/ShieldBotVerdictGuard.sol";
import {ShieldBotVerdictRegistry} from "../src/ShieldBotVerdictRegistry.sol";

contract ShieldBotVerdictGuardTest is Test {
    ShieldBotVerdictRegistry registry;
    ShieldBotVerdictGuard guard;

    address subject = makeAddr("subject");
    bytes32 constant HASH = keccak256("evidence");
    uint64 constant PUBLISHED_AT = 1_800_000_000;
    uint64 constant MAX_AGE = 300;

    function setUp() public {
        vm.warp(PUBLISHED_AT);
        registry = new ShieldBotVerdictRegistry(address(this));
        guard = new ShieldBotVerdictGuard(address(registry));
    }

    function _assertDecision(address token, uint64 maxAge, ShieldBotVerdictGuard.Reason expected) internal {
        (bool allowed, uint8 reason) = guard.check(token, maxAge);
        assertEq(reason, uint8(expected));
        assertEq(allowed, expected == ShieldBotVerdictGuard.Reason.ALLOWED);
        if (!allowed) {
            vm.expectRevert(abi.encodeWithSelector(ShieldBotVerdictGuard.NotAllowed.selector, token, reason));
        }
        guard.requireAllowed(token, maxAge);
    }

    function test_Constructor_SetsRegistry() public view {
        assertEq(address(guard.registry()), address(registry));
    }

    function test_Constructor_RejectsZeroRegistry() public {
        vm.expectRevert(ShieldBotVerdictGuard.ZeroAddress.selector);
        new ShieldBotVerdictGuard(address(0));
    }

    function test_Check_AllVerdictsFresh() public {
        ShieldBotVerdictGuard.Reason[5] memory reasons = [
            ShieldBotVerdictGuard.Reason.UNKNOWN,
            ShieldBotVerdictGuard.Reason.ALLOWED,
            ShieldBotVerdictGuard.Reason.ALLOWED,
            ShieldBotVerdictGuard.Reason.HIGH,
            ShieldBotVerdictGuard.Reason.HONEYPOT
        ];
        for (uint8 v; v < 5; ++v) {
            vm.warp(PUBLISHED_AT);
            registry.record(subject, ShieldBotVerdictRegistry.Verdict(v), HASH, 69_634_858);
            vm.warp(PUBLISHED_AT + 100);
            _assertDecision(subject, MAX_AGE, reasons[v]);
        }
    }

    function test_Check_AllVerdictsExpired() public {
        ShieldBotVerdictGuard.Reason[5] memory reasons = [
            ShieldBotVerdictGuard.Reason.EXPIRED,
            ShieldBotVerdictGuard.Reason.EXPIRED,
            ShieldBotVerdictGuard.Reason.EXPIRED,
            ShieldBotVerdictGuard.Reason.HIGH,
            ShieldBotVerdictGuard.Reason.HONEYPOT
        ];
        for (uint8 v; v < 5; ++v) {
            vm.warp(PUBLISHED_AT);
            registry.record(subject, ShieldBotVerdictRegistry.Verdict(v), HASH, 69_634_858);
            vm.warp(PUBLISHED_AT + MAX_AGE + 1);
            _assertDecision(subject, MAX_AGE, reasons[v]);
        }
    }

    function test_Check_NoRecordDiffersFromRecordedUnknown() public {
        _assertDecision(subject, MAX_AGE, ShieldBotVerdictGuard.Reason.NO_RECORD);
        registry.record(subject, ShieldBotVerdictRegistry.Verdict.UNKNOWN, HASH, 0);
        _assertDecision(subject, MAX_AGE, ShieldBotVerdictGuard.Reason.UNKNOWN);
    }

    function test_Check_ZeroSubjectHasNoRecord() public {
        _assertDecision(address(0), MAX_AGE, ShieldBotVerdictGuard.Reason.NO_RECORD);
        _assertDecision(address(0), 0, ShieldBotVerdictGuard.Reason.NO_RECORD);
    }

    function test_Check_ExactExpiryBoundary() public {
        for (uint8 v = 1; v <= 2; ++v) {
            vm.warp(PUBLISHED_AT);
            registry.record(subject, ShieldBotVerdictRegistry.Verdict(v), HASH, 0);
            vm.warp(PUBLISHED_AT + MAX_AGE);
            _assertDecision(subject, MAX_AGE, ShieldBotVerdictGuard.Reason.ALLOWED);
            vm.warp(PUBLISHED_AT + MAX_AGE + 1);
            _assertDecision(subject, MAX_AGE, ShieldBotVerdictGuard.Reason.EXPIRED);
        }
    }

    function test_Check_FutureTimestampAllVerdicts() public {
        ShieldBotVerdictGuard.Reason[5] memory reasons = [
            ShieldBotVerdictGuard.Reason.FUTURE_TIMESTAMP,
            ShieldBotVerdictGuard.Reason.FUTURE_TIMESTAMP,
            ShieldBotVerdictGuard.Reason.FUTURE_TIMESTAMP,
            ShieldBotVerdictGuard.Reason.HIGH,
            ShieldBotVerdictGuard.Reason.HONEYPOT
        ];
        // Rewind the test clock after real publication to exercise an otherwise unreachable malformed age.
        for (uint8 v; v < 5; ++v) {
            vm.warp(PUBLISHED_AT);
            registry.record(subject, ShieldBotVerdictRegistry.Verdict(v), HASH, 0);
            vm.warp(PUBLISHED_AT - 1);
            _assertDecision(subject, type(uint64).max, reasons[v]);
            _assertDecision(subject, 0, reasons[v]);
        }
    }

    function test_Check_ZeroMaxAgeDeniesAllVerdictsWithAdversePrecedence() public {
        ShieldBotVerdictGuard.Reason[5] memory reasons = [
            ShieldBotVerdictGuard.Reason.EXPIRED,
            ShieldBotVerdictGuard.Reason.EXPIRED,
            ShieldBotVerdictGuard.Reason.EXPIRED,
            ShieldBotVerdictGuard.Reason.HIGH,
            ShieldBotVerdictGuard.Reason.HONEYPOT
        ];
        for (uint8 v; v < 5; ++v) {
            vm.warp(PUBLISHED_AT);
            registry.record(subject, ShieldBotVerdictRegistry.Verdict(v), HASH, 0);
            _assertDecision(subject, 0, reasons[v]);
            vm.warp(PUBLISHED_AT + 1);
            _assertDecision(subject, 0, reasons[v]);
        }
    }

    function test_Check_PublicationAtTimestampZeroIsRecorded() public {
        vm.warp(0);
        registry.record(subject, ShieldBotVerdictRegistry.Verdict.LOW, HASH, 0);
        _assertDecision(subject, 1, ShieldBotVerdictGuard.Reason.ALLOWED);
    }

    function test_Check_IgnoresBothBlockNumberDomains() public {
        vm.roll(26_032_864);
        registry.record(subject, ShieldBotVerdictRegistry.Verdict.LOW, HASH, 69_634_858);
        _assertDecision(subject, MAX_AGE, ShieldBotVerdictGuard.Reason.ALLOWED);
        vm.roll(type(uint64).max);
        _assertDecision(subject, MAX_AGE, ShieldBotVerdictGuard.Reason.ALLOWED);
        vm.warp(PUBLISHED_AT + MAX_AGE + 1);
        _assertDecision(subject, MAX_AGE, ShieldBotVerdictGuard.Reason.EXPIRED);
    }

    function test_Check_EachConsumerChoosesItsOwnAgeLimit() public {
        registry.record(subject, ShieldBotVerdictRegistry.Verdict.MEDIUM, HASH, 0);
        vm.warp(PUBLISHED_AT + 600);
        _assertDecision(subject, 300, ShieldBotVerdictGuard.Reason.EXPIRED);
        _assertDecision(subject, 600, ShieldBotVerdictGuard.Reason.ALLOWED);
    }

    function test_Check_UsesLatestPublication() public {
        registry.record(subject, ShieldBotVerdictRegistry.Verdict.LOW, HASH, 0);
        _assertDecision(subject, MAX_AGE, ShieldBotVerdictGuard.Reason.ALLOWED);
        registry.record(subject, ShieldBotVerdictRegistry.Verdict.HONEYPOT, keccak256("updated"), 0);
        _assertDecision(subject, MAX_AGE, ShieldBotVerdictGuard.Reason.HONEYPOT);
        vm.warp(PUBLISHED_AT + MAX_AGE + 1);
        registry.record(subject, ShieldBotVerdictRegistry.Verdict.MEDIUM, HASH, 0);
        _assertDecision(subject, MAX_AGE, ShieldBotVerdictGuard.Reason.ALLOWED);
    }

    function test_Check_OneRegistryReadAndNoStorageWrites() public {
        registry.record(subject, ShieldBotVerdictRegistry.Verdict.LOW, HASH, 0);
        vm.expectCall(address(registry), abi.encodeCall(registry.latestRecord, (subject)), uint64(1));
        vm.record();
        guard.check(subject, MAX_AGE);
        (bytes32[] memory reads, bytes32[] memory writes) = vm.accesses(address(registry));
        assertGt(reads.length, 0);
        assertEq(writes.length, 0);
        (reads, writes) = vm.accesses(address(guard));
        assertEq(reads.length, 0);
        assertEq(writes.length, 0);
    }

    function test_RequireAllowed_OneRegistryRead() public {
        registry.record(subject, ShieldBotVerdictRegistry.Verdict.MEDIUM, HASH, 0);
        vm.expectCall(address(registry), abi.encodeCall(registry.latestRecord, (subject)), uint64(1));
        guard.requireAllowed(subject, MAX_AGE);
    }

    function test_NoPayableEntryPoints() public {
        vm.deal(address(this), 3);
        (bool ok,) = address(guard).call{value: 1}("");
        assertFalse(ok);
        (ok,) = address(guard).call{value: 1}(abi.encodeCall(guard.check, (subject, MAX_AGE)));
        assertFalse(ok);
        (ok,) = address(guard).call{value: 1}(abi.encodeCall(guard.requireAllowed, (subject, MAX_AGE)));
        assertFalse(ok);
        assertEq(address(guard).balance, 0);
    }

    /// forge-config: default.fuzz.runs = 10000
    function testFuzz_Check_AllowedOnlyForFreshRecordedLowOrMedium(
        uint8 rawVerdict,
        uint64 age,
        uint64 maxAge,
        bool recorded,
        bool future
    ) public {
        ShieldBotVerdictRegistry.Verdict verdict = ShieldBotVerdictRegistry.Verdict(bound(rawVerdict, 0, 4));
        uint256 publishedAt = type(uint64).max;
        vm.warp(publishedAt);
        if (recorded) registry.record(subject, verdict, HASH, 69_634_858);
        vm.warp(future ? publishedAt - age : publishedAt + age);

        (bool allowed, uint8 reason) = guard.check(subject, maxAge);
        bool expected = recorded && (!future || age == 0) && maxAge != 0 && age <= maxAge
            && (verdict == ShieldBotVerdictRegistry.Verdict.LOW || verdict == ShieldBotVerdictRegistry.Verdict.MEDIUM);
        assertEq(allowed, expected);
        assertEq(reason == uint8(ShieldBotVerdictGuard.Reason.ALLOWED), expected);
        if (!allowed) {
            vm.expectRevert(abi.encodeWithSelector(ShieldBotVerdictGuard.NotAllowed.selector, subject, reason));
        }
        guard.requireAllowed(subject, maxAge);
    }

    function test_Gas_CheckColdAndWarmRegistry() public {
        registry.record(subject, ShieldBotVerdictRegistry.Verdict.LOW, HASH, 0);
        // Measure cold versus warm record slots with the registry account explicitly warm in both cases.
        vm.cool(address(registry));
        assertEq(registry.totalRecords(), 1);
        (bool coldAllowed,) = guard.check(subject, MAX_AGE);
        uint256 coldGas = vm.snapshotGasLastCall("check_cold_registry");
        (bool warmAllowed,) = guard.check(subject, MAX_AGE);
        uint256 warmGas = vm.snapshotGasLastCall("check_warm_registry");
        assertTrue(coldAllowed && warmAllowed);
        assertEq(coldGas - warmGas, 4_000);
        emit log_named_uint("check cold registry (callee gas)", coldGas);
        emit log_named_uint("check warm registry (callee gas)", warmGas);
    }
}
