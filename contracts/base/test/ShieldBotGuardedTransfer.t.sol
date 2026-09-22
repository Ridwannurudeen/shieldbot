// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test, Vm} from "forge-std/Test.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {IERC20Errors} from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {ShieldBotGuardedTransfer} from "../src/ShieldBotGuardedTransfer.sol";
import {ShieldBotVerdictGuard} from "../src/ShieldBotVerdictGuard.sol";
import {ShieldBotVerdictRegistry} from "../src/ShieldBotVerdictRegistry.sol";

contract TransferUSDG is ERC20 {
    constructor() ERC20("Mock USDG", "USDG") {}

    function mint(address account, uint256 amount) external {
        _mint(account, amount);
    }
}

contract ReentrantUSDG is TransferUSDG {
    ShieldBotGuardedTransfer target;
    bool public attempted;
    bool public reentered;
    bytes public rejection;
    uint256 public transferCalls;

    function arm(ShieldBotGuardedTransfer transferContract, uint256 amount) external {
        target = transferContract;
        _mint(address(this), amount);
        _approve(address(this), address(target), amount);
    }

    function transferFrom(address from, address to, uint256 amount) public override returns (bool) {
        ++transferCalls;
        super.transferFrom(from, to, amount);
        if (!attempted) {
            attempted = true;
            // Fund and approve the nested sender so only the reentrancy lock stops the second transfer.
            (reentered, rejection) = address(target).call(abi.encodeCall(target.transfer, (amount, uint64(300))));
        }
        return true;
    }
}

contract FeeUSDG is TransferUSDG {
    function transferFrom(address from, address to, uint256 amount) public override returns (bool) {
        super.transferFrom(from, to, amount);
        _burn(to, amount / 100);
        return true;
    }
}

contract BonusUSDG is TransferUSDG {
    function transferFrom(address from, address to, uint256 amount) public override returns (bool) {
        super.transferFrom(from, to, amount);
        _mint(to, 1);
        return true;
    }
}

contract FalseReturnUSDG is TransferUSDG {
    function transferFrom(address from, address to, uint256 amount) public override returns (bool) {
        super.transferFrom(from, to, amount);
        return false;
    }
}

contract NoReturnUSDG is TransferUSDG {
    function transferFrom(address from, address to, uint256 amount) public override returns (bool) {
        super.transferFrom(from, to, amount);
        assembly ("memory-safe") {
            return(0, 0)
        }
    }
}

contract ShieldBotGuardedTransferTest is Test {
    ShieldBotVerdictRegistry registry;
    ShieldBotVerdictGuard guard;
    ShieldBotGuardedTransfer guardedTransfer;
    TransferUSDG usdg;

    address subject = makeAddr("subject");
    address caller = makeAddr("caller");
    address recipient = makeAddr("recipient");
    bytes32 constant HASH = keccak256("evidence");
    uint64 constant PUBLISHED_AT = 1_800_000_000;
    uint64 constant MAX_AGE = 300;
    uint256 constant BALANCE = 1_000 ether;
    uint256 constant AMOUNT = 10 ether;

    function setUp() public {
        vm.warp(PUBLISHED_AT);
        registry = new ShieldBotVerdictRegistry(address(this));
        guard = new ShieldBotVerdictGuard(address(registry));
        usdg = new TransferUSDG();
        guardedTransfer = new ShieldBotGuardedTransfer(address(guard), subject, address(usdg), recipient);
        usdg.mint(caller, BALANCE);
        vm.prank(caller);
        usdg.approve(address(guardedTransfer), BALANCE);
    }

    function _assertDenied(ShieldBotVerdictGuard.Reason reason, uint64 maxAge) internal {
        // A reverted transfer would also restore balances. Zero calls proves the stronger ordering property.
        vm.expectCall(address(usdg), abi.encodeWithSelector(usdg.transferFrom.selector), uint64(0));
        vm.expectRevert(abi.encodeWithSelector(ShieldBotVerdictGuard.NotAllowed.selector, subject, uint8(reason)));
        vm.prank(caller);
        guardedTransfer.transfer(AMOUNT, maxAge);
        assertEq(usdg.balanceOf(caller), BALANCE);
        assertEq(usdg.balanceOf(recipient), 0);
        assertEq(usdg.balanceOf(address(guardedTransfer)), 0);
        assertEq(usdg.allowance(caller, address(guardedTransfer)), BALANCE);
    }

    function _assertAllowed(ShieldBotVerdictRegistry.Verdict verdict, uint64 age) internal {
        registry.record(subject, verdict, HASH, 0);
        vm.warp(PUBLISHED_AT + age);
        vm.expectCall(address(guard), abi.encodeCall(guard.requireAllowed, (subject, MAX_AGE)), uint64(1));
        vm.expectEmit(true, true, false, true, address(guardedTransfer));
        emit ShieldBotGuardedTransfer.GuardedTransfer(subject, caller, AMOUNT, MAX_AGE);
        vm.prank(caller);
        guardedTransfer.transfer(AMOUNT, MAX_AGE);
        assertEq(usdg.balanceOf(caller), BALANCE - AMOUNT);
        assertEq(usdg.balanceOf(recipient), AMOUNT);
        assertEq(usdg.balanceOf(address(guardedTransfer)), 0);
        assertEq(usdg.allowance(caller, address(guardedTransfer)), BALANCE - AMOUNT);
    }

    function test_Constructor_SetsImmutables() public view {
        assertEq(address(guardedTransfer.guard()), address(guard));
        assertEq(guardedTransfer.subject(), subject);
        assertEq(address(guardedTransfer.usdg()), address(usdg));
        assertEq(guardedTransfer.recipient(), recipient);
    }

    function test_Constructor_RejectsZeroGuard() public {
        vm.expectRevert(ShieldBotGuardedTransfer.ZeroAddress.selector);
        new ShieldBotGuardedTransfer(address(0), subject, address(usdg), recipient);
    }

    function test_Constructor_RejectsZeroSubject() public {
        vm.expectRevert(ShieldBotGuardedTransfer.ZeroAddress.selector);
        new ShieldBotGuardedTransfer(address(guard), address(0), address(usdg), recipient);
    }

    function test_Constructor_RejectsZeroUSDG() public {
        vm.expectRevert(ShieldBotGuardedTransfer.ZeroAddress.selector);
        new ShieldBotGuardedTransfer(address(guard), subject, address(0), recipient);
    }

    function test_Constructor_RejectsZeroRecipient() public {
        vm.expectRevert(ShieldBotGuardedTransfer.ZeroAddress.selector);
        new ShieldBotGuardedTransfer(address(guard), subject, address(usdg), address(0));
    }

    function test_Transfer_NoRecordDeniesBeforeTokenCall() public {
        _assertDenied(ShieldBotVerdictGuard.Reason.NO_RECORD, MAX_AGE);
    }

    function test_Transfer_UnknownDeniesBeforeTokenCall() public {
        registry.record(subject, ShieldBotVerdictRegistry.Verdict.UNKNOWN, HASH, 0);
        _assertDenied(ShieldBotVerdictGuard.Reason.UNKNOWN, MAX_AGE);
    }

    function test_Transfer_HighDeniesBeforeTokenCall() public {
        registry.record(subject, ShieldBotVerdictRegistry.Verdict.HIGH, HASH, 0);
        _assertDenied(ShieldBotVerdictGuard.Reason.HIGH, MAX_AGE);
    }

    function test_Transfer_HoneypotDeniesBeforeTokenCall() public {
        registry.record(subject, ShieldBotVerdictRegistry.Verdict.HONEYPOT, HASH, 0);
        _assertDenied(ShieldBotVerdictGuard.Reason.HONEYPOT, MAX_AGE);
    }

    function test_Transfer_ExpiredDeniesBeforeTokenCall() public {
        registry.record(subject, ShieldBotVerdictRegistry.Verdict.LOW, HASH, 0);
        vm.warp(PUBLISHED_AT + MAX_AGE + 1);
        _assertDenied(ShieldBotVerdictGuard.Reason.EXPIRED, MAX_AGE);
    }

    function test_Transfer_FutureTimestampDeniesBeforeTokenCall() public {
        registry.record(subject, ShieldBotVerdictRegistry.Verdict.LOW, HASH, 0);
        vm.warp(PUBLISHED_AT - 1);
        _assertDenied(ShieldBotVerdictGuard.Reason.FUTURE_TIMESTAMP, MAX_AGE);
    }

    function test_Transfer_ZeroMaxAgeDeniesBeforeTokenCall() public {
        registry.record(subject, ShieldBotVerdictRegistry.Verdict.LOW, HASH, 0);
        _assertDenied(ShieldBotVerdictGuard.Reason.EXPIRED, 0);
    }

    function test_Transfer_FreshLow() public {
        _assertAllowed(ShieldBotVerdictRegistry.Verdict.LOW, 100);
    }

    function test_Transfer_FreshMedium() public {
        _assertAllowed(ShieldBotVerdictRegistry.Verdict.MEDIUM, 100);
    }

    function test_Transfer_ExactExpiryBoundary() public {
        _assertAllowed(ShieldBotVerdictRegistry.Verdict.LOW, MAX_AGE);
    }

    function test_Transfer_ExactCreditWithExistingRecipientBalance() public {
        registry.record(subject, ShieldBotVerdictRegistry.Verdict.LOW, HASH, 0);
        usdg.mint(recipient, BALANCE);
        vm.expectEmit(true, true, false, true, address(guardedTransfer));
        emit ShieldBotGuardedTransfer.GuardedTransfer(subject, caller, AMOUNT, MAX_AGE);
        vm.prank(caller);
        guardedTransfer.transfer(AMOUNT, MAX_AGE);
        assertEq(usdg.balanceOf(caller), BALANCE - AMOUNT);
        assertEq(usdg.balanceOf(recipient), BALANCE + AMOUNT);
    }

    function test_Transfer_SelfTransferHasNoCreditAndReverts() public {
        ShieldBotGuardedTransfer target = new ShieldBotGuardedTransfer(address(guard), subject, address(usdg), caller);
        registry.record(subject, ShieldBotVerdictRegistry.Verdict.LOW, HASH, 0);
        vm.prank(caller);
        usdg.approve(address(target), AMOUNT);
        vm.expectRevert(abi.encodeWithSelector(ShieldBotGuardedTransfer.ShortDelivery.selector, AMOUNT, 0));
        vm.prank(caller);
        target.transfer(AMOUNT, MAX_AGE);
        assertEq(usdg.balanceOf(caller), BALANCE);
        assertEq(usdg.allowance(caller, address(target)), AMOUNT);
    }

    function test_Transfer_ZeroAmountBeforeGuardOrTokenCall() public {
        vm.expectCall(address(guard), abi.encodeWithSelector(guard.requireAllowed.selector), uint64(0));
        vm.expectCall(address(usdg), abi.encodeWithSelector(usdg.transferFrom.selector), uint64(0));
        vm.expectRevert(ShieldBotGuardedTransfer.ZeroAmount.selector);
        vm.prank(caller);
        guardedTransfer.transfer(0, MAX_AGE);
        assertEq(usdg.balanceOf(caller), BALANCE);
        assertEq(usdg.balanceOf(recipient), 0);
    }

    function test_Transfer_InsufficientBalanceIsAtomic() public {
        registry.record(subject, ShieldBotVerdictRegistry.Verdict.LOW, HASH, 0);
        vm.prank(caller);
        usdg.approve(address(guardedTransfer), BALANCE + 1);
        vm.expectRevert(
            abi.encodeWithSelector(IERC20Errors.ERC20InsufficientBalance.selector, caller, BALANCE, BALANCE + 1)
        );
        vm.prank(caller);
        guardedTransfer.transfer(BALANCE + 1, MAX_AGE);
        assertEq(usdg.balanceOf(caller), BALANCE);
        assertEq(usdg.balanceOf(recipient), 0);
        assertEq(usdg.balanceOf(address(guardedTransfer)), 0);
        assertEq(usdg.allowance(caller, address(guardedTransfer)), BALANCE + 1);
    }

    function test_Transfer_InsufficientAllowanceIsAtomic() public {
        registry.record(subject, ShieldBotVerdictRegistry.Verdict.LOW, HASH, 0);
        vm.prank(caller);
        usdg.approve(address(guardedTransfer), AMOUNT - 1);
        vm.expectRevert(
            abi.encodeWithSelector(
                IERC20Errors.ERC20InsufficientAllowance.selector, address(guardedTransfer), AMOUNT - 1, AMOUNT
            )
        );
        vm.prank(caller);
        guardedTransfer.transfer(AMOUNT, MAX_AGE);
        assertEq(usdg.balanceOf(caller), BALANCE);
        assertEq(usdg.balanceOf(recipient), 0);
        assertEq(usdg.balanceOf(address(guardedTransfer)), 0);
        assertEq(usdg.allowance(caller, address(guardedTransfer)), AMOUNT - 1);
    }

    function test_Transfer_CannotSpendAnotherCallersApprovalOrStrandedBalance() public {
        registry.record(subject, ShieldBotVerdictRegistry.Verdict.LOW, HASH, 0);
        usdg.mint(address(guardedTransfer), AMOUNT);
        address otherCaller = makeAddr("otherCaller");
        vm.expectRevert(
            abi.encodeWithSelector(
                IERC20Errors.ERC20InsufficientAllowance.selector, address(guardedTransfer), 0, AMOUNT
            )
        );
        vm.prank(otherCaller);
        guardedTransfer.transfer(AMOUNT, MAX_AGE);
        assertEq(usdg.balanceOf(caller), BALANCE);
        vm.prank(caller);
        guardedTransfer.transfer(AMOUNT, MAX_AGE);
        assertEq(usdg.balanceOf(caller), BALANCE - AMOUNT);
        assertEq(usdg.balanceOf(otherCaller), 0);
        assertEq(usdg.balanceOf(recipient), AMOUNT);
        assertEq(usdg.balanceOf(address(guardedTransfer)), AMOUNT);
    }

    function test_Transfer_ReentrancyBlockedWithoutDoubleTransferOrDrain() public {
        ReentrantUSDG malicious = new ReentrantUSDG();
        ShieldBotGuardedTransfer target =
            new ShieldBotGuardedTransfer(address(guard), subject, address(malicious), recipient);
        registry.record(subject, ShieldBotVerdictRegistry.Verdict.LOW, HASH, 0);
        malicious.mint(caller, BALANCE);
        malicious.mint(address(target), AMOUNT);
        malicious.arm(target, AMOUNT);
        vm.prank(caller);
        malicious.approve(address(target), BALANCE);
        vm.prank(caller);
        target.transfer(AMOUNT, MAX_AGE);
        assertTrue(malicious.attempted());
        assertFalse(malicious.reentered());
        assertEq(malicious.rejection(), abi.encodeWithSelector(ReentrancyGuard.ReentrancyGuardReentrantCall.selector));
        assertEq(malicious.transferCalls(), 1);
        assertEq(malicious.balanceOf(caller), BALANCE - AMOUNT);
        assertEq(malicious.balanceOf(recipient), AMOUNT);
        assertEq(malicious.balanceOf(address(target)), AMOUNT);
        assertEq(malicious.balanceOf(address(malicious)), AMOUNT);
        assertEq(malicious.allowance(caller, address(target)), BALANCE - AMOUNT);
    }

    function test_Transfer_FeeOnTransferRevertsWithoutCreditOrEvent() public {
        FeeUSDG feeToken = new FeeUSDG();
        ShieldBotGuardedTransfer target =
            new ShieldBotGuardedTransfer(address(guard), subject, address(feeToken), recipient);
        registry.record(subject, ShieldBotVerdictRegistry.Verdict.LOW, HASH, 0);
        feeToken.mint(caller, AMOUNT);
        feeToken.mint(recipient, BALANCE);
        vm.prank(caller);
        feeToken.approve(address(target), AMOUNT);
        vm.recordLogs();
        vm.expectRevert(
            abi.encodeWithSelector(ShieldBotGuardedTransfer.ShortDelivery.selector, AMOUNT, AMOUNT - AMOUNT / 100)
        );
        vm.prank(caller);
        target.transfer(AMOUNT, MAX_AGE);
        assertEq(feeToken.balanceOf(caller), AMOUNT);
        assertEq(feeToken.balanceOf(recipient), BALANCE);
        assertEq(feeToken.balanceOf(address(target)), 0);
        assertEq(feeToken.allowance(caller, address(target)), AMOUNT);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        for (uint256 i; i < logs.length; ++i) {
            assertNotEq(logs[i].emitter, address(target));
        }
    }

    function test_Transfer_ExcessCreditReverts() public {
        BonusUSDG bonusToken = new BonusUSDG();
        ShieldBotGuardedTransfer target =
            new ShieldBotGuardedTransfer(address(guard), subject, address(bonusToken), recipient);
        registry.record(subject, ShieldBotVerdictRegistry.Verdict.LOW, HASH, 0);
        bonusToken.mint(caller, AMOUNT);
        vm.prank(caller);
        bonusToken.approve(address(target), AMOUNT);
        vm.expectRevert(abi.encodeWithSelector(ShieldBotGuardedTransfer.ShortDelivery.selector, AMOUNT, AMOUNT + 1));
        vm.prank(caller);
        target.transfer(AMOUNT, MAX_AGE);
        assertEq(bonusToken.balanceOf(caller), AMOUNT);
        assertEq(bonusToken.balanceOf(recipient), 0);
        assertEq(bonusToken.allowance(caller, address(target)), AMOUNT);
    }

    function test_Transfer_FalseReturnRollsBackTokenMovement() public {
        FalseReturnUSDG falseToken = new FalseReturnUSDG();
        ShieldBotGuardedTransfer target =
            new ShieldBotGuardedTransfer(address(guard), subject, address(falseToken), recipient);
        registry.record(subject, ShieldBotVerdictRegistry.Verdict.LOW, HASH, 0);
        falseToken.mint(caller, AMOUNT);
        vm.prank(caller);
        falseToken.approve(address(target), AMOUNT);
        vm.expectRevert(abi.encodeWithSelector(SafeERC20.SafeERC20FailedOperation.selector, address(falseToken)));
        vm.prank(caller);
        target.transfer(AMOUNT, MAX_AGE);
        assertEq(falseToken.balanceOf(caller), AMOUNT);
        assertEq(falseToken.balanceOf(recipient), 0);
        assertEq(falseToken.allowance(caller, address(target)), AMOUNT);
    }

    function test_Transfer_NoReturnTokenAccepted() public {
        NoReturnUSDG noReturnToken = new NoReturnUSDG();
        ShieldBotGuardedTransfer target =
            new ShieldBotGuardedTransfer(address(guard), subject, address(noReturnToken), recipient);
        registry.record(subject, ShieldBotVerdictRegistry.Verdict.LOW, HASH, 0);
        noReturnToken.mint(caller, AMOUNT);
        vm.prank(caller);
        noReturnToken.approve(address(target), AMOUNT);
        vm.prank(caller);
        target.transfer(AMOUNT, MAX_AGE);
        assertEq(noReturnToken.balanceOf(caller), 0);
        assertEq(noReturnToken.balanceOf(recipient), AMOUNT);
        assertEq(noReturnToken.balanceOf(address(target)), 0);
    }

    function test_NoPayableEntryPointsOrFallback() public {
        vm.deal(address(this), 2);
        (bool ok,) = address(guardedTransfer).call{value: 1}("");
        assertFalse(ok);
        (ok,) = address(guardedTransfer).call{value: 1}(abi.encodeCall(guardedTransfer.transfer, (AMOUNT, MAX_AGE)));
        assertFalse(ok);
        (ok,) = address(guardedTransfer).call(hex"deadbeef");
        assertFalse(ok);
        assertEq(address(guardedTransfer).balance, 0);
    }

    /// forge-config: default.fuzz.runs = 10000
    function testFuzz_Transfer_MovesIfAndOnlyIfGuardAllows(
        uint8 rawVerdict,
        uint64 age,
        uint64 maxAge,
        uint256 amount,
        bool recorded,
        bool future
    ) public {
        ShieldBotVerdictRegistry.Verdict verdict = ShieldBotVerdictRegistry.Verdict(bound(rawVerdict, 0, 4));
        // The iff property requires a positive, funded, approved amount and an ordinary ERC-20.
        amount = bound(amount, 1, BALANCE);
        uint256 publishedAt = type(uint64).max;
        vm.warp(publishedAt);
        if (recorded) registry.record(subject, verdict, HASH, 0);
        vm.warp(future ? publishedAt - age : publishedAt + age);
        (bool allowed, uint8 reason) = guard.check(subject, maxAge);
        bool expected = recorded && (!future || age == 0) && maxAge != 0 && age <= maxAge
            && (verdict == ShieldBotVerdictRegistry.Verdict.LOW || verdict == ShieldBotVerdictRegistry.Verdict.MEDIUM);
        assertEq(allowed, expected);
        vm.expectCall(
            address(usdg), abi.encodeWithSelector(usdg.transferFrom.selector), allowed ? uint64(1) : uint64(0)
        );
        if (!allowed) {
            vm.expectRevert(abi.encodeWithSelector(ShieldBotVerdictGuard.NotAllowed.selector, subject, reason));
        }
        vm.prank(caller);
        guardedTransfer.transfer(amount, maxAge);
        assertEq(usdg.balanceOf(caller), allowed ? BALANCE - amount : BALANCE);
        assertEq(usdg.balanceOf(recipient), allowed ? amount : 0);
        assertEq(usdg.balanceOf(address(guardedTransfer)), 0);
        assertEq(usdg.allowance(caller, address(guardedTransfer)), allowed ? BALANCE - amount : BALANCE);
    }

    function test_Gas_PermittedTransferCold() public {
        registry.record(subject, ShieldBotVerdictRegistry.Verdict.LOW, HASH, 0);
        vm.cool(address(registry));
        vm.cool(address(guard));
        vm.cool(address(usdg));
        vm.cool(address(guardedTransfer));
        vm.prank(caller);
        guardedTransfer.transfer(AMOUNT, MAX_AGE);
        uint256 used = vm.snapshotGasLastCall("transfer_low_cold");
        assertEq(usdg.balanceOf(recipient), AMOUNT);
        emit log_named_uint("permitted LOW transfer (cold callee gas)", used);
    }
}
