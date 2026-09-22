// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IERC20, SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {ShieldBotVerdictGuard} from "./ShieldBotVerdictGuard.sol";

/// @title ShieldBotGuardedTransfer
/// @notice Move the caller's USDG to a pinned recipient only when the pinned subject's verdict is allowed.
/// @dev Allowed means a recorded LOW or MEDIUM verdict at the time of this transaction, with publication age
///      within the caller's tolerance. It does not mean the subject token is safe. Trusts the pinned guard,
///      its registry/recorder and the pinned USDG implementation. No custody or recovery of unsolicited funds.
contract ShieldBotGuardedTransfer is ReentrancyGuard {
    using SafeERC20 for IERC20;

    ShieldBotVerdictGuard public immutable guard;
    address public immutable subject;
    IERC20 public immutable usdg;
    address public immutable recipient;

    /// @notice A pinned address is zero.
    error ZeroAddress();
    /// @notice Transfers must request a positive amount.
    error ZeroAmount();
    /// @notice The recipient's credit did not equal the requested amount; a balance decrease reports zero delivered.
    error ShortDelivery(uint256 requested, uint256 delivered);

    /// @notice The guard allowed the subject and the recipient was credited exactly the requested amount.
    /// @param amount Token units requested and credited to the recipient.
    /// @param maxAge The caller's satisfied publication-age tolerance in seconds.
    event GuardedTransfer(address indexed subject, address indexed caller, uint256 amount, uint64 maxAge);

    /// @param guardAddress The trusted verdict guard, fixed for this contract's lifetime.
    /// @param subjectToken The token whose verdict gates transfers; it need not be USDG.
    /// @param usdgAddress The USDG token on this chain.
    /// @param recipientAddress The sole destination for callers' transfers.
    constructor(address guardAddress, address subjectToken, address usdgAddress, address recipientAddress) {
        if (
            guardAddress == address(0) || subjectToken == address(0) || usdgAddress == address(0)
                || recipientAddress == address(0)
        ) revert ZeroAddress();
        guard = ShieldBotVerdictGuard(guardAddress);
        subject = subjectToken;
        usdg = IERC20(usdgAddress);
        recipient = recipientAddress;
    }

    /// @notice Transfer the caller's approved USDG if the subject meets their freshness policy.
    /// @dev Requires exact recipient credit. The recipient must be an EOA or passive contract; a hook that
    ///      forwards funds onward fails the balance-delta check, as do transfer fees or excess credit.
    ///      The guard's view call uses STATICCALL; the ERC-20 call can execute arbitrary callbacks.
    ///      The lock is not strictly needed to protect shared balances/accounting here: there is no custody
    ///      accounting, every call checks the guard first, and transferFrom debits only that call's sender.
    ///      It explicitly blocks nested executions through token callbacks; it cannot make a malicious token honest.
    /// @param amount Positive amount of token units to request from the caller.
    /// @param maxAge Maximum publication age in seconds, inclusive; zero always denies.
    function transfer(uint256 amount, uint64 maxAge) external nonReentrant {
        if (amount == 0) revert ZeroAmount();
        guard.requireAllowed(subject, maxAge);
        uint256 balanceBefore = usdg.balanceOf(recipient);
        usdg.safeTransferFrom(msg.sender, recipient, amount);
        uint256 balanceAfter = usdg.balanceOf(recipient);
        uint256 delivered = balanceAfter > balanceBefore ? balanceAfter - balanceBefore : 0;
        if (delivered != amount) revert ShortDelivery(amount, delivered);
        emit GuardedTransfer(subject, msg.sender, amount, maxAge);
    }
}
