// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {ShieldBotVerdictRegistry} from "./ShieldBotVerdictRegistry.sol";

/// @title ShieldBotVerdictGuard
/// @notice Deny-by-default, read-only policy for consumers of ShieldBot verdicts.
/// @dev Ownerless by design: consumers supply publication-freshness tolerances; no administrator can relax them.
///      Trusts the immutable registry and its recorder's verdicts. The registry timestamps execution of the
///      recording transaction. The publisher's observation-age cutoff only gates broadcast; an already broadcast
///      transaction can land arbitrarily later. Observation age is not bounded on-chain.
///      On Arbitrum, block.timestamp is sequencer-set (roughly 24h past / 1h future tolerance).
///      Both publication and checking use that same clock; sequencer clock integrity is a trust assumption.
///      observedBlock is an L2 block number while block.number is L1-derived; neither is used to measure age.
contract ShieldBotVerdictGuard {
    /// @notice Reason codes returned by check and included in NotAllowed.
    enum Reason {
        ALLOWED,
        NO_RECORD,
        UNKNOWN,
        HIGH,
        HONEYPOT,
        EXPIRED,
        FUTURE_TIMESTAMP
    }

    /// @notice The sole source of verdicts, fixed at construction.
    ShieldBotVerdictRegistry public immutable registry;

    /// @notice The registry address is zero.
    error ZeroAddress();
    /// @notice The subject failed the caller's policy; reason is a Reason code.
    error NotAllowed(address subject, uint8 reason);

    /// @param registryAddress The trusted verdict registry on this chain.
    constructor(address registryAddress) {
        if (registryAddress == address(0)) revert ZeroAddress();
        registry = ShieldBotVerdictRegistry(registryAddress);
    }

    /// @notice Allow only recorded LOW or MEDIUM verdicts within the caller's publication-age limit.
    /// @dev Reason precedence: NO_RECORD, HIGH/HONEYPOT, FUTURE_TIMESTAMP, EXPIRED, ALLOWED, UNKNOWN.
    ///      Reason is only consulted on denial, so precedence is informational and cannot change what is allowed.
    ///      An expired LOW reports EXPIRED because its permission lapsed; an expired HONEYPOT reports HONEYPOT
    ///      rather than inviting a retry against a known honeypot. UNKNOWN carries no adverse content and stays
    ///      after expiry. A zero subject has NO_RECORD because the registry forbids recording it.
    ///      Registry read failures propagate as reverts.
    ///      LOW and MEDIUM are deliberately accepted: this policy tolerates moderate reported risk while denying
    ///      incomplete, high-risk and honeypot verdicts. It is not a LOW-only policy or a token-safety guarantee;
    ///      consumers requiring LOW only must enforce that stricter verdict policy separately from maxAge.
    /// @param subject The token to check.
    /// @param maxAge Maximum publication age in seconds, inclusive. Zero ALWAYS denies, even in the publication
    ///        block; it never disables expiry. Missing, adverse and future reasons retain precedence over expiry.
    /// @return allowed Whether the subject meets this policy.
    /// @return reason The Reason code explaining the decision.
    // Age comparisons intentionally use the sequencer clock under the trust assumption documented above.
    // slither-disable-next-line timestamp
    function check(address subject, uint64 maxAge) public view returns (bool allowed, uint8 reason) {
        ShieldBotVerdictRegistry.Record memory latest = registry.latestRecord(subject);
        if (latest.evidenceHash == bytes32(0)) return (false, uint8(Reason.NO_RECORD));
        if (latest.verdict == ShieldBotVerdictRegistry.Verdict.HIGH) return (false, uint8(Reason.HIGH));
        if (latest.verdict == ShieldBotVerdictRegistry.Verdict.HONEYPOT) return (false, uint8(Reason.HONEYPOT));
        // forge-lint: disable-next-line(block-timestamp)
        if (latest.timestamp > block.timestamp) return (false, uint8(Reason.FUTURE_TIMESTAMP));
        // forge-lint: disable-next-line(block-timestamp)
        if (maxAge == 0 || block.timestamp - latest.timestamp > maxAge) return (false, uint8(Reason.EXPIRED));
        if (
            latest.verdict == ShieldBotVerdictRegistry.Verdict.LOW
                || latest.verdict == ShieldBotVerdictRegistry.Verdict.MEDIUM
        ) {
            return (true, uint8(Reason.ALLOWED));
        }
        return (false, uint8(Reason.UNKNOWN));
    }

    /// @notice Revert with NotAllowed if check denies the subject; registry read failures propagate unchanged.
    /// @param subject The token to check.
    /// @param maxAge Maximum publication age in seconds, inclusive; zero always denies.
    function requireAllowed(address subject, uint64 maxAge) external view {
        (bool allowed, uint8 reason) = check(subject, maxAge);
        if (!allowed) revert NotAllowed(subject, reason);
    }
}
