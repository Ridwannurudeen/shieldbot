// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script, console2} from "forge-std/Script.sol";
import {ShieldBotVerdictRegistry} from "../src/ShieldBotVerdictRegistry.sol";
import {ShieldBotVerdictGuard} from "../src/ShieldBotVerdictGuard.sol";
import {ShieldBotGuardedTransfer} from "../src/ShieldBotGuardedTransfer.sol";

/// @notice Deploys the verdict guard and guarded USDG transfer on Robinhood Chain (4663).
/// @dev Reads only public addresses from REGISTRY, EXPECTED_RECORDER, SUBJECT, USDG and RECIPIENT.
///      No key is read here: the owner signs with a Foundry keystore (--account). See DEPLOY_ROBINHOOD.md.
contract DeployGuardAndTransfer is Script {
    /// @notice Deployment was attempted on a chain other than Robinhood Chain (4663).
    /// @param actualChainId The chain ID of the selected RPC.
    error WrongChain(uint256 actualChainId);

    function run() external returns (ShieldBotVerdictGuard guard, ShieldBotGuardedTransfer guardedTransfer) {
        if (block.chainid != 4663) revert WrongChain(block.chainid);
        address registry = vm.envAddress("REGISTRY");
        address expectedRecorder = vm.envAddress("EXPECTED_RECORDER");
        address subject = vm.envAddress("SUBJECT");
        address usdg = vm.envAddress("USDG");
        address recipient = vm.envAddress("RECIPIENT");

        console2.log("Deploying ShieldBotVerdictGuard and ShieldBotGuardedTransfer");
        console2.log("  Chain id:          ", block.chainid);

        vm.startBroadcast();
        guard = new ShieldBotVerdictGuard(registry);
        guardedTransfer = new ShieldBotGuardedTransfer(address(guard), subject, usdg, recipient);
        vm.stopBroadcast();

        console2.log("Guard deployed at:", address(guard));
        console2.log("Transfer deployed at:", address(guardedTransfer));
        console2.log("  guard.registry():  ", address(guard.registry()));
        console2.log("  REGISTRY:          ", registry);
        console2.log("  recorder():        ", ShieldBotVerdictRegistry(registry).recorder());
        console2.log("  EXPECTED_RECORDER: ", expectedRecorder);
        console2.log("  transfer.guard():  ", address(guardedTransfer.guard()));
        console2.log("  transfer.subject():", guardedTransfer.subject());
        console2.log("  SUBJECT:           ", subject);
        console2.log("  transfer.recipient():", guardedTransfer.recipient());
        console2.log("  RECIPIENT:         ", recipient);
        console2.log("  transfer.usdg():   ", address(guardedTransfer.usdg()));
        console2.log("  USDG:              ", usdg);
        console2.log("  Paxos USDG proxy:  ", address(0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168));

        assert(address(guard.registry()) == registry);
        assert(ShieldBotVerdictRegistry(registry).recorder() == expectedRecorder);
        assert(address(guardedTransfer.guard()) == address(guard));
        assert(guardedTransfer.subject() == subject);
        assert(guardedTransfer.recipient() == recipient);
        assert(address(guardedTransfer.usdg()) == usdg);
        assert(usdg == 0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168);
    }
}
