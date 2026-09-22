// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script, console2} from "forge-std/Script.sol";
import {ShieldBotVerdictRegistry} from "../src/ShieldBotVerdictRegistry.sol";

/// @notice Deploys ShieldBotVerdictRegistry on Robinhood Chain (4663).
/// @dev Reads the recorder's public address from INITIAL_RECORDER. The broadcasting account becomes the owner.
///      No key is read here: the owner signs with a Foundry keystore (--account). See DEPLOY_ROBINHOOD.md.
///      Dry run (no transaction is sent):
///        INITIAL_RECORDER=0x... forge script script/DeployVerdictRegistry.s.sol:DeployVerdictRegistry \
///          --rpc-url https://rpc.mainnet.chain.robinhood.com --sender <owner address>
contract DeployVerdictRegistry is Script {
    /// @notice Deployment was attempted on a chain other than Robinhood Chain (4663).
    /// @param actualChainId The chain ID of the selected RPC.
    error WrongChain(uint256 actualChainId);

    function run() external returns (ShieldBotVerdictRegistry registry) {
        if (block.chainid != 4663) revert WrongChain(block.chainid);
        address initialRecorder = vm.envAddress("INITIAL_RECORDER");

        console2.log("Deploying ShieldBotVerdictRegistry");
        console2.log("  Chain id:          ", block.chainid);
        console2.log("  Initial recorder:  ", initialRecorder);
        console2.log("  Deployer (owner):  ", msg.sender);

        vm.startBroadcast();
        registry = new ShieldBotVerdictRegistry(initialRecorder);
        vm.stopBroadcast();

        console2.log("Deployed at:", address(registry));
        console2.log("  owner():           ", registry.owner());
        console2.log("  recorder():        ", registry.recorder());
    }
}
