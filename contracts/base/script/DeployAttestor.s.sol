// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script, console2} from "forge-std/Script.sol";
import {ShieldBotAttestor} from "../src/ShieldBotAttestor.sol";

/// @notice Deploys ShieldBotAttestor on Base.
/// @dev Reads SCHEMA_UID and INITIAL_VERIFIER from env. Owner is the broadcasting account.
///      Usage:
///        SCHEMA_UID=0x... INITIAL_VERIFIER=0x... \
///          forge script script/DeployAttestor.s.sol --rpc-url base --broadcast --account <keystore> --verify
contract DeployAttestor is Script {
    // Base mainnet EAS predeploy
    address constant EAS = 0x4200000000000000000000000000000000000021;

    function run() external returns (ShieldBotAttestor attestor) {
        bytes32 schemaUID = vm.envBytes32("SCHEMA_UID");
        address initialVerifier = vm.envAddress("INITIAL_VERIFIER");

        console2.log("Deploying ShieldBotAttestor");
        console2.log("  EAS:               ", EAS);
        console2.log("  Schema UID:        ");
        console2.logBytes32(schemaUID);
        console2.log("  Initial verifier:  ", initialVerifier);
        console2.log("  Deployer (owner):  ", msg.sender);

        vm.startBroadcast();
        attestor = new ShieldBotAttestor(EAS, schemaUID, initialVerifier);
        vm.stopBroadcast();

        console2.log("Deployed at:", address(attestor));
    }
}
