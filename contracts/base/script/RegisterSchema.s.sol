// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script, console2} from "forge-std/Script.sol";
import {ISchemaRegistry} from "@eas/ISchemaRegistry.sol";
import {ISchemaResolver} from "@eas/resolver/ISchemaResolver.sol";

/// @notice Registers the ShieldBot threat-attestation schema on Base.
/// @dev Run once before deploying the attestor. The schema UID is deterministic — re-running is a no-op revert.
///      Usage: forge script script/RegisterSchema.s.sol --rpc-url base --broadcast --account <keystore>
contract RegisterSchema is Script {
    // Base mainnet predeploy
    address constant SCHEMA_REGISTRY = 0x4200000000000000000000000000000000000020;

    string constant SCHEMA =
        "address scannedAddress,uint8 riskLevel,string scanType,uint64 sourceChainId,bytes32 evidenceHash,string evidenceURI";

    function run() external {
        ISchemaRegistry registry = ISchemaRegistry(SCHEMA_REGISTRY);

        bytes32 expectedUID = keccak256(abi.encodePacked(SCHEMA, address(0), true));
        console2.log("Expected schema UID:");
        console2.logBytes32(expectedUID);

        vm.startBroadcast();
        bytes32 uid = registry.register(SCHEMA, ISchemaResolver(address(0)), true);
        vm.stopBroadcast();

        console2.log("Registered schema UID:");
        console2.logBytes32(uid);
        require(uid == expectedUID, "UID mismatch");
    }
}
