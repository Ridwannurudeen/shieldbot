// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {DeployVerdictRegistry} from "../script/DeployVerdictRegistry.s.sol";
import {ShieldBotVerdictRegistry} from "../src/ShieldBotVerdictRegistry.sol";

contract DeployVerdictRegistryTest is Test {
    /// One test function, because forge runs test functions in parallel and both steps set the same env var.
    function test_Run_RequiresRecorderAndDeploysWithIt() public {
        DeployVerdictRegistry script = new DeployVerdictRegistry();

        vm.setEnv("INITIAL_RECORDER", "");
        vm.expectRevert();
        script.run();

        address recorder = makeAddr("recorder");
        vm.setEnv("INITIAL_RECORDER", vm.toString(recorder));
        ShieldBotVerdictRegistry registry = script.run();

        assertEq(registry.recorder(), recorder);
        // The broadcasting account, not the script contract, owns the registry.
        assertEq(registry.owner(), tx.origin);
        assertEq(registry.totalRecords(), 0);
    }
}
