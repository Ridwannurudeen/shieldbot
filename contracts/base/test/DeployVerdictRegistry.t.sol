// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {DeployVerdictRegistry} from "../script/DeployVerdictRegistry.s.sol";
import {ShieldBotVerdictRegistry} from "../src/ShieldBotVerdictRegistry.sol";

contract DeployVerdictRegistryTest is Test {
    /// Keep env var mutations in one test because forge runs test functions in parallel.
    function test_Run_RequiresRecorderAndDeploysWithIt() public {
        vm.chainId(4663);
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

    function test_Run_RejectsWrongChainBeforeReadingRecorder() public {
        vm.chainId(8453);
        DeployVerdictRegistry script = new DeployVerdictRegistry();
        vm.expectRevert(abi.encodeWithSelector(DeployVerdictRegistry.WrongChain.selector, uint256(8453)));
        script.run();
    }
}
