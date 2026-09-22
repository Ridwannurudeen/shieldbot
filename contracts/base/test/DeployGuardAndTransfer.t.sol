// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test, stdError} from "forge-std/Test.sol";
import {DeployGuardAndTransfer} from "../script/DeployGuardAndTransfer.s.sol";
import {ShieldBotVerdictRegistry} from "../src/ShieldBotVerdictRegistry.sol";
import {ShieldBotVerdictGuard} from "../src/ShieldBotVerdictGuard.sol";
import {ShieldBotGuardedTransfer} from "../src/ShieldBotGuardedTransfer.sol";

contract DeployGuardAndTransferTest is Test {
    /// Keep env var mutations in one test because forge runs test functions in parallel.
    function test_Run_RequiresAddressesAndAssertsDeployment() public {
        vm.chainId(4663);
        DeployGuardAndTransfer script = new DeployGuardAndTransfer();
        address recorder = makeAddr("recorder");
        ShieldBotVerdictRegistry registry = new ShieldBotVerdictRegistry(recorder);
        address subject = makeAddr("subject");
        address recipient = makeAddr("recipient");
        address usdg = 0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168;

        string[5] memory names = ["REGISTRY", "EXPECTED_RECORDER", "SUBJECT", "USDG", "RECIPIENT"];
        address[5] memory values = [address(registry), recorder, subject, usdg, recipient];
        for (uint256 i; i < names.length; ++i) {
            vm.setEnv(names[i], vm.toString(values[i]));
        }
        for (uint256 i; i < names.length; ++i) {
            vm.setEnv(names[i], "");
            vm.expectRevert();
            script.run();
            vm.setEnv(names[i], vm.toString(values[i]));
        }

        vm.setEnv("EXPECTED_RECORDER", vm.toString(makeAddr("wrong recorder")));
        vm.expectRevert(stdError.assertionError);
        script.run();
        vm.setEnv("EXPECTED_RECORDER", vm.toString(recorder));

        vm.setEnv("USDG", vm.toString(makeAddr("wrong USDG")));
        vm.expectRevert(stdError.assertionError);
        script.run();
        vm.setEnv("USDG", vm.toString(usdg));

        (ShieldBotVerdictGuard guard, ShieldBotGuardedTransfer guardedTransfer) = script.run();
        assertEq(address(guard.registry()), address(registry));
        assertEq(registry.recorder(), recorder);
        assertEq(address(guardedTransfer.guard()), address(guard));
        assertEq(guardedTransfer.subject(), subject);
        assertEq(guardedTransfer.recipient(), recipient);
        assertEq(address(guardedTransfer.usdg()), usdg);
    }

    function test_Run_RejectsWrongChainBeforeReadingAddresses() public {
        vm.chainId(8453);
        DeployGuardAndTransfer script = new DeployGuardAndTransfer();
        vm.expectRevert(abi.encodeWithSelector(DeployGuardAndTransfer.WrongChain.selector, uint256(8453)));
        script.run();
    }
}
