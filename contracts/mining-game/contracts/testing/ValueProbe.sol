// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Records what the EVM actually sees as msg.value.
/// @dev Used to establish the native-value denomination of the WATTx EVM, which
///      is Qtum-derived and therefore may not be wei. Any contract ported from
///      an 18-decimal native chain prices things in `ether` literals; if this
///      chain denominates msg.value differently those literals are unpayable.
contract ValueProbe {
    uint256 public lastValue;
    uint256 public callCount;

    function pay() external payable {
        lastValue = msg.value;
        callCount++;
    }

    function balance() external view returns (uint256) {
        return address(this).balance;
    }
}
