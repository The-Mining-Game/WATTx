// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ArgTest {
    address public token0;
    address public token1;

    constructor(address _t0, address _t1) {
        token0 = _t0;
        token1 = _t1;
    }

    function getTokens() external view returns (address, address) {
        return (token0, token1);
    }
}
