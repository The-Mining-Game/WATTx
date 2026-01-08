// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
}

contract TinyDEX {
    address public token0;
    address public token1;
    uint256 public reserve0;
    uint256 public reserve1;
    uint256 public totalLP;
    mapping(address => uint256) public lp;
    address public owner;

    constructor(address _t0, address _t1) {
        token0 = _t0;
        token1 = _t1;
        owner = msg.sender;
    }

    function addLiq(uint256 a0, uint256 a1) external returns (uint256 lpAmt) {
        require(IERC20(token0).transferFrom(msg.sender, address(this), a0), "tf0");
        require(IERC20(token1).transferFrom(msg.sender, address(this), a1), "tf1");

        if (totalLP == 0) {
            lpAmt = sqrt(a0 * a1);
        } else {
            uint256 lp0 = (a0 * totalLP) / reserve0;
            uint256 lp1 = (a1 * totalLP) / reserve1;
            lpAmt = lp0 < lp1 ? lp0 : lp1;
        }

        lp[msg.sender] += lpAmt;
        totalLP += lpAmt;
        reserve0 += a0;
        reserve1 += a1;
    }

    function swap(address tin, uint256 ain, uint256 minOut) external returns (uint256 aout) {
        require(tin == token0 || tin == token1, "bad");
        bool is0 = tin == token0;
        uint256 ri = is0 ? reserve0 : reserve1;
        uint256 ro = is0 ? reserve1 : reserve0;
        address tout = is0 ? token1 : token0;

        uint256 aif = ain * 997;
        aout = (aif * ro) / (ri * 1000 + aif);
        require(aout >= minOut, "slip");

        require(IERC20(tin).transferFrom(msg.sender, address(this), ain), "ti");
        require(IERC20(tout).transfer(msg.sender, aout), "to");

        if (is0) { reserve0 += ain; reserve1 -= aout; }
        else { reserve1 += ain; reserve0 -= aout; }
    }

    function sqrt(uint256 y) internal pure returns (uint256 z) {
        if (y > 3) {
            z = y;
            uint256 x = y / 2 + 1;
            while (x < z) { z = x; x = (y / x + x) / 2; }
        } else if (y != 0) { z = 1; }
    }
}
