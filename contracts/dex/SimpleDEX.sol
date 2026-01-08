// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IERC20 {
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/**
 * @title SimpleDEX
 * @dev Minimal AMM DEX for WATTx blockchain
 */
contract SimpleDEX {
    address public token0;
    address public token1;
    uint256 public reserve0;
    uint256 public reserve1;
    uint256 public totalLiquidity;
    mapping(address => uint256) public liquidity;

    uint256 public constant FEE_BPS = 30; // 0.3%
    uint256 public constant BPS = 10000;
    uint256 public constant MIN_LIQUIDITY = 1000;

    address public owner;

    event LiquidityAdded(address indexed provider, uint256 amount0, uint256 amount1, uint256 lp);
    event LiquidityRemoved(address indexed provider, uint256 amount0, uint256 amount1, uint256 lp);
    event Swap(address indexed trader, address tokenIn, uint256 amountIn, address tokenOut, uint256 amountOut);

    constructor(address _token0, address _token1) {
        require(_token0 != _token1, "IDENTICAL");
        require(_token0 != address(0) && _token1 != address(0), "ZERO");
        // Order tokens
        if (_token0 < _token1) {
            token0 = _token0;
            token1 = _token1;
        } else {
            token0 = _token1;
            token1 = _token0;
        }
        owner = msg.sender;
    }

    function getReserves() external view returns (uint256, uint256) {
        return (reserve0, reserve1);
    }

    function addLiquidity(uint256 amount0, uint256 amount1) external returns (uint256 lp) {
        require(amount0 > 0 && amount1 > 0, "ZERO_AMOUNT");

        require(IERC20(token0).transferFrom(msg.sender, address(this), amount0), "TF0");
        require(IERC20(token1).transferFrom(msg.sender, address(this), amount1), "TF1");

        if (totalLiquidity == 0) {
            lp = sqrt(amount0 * amount1) - MIN_LIQUIDITY;
            liquidity[address(0)] = MIN_LIQUIDITY;
        } else {
            uint256 lp0 = (amount0 * totalLiquidity) / reserve0;
            uint256 lp1 = (amount1 * totalLiquidity) / reserve1;
            lp = lp0 < lp1 ? lp0 : lp1;
        }

        require(lp > 0, "LP_ZERO");
        liquidity[msg.sender] += lp;
        totalLiquidity += lp;
        reserve0 += amount0;
        reserve1 += amount1;

        emit LiquidityAdded(msg.sender, amount0, amount1, lp);
    }

    function removeLiquidity(uint256 lpAmount) external returns (uint256 amount0, uint256 amount1) {
        require(lpAmount > 0 && liquidity[msg.sender] >= lpAmount, "INSUFF_LP");

        amount0 = (lpAmount * reserve0) / totalLiquidity;
        amount1 = (lpAmount * reserve1) / totalLiquidity;

        liquidity[msg.sender] -= lpAmount;
        totalLiquidity -= lpAmount;
        reserve0 -= amount0;
        reserve1 -= amount1;

        require(IERC20(token0).transfer(msg.sender, amount0), "T0");
        require(IERC20(token1).transfer(msg.sender, amount1), "T1");

        emit LiquidityRemoved(msg.sender, amount0, amount1, lpAmount);
    }

    function swap(address tokenIn, uint256 amountIn, uint256 minOut) external returns (uint256 amountOut) {
        require(tokenIn == token0 || tokenIn == token1, "INVALID_TOKEN");
        require(amountIn > 0, "ZERO_IN");

        bool isToken0 = tokenIn == token0;
        uint256 resIn = isToken0 ? reserve0 : reserve1;
        uint256 resOut = isToken0 ? reserve1 : reserve0;
        address tokenOut = isToken0 ? token1 : token0;

        uint256 amountInWithFee = amountIn * (BPS - FEE_BPS);
        amountOut = (amountInWithFee * resOut) / (resIn * BPS + amountInWithFee);
        require(amountOut >= minOut, "SLIPPAGE");

        require(IERC20(tokenIn).transferFrom(msg.sender, address(this), amountIn), "TIN");
        require(IERC20(tokenOut).transfer(msg.sender, amountOut), "TOUT");

        if (isToken0) {
            reserve0 += amountIn;
            reserve1 -= amountOut;
        } else {
            reserve1 += amountIn;
            reserve0 -= amountOut;
        }

        emit Swap(msg.sender, tokenIn, amountIn, tokenOut, amountOut);
    }

    function getAmountOut(uint256 amountIn, uint256 resIn, uint256 resOut) public pure returns (uint256) {
        require(amountIn > 0 && resIn > 0 && resOut > 0, "ZERO");
        uint256 amountInWithFee = amountIn * (BPS - FEE_BPS);
        return (amountInWithFee * resOut) / (resIn * BPS + amountInWithFee);
    }

    function sqrt(uint256 y) internal pure returns (uint256 z) {
        if (y > 3) {
            z = y;
            uint256 x = y / 2 + 1;
            while (x < z) {
                z = x;
                x = (y / x + x) / 2;
            }
        } else if (y != 0) {
            z = 1;
        }
    }
}
