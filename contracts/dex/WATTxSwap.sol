// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./IERC20.sol";

/**
 * @title WATTxSwap
 * @dev AMM-style decentralized exchange for WATTx blockchain
 * Based on constant product formula (x * y = k)
 */
contract WATTxSwap {
    // ============ State Variables ============

    struct Pool {
        address token0;           // First token in the pair
        address token1;           // Second token in the pair
        uint256 reserve0;         // Reserve of token0
        uint256 reserve1;         // Reserve of token1
        uint256 totalLiquidity;   // Total LP tokens
        mapping(address => uint256) liquidity; // LP balance per provider
        bool exists;
    }

    // Pool ID => Pool
    mapping(bytes32 => Pool) public pools;

    // List of all pool IDs
    bytes32[] public poolIds;

    // Fee in basis points (30 = 0.3%)
    uint256 public constant FEE_BPS = 30;
    uint256 public constant BPS_DENOMINATOR = 10000;

    // Minimum liquidity to prevent division by zero attacks
    uint256 public constant MINIMUM_LIQUIDITY = 1000;

    // Owner
    address public owner;

    // ============ Events ============

    event PoolCreated(bytes32 indexed poolId, address token0, address token1);
    event LiquidityAdded(bytes32 indexed poolId, address indexed provider, uint256 amount0, uint256 amount1, uint256 liquidity);
    event LiquidityRemoved(bytes32 indexed poolId, address indexed provider, uint256 amount0, uint256 amount1, uint256 liquidity);
    event Swap(bytes32 indexed poolId, address indexed trader, address tokenIn, uint256 amountIn, address tokenOut, uint256 amountOut);

    // ============ Constructor ============

    constructor() {
        owner = msg.sender;
    }

    // ============ Pool Management ============

    /**
     * @dev Get the pool ID for a token pair (order independent)
     */
    function getPoolId(address tokenA, address tokenB) public pure returns (bytes32) {
        (address token0, address token1) = tokenA < tokenB ? (tokenA, tokenB) : (tokenB, tokenA);
        return keccak256(abi.encodePacked(token0, token1));
    }

    /**
     * @dev Create a new liquidity pool
     */
    function createPool(address tokenA, address tokenB) external returns (bytes32 poolId) {
        require(tokenA != tokenB, "WATTxSwap: identical addresses");
        require(tokenA != address(0) && tokenB != address(0), "WATTxSwap: zero address");

        (address token0, address token1) = tokenA < tokenB ? (tokenA, tokenB) : (tokenB, tokenA);
        poolId = getPoolId(token0, token1);

        require(!pools[poolId].exists, "WATTxSwap: pool exists");

        Pool storage pool = pools[poolId];
        pool.token0 = token0;
        pool.token1 = token1;
        pool.exists = true;

        poolIds.push(poolId);

        emit PoolCreated(poolId, token0, token1);
    }

    /**
     * @dev Get pool count
     */
    function getPoolCount() external view returns (uint256) {
        return poolIds.length;
    }

    /**
     * @dev Get pool info
     */
    function getPool(bytes32 poolId) external view returns (
        address token0,
        address token1,
        uint256 reserve0,
        uint256 reserve1,
        uint256 totalLiquidity
    ) {
        Pool storage pool = pools[poolId];
        return (pool.token0, pool.token1, pool.reserve0, pool.reserve1, pool.totalLiquidity);
    }

    /**
     * @dev Get liquidity balance for a provider
     */
    function getLiquidity(bytes32 poolId, address provider) external view returns (uint256) {
        return pools[poolId].liquidity[provider];
    }

    // ============ Liquidity Functions ============

    /**
     * @dev Add liquidity to a pool
     */
    function addLiquidity(
        address tokenA,
        address tokenB,
        uint256 amountADesired,
        uint256 amountBDesired,
        uint256 amountAMin,
        uint256 amountBMin
    ) external returns (uint256 amountA, uint256 amountB, uint256 liquidity) {
        bytes32 poolId = getPoolId(tokenA, tokenB);
        Pool storage pool = pools[poolId];
        require(pool.exists, "WATTxSwap: pool not found");

        (address token0, address token1) = tokenA < tokenB ? (tokenA, tokenB) : (tokenB, tokenA);
        (uint256 amount0Desired, uint256 amount1Desired) = tokenA < tokenB
            ? (amountADesired, amountBDesired)
            : (amountBDesired, amountADesired);
        (uint256 amount0Min, uint256 amount1Min) = tokenA < tokenB
            ? (amountAMin, amountBMin)
            : (amountBMin, amountAMin);

        uint256 amount0;
        uint256 amount1;

        if (pool.reserve0 == 0 && pool.reserve1 == 0) {
            // First liquidity provision
            amount0 = amount0Desired;
            amount1 = amount1Desired;
        } else {
            // Calculate optimal amounts based on current ratio
            uint256 amount1Optimal = (amount0Desired * pool.reserve1) / pool.reserve0;
            if (amount1Optimal <= amount1Desired) {
                require(amount1Optimal >= amount1Min, "WATTxSwap: insufficient B amount");
                amount0 = amount0Desired;
                amount1 = amount1Optimal;
            } else {
                uint256 amount0Optimal = (amount1Desired * pool.reserve0) / pool.reserve1;
                require(amount0Optimal <= amount0Desired, "WATTxSwap: excessive A amount");
                require(amount0Optimal >= amount0Min, "WATTxSwap: insufficient A amount");
                amount0 = amount0Optimal;
                amount1 = amount1Desired;
            }
        }

        // Transfer tokens to contract
        require(IERC20(token0).transferFrom(msg.sender, address(this), amount0), "WATTxSwap: transfer0 failed");
        require(IERC20(token1).transferFrom(msg.sender, address(this), amount1), "WATTxSwap: transfer1 failed");

        // Calculate liquidity tokens
        if (pool.totalLiquidity == 0) {
            liquidity = sqrt(amount0 * amount1) - MINIMUM_LIQUIDITY;
            pool.liquidity[address(0)] = MINIMUM_LIQUIDITY; // Lock minimum liquidity
        } else {
            liquidity = min(
                (amount0 * pool.totalLiquidity) / pool.reserve0,
                (amount1 * pool.totalLiquidity) / pool.reserve1
            );
        }

        require(liquidity > 0, "WATTxSwap: insufficient liquidity minted");

        // Update state
        pool.liquidity[msg.sender] += liquidity;
        pool.totalLiquidity += liquidity;
        pool.reserve0 += amount0;
        pool.reserve1 += amount1;

        // Return values in original order
        (amountA, amountB) = tokenA < tokenB ? (amount0, amount1) : (amount1, amount0);

        emit LiquidityAdded(poolId, msg.sender, amount0, amount1, liquidity);
    }

    /**
     * @dev Remove liquidity from a pool
     */
    function removeLiquidity(
        address tokenA,
        address tokenB,
        uint256 liquidity,
        uint256 amountAMin,
        uint256 amountBMin
    ) external returns (uint256 amountA, uint256 amountB) {
        bytes32 poolId = getPoolId(tokenA, tokenB);
        Pool storage pool = pools[poolId];
        require(pool.exists, "WATTxSwap: pool not found");
        require(pool.liquidity[msg.sender] >= liquidity, "WATTxSwap: insufficient liquidity");

        (address token0, address token1) = tokenA < tokenB ? (tokenA, tokenB) : (tokenB, tokenA);

        // Calculate amounts to return
        uint256 amount0 = (liquidity * pool.reserve0) / pool.totalLiquidity;
        uint256 amount1 = (liquidity * pool.reserve1) / pool.totalLiquidity;

        (uint256 amountAOut, uint256 amountBOut) = tokenA < tokenB ? (amount0, amount1) : (amount1, amount0);
        require(amountAOut >= amountAMin, "WATTxSwap: insufficient A amount");
        require(amountBOut >= amountBMin, "WATTxSwap: insufficient B amount");

        // Update state
        pool.liquidity[msg.sender] -= liquidity;
        pool.totalLiquidity -= liquidity;
        pool.reserve0 -= amount0;
        pool.reserve1 -= amount1;

        // Transfer tokens back
        require(IERC20(token0).transfer(msg.sender, amount0), "WATTxSwap: transfer0 failed");
        require(IERC20(token1).transfer(msg.sender, amount1), "WATTxSwap: transfer1 failed");

        amountA = amountAOut;
        amountB = amountBOut;

        emit LiquidityRemoved(poolId, msg.sender, amount0, amount1, liquidity);
    }

    // ============ Swap Functions ============

    /**
     * @dev Get the output amount for a swap
     */
    function getAmountOut(
        uint256 amountIn,
        uint256 reserveIn,
        uint256 reserveOut
    ) public pure returns (uint256 amountOut) {
        require(amountIn > 0, "WATTxSwap: insufficient input");
        require(reserveIn > 0 && reserveOut > 0, "WATTxSwap: insufficient liquidity");

        uint256 amountInWithFee = amountIn * (BPS_DENOMINATOR - FEE_BPS);
        uint256 numerator = amountInWithFee * reserveOut;
        uint256 denominator = (reserveIn * BPS_DENOMINATOR) + amountInWithFee;
        amountOut = numerator / denominator;
    }

    /**
     * @dev Get the input amount required for a desired output
     */
    function getAmountIn(
        uint256 amountOut,
        uint256 reserveIn,
        uint256 reserveOut
    ) public pure returns (uint256 amountIn) {
        require(amountOut > 0, "WATTxSwap: insufficient output");
        require(reserveIn > 0 && reserveOut > 0, "WATTxSwap: insufficient liquidity");
        require(amountOut < reserveOut, "WATTxSwap: insufficient liquidity");

        uint256 numerator = reserveIn * amountOut * BPS_DENOMINATOR;
        uint256 denominator = (reserveOut - amountOut) * (BPS_DENOMINATOR - FEE_BPS);
        amountIn = (numerator / denominator) + 1;
    }

    /**
     * @dev Swap exact tokens for tokens
     */
    function swapExactTokensForTokens(
        uint256 amountIn,
        uint256 amountOutMin,
        address tokenIn,
        address tokenOut
    ) external returns (uint256 amountOut) {
        bytes32 poolId = getPoolId(tokenIn, tokenOut);
        Pool storage pool = pools[poolId];
        require(pool.exists, "WATTxSwap: pool not found");

        bool isToken0In = tokenIn < tokenOut;
        (uint256 reserveIn, uint256 reserveOut) = isToken0In
            ? (pool.reserve0, pool.reserve1)
            : (pool.reserve1, pool.reserve0);

        amountOut = getAmountOut(amountIn, reserveIn, reserveOut);
        require(amountOut >= amountOutMin, "WATTxSwap: insufficient output amount");

        // Transfer tokens
        require(IERC20(tokenIn).transferFrom(msg.sender, address(this), amountIn), "WATTxSwap: transferIn failed");
        require(IERC20(tokenOut).transfer(msg.sender, amountOut), "WATTxSwap: transferOut failed");

        // Update reserves
        if (isToken0In) {
            pool.reserve0 += amountIn;
            pool.reserve1 -= amountOut;
        } else {
            pool.reserve1 += amountIn;
            pool.reserve0 -= amountOut;
        }

        emit Swap(poolId, msg.sender, tokenIn, amountIn, tokenOut, amountOut);
    }

    /**
     * @dev Swap tokens for exact tokens
     */
    function swapTokensForExactTokens(
        uint256 amountOut,
        uint256 amountInMax,
        address tokenIn,
        address tokenOut
    ) external returns (uint256 amountIn) {
        bytes32 poolId = getPoolId(tokenIn, tokenOut);
        Pool storage pool = pools[poolId];
        require(pool.exists, "WATTxSwap: pool not found");

        bool isToken0In = tokenIn < tokenOut;
        (uint256 reserveIn, uint256 reserveOut) = isToken0In
            ? (pool.reserve0, pool.reserve1)
            : (pool.reserve1, pool.reserve0);

        amountIn = getAmountIn(amountOut, reserveIn, reserveOut);
        require(amountIn <= amountInMax, "WATTxSwap: excessive input amount");

        // Transfer tokens
        require(IERC20(tokenIn).transferFrom(msg.sender, address(this), amountIn), "WATTxSwap: transferIn failed");
        require(IERC20(tokenOut).transfer(msg.sender, amountOut), "WATTxSwap: transferOut failed");

        // Update reserves
        if (isToken0In) {
            pool.reserve0 += amountIn;
            pool.reserve1 -= amountOut;
        } else {
            pool.reserve1 += amountIn;
            pool.reserve0 -= amountOut;
        }

        emit Swap(poolId, msg.sender, tokenIn, amountIn, tokenOut, amountOut);
    }

    // ============ Helper Functions ============

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

    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }
}
