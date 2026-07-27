// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IMinerRigConfig
 * @dev Interface for miner rig configuration
 *
 * Allows NFT mining rig owners to configure:
 * - Algorithm selection (which algorithm to mine with)
 * - Coin selection (which coin to mine)
 * - Pool selection (which registered pool to mine on)
 */
interface IMinerRigConfig {
    /// @notice Supported mining algorithms
    enum Algorithm {
        SHA256D,    // 0: Bitcoin, BCH, BSV
        SCRYPT,     // 1: Litecoin, Dogecoin
        ETHASH,     // 2: ETC (Ethereum Classic)
        RANDOMX,    // 3: Monero
        EQUIHASH,   // 4: Zcash, Horizen
        X11,        // 5: Dash
        KHEAVYHASH  // 6: Kaspa
    }

    /// @notice Supported coins (mapped to algorithms)
    enum Coin {
        BTC,    // 0: Bitcoin (SHA256D)
        BCH,    // 1: Bitcoin Cash (SHA256D)
        BSV,    // 2: Bitcoin SV (SHA256D)
        LTC,    // 3: Litecoin (Scrypt)
        DOGE,   // 4: Dogecoin (Scrypt)
        ETC,    // 5: Ethereum Classic (Ethash)
        XMR,    // 6: Monero (RandomX)
        ZEC,    // 7: Zcash (Equihash)
        ZEN,    // 8: Horizen (Equihash)
        DASH,   // 9: Dash (X11)
        KAS     // 10: Kaspa (kHeavyHash)
    }

    /// @notice Mining rig configuration
    struct RigConfig {
        uint256 rigId;              // NFT token ID
        address owner;              // Current owner
        Algorithm algorithm;        // Selected algorithm
        Coin coin;                  // Selected coin
        address poolOperator;       // Selected pool operator
        bool isActive;              // Is mining active
        uint256 lastConfigUpdate;   // Last configuration change timestamp
        uint256 totalMiningTime;    // Total time spent mining
    }

    /// @notice Configure a mining rig
    /// @param rigId NFT token ID
    /// @param algorithm Mining algorithm to use
    /// @param coin Coin to mine
    /// @param poolOperator Pool operator address to mine on
    function configureRig(
        uint256 rigId,
        Algorithm algorithm,
        Coin coin,
        address poolOperator
    ) external;

    /// @notice Change algorithm for a rig
    function setAlgorithm(uint256 rigId, Algorithm algorithm) external;

    /// @notice Change coin for a rig (must match algorithm)
    function setCoin(uint256 rigId, Coin coin) external;

    /// @notice Change pool for a rig
    function setPool(uint256 rigId, address poolOperator) external;

    /// @notice Start mining with configured settings
    function startMining(uint256 rigId) external;

    /// @notice Stop mining
    function stopMining(uint256 rigId) external;

    /// @notice Get rig configuration
    function getRigConfig(uint256 rigId) external view returns (RigConfig memory);

    /// @notice Get algorithm for a coin
    function getCoinAlgorithm(Coin coin) external pure returns (Algorithm);

    /// @notice Get coins for an algorithm
    /// @dev view, not pure: the mapping is configurable storage, not a constant table
    function getCoinsForAlgorithm(Algorithm algorithm) external view returns (Coin[] memory);

    /// @notice Check if coin matches algorithm
    /// @dev view, not pure: reads the configurable coin->algorithm mapping
    function isCoinValidForAlgorithm(Coin coin, Algorithm algorithm) external view returns (bool);

    // Events
    event RigConfigured(
        uint256 indexed rigId,
        address indexed owner,
        Algorithm algorithm,
        Coin coin,
        address poolOperator
    );
    event AlgorithmChanged(uint256 indexed rigId, Algorithm oldAlgorithm, Algorithm newAlgorithm);
    event CoinChanged(uint256 indexed rigId, Coin oldCoin, Coin newCoin);
    event PoolChanged(uint256 indexed rigId, address oldPool, address newPool);
    event MiningStarted(uint256 indexed rigId, address poolOperator);
    event MiningStopped(uint256 indexed rigId, uint256 duration);
}
