// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "../interfaces/IMinerRigConfig.sol";
import "../interfaces/IPoolRegistry.sol";
import "../interfaces/IMiningRigNFT.sol";

/**
 * @title MinerRigConfig
 * @dev Allows NFT mining rig owners to configure their rigs
 *
 * Features:
 * - Select mining algorithm (must match rig's built-in algorithm or pay upgrade)
 * - Select coin (must match algorithm)
 * - Select pool (must be registered and support the algorithm)
 * - Start/stop mining sessions
 */
contract MinerRigConfig is IMinerRigConfig, Ownable, ReentrancyGuard {
    // ============================================================================
    // State Variables
    // ============================================================================

    IMiningRigNFT public immutable miningRigNFT;
    IPoolRegistry public immutable poolRegistry;

    // Rig ID => Configuration
    mapping(uint256 => RigConfig) public rigConfigs;

    // Cooldown period between configuration changes (prevent gaming)
    uint256 public configCooldown = 1 hours;

    // Whether algorithm must match NFT's built-in algorithm
    bool public requireMatchingAlgorithm = false;

    // Mining session tracking
    mapping(uint256 => uint256) public miningStartTime;

    // ============================================================================
    // Algorithm-Coin Mappings
    // ============================================================================

    // Coin => Required Algorithm
    mapping(Coin => Algorithm) private _coinToAlgorithm;

    // Algorithm => List of valid coins
    mapping(Algorithm => Coin[]) private _algorithmToCoins;

    // ============================================================================
    // Constructor
    // ============================================================================

    constructor(address _miningRigNFT, address _poolRegistry) Ownable(msg.sender) {
        require(_miningRigNFT != address(0), "Invalid NFT address");
        require(_poolRegistry != address(0), "Invalid registry address");

        miningRigNFT = IMiningRigNFT(_miningRigNFT);
        poolRegistry = IPoolRegistry(_poolRegistry);

        // Initialize coin-algorithm mappings
        _initializeMappings();
    }

    function _initializeMappings() internal {
        // SHA256D coins
        _coinToAlgorithm[Coin.BTC] = Algorithm.SHA256D;
        _coinToAlgorithm[Coin.BCH] = Algorithm.SHA256D;
        _coinToAlgorithm[Coin.BSV] = Algorithm.SHA256D;
        _algorithmToCoins[Algorithm.SHA256D] = [Coin.BTC, Coin.BCH, Coin.BSV];

        // Scrypt coins
        _coinToAlgorithm[Coin.LTC] = Algorithm.SCRYPT;
        _coinToAlgorithm[Coin.DOGE] = Algorithm.SCRYPT;
        _algorithmToCoins[Algorithm.SCRYPT] = [Coin.LTC, Coin.DOGE];

        // Ethash coins
        _coinToAlgorithm[Coin.ETC] = Algorithm.ETHASH;
        _algorithmToCoins[Algorithm.ETHASH] = [Coin.ETC];

        // RandomX coins
        _coinToAlgorithm[Coin.XMR] = Algorithm.RANDOMX;
        _algorithmToCoins[Algorithm.RANDOMX] = [Coin.XMR];

        // Equihash coins
        _coinToAlgorithm[Coin.ZEC] = Algorithm.EQUIHASH;
        _coinToAlgorithm[Coin.ZEN] = Algorithm.EQUIHASH;
        _algorithmToCoins[Algorithm.EQUIHASH] = [Coin.ZEC, Coin.ZEN];

        // X11 coins
        _coinToAlgorithm[Coin.DASH] = Algorithm.X11;
        _algorithmToCoins[Algorithm.X11] = [Coin.DASH];

        // kHeavyHash coins
        _coinToAlgorithm[Coin.KAS] = Algorithm.KHEAVYHASH;
        _algorithmToCoins[Algorithm.KHEAVYHASH] = [Coin.KAS];
    }

    // ============================================================================
    // Configuration Functions
    // ============================================================================

    /**
     * @dev Configure a mining rig with algorithm, coin, and pool
     */
    function configureRig(
        uint256 rigId,
        Algorithm algorithm,
        Coin coin,
        address poolOperator
    ) external override nonReentrant {
        _requireOwnerOf(rigId);
        _requireNotMining(rigId);
        _requireCooldownPassed(rigId);
        _validateConfiguration(rigId, algorithm, coin, poolOperator);

        RigConfig storage config = rigConfigs[rigId];

        // Store old values for events
        Algorithm oldAlgo = config.algorithm;
        Coin oldCoin = config.coin;
        address oldPool = config.poolOperator;

        // Update configuration
        config.rigId = rigId;
        config.owner = msg.sender;
        config.algorithm = algorithm;
        config.coin = coin;
        config.poolOperator = poolOperator;
        config.lastConfigUpdate = block.timestamp;

        emit RigConfigured(rigId, msg.sender, algorithm, coin, poolOperator);

        if (config.rigId != 0) { // Not first configuration
            if (oldAlgo != algorithm) {
                emit AlgorithmChanged(rigId, oldAlgo, algorithm);
            }
            if (oldCoin != coin) {
                emit CoinChanged(rigId, oldCoin, coin);
            }
            if (oldPool != poolOperator) {
                emit PoolChanged(rigId, oldPool, poolOperator);
            }
        }
    }

    /**
     * @dev Change only the algorithm for a rig
     */
    function setAlgorithm(uint256 rigId, Algorithm algorithm) external override nonReentrant {
        _requireOwnerOf(rigId);
        _requireNotMining(rigId);
        _requireCooldownPassed(rigId);
        _requireConfigured(rigId);

        RigConfig storage config = rigConfigs[rigId];

        // Check if current coin is valid for new algorithm
        require(
            _coinToAlgorithm[config.coin] == algorithm,
            "Current coin not valid for new algorithm"
        );

        // Check pool supports new algorithm
        _validatePoolAlgorithm(config.poolOperator, algorithm);

        Algorithm oldAlgorithm = config.algorithm;
        config.algorithm = algorithm;
        config.lastConfigUpdate = block.timestamp;

        emit AlgorithmChanged(rigId, oldAlgorithm, algorithm);
    }

    /**
     * @dev Change only the coin for a rig
     */
    function setCoin(uint256 rigId, Coin coin) external override nonReentrant {
        _requireOwnerOf(rigId);
        _requireNotMining(rigId);
        _requireCooldownPassed(rigId);
        _requireConfigured(rigId);

        RigConfig storage config = rigConfigs[rigId];

        // Coin must match current algorithm
        require(
            _coinToAlgorithm[coin] == config.algorithm,
            "Coin not valid for current algorithm"
        );

        Coin oldCoin = config.coin;
        config.coin = coin;
        config.lastConfigUpdate = block.timestamp;

        emit CoinChanged(rigId, oldCoin, coin);
    }

    /**
     * @dev Change only the pool for a rig
     */
    function setPool(uint256 rigId, address poolOperator) external override nonReentrant {
        _requireOwnerOf(rigId);
        _requireNotMining(rigId);
        _requireCooldownPassed(rigId);
        _requireConfigured(rigId);

        RigConfig storage config = rigConfigs[rigId];

        // Validate pool
        _validatePoolAlgorithm(poolOperator, config.algorithm);

        address oldPool = config.poolOperator;
        config.poolOperator = poolOperator;
        config.lastConfigUpdate = block.timestamp;

        emit PoolChanged(rigId, oldPool, poolOperator);
    }

    // ============================================================================
    // Mining Control
    // ============================================================================

    /**
     * @dev Start mining with configured settings
     */
    function startMining(uint256 rigId) external override nonReentrant {
        _requireOwnerOf(rigId);
        _requireConfigured(rigId);
        _requireNotMining(rigId);

        RigConfig storage config = rigConfigs[rigId];

        // Verify pool is still active and online
        require(poolRegistry.isNodeOnline(config.poolOperator), "Pool node offline");

        config.isActive = true;
        miningStartTime[rigId] = block.timestamp;

        // Notify NFT contract
        miningRigNFT.setMining(rigId, true);

        emit MiningStarted(rigId, config.poolOperator);
    }

    /**
     * @dev Stop mining
     */
    function stopMining(uint256 rigId) external override nonReentrant {
        _requireOwnerOf(rigId);

        RigConfig storage config = rigConfigs[rigId];
        require(config.isActive, "Not mining");

        uint256 duration = block.timestamp - miningStartTime[rigId];
        config.isActive = false;
        config.totalMiningTime += duration;

        // Notify NFT contract
        miningRigNFT.setMining(rigId, false);

        emit MiningStopped(rigId, duration);
    }

    // ============================================================================
    // View Functions
    // ============================================================================

    /**
     * @dev Get rig configuration
     */
    function getRigConfig(uint256 rigId) external view override returns (RigConfig memory) {
        return rigConfigs[rigId];
    }

    /**
     * @dev Get algorithm for a coin
     */
    function getCoinAlgorithm(Coin coin) external pure override returns (Algorithm) {
        if (coin == Coin.BTC || coin == Coin.BCH || coin == Coin.BSV) return Algorithm.SHA256D;
        if (coin == Coin.LTC || coin == Coin.DOGE) return Algorithm.SCRYPT;
        if (coin == Coin.ETC) return Algorithm.ETHASH;
        if (coin == Coin.XMR) return Algorithm.RANDOMX;
        if (coin == Coin.ZEC || coin == Coin.ZEN) return Algorithm.EQUIHASH;
        if (coin == Coin.DASH) return Algorithm.X11;
        if (coin == Coin.KAS) return Algorithm.KHEAVYHASH;
        revert("Unknown coin");
    }

    /**
     * @dev Get coins for an algorithm
     */
    function getCoinsForAlgorithm(Algorithm algorithm) external view override returns (Coin[] memory) {
        return _algorithmToCoins[algorithm];
    }

    /**
     * @dev Check if coin matches algorithm
     */
    function isCoinValidForAlgorithm(Coin coin, Algorithm algorithm) external view override returns (bool) {
        return _coinToAlgorithm[coin] == algorithm;
    }

    /**
     * @dev Get algorithm name
     */
    function getAlgorithmName(Algorithm algo) external pure returns (string memory) {
        if (algo == Algorithm.SHA256D) return "SHA256D";
        if (algo == Algorithm.SCRYPT) return "Scrypt";
        if (algo == Algorithm.ETHASH) return "Ethash";
        if (algo == Algorithm.RANDOMX) return "RandomX";
        if (algo == Algorithm.EQUIHASH) return "Equihash";
        if (algo == Algorithm.X11) return "X11";
        if (algo == Algorithm.KHEAVYHASH) return "kHeavyHash";
        return "Unknown";
    }

    /**
     * @dev Get coin name
     */
    function getCoinName(Coin coin) external pure returns (string memory) {
        if (coin == Coin.BTC) return "Bitcoin";
        if (coin == Coin.BCH) return "Bitcoin Cash";
        if (coin == Coin.BSV) return "Bitcoin SV";
        if (coin == Coin.LTC) return "Litecoin";
        if (coin == Coin.DOGE) return "Dogecoin";
        if (coin == Coin.ETC) return "Ethereum Classic";
        if (coin == Coin.XMR) return "Monero";
        if (coin == Coin.ZEC) return "Zcash";
        if (coin == Coin.ZEN) return "Horizen";
        if (coin == Coin.DASH) return "Dash";
        if (coin == Coin.KAS) return "Kaspa";
        return "Unknown";
    }

    /**
     * @dev Get current mining duration for an active rig
     */
    function getCurrentMiningDuration(uint256 rigId) external view returns (uint256) {
        if (!rigConfigs[rigId].isActive) return 0;
        return block.timestamp - miningStartTime[rigId];
    }

    /**
     * @dev Get all rigs configured for a specific pool
     */
    function getRigsForPool(address poolOperator, uint256 startId, uint256 endId)
        external view returns (uint256[] memory rigIds, RigConfig[] memory configs)
    {
        // Count matching rigs
        uint256 count = 0;
        for (uint256 i = startId; i <= endId; i++) {
            if (rigConfigs[i].poolOperator == poolOperator) {
                count++;
            }
        }

        // Build arrays
        rigIds = new uint256[](count);
        configs = new RigConfig[](count);

        uint256 j = 0;
        for (uint256 i = startId; i <= endId; i++) {
            if (rigConfigs[i].poolOperator == poolOperator) {
                rigIds[j] = i;
                configs[j] = rigConfigs[i];
                j++;
            }
        }
    }

    // ============================================================================
    // Internal Validation Functions
    // ============================================================================

    function _requireOwnerOf(uint256 rigId) internal view {
        require(miningRigNFT.ownerOf(rigId) == msg.sender, "Not rig owner");
    }

    function _requireNotMining(uint256 rigId) internal view {
        require(!rigConfigs[rigId].isActive, "Stop mining first");
    }

    function _requireConfigured(uint256 rigId) internal view {
        require(rigConfigs[rigId].rigId != 0, "Rig not configured");
    }

    function _requireCooldownPassed(uint256 rigId) internal view {
        if (rigConfigs[rigId].lastConfigUpdate > 0) {
            require(
                block.timestamp >= rigConfigs[rigId].lastConfigUpdate + configCooldown,
                "Config cooldown not passed"
            );
        }
    }

    function _validateConfiguration(
        uint256 rigId,
        Algorithm algorithm,
        Coin coin,
        address poolOperator
    ) internal view {
        // Coin must match algorithm
        require(
            _coinToAlgorithm[coin] == algorithm,
            "Coin not valid for algorithm"
        );

        // If requireMatchingAlgorithm is true, check NFT's built-in algorithm
        if (requireMatchingAlgorithm) {
            IMiningRigNFT.RigTraits memory traits = miningRigNFT.rigTraits(rigId);
            require(
                traits.algorithm == uint8(algorithm),
                "Algorithm must match rig"
            );
        }

        // Validate pool
        _validatePoolAlgorithm(poolOperator, algorithm);
    }

    function _validatePoolAlgorithm(address poolOperator, Algorithm algorithm) internal view {
        // Pool must be registered and active
        require(poolRegistry.isRegistered(poolOperator), "Pool not registered");

        IPoolRegistry.PoolInfo memory poolInfo = poolRegistry.getPool(poolOperator);
        require(
            poolInfo.status == IPoolRegistry.PoolStatus.ACTIVE,
            "Pool not active"
        );

        // Pool must support the algorithm
        bool supportsAlgo = false;
        for (uint256 i = 0; i < poolInfo.supportedAlgorithms.length; i++) {
            if (poolInfo.supportedAlgorithms[i] == uint8(algorithm)) {
                supportsAlgo = true;
                break;
            }
        }
        require(supportsAlgo, "Pool does not support algorithm");
    }

    // ============================================================================
    // Admin Functions
    // ============================================================================

    /**
     * @dev Set configuration cooldown period
     */
    function setConfigCooldown(uint256 newCooldown) external onlyOwner {
        require(newCooldown <= 24 hours, "Cooldown too long");
        configCooldown = newCooldown;
    }

    /**
     * @dev Set whether algorithm must match NFT's built-in algorithm
     */
    function setRequireMatchingAlgorithm(bool required) external onlyOwner {
        requireMatchingAlgorithm = required;
    }
}
