// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "../interfaces/IWATT.sol";
import "../interfaces/IMiningRigNFT.sol";
import "./PayoutHub.sol";

/**
 * @title NodeMiningEngine
 * @dev Point an NFT rig at somebody's node and get paid in that chain's coin.
 *
 * The shift from MiningEngine: what a rig earns is no longer decided by its
 * algorithm trait. A miner picks a pool, the pool names a payout target, and
 * that is what they are paid in -- which is what makes proof-of-stake chains
 * and masternodes possible as payout options at all, since neither is reached
 * by a mining algorithm. Traits still decide how MUCH: effective power is
 * hashRate x efficiency / wattConsumption, exactly as before, and a rig's share
 * is diluted by the other rigs pointed at the same pool.
 *
 * Pools may still demand a specific algorithm (a real SHA256d pool wants
 * SHA256d rigs); PoS and masternode pools normally take anything.
 *
 * Two things the pool owner earns:
 *   1. a share of each miner's reward, at a rate of their choosing, and
 *   2. a share of the WATT their miners consume, after the burn.
 *
 * WATT consumption splits three ways: a protocol-fixed BURN_BPS is sent to the
 * dead address and can never be lowered by a pool, the owner takes their chosen
 * cut of what survives, and the rest goes to the stakers. WATT has no burn()
 * -- it is an already-deployed ERC20 -- so the burn is a transfer to
 * 0x…dEaD, which anyone can verify.
 *
 * FEE POLICY, stated plainly because it is unusual: rewardFeeBps is uncapped
 * and the owner may change it at any time, including while sessions are open.
 * A pool owner can therefore set 100% and take everything a miner subsequently
 * earns. This is deliberate. Every change emits PoolFeeChanged, the current
 * rate is readable on-chain before joining, and the rate actually applied is
 * emitted with each payout -- so the behaviour is auditable, not hidden. Miners
 * should check the fee before pointing a rig at a pool, and can stop mining at
 * any time; already-credited rewards cannot be clawed back.
 */
contract NodeMiningEngine is Ownable, ReentrancyGuard {
    uint16 public constant BPS = 10000;

    /// @dev Protocol-fixed share of consumed WATT that is destroyed. No pool
    ///      can reduce it; it is a constant so it cannot be governance-tuned.
    uint16 public constant BURN_BPS = 5000; // 50%

    address public constant DEAD = 0x000000000000000000000000000000000000dEaD;

    /// @dev 255 means "any rig"; 0-6 pins the pool to one algorithm.
    uint8 public constant ANY_ALGO = 255;

    IWATT public immutable watt;
    PayoutHub public immutable hub;
    address public stakingPool;

    uint256 public rewardRate = 1e12; // per unit effective power per second

    struct Pool {
        address owner;
        uint256 targetId;        // payout target in the hub
        uint8 requiredAlgo;      // ANY_ALGO for PoS/masternode pools
        uint16 rewardFeeBps;     // owner's cut of miner rewards (uncapped)
        uint16 wattCutBps;       // owner's cut of WATT that survives the burn
        string name;
        string nodeEndpoint;     // RPC/masternode the miner is pointing at
        bool active;
        uint256 hashRate;        // sum of hashRate trait across active rigs
        uint256 minersActive;
        uint256 feesEarned;      // reward-side fees, in target units
        uint256 wattEarned;
    }

    Pool[] public pools;

    struct Session {
        address owner;
        address nftContract;
        uint256 rigId;
        uint256 poolId;
        uint256 startTime;
        uint256 lastClaimTime;
        uint256 wattDeposited;
        uint256 wattSettled;     // WATT already split away
        uint256 earned;          // credited to the miner, net of fee
        uint256 owed;            // accrued but the target could not cover it
        bool active;
    }

    mapping(bytes32 => Session) public sessions;
    mapping(address => bytes32[]) public sessionsOf;
    mapping(address => bool) public allowedNFT;

    event NFTContractAllowed(address indexed nft, bool allowed);
    event PoolCreated(uint256 indexed poolId, address indexed owner, uint256 targetId, string name);
    event PoolFeeChanged(uint256 indexed poolId, uint16 oldRewardFeeBps, uint16 newRewardFeeBps,
                         uint16 oldWattCutBps, uint16 newWattCutBps);
    event PoolActiveSet(uint256 indexed poolId, bool active);
    event MiningStarted(uint256 indexed poolId, address indexed nft, uint256 indexed rigId,
                        address miner, uint256 wattDeposited);
    event MiningStopped(uint256 indexed poolId, address indexed nft, uint256 indexed rigId, address miner);
    event Paid(uint256 indexed poolId, address indexed miner, uint256 gross, uint256 fee,
               uint256 net, uint16 feeBpsApplied);
    event Unpaid(uint256 indexed poolId, address indexed miner, uint256 amountOwed);
    event WattSplit(uint256 indexed poolId, uint256 consumed, uint256 burned,
                    uint256 toOwner, uint256 toStakers);

    modifier validPool(uint256 poolId) { require(poolId < pools.length, "No such pool"); _; }

    constructor(address _watt, address _hub) Ownable(msg.sender) {
        require(_watt != address(0) && _hub != address(0), "Zero address");
        watt = IWATT(_watt);
        hub = PayoutHub(_hub);
    }

    // --- administration --------------------------------------------------

    function setStakingPool(address p) external onlyOwner { stakingPool = p; }
    function setRewardRate(uint256 r) external onlyOwner { rewardRate = r; }

    function setNFTContract(address nft, bool allowed) external onlyOwner {
        allowedNFT[nft] = allowed;
        emit NFTContractAllowed(nft, allowed);
    }

    // --- pools -------------------------------------------------------------

    /// @param rewardFeeBps owner's cut of miner rewards. Uncapped by design.
    /// @param wattCutBps   owner's cut of the WATT left after the fixed burn.
    function createPool(
        uint256 targetId,
        uint8 requiredAlgo,
        uint16 rewardFeeBps,
        uint16 wattCutBps,
        string calldata name,
        string calldata nodeEndpoint
    ) external returns (uint256 poolId) {
        require(targetId < hub.targetCount(), "No such target");
        require(rewardFeeBps <= BPS && wattCutBps <= BPS, "Over 100%");
        require(requiredAlgo == ANY_ALGO || requiredAlgo < 7, "Bad algo");

        poolId = pools.length;
        pools.push(Pool({
            owner: msg.sender, targetId: targetId, requiredAlgo: requiredAlgo,
            rewardFeeBps: rewardFeeBps, wattCutBps: wattCutBps,
            name: name, nodeEndpoint: nodeEndpoint, active: true,
            hashRate: 0, minersActive: 0, feesEarned: 0, wattEarned: 0
        }));
        emit PoolCreated(poolId, msg.sender, targetId, name);
    }

    /// @dev Changeable at any time, including on open sessions -- see the fee
    ///      policy note on this contract. The event is the miner's audit trail.
    function setPoolFees(uint256 poolId, uint16 rewardFeeBps, uint16 wattCutBps)
        external validPool(poolId)
    {
        Pool storage p = pools[poolId];
        require(msg.sender == p.owner, "Not pool owner");
        require(rewardFeeBps <= BPS && wattCutBps <= BPS, "Over 100%");
        emit PoolFeeChanged(poolId, p.rewardFeeBps, rewardFeeBps, p.wattCutBps, wattCutBps);
        p.rewardFeeBps = rewardFeeBps;
        p.wattCutBps = wattCutBps;
    }

    function setPoolActive(uint256 poolId, bool active) external validPool(poolId) {
        Pool storage p = pools[poolId];
        require(msg.sender == p.owner || msg.sender == owner(), "Not authorized");
        p.active = active;
        emit PoolActiveSet(poolId, active);
    }

    function setPoolEndpoint(uint256 poolId, string calldata endpoint) external validPool(poolId) {
        require(msg.sender == pools[poolId].owner, "Not pool owner");
        pools[poolId].nodeEndpoint = endpoint;
    }

    // --- mining ------------------------------------------------------------

    function startMining(address nftContract, uint256 rigId, uint256 wattAmount, uint256 poolId)
        external nonReentrant validPool(poolId)
    {
        require(allowedNFT[nftContract], "NFT contract not allowed");
        Pool storage p = pools[poolId];
        require(p.active, "Pool inactive");

        IMiningRigNFT nft = IMiningRigNFT(nftContract);
        require(nft.ownerOf(rigId) == msg.sender, "Not owner");
        require(!nft.isStaked(rigId), "Rig is staked");

        bytes32 key = _key(nftContract, rigId);
        require(!sessions[key].active, "Already mining");

        IMiningRigNFT.RigTraits memory t = nft.rigTraits(rigId);
        require(p.requiredAlgo == ANY_ALGO || p.requiredAlgo == t.algorithm, "Wrong algorithm for pool");

        uint256 perHour = uint256(t.wattConsumption) * 1e18;
        require(wattAmount >= perHour, "Min 1 hour WATT required");
        require(watt.transferFrom(msg.sender, address(this), wattAmount), "WATT transfer failed");

        nft.transferFrom(msg.sender, address(this), rigId);
        nft.setMining(rigId, true);

        sessions[key] = Session({
            owner: msg.sender, nftContract: nftContract, rigId: rigId, poolId: poolId,
            startTime: block.timestamp, lastClaimTime: block.timestamp,
            wattDeposited: wattAmount, wattSettled: 0, earned: 0, owed: 0, active: true
        });
        sessionsOf[msg.sender].push(key);

        p.hashRate += t.hashRate;
        p.minersActive++;

        emit MiningStarted(poolId, nftContract, rigId, msg.sender, wattAmount);
    }

    function claim(address nftContract, uint256 rigId) external nonReentrant {
        bytes32 key = _key(nftContract, rigId);
        require(sessions[key].owner == msg.sender, "Not owner");
        require(sessions[key].active, "Not mining");
        _settle(key);
    }

    /**
     * @dev Unwind a session and return the rig.
     *
     * Settlement here must never be able to revert the unwind: the rig is held
     * by this contract, so a failure to pay would otherwise strand it. Anything
     * the payout target cannot cover is recorded as owed and emitted, and the
     * NFT goes back regardless.
     */
    function stopMining(address nftContract, uint256 rigId) external nonReentrant {
        bytes32 key = _key(nftContract, rigId);
        Session storage s = sessions[key];
        require(s.owner == msg.sender, "Not owner");
        require(s.active, "Not mining");

        _settle(key);

        Pool storage p = pools[s.poolId];
        IMiningRigNFT nft = IMiningRigNFT(nftContract);
        IMiningRigNFT.RigTraits memory t = nft.rigTraits(rigId);

        uint256 refund = s.wattDeposited > s.wattSettled ? s.wattDeposited - s.wattSettled : 0;

        s.active = false;
        if (p.hashRate >= t.hashRate) p.hashRate -= t.hashRate; else p.hashRate = 0;
        if (p.minersActive > 0) p.minersActive--;

        if (refund > 0) require(watt.transfer(msg.sender, refund), "Refund failed");

        nft.setMining(rigId, false);
        nft.transferFrom(address(this), msg.sender, rigId);

        emit MiningStopped(s.poolId, nftContract, rigId, msg.sender);
    }

    // --- internals ---------------------------------------------------------

    function _settle(bytes32 key) internal {
        _settleWatt(key);
        _settleRewards(key);
    }

    /// @dev Split the WATT consumed since last settlement: burn, owner, stakers.
    function _settleWatt(bytes32 key) internal {
        Session storage s = sessions[key];
        Pool storage p = pools[s.poolId];

        uint256 consumedTotal = _wattConsumed(key);
        if (consumedTotal <= s.wattSettled) return;

        uint256 amount = consumedTotal - s.wattSettled;
        s.wattSettled = consumedTotal;

        uint256 burned = (amount * BURN_BPS) / BPS;
        uint256 rest = amount - burned;
        uint256 toOwner = (rest * p.wattCutBps) / BPS;
        uint256 toStakers = rest - toOwner;

        if (burned > 0) require(watt.transfer(DEAD, burned), "Burn failed");
        if (toOwner > 0) {
            require(watt.transfer(p.owner, toOwner), "Owner WATT failed");
            p.wattEarned += toOwner;
        }
        if (toStakers > 0 && stakingPool != address(0)) {
            require(watt.transfer(stakingPool, toStakers), "Staker WATT failed");
            // Best-effort notify; a staking pool that does not implement it
            // must not be able to block settlement.
            (bool ok, ) = stakingPool.call(abi.encodeWithSignature("notifyReward(uint256)", toStakers));
            ok; // deliberately ignored
        }
        emit WattSplit(s.poolId, amount, burned, toOwner, toStakers);
    }

    function _settleRewards(bytes32 key) internal {
        Session storage s = sessions[key];
        Pool storage p = pools[s.poolId];

        uint256 gross = pendingRewards(s.nftContract, s.rigId) + s.owed;
        s.lastClaimTime = block.timestamp;
        s.owed = 0;
        if (gross == 0) return;

        uint16 feeBps = p.rewardFeeBps;         // rate at settlement time
        uint256 fee = (gross * feeBps) / BPS;
        uint256 net = gross - fee;

        uint256 paidNet = net > 0 ? hub.credit(s.owner, p.targetId, net) : 0;
        uint256 paidFee = fee > 0 ? hub.credit(p.owner, p.targetId, fee) : 0;

        s.earned += paidNet;
        p.feesEarned += paidFee;

        uint256 short = (net - paidNet) + (fee - paidFee);
        if (short > 0) {
            s.owed = short;
            emit Unpaid(s.poolId, s.owner, short);
        }
        emit Paid(s.poolId, s.owner, gross, paidFee, paidNet, feeBps);
    }

    function _wattConsumed(bytes32 key) internal view returns (uint256) {
        Session memory s = sessions[key];
        uint256 perHour = IMiningRigNFT(s.nftContract).getWattPerHour(s.rigId);
        uint256 used = ((block.timestamp - s.startTime) * perHour) / 3600;
        return used > s.wattDeposited ? s.wattDeposited : used;
    }

    function _key(address nft, uint256 rigId) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(nft, rigId));
    }

    // --- views ---------------------------------------------------------------

    /// @dev Traits set the rate; the pool's total hashrate dilutes it.
    function pendingRewards(address nftContract, uint256 rigId) public view returns (uint256) {
        bytes32 key = _key(nftContract, rigId);
        Session memory s = sessions[key];
        if (!s.active) return 0;

        uint256 poolHash = pools[s.poolId].hashRate;
        if (poolHash == 0) return 0;

        uint256 power = IMiningRigNFT(nftContract).getEffectivePower(rigId);
        return (power * (block.timestamp - s.lastClaimTime) * rewardRate) / poolHash;
    }

    function poolCount() external view returns (uint256) { return pools.length; }

    function getPool(uint256 poolId) external view returns (Pool memory) {
        require(poolId < pools.length, "No such pool");
        return pools[poolId];
    }

    function getSession(address nftContract, uint256 rigId) external view returns (Session memory) {
        return sessions[_key(nftContract, rigId)];
    }

    function wattConsumedSoFar(address nftContract, uint256 rigId) external view returns (uint256) {
        return _wattConsumed(_key(nftContract, rigId));
    }
}
